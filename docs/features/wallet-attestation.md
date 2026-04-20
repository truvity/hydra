# Feature: Wallet Attestation Client Authentication (draft-07)

## Overview

This feature implements Wallet Attestation client authentication (`attest_jwt_client_auth`) for the Hydra AS fork per draft-ietf-oauth-attestation-based-client-auth-07, OIDC4VCI Appendix E, and HAIP §4.4.1.

Wallet Attestation is a `ClientAuthenticationStrategy` — not a `TokenEndpointHandler` — that plugs into `Fosite.AuthenticateClient()` via `fositex.Config.GetClientAuthenticationStrategy()`. It validates two HTTP headers on PAR and Token requests:

- `OAuth-Client-Attestation` — a JWT signed by the Wallet Provider (Client Attester), with `typ: oauth-client-attestation+jwt`, carrying the `cnf` claim binding the Client Instance Key (draft-07 §5.1)
- `OAuth-Client-Attestation-PoP` — a Proof of Possession JWT signed by the Wallet instance using the key from `cnf`, with `typ: oauth-client-attestation-pop+jwt` (draft-07 §5.2)

The authenticator lives in `fosite/handler/wallet_attestation/`. It is not registered via `Compose()` — it is created lazily on `fositex.Config` and invoked by the strategy function returned from `GetClientAuthenticationStrategy`.

The scope is strictly the Authorization Server role.

## Client Model

Wallet Attestation uses a shared pre-registered client record per wallet type. The operator creates one `Wallet_Type_Client_Record` per trusted wallet type:

- `client_id` matches the `sub` claim from the Wallet Provider's attestations (e.g., `https://wallet.example.org`)
- `token_endpoint_auth_method` set to `attest_jwt_client_auth`
- Grant types, scopes, redirect URIs, and audience restrictions configured as needed

The `sub` claim identifies the wallet type, not an individual wallet instance — this is mandated by HAIP §4.4.1 and OIDC4VCI §15.4.4 for privacy. Individual wallet instances are distinguished by their Client Instance Key (the `cnf.jwk` in the attestation), which is used for refresh token binding.

## Configuration

### Config Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `wallet_attestation.enabled` (`KeyWalletAttestationEnabled`) | `bool` | `false` | Enable Wallet Attestation authenticator |
| `wallet_attestation.trust_anchors` (`KeyWalletAttestationTrustAnchors`) | `[]string` | `[]` | PEM-encoded trust anchor (root CA) certificates |

### Provider Interface

- `WalletAttestationConfigProvider` (`fosite/config.go`) — `GetWalletAttestationEnabled(ctx) bool`, `GetWalletAttestationTrustAnchors(ctx) []*x509.Certificate`

Embedded in the Fosite `Configurator` interface and implemented on `driver/config.DefaultProvider`. The `fositex.Config` runtime adapter inherits these methods via its embedded `*config.DefaultProvider`.

### Example Configuration

```yaml
wallet_attestation:
  enabled: true
  trust_anchors:
    - |
      -----BEGIN CERTIFICATE-----
      MIIBxTCCAWugAwIBAgIUJnZ+av7kFRaCrKlNi4RSgRMlMzcwCg...
      -----END CERTIFICATE-----
```

## Operator Setup Guide

1. Obtain the root CA certificate(s) of the Wallet Provider(s) you trust.
2. Add each PEM-encoded certificate to `wallet_attestation.trust_anchors`.
3. Set `wallet_attestation.enabled: true`.
4. For each wallet type, create a client record:

```
POST /admin/clients
{
  "client_id": "https://wallet.example.org",
  "token_endpoint_auth_method": "attest_jwt_client_auth",
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid ...",
  "redirect_uris": ["..."]
}
```

The `client_id` must match the `sub` value that the Wallet Provider puts in its attestation JWTs. All wallet instances of that type share this single client record.

## Authentication Flow

When a PAR or Token request arrives, `Fosite.AuthenticateClient()` calls `GetClientAuthenticationStrategy()`:

1. If `OAuth-Client-Attestation` header is absent → fallback to `DefaultClientAuthenticationStrategy` (handles `client_secret_post`, `client_secret_basic`, `private_key_jwt`, `none`).
2. If header is present → delegate to the Wallet Attestation authenticator.

The authenticator validates in order (attestation first per draft-07 §6.1 recommendation):

### Phase 1: Client Attestation JWT (draft-07 §5.1, §9)

1. Parse JWT from `OAuth-Client-Attestation` header
2. Validate `typ` == `oauth-client-attestation+jwt`
3. Validate `alg` is a supported asymmetric algorithm (not `none`, not symmetric)
4. Extract `x5c` JOSE header (required per HAIP §4.4.1)
5. Decode and parse X.509 certificate chain
6. HAIP: verify leaf cert is not self-signed
7. HAIP: verify trust anchor is not in the `x5c` chain
8. Verify chain terminates at a configured trust anchor via `x509.Certificate.Verify()`
9. Verify JWT signature using leaf cert's public key
10. Validate `exp` (not expired, with clock skew tolerance)
11. Validate `nbf` if present
12. Validate `iss` is present
13. Extract `sub` (this is the `client_id`)
14. Extract `cnf.jwk` — must be a public key (no `d` parameter)
15. If `client_id` in form body, verify it matches `sub`

### Phase 2: Client Attestation PoP JWT (draft-07 §5.2, §9)

16. Parse JWT from `OAuth-Client-Attestation-PoP` header
17. Validate `typ` == `oauth-client-attestation-pop+jwt`
18. Validate `alg` (same rules as attestation JWT)
19. Verify signature using `cnf.jwk` from Phase 1
20. Validate `iss` matches `sub` from attestation
21. Validate `aud` matches AS Issuer Identifier
22. Validate `iat` is recent (within freshness window, default 60s)
23. Validate `jti` is unique (replay detection via shared DPoP JTI table)
24. Validate `nbf` if present

### Phase 3: Client Lookup

25. Look up client by `sub` via `Store.GetClient(ctx, sub)`
26. Verify `token_endpoint_auth_method == "attest_jwt_client_auth"`
27. Return authenticated client

## HAIP-Specific Constraints (HAIP §4.4.1)

- The `x5c` JOSE header is required on the Client Attestation JWT for key resolution.
- The trust anchor certificate itself must NOT be included in the `x5c` chain.
- The leaf certificate (signing certificate) must NOT be self-signed.
- The `sub` claim must be shared across all wallet instances of the same type — it identifies the wallet type, not the individual instance.
- Wallets must authenticate at both PAR and Token endpoints using the same rules.

## Refresh Token Binding (draft-07 §10.3)

Refresh tokens issued via Wallet Attestation are bound to the Client Instance Key:

- On token issuance: the JWK Thumbprint (SHA-256, base64url per RFC 7638) of the `cnf.jwk` is stored in `session.Extra["wallet_attestation_cnf_jkt"]`.
- On refresh: the current attestation's `cnf.jwk` thumbprint is compared against the stored value. If they differ, the request is rejected with `invalid_client`.

This ensures only the original wallet instance (with the same key pair) can use the refresh token, per draft-07 §10.3: "The client MUST also use the same key that was present in the cnf claim of the client attestation that was used when the refresh token was issued."

A lightweight `RefreshBindingHandler` (`TokenEndpointHandler`) handles the session storage and comparison, since the `ClientAuthenticationStrategy` function does not have access to the session.

## Attestation Reuse (draft-07 §10.2)

A single Client Attestation JWT can be reused across multiple requests with fresh PoP JWTs. Replay protection applies only to the PoP JWT's `jti`, not to the attestation JWT itself. The attestation's `exp` claim controls how long it can be reused.

## Error Codes

All validation errors use `invalid_client` (HTTP 401) with specific `.WithHint()` messages. The optional `invalid_client_attestation` error code from draft-07 §6.2 is also available.

| Error | Hint | Cause |
|-------|------|-------|
| `invalid_client` | Wallet Attestation is not a well-formed JWT | Malformed JWT in header |
| `invalid_client` | Wallet Attestation typ must be oauth-client-attestation+jwt | Wrong `typ` header |
| `invalid_client` | Wallet Attestation uses unsupported signing algorithm | `alg` is `none`, symmetric, or unsupported |
| `invalid_client` | Wallet Attestation is missing the x5c JOSE header | No `x5c` in attestation JWT |
| `invalid_client` | Wallet Attestation signing certificate must not be self-signed | HAIP: leaf cert is self-signed |
| `invalid_client` | Trust anchor must not be included in x5c chain | HAIP: trust anchor found in `x5c` |
| `invalid_client` | Wallet Attestation certificate chain is not trusted | Chain doesn't terminate at trust anchor |
| `invalid_client` | Wallet Attestation signature verification failed | Signature doesn't verify with leaf cert key |
| `invalid_client` | Wallet Attestation is expired | `exp` has passed |
| `invalid_client` | Wallet Attestation is not yet valid | `nbf` is in the future |
| `invalid_client` | Wallet Attestation is missing iss claim | No `iss` claim |
| `invalid_client` | Wallet Attestation sub does not match client_id | `sub` != form `client_id` |
| `invalid_client` | Wallet Attestation is missing the cnf claim | No `cnf.jwk` |
| `invalid_client` | Wallet Attestation cnf must contain a public key only | Private key material in `cnf.jwk` |
| `invalid_client` | OAuth-Client-Attestation-PoP header is required | Missing PoP header |
| `invalid_client` | PoP JWT typ must be oauth-client-attestation-pop+jwt | Wrong PoP `typ` |
| `invalid_client` | PoP JWT uses unsupported signing algorithm | PoP `alg` unsupported |
| `invalid_client` | PoP JWT signature verification failed | PoP signature invalid |
| `invalid_client` | PoP JWT iss does not match client_id | PoP `iss` != attestation `sub` |
| `invalid_client` | PoP JWT aud does not match AS issuer | PoP `aud` != AS issuer URL |
| `invalid_client` | PoP JWT iat is not recent | `iat` outside freshness window |
| `invalid_client` | PoP JWT jti has already been used | Replay detected |
| `invalid_client` | PoP JWT is not yet valid | PoP `nbf` in the future |
| `invalid_client` | No client record found for wallet type | No client with matching `client_id` |
| `invalid_client` | Client is not configured for attestation-based authentication | Wrong `token_endpoint_auth_method` |
| `invalid_client` | Refresh token is bound to a different client instance key | `cnf.jwk` thumbprint mismatch on refresh |

## Integration Point

`GetClientAuthenticationStrategy` on `fositex.Config` returns a non-nil strategy function when Wallet Attestation is enabled. The strategy checks for the `OAuth-Client-Attestation` header:

- Present → Wallet Attestation authenticator
- Absent → `fositeInstance.DefaultClientAuthenticationStrategy(ctx, r, form)`

When Wallet Attestation is disabled, `GetClientAuthenticationStrategy` returns `nil` and Fosite uses its default authentication directly.

The circular dependency between `fositex.Config` and the `*fosite.Fosite` instance (needed for fallback) is resolved via `SetFositeInstance()`, called in `RegistrySQL.OAuth2Provider()` after Fosite creation.

## References

- [draft-ietf-oauth-attestation-based-client-auth-07](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html) — Primary protocol specification
- [HAIP §4.4.1](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html#section-4.4.1) — Wallet Attestation profile rules (x5c required, trust anchor exclusion, no self-signed certs, shared sub)
- [OIDC4VCI Appendix E](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-E) — Wallet Attestations in JWT format (additional claims: wallet_name, wallet_link, status)
