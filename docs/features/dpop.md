# Feature: DPoP Token Binding (RFC 9449)

## Overview

This feature implements DPoP (Demonstrating Proof of Possession — RFC 9449) token binding for the Hydra AS fork:

- **DPoP proof validation** — A cross-cutting Fosite handler (`fosite/handler/dpop/`) that validates DPoP proof JWTs per the full RFC 9449 §4.3 checklist (12 checks) on token and PAR requests.
- **Token binding** — When a valid DPoP proof is present, the handler binds the issued access token to the client's public key via `cnf.jkt` and sets `token_type=DPoP`.
- **Nonce exchange** — Optional stateless HMAC-based nonce mechanism for replay protection of pre-computed DPoP proofs.
- **Authorization code binding** — `dpop_jkt` parameter support at PAR for binding authorization codes to a specific DPoP key (RFC 9449 §10).
- **Refresh token binding** — DPoP key binding on refresh tokens for public clients, preventing stolen refresh tokens from being used without the private key.

The DPoP handler is a cross-cutting `TokenEndpointHandler` that decorates all grant types — it does not own a grant type. When a `DPoP` HTTP header is present on a token request, the handler validates the proof, binds the token, and sets the token type. The handler also implements `PushedAuthorizeEndpointHandler` for `dpop_jkt` extraction at PAR.

The scope is strictly the Authorization Server role. The Credential Issuer validates DPoP proofs against `cnf.jkt` from introspection independently — that is out of scope.

## Why DPoP?

Standard OAuth 2.0 Bearer tokens are vulnerable to token theft — anyone who obtains the token can use it. DPoP sender-constrains access tokens by binding them to a client's public key at the application layer. The Wallet proves possession of the corresponding private key on every request, so a stolen token is useless without the key.

DPoP operates at the application layer (HTTP headers), unlike mTLS which requires TLS-level certificate binding. This makes DPoP practical for mobile Wallet apps and browser-based clients where mTLS is difficult to deploy.

The HAIP (High Assurance Interoperability Profile) requires DPoP with ES256 for all credential issuance flows.

## Configuration

### Config Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dpop.enabled` (`KeyDPoPEnabled`) | `bool` | `false` | Enable DPoP handler registration in the Fosite pipeline |
| `dpop.signing_alg_values_supported` (`KeyDPoPSigningAlgValues`) | `[]string` | `["ES256"]` | Supported JWS algorithms for DPoP proof JWTs |
| `dpop.nonce_enabled` (`KeyDPoPNonceEnabled`) | `bool` | `false` | Enable DPoP nonce exchange for replay protection |
| `dpop.nonce_lifespan` (`KeyDPoPNonceLifespan`) | `duration` | `5m` | Lifespan of server-issued DPoP nonces |
| `dpop.proof_max_age` (`KeyDPoPProofMaxAge`) | `duration` | `60s` | Maximum age for DPoP proof `iat` claim |

### Provider Interface

- **`DPoPConfigProvider`** (`fosite/config.go`) — `GetDPoPEnabled(ctx) bool`, `GetDPoPSigningAlgValuesSupported(ctx) []string`, `GetDPoPNonceEnabled(ctx) bool`, `GetDPoPNonceLifespan(ctx) time.Duration`, `GetDPoPProofMaxAge(ctx) time.Duration`, `GetDPoPPARURLs(ctx) []string`

Embedded in the Fosite `Configurator` interface and implemented on `driver/config.DefaultProvider`. The `fositex.Config` runtime adapter inherits these methods via its embedded `*config.DefaultProvider`. `GetDPoPPARURLs` is computed from `PublicURL` and `IssuerURL` (no separate config key), mirroring the existing `GetTokenURLs` pattern.

### Example Configuration

```yaml
dpop:
  enabled: true
  signing_alg_values_supported:
    - ES256
  nonce_enabled: true
  nonce_lifespan: 5m
  proof_max_age: 60s
```

## DPoP Proof Validation (RFC 9449 §4.3 Checklist)

When a token or PAR request includes a `DPoP` HTTP header, the handler validates the proof JWT through all 12 checks defined in RFC 9449 §4.3. Any check failure results in an `invalid_dpop_proof` error (HTTP 400).

| # | Check | Description |
|---|-------|-------------|
| 1 | Single header | Verify there is not more than one `DPoP` header field. Multiple headers → reject. |
| 2 | Well-formed JWT | Parse the header value as a valid JWT per RFC 7519. Malformed → reject. |
| 3 | Required claims | Verify `jti`, `htm`, `htu`, and `iat` claims are all present. Missing → reject. |
| 4 | `typ` header | Verify the `typ` JOSE header is `dpop+jwt`. Wrong or missing → reject. |
| 5 | `alg` header | Verify `alg` is a registered asymmetric algorithm, not `none`, not symmetric (HS*), and in `GetDPoPSigningAlgValuesSupported()`. Unsupported → reject. |
| 6 | Signature | Extract the public key from the `jwk` JOSE header and verify the JWT signature. Invalid → reject. |
| 7 | No private key material | Verify `jwk` does not contain private key fields (`d`, `p`, `q`, `dp`, `dq`, `qi` for RSA; `d` for EC/OKP). Present → reject. |
| 8 | `htm` claim | Verify `htm` matches `POST`. Mismatch → reject. |
| 9 | `htu` claim | Verify `htu` matches the expected endpoint URL (token or PAR) after RFC 3986 §6.2.2–6.2.3 normalization (lowercase scheme/host, remove default port, normalize path). Mismatch → reject. |
| 10 | `nonce` claim | When nonces are enabled: verify `nonce` matches a valid server nonce via `ValidateDPoPNonce`. Missing/invalid → return `use_dpop_nonce` with fresh nonce in `DPoP-Nonce` header. |
| 11 | `iat` freshness | Verify `iat` is within `[now - GetDPoPProofMaxAge(), now + 5s]`. The 5-second future tolerance is hardcoded for clock skew. Out of range → reject. |
| 12 | `jti` uniqueness | Check `IsJTIUsed(jti)`. If used → reject. If unique → `MarkJTIUsed(jti, expiry)`. |

The `ath` (access token hash) check from §4.3 applies only at the resource server, not at the token endpoint where the access token has not yet been issued. It is out of scope for this handler.

## Error Codes

All DPoP errors use HTTP 400 status code per RFC 9449. Error constants are defined in `fosite/handler/dpop/errors.go`.

| Error Code | Constant | Condition |
|------------|----------|-----------|
| `invalid_dpop_proof` | `ErrInvalidDPoPProof` | DPoP proof fails any of the 12 validation checks, `dpop_jkt` binding mismatch, or refresh token key mismatch |
| `use_dpop_nonce` | `ErrUseDPoPNonce` | Nonces are enabled but the proof is missing a valid `nonce` claim. Response includes `DPoP-Nonce` header with a fresh nonce. |

Context is added via `.WithHint()` and `.WithDebugf()` at each call site, following the RAR handler pattern.

## Nonce Exchange Flow

When `dpop.nonce_enabled` is `true`, the AS requires a server-issued nonce in every DPoP proof. This prevents pre-computed proofs from XSS attacks.

### Stateless HMAC-Based Nonces

Nonces are stateless — no database table is needed. Each nonce is self-verifying:

**Format**: `base64url(timestamp_8bytes || random_16bytes || hmac_16bytes)`

- `timestamp_8bytes` — Big-endian Unix timestamp (seconds) of nonce creation
- `random_16bytes` — 128 bits of cryptographic randomness
- `hmac_16bytes` — Truncated HMAC-SHA256 over `timestamp || random` using the global secret

Any AS instance can validate nonces created by any other instance (they share the global secret). The timestamp enables expiry enforcement against `GetDPoPNonceLifespan()`.

### Exchange Sequence

1. Client sends a token request with a DPoP proof (no `nonce` claim on first attempt).
2. AS rejects with `use_dpop_nonce` error and sets `DPoP-Nonce: <fresh_nonce>` response header.
3. Client retries with the nonce in the DPoP proof's `nonce` claim.
4. AS validates the nonce, issues the token, and sets `DPoP-Nonce: <new_nonce>` on the success response for the client's next request.

The `DPoP-Nonce` header is set on both success and error responses when nonces are enabled. The handler delivers the nonce via a `*string` pointer in the request context — the endpoint handler reads it after the Fosite call returns and sets the HTTP header.

## Authorization Code Binding via `dpop_jkt` (RFC 9449 §10)

The `dpop_jkt` parameter binds an authorization code to a specific DPoP key at PAR time. Even if the authorization code is intercepted, it cannot be exchanged without the corresponding private key.

### PAR Integration

The DPoP handler implements `PushedAuthorizeEndpointHandler` to process `dpop_jkt` at PAR:

**Two mechanisms** (RFC 9449 §10.1 requires support for both when PAR and DPoP are enabled):

1. **`dpop_jkt` parameter** — Client includes the JWK Thumbprint of its DPoP public key as a PAR request parameter. The handler stores it in the request form for PAR session persistence.

2. **`DPoP` header on PAR** — Client includes a DPoP proof JWT on the PAR request itself. The handler validates the proof (adapted for PAR: `htm=POST`, `htu` from `GetDPoPPARURLs()`), computes the JKT, and stores it as `dpop_jkt` in the request form.

**Both present**: If both `dpop_jkt` parameter and `DPoP` header are present, the handler verifies the thumbprints match. Mismatch → `invalid_dpop_proof`.

**Neither present**: The handler returns `nil` (not responsible).

### Propagation Path

1. `dpop_jkt` is stored in the PAR session's request form.
2. `authorizeRequestFromPAR()` merges PAR form data into the authorize request.
3. `dpop_jkt` is carried through the authorization session to the token endpoint.
4. At the token endpoint, `HandleTokenEndpointRequest` reads `dpop_jkt` from the session and verifies the DPoP proof's public key matches.

## Refresh Token DPoP Binding (RFC 9449 §5)

DPoP binding on refresh tokens depends on whether the client is public or confidential.

### Public vs Confidential Client Detection

The handler detects client type by checking the token endpoint authentication method:

| Auth Method | Client Type | Refresh Token Binding |
|-------------|-------------|----------------------|
| `none` | Public | DPoP key bound |
| `attest_jwt_client_auth` | Public (Wallet Attestation) | DPoP key bound |
| `client_secret_post` | Confidential | Not bound |
| `client_secret_basic` | Confidential | Not bound |
| `private_key_jwt` | Confidential | Not bound |

### Binding Rules

- **Public clients**: When a refresh token is issued with a valid DPoP proof, the JKT is stored in `session.Extra["dpop_jkt_binding"]`. On subsequent refresh token exchanges, the DPoP proof must use the same public key. A different key → `invalid_dpop_proof`.

- **Confidential clients**: The access token is DPoP-bound (`cnf.jkt`), but the refresh token is not. Confidential clients are already sender-constrained via client authentication, and not binding the refresh token avoids breaking key rotation scenarios.

## Token Binding and Introspection

### `cnf.jkt` in Session.Extra

After `PopulateTokenEndpointResponse`, the session contains:

```go
session.Extra = map[string]interface{}{
    "cnf": map[string]interface{}{
        "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    },
    "dpop_jkt_binding": "0ZcOCORZNYy-...", // only for public clients
}
```

The `cnf.jkt` value flows to introspection at `ext.cnf.jkt` via existing `Session.Extra` propagation. No code changes are needed — Hydra's admin introspection endpoint maps `Session.Extra` → `Introspection.Extra`, which is serialized as `"ext"` in JSON.

### Introspection Response

```json
{
  "active": true,
  "token_type": "DPoP",
  "ext": {
    "cnf": {
      "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    }
  }
}
```

The Credential Issuer reads `ext.cnf.jkt` from the introspection response to validate DPoP proofs from the Wallet.

The `dpop_jkt_binding` value is used internally for refresh token DPoP binding validation. It is not exposed in the token response or introspection — it is a Hydra-internal mechanism.

### Token Response

When DPoP is active, the token response includes `token_type: "DPoP"` instead of `Bearer`:

```json
{
  "access_token": "...",
  "token_type": "DPoP",
  "expires_in": 3600,
  "refresh_token": "..."
}
```

With nonces enabled, the HTTP response also includes:
```
DPoP-Nonce: eyJ0aW1lc3RhbXAi...
```

## DPoP HTTP Header Access

Fosite handlers receive `AccessRequester` which wraps the parsed form, not the raw HTTP request. The `DPoP` header is made available via form parameter injection at the endpoint handler level.

The `InjectDPoPHeader` helper (`fosite/handler/dpop/inject.go`) is called from `oauth2/handler.go` before Fosite processes the request:

- Single `DPoP` header → `dpop_proof` form parameter set to the header value
- Multiple `DPoP` headers → `dpop_proof_error=multiple_headers` (handler activates to reject)
- No `DPoP` header → both parameters unset

This injection happens on both the token endpoint (before `NewAccessRequest`) and the PAR endpoint (before `NewPushedAuthorizeRequest`).

## Database Migration

Migration `persistence/sql/migrations/YYYYMMDDHHMMSS_oidc4vci_create_dpop_jti.up.sql` creates the JTI replay detection table:

| Column | Type | Description |
|--------|------|-------------|
| `jti` | `VARCHAR(255) NOT NULL` | The `jti` claim from the DPoP proof JWT |
| `nid` | `UUID NOT NULL` | Network ID (multi-tenancy) |
| `used_at` | `TIMESTAMP NOT NULL` | When the JTI was first seen |
| `expires_at` | `TIMESTAMP NOT NULL` | TTL for cleanup — rows past this time can be purged |

Primary key: `(jti, nid)`. Index: `idx_dpop_jti_expires_at` on `(nid, expires_at)`.

Supports PostgreSQL, MySQL, CockroachDB, and SQLite. Nonces do not require a database table — they are stateless HMAC-based.

## File Layout

| File | Purpose |
|------|---------|
| `fosite/handler/dpop/handler.go` | `Handler` struct, `HandlePushedAuthorizeEndpointRequest`, shared proof validation |
| `fosite/handler/dpop/token_handler.go` | `TokenEndpointHandler` implementation (`CanHandle`, `HandleTokenEndpointRequest`, `PopulateTokenEndpointResponse`) |
| `fosite/handler/dpop/errors.go` | `ErrInvalidDPoPProof`, `ErrUseDPoPNonce` constants |
| `fosite/handler/dpop/storage.go` | `DPoPNonceStorage` interface |
| `fosite/handler/dpop/inject.go` | `InjectDPoPHeader` helper, `DPoPNonceContextKey` |
| `fosite/handler/dpop/handler_test.go` | Unit and property-based tests |
| `fosite/compose/compose_dpop.go` | `DPoPFactory` compose factory |
| `fosite/config.go` | `DPoPConfigProvider` interface |
| `driver/config/provider.go` | `KeyDPoP*` constants and `GetDPoP*` methods on `DefaultProvider` |
| `persistence/sql/migrations/` | JTI table migration (up and down) |
| `persistence/sql/persister_dpop.go` | SQL implementation of `DPoPNonceStorage` |
| `persistence/definitions.go` | `DPoPNonceStorage` embedded in `Persister` |
| `driver/registry_sql.go` | `DPoPNonceStorage()` accessor, `DPoPFactory` registration in `ExtraFositeFactories()` |
| `oauth2/handler.go` | DPoP header injection and `DPoP-Nonce` header delivery |

## References

- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://datatracker.ietf.org/doc/html/rfc7638)
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)
- Design doc: `.kiro/specs/oidc4vci-dpop/design.md`
- AI context: `docs/ai-context/features/feature-dpop.md`
