# Feature: Pre-Authorized Code Grant Type (OIDC4VCI)

## Overview

This feature implements the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) for the Hydra AS fork, per OIDC4VCI §3.5:

- **Pre-Authorized Code handler** — A Fosite handler (`fosite/handler/preauth/`) that implements `TokenEndpointHandler` for the Pre-Authorized Code grant type. The Credential Issuer creates codes via an admin API, includes them in Credential Offers, and Wallets exchange them at the token endpoint.
- **Transaction code (tx_code) validation** — Optional one-time PIN validation (e.g., SMS/email code) per OIDC4VCI §6.3, using SHA-256 hashing and constant-time comparison.
- **Admin API** — `POST /admin/oauth2/preauth` endpoint for Credential Issuers to create pre-authorized codes with configurable credential configuration IDs, optional client binding, and optional transaction codes.
- **authorization_details subset validation** — Wallets can send `authorization_details` in the token request to select a subset of offered credential configurations, or omit it to receive the full set.
- **Anonymous access** — Configurable support for token exchange without client authentication, enabling Wallets without registered client credentials to participate in issuer-initiated flows.

The handler is a `TokenEndpointHandler` that owns the `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant type. DPoP token binding is handled independently by the cross-cutting DPoP handler — the Pre-Auth handler does not call DPoP directly.

The scope is strictly the Authorization Server role. The Credential Issuer is a separate microservice and is out of scope.

## Why Pre-Authorized Codes?

Standard OAuth 2.0 flows require the user to go through the authorization endpoint (login + consent). Pre-Authorized Codes skip this entirely — the Credential Issuer prepares everything upfront and the Wallet goes directly to the token endpoint. This is the "issuer-initiated" flow where the Credential Issuer decides what credentials to offer, optionally protects the exchange with a transaction code (PIN), and the Wallet simply exchanges the code for an access token.

This is useful for scenarios like:
- University issuing a degree credential to a graduate (no consent screen needed — the university already decided)
- Government issuing an identity document after in-person verification
- Employer issuing an employment credential after onboarding

## Configuration

### Config Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `preauth.enabled` (`KeyPreAuthorizedCodeEnabled`) | `bool` | `false` | Enable Pre-Authorized Code handler registration in the Fosite pipeline |
| `preauth.lifespan` (`KeyPreAuthorizedCodeLifespan`) | `duration` | `30m` | Validity window for pre-authorized codes |
| `preauth.anonymous_access` (`KeyPreAuthorizedCodeAnonymousAccess`) | `bool` | `false` | Allow token exchange without client authentication |

### Provider Interface

- **`PreAuthorizedCodeConfigProvider`** (`fosite/config.go`) — `GetPreAuthorizedCodeEnabled(ctx) bool`, `GetPreAuthorizedCodeLifespan(ctx) time.Duration`, `GetPreAuthorizedCodeAnonymousAccess(ctx) bool`

Embedded in the Fosite `Configurator` interface and implemented on `driver/config.DefaultProvider`. The `fositex.Config` runtime adapter inherits these methods via its embedded `*config.DefaultProvider`.

### Example Configuration

```yaml
preauth:
  enabled: true
  lifespan: 30m
  anonymous_access: false
```

## Admin API: Code Creation

### `POST /admin/oauth2/preauth`

The Credential Issuer calls this endpoint to create a pre-authorized code for inclusion in a Credential Offer.

### Request Body

```json
{
  "client_id": "wallet-app",
  "credential_configuration_ids": ["UniversityDegree_JWT", "org.iso.18013.5.1.mDL"],
  "scope": "UniversityDegree_JWT offline",
  "tx_code": "493536",
  "tx_code_input_mode": "numeric",
  "tx_code_length": 6
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | No | OAuth 2.0 client ID to bind the code to. If omitted, any client (or anonymous if configured) can redeem. |
| `credential_configuration_ids` | []string | Yes | Credential configuration IDs the Issuer plans to offer. Defines the authorization envelope. |
| `scope` | string | No | Space-separated scopes. Include `offline` or `offline_access` to enable refresh token issuance. |
| `tx_code` | string | No | Transaction code in plaintext. The AS computes the SHA-256 hash before storage — the plaintext is never stored. |
| `tx_code_input_mode` | string | No | `"numeric"` or `"text"`. Stored for metadata completeness. |
| `tx_code_length` | int | No | Expected length of the transaction code. |

### Response (201 Created)

```json
{
  "pre_authorized_code": "oaKazRN8I0IbtZ0C7JuMn5.base64hmac",
  "expires_at": "2026-04-16T15:30:00Z"
}
```

### Validation Rules

- `credential_configuration_ids` must be non-empty (400 if missing or empty)
- If `client_id` is provided, it must correspond to a registered OAuth 2.0 client (400 if not found)
- If `client_id` is omitted, the code is unbound — any client or anonymous can redeem it

## Token Exchange Flow

Step-by-step flow from Credential Offer to access token:

1. **Credential Issuer creates code** — Calls `POST /admin/oauth2/preauth` with credential configuration IDs, optional client binding, and optional transaction code. Receives the raw pre-authorized code.

2. **Credential Issuer sends Credential Offer** — Includes the pre-authorized code in the Credential Offer sent to the Wallet (e.g., via QR code, deep link, or push notification). The Credential Offer is constructed independently by the Credential Issuer — Hydra never sees it:

```json
{
  "credential_issuer": "https://credential-issuer.example.com",
  "credential_configuration_ids": ["UniversityDegree_JWT", "org.iso.18013.5.1.mDL"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5.base64hmac",
      "tx_code": {
        "length": 6,
        "input_mode": "numeric",
        "description": "Please enter the code sent to your email"
      }
    }
  }
}
```

3. **Wallet sends token request** — `POST /oauth2/token` with:
   - `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
   - `pre-authorized_code=<the code from the offer>`
   - `tx_code=<PIN if required>` (optional)
   - `authorization_details=<JSON array>` (optional, for subset selection)
   - `DPoP: <proof JWT>` header (optional, for DPoP binding)

4. **AS validates the code** — The handler:
   - Extracts the HMAC signature from the raw code
   - Loads the stored grant data by signature
   - Checks: not redeemed, not expired, client_id match (if bound), tx_code match (if required)
   - Atomically marks the code as redeemed (prevents double redemption)
   - Validates `authorization_details` (subset check) or constructs default set

5. **Token Hook fires** — The Credential Issuer's webhook receives `Session.Extra` (including `authorization_details`) and enriches it with `credential_identifiers`. The Token Hook uses full-replacement semantics — the webhook must return the complete `session.access_token` map.

6. **DPoP handler runs** — If a `DPoP` header is present, the DPoP handler binds the access token to the client's public key and sets `token_type=DPoP`.

7. **AS returns token response** — Includes `access_token`, `token_type`, `expires_in`, `authorization_details` (with `credential_identifiers` from the Token Hook), and optionally `refresh_token`.

### Example Token Response

```json
{
  "access_token": "...",
  "token_type": "bearer",
  "expires_in": 3600,
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegree_JWT",
      "credential_identifiers": ["cred-id-1"]
    }
  ]
}
```

## tx_code Validation Rules

The transaction code (`tx_code`) is a one-time PIN (e.g., sent via SMS or email) that protects the pre-authorized code exchange. The AS validates it using SHA-256 hashing and constant-time comparison.

| Stored `TxCodeHash` | Request `tx_code` | Result |
|----------------------|-------------------|--------|
| Non-empty | Present, hash matches | Proceed — tx_code is valid |
| Non-empty | Present, hash mismatch | Reject: `invalid_grant` — "tx_code does not match" |
| Non-empty | Missing | Reject: `invalid_request` — "tx_code required but not provided" |
| Empty | Present | Reject: `invalid_request` — "tx_code provided but not expected" |
| Empty | Missing | Proceed — no tx_code required |

The Admin API receives the `tx_code` in plaintext from the Credential Issuer, computes the SHA-256 hash, and stores only the hash. At the token endpoint, the Wallet-provided `tx_code` is hashed with the same algorithm and compared using `subtle.ConstantTimeCompare`.

## authorization_details

### Subset Validation

When the Wallet sends `authorization_details` in the token request, the handler validates that every requested `credential_configuration_id` is present in the stored `CredentialConfigurationIDs` set (the authorization envelope from code creation). This allows the Wallet to request a specific subset of offered credentials.

- If any requested ID is not in the allowed set → `invalid_request` ("requested credential_configuration_id not authorized")
- An empty array `[]` is rejected per RFC 9396 §2 (must be non-empty)

### Default Set Construction

When the Wallet does NOT send `authorization_details`, the handler constructs a default set from all stored `CredentialConfigurationIDs`, each as:

```json
{"type": "openid_credential", "credential_configuration_id": "<id>"}
```

### Token Hook Enrichment

The handler sets `Session.Extra["authorization_details"]` WITHOUT `credential_identifiers` — those are added by the Credential Issuer via the Token Hook. The Token Hook uses full-replacement semantics: the Credential Issuer's webhook must return the complete `session.access_token` map including `authorization_details` with `credential_identifiers` added. A `204 No Content` response leaves the session unchanged.

## Error Codes

All token endpoint errors use standard OAuth 2.0 error codes per OIDC4VCI §6.3. No custom error codes are defined.

### Token Endpoint Errors

| Error Code | Condition | Hint |
|------------|-----------|------|
| `invalid_request` | `pre-authorized_code` parameter missing | "pre-authorized_code parameter is required" |
| `invalid_request` | `tx_code` required but not provided | "tx_code required but not provided" |
| `invalid_request` | `tx_code` provided but not expected | "tx_code provided but not expected" |
| `invalid_request` | `credential_configuration_id` not in allowed set | "requested credential_configuration_id not authorized" |
| `invalid_request` | `authorization_details` is empty array `[]` | "authorization_details must be a non-empty array" |
| `invalid_request` | `authorization_details` is malformed JSON | "malformed authorization_details JSON" |
| `invalid_grant` | Pre-authorized code not found | "pre-authorized code not found" |
| `invalid_grant` | Pre-authorized code already redeemed | "pre-authorized code already redeemed" |
| `invalid_grant` | Pre-authorized code expired | "pre-authorized code expired" |
| `invalid_grant` | `tx_code` hash mismatch | "tx_code does not match" |
| `invalid_grant` | Authenticated `client_id` ≠ stored `client_id` | "client_id mismatch" |
| `invalid_client` | Client auth required but not provided (anonymous disabled) | Handled by Fosite core |

### Admin API Errors

| HTTP Status | Condition |
|-------------|-----------|
| 400 | `credential_configuration_ids` missing or empty |
| 400 | `client_id` provided but not a registered client |
| 500 | Internal error (HMAC generation or storage failure) |

## Refresh Token Rules

Refresh token issuance for pre-authorized code exchanges follows strict eligibility rules:

1. **Bound client required** — The code must be bound to a `client_id`. Anonymous (unbound) codes never receive refresh tokens, regardless of scope or client configuration. A refresh token without client binding is a security risk.

2. **Client grant type** — The bound client's registered grant types must include `refresh_token`.

3. **Offline scope** — The granted scopes must include one of `GetRefreshTokenScopes(ctx)` (defaults to `["offline", "offline_access"]`), OR `GetRefreshTokenScopes` returns an empty list (meaning all exchanges get refresh tokens).

The `scope` parameter on the admin API code creation request controls which scopes are granted, so the Credential Issuer controls refresh token eligibility by including `offline` or `offline_access` in the scope.

## DPoP Interaction

DPoP token binding is handled independently by the cross-cutting DPoP handler (`fosite/handler/dpop/`). The Pre-Auth handler does not call DPoP — DPoP's `PopulateTokenEndpointResponse` runs after Pre-Auth's and binds the token if a `DPoP` header is present on the token request.

When DPoP is active:
- The Pre-Auth handler sets `token_type=bearer`
- The DPoP handler overrides it to `token_type=DPoP`
- The DPoP handler adds `cnf.jkt` to `Session.Extra`
- The introspection response includes both `ext.authorization_details` and `ext.cnf.jkt`

## Token Hook Semantics

The Token Hook (`oauth2.token_hook` config) fires for all grant types, including pre-authorized code. The hook fires after `HandleTokenEndpointRequest` populates `Session.Extra["authorization_details"]` but before the token response is finalized.

The Token Hook uses full-replacement semantics: `session.Extra = respBody.Session.AccessToken`. The Credential Issuer's webhook receives the full session (including `authorization_details`) in the request body. It must return the complete `session.access_token` map including `authorization_details` with `credential_identifiers` added. If it returns only `credential_identifiers` without the rest of `Session.Extra`, all other session extras are lost.

A `204 No Content` response from the webhook leaves the session unchanged (no-op). This is valid when the Credential Issuer resolves `credential_identifiers` at credential endpoint time rather than at token time.

## Introspection Path

`authorization_details` is available in the introspection response at `ext.authorization_details`. No special code is needed — Hydra's admin introspection endpoint maps `Session.Extra` → `Introspection.Extra`, which is serialized as `"ext"` in JSON.

Example introspection response (relevant fields):

```json
{
  "active": true,
  "ext": {
    "authorization_details": [
      {
        "type": "openid_credential",
        "credential_configuration_id": "UniversityDegree_JWT",
        "credential_identifiers": ["cred-id-1"]
      }
    ]
  }
}
```

The Credential Issuer reads `ext.authorization_details` from the introspection response to determine which credentials to issue.

## HAIP Independence

The Pre-Authorized Code grant type is independently configurable from HAIP enforcement:

- `KeyPreAuthorizedCodeEnabled` is independent of `KeyHAIPEnforced`
- HAIP does not mandate the Pre-Authorized Code flow — HAIP mandates DPoP, PAR, PKCE S256, and RFC 9207
- Operators who want both HAIP compliance and Pre-Authorized Code support must enable `preauth.enabled` separately
- When both `haip.enforced=true` and `preauth.anonymous_access=true`, the AS logs a startup warning about the configuration contradiction — HAIP requires client authentication at the token endpoint, which contradicts anonymous access

## File Layout

| File | Purpose |
|------|---------|
| `fosite/handler/preauth/handler.go` | `Handler` struct, `HandleTokenEndpointRequest`, `PopulateTokenEndpointResponse`, `CanHandleTokenEndpointRequest`, `CanSkipClientAuth` |
| `fosite/handler/preauth/storage.go` | `PreAuthorizedCodeStorage` interface, `PreAuthorizedCodeData` struct |
| `fosite/handler/preauth/errors.go` | Error hint documentation (reuses `fosite.ErrInvalidGrant` / `fosite.ErrInvalidRequest`) |
| `fosite/handler/preauth/handler_test.go` | Unit and property-based tests |
| `fosite/compose/compose_preauth.go` | `PreAuthorizedCodeFactory` compose factory |
| `fosite/config.go` | `PreAuthorizedCodeConfigProvider` interface |
| `driver/config/provider.go` | `KeyPreAuthorizedCode*` constants and `GetPreAuthorizedCode*` methods |
| `persistence/sql/migrations/` | `hydra_oauth2_preauth_code` table migration |
| `persistence/sql/persister_preauth.go` | SQL implementation of `PreAuthorizedCodeStorage` |
| `persistence/definitions.go` | `PreAuthorizedCodeStorage` embedded in `Persister` |
| `driver/registry_sql.go` | `PreAuthorizedCodeStorage()` accessor, `PreAuthorizedCodeFactory` registration |
| `oauth2/handler.go` | Admin API route registration (`POST /admin/oauth2/preauth`) in `SetAdminRoutes` |
| `oauth2/handler_preauth.go` | Admin API handler method, Swagger-annotated request/response types, `preauthCodeData` persistence struct |
| `cmd/server/handler.go` | HAIP + anonymous access startup warning |

## References

- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) — §3.5 (Pre-Authorized Code Flow), §6.1 (Token Request), §6.3 (tx_code)
- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396) — §2 (authorization_details format)
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)
- Design doc: `.kiro/specs/oidc4vci-preauth/design.md`
- AI context: `docs/ai-context/features/feature-pre-authorized-code.md`
