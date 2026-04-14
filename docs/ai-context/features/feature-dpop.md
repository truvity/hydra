# Feature: DPoP (Demonstrating Proof of Possession — RFC 9449)

## Purpose

Steering document for implementing DPoP token binding in the Hydra AS fork. DPoP is a cross-cutting `TokenEndpointHandler` that decorates all grant types — it does not own a grant type. When a `DPoP` HTTP header is present on a token request, this handler validates the proof and binds the issued access token to the client's public key.

## Location

- Handler: `fosite/handler/dpop/handler.go`
- Storage interface: `fosite/handler/dpop/storage.go`
- Tests: `fosite/handler/dpop/handler_test.go`
- Factory: `fosite/compose/compose_dpop.go` → `DPoPFactory`
- Config keys: `driver/config/` → `KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`

## Handler Design

### Struct

```go
type DPoPHandler struct {
    Config     DPoPConfigProvider
    NonceStore DPoPNonceStorage
}
```

### `TokenEndpointHandler` Interface Implementation

**`CanHandleTokenEndpointRequest(ctx, requester)`**
- Returns `true` when the HTTP request contains a `DPoP` header (not grant-type specific)
- The DPoP header is extracted from the request context — the handler checks for its presence regardless of which grant type is being processed
- This makes DPoP a cross-cutting concern, similar to how `fosite/handler/verifiable/` decorates token responses

**`CanSkipClientAuth(ctx, requester)`**
- Always returns `false` — DPoP never skips client authentication
- DPoP is a token binding mechanism, not a client authentication method

**`HandleTokenEndpointRequest(ctx, requester)`**
- Validates the DPoP proof JWT from the `DPoP` header per RFC 9449 §4.3:
  1. Verify there is not more than one `DPoP` HTTP request header field — reject with `ErrInvalidDPoPProof` if multiple are present (§4.3 check #1)
  2. Verify the `DPoP` header value is a single well-formed JWT (§4.3 check #2)
  3. Verify all required claims are present: `jti`, `htm`, `htu`, `iat` (§4.3 check #3)
  4. Verify the `typ` JOSE Header Parameter has the value `dpop+jwt` — reject if missing or different (§4.3 check #4)
  5. Verify the `alg` JOSE Header Parameter indicates a registered asymmetric digital signature algorithm, is not `none`, is not a symmetric algorithm (e.g., `HS256`), and is in the configured `GetDPoPSigningAlgValuesSupported()` list (§4.3 check #5)
  6. Parse the `jwk` JOSE Header Parameter to extract the client's public key. Verify the JWT signature using this public key (§4.3 check #6)
  7. Verify the `jwk` JOSE Header Parameter does not contain private key material — reject if fields like `d`, `p`, `q`, `dp`, `dq`, `qi` (RSA) or `d` (EC/OKP) are present (§4.3 check #7)
  8. Validate `htm` claim matches `POST` (token endpoint is always POST) (§4.3 check #8)
  9. Validate `htu` claim matches the token endpoint URL (from `Configurator.GetTokenURLs()`). Apply syntax-based and scheme-based URI normalization per RFC 3986 §6.2.2–6.2.3 before comparing (§4.3 check #9)
  10. If nonces are enabled (`GetDPoPNonceEnabled(ctx) == true`): validate `nonce` claim matches a valid server nonce via `DPoPNonceStorage.ValidateDPoPNonce(ctx, nonce)` (§4.3 check #10)
  11. Validate `iat` (issued-at) is recent — within a configurable clock skew window (§4.3 check #11)
  12. Check `jti` uniqueness via `DPoPNonceStorage.IsJTIUsed(ctx, jti)` — reject replayed proofs
  13. Mark the `jti` as used via `DPoPNonceStorage.MarkJTIUsed(ctx, jti, expiry)`
- Note: §4.3 check #12 (`ath` claim and access token binding) applies only at the resource server, not at the token endpoint — out of scope for this handler
- On any validation failure: return `ErrInvalidDPoPProof` (maps to `invalid_dpop_proof` error code)
- On missing/invalid nonce when nonces are required: set the `DPoP-Nonce` HTTP response header with a fresh nonce value via `DPoPNonceStorage.CreateDPoPNonce(ctx)`, then return `ErrUseDPoPNonce` (maps to `use_dpop_nonce` error code). Per RFC 9449 §8, the error response MUST include the `DPoP-Nonce` header — the handler must set this header before returning the error so the HTTP response writer includes it

**`PopulateTokenEndpointResponse(ctx, requester, responder)`**
- Extract the public key from the validated DPoP proof's `jwk` header
- Compute `jkt` (JWK Thumbprint per RFC 7638) from the public key
- Store `jkt` as a confirmation claim in the session: `session.Extra["cnf"] = map[string]interface{}{"jkt": thumbprint}`
- Set `token_type` to `DPoP` on the response: `responder.SetTokenType("DPoP")`
- If nonces are enabled: generate a fresh nonce via `DPoPNonceStorage.CreateDPoPNonce(ctx)` and set the `DPoP-Nonce` HTTP response header

## DPoP-Bound Refresh Tokens (RFC 9449 §5)

Per RFC 9449 §5, when the AS issues a refresh token to a **public client** that presents a valid DPoP proof, the refresh token MUST be bound to the DPoP public key. On subsequent refresh token exchanges, the client MUST present a DPoP proof for the same key.

**Rules:**
- **Public clients**: Refresh tokens MUST be bound to the DPoP proof's public key. When the refresh token is later used, the AS MUST validate that the DPoP proof in the new token request uses the same key (matching `jkt`). If the key doesn't match, reject with `invalid_dpop_proof`.
- **Confidential clients**: Refresh tokens are NOT bound to the DPoP key — they are already sender-constrained via client authentication per RFC 6749. This avoids breaking credential rotation for confidential clients.
- **Implementation**: The DPoP `jkt` is stored in the session alongside the refresh token. During `HandleTokenEndpointRequest` for `grant_type=refresh_token`, the handler checks if the existing session has a DPoP `jkt` binding and, if so, validates that the new DPoP proof's public key matches.

## Authorization Code Binding via `dpop_jkt` (RFC 9449 §10)

RFC 9449 §10 defines the `dpop_jkt` authorization request parameter for binding the authorization code to a specific DPoP key. RFC 9449 §10.1 requires that an AS supporting both PAR and DPoP MUST support both mechanisms:

1. **`dpop_jkt` parameter in PAR/authorization requests**: The client includes `dpop_jkt` (the JWK Thumbprint of its DPoP public key) as an authorization request parameter. At the token endpoint, the AS computes the JWK Thumbprint from the DPoP proof and verifies it matches the `dpop_jkt` from the authorization request. If they don't match, the request MUST be rejected.

2. **`DPoP` header on PAR requests**: The client includes a `DPoP` header on the PAR request itself. The AS validates the DPoP proof per §4.3 and treats the contained public key's thumbprint as an implicit `dpop_jkt`. At the token endpoint, the same key matching applies.

3. **Both present**: If both `dpop_jkt` parameter and `DPoP` header are present on a PAR request, the AS MUST reject the request if the JWK Thumbprint in `dpop_jkt` does not match the public key in the `DPoP` header.

**Implementation:**
- The `dpop_jkt` value (from either mechanism) is stored alongside the authorization session during PAR/authorize processing
- During token exchange, the DPoP handler compares the `jkt` from the current DPoP proof against the stored `dpop_jkt` — mismatch results in `invalid_dpop_proof`
- This requires the DPoP handler to also implement `PushedAuthorizeEndpointHandler` (or coordinate with the PAR handler) to extract and store `dpop_jkt` during PAR processing
- The `DPoPHandler` struct gains an additional interface implementation: `fosite.PushedAuthorizeEndpointHandler` with `HandlePushedAuthorizeEndpointRequest()` that validates the DPoP proof on PAR requests and stores the `jkt`

**Note:** Use of `dpop_jkt` is OPTIONAL for clients, but the AS MUST support it when both PAR and DPoP are enabled.

## Config Provider

```go
type DPoPConfigProvider interface {
    GetDPoPEnabled(ctx context.Context) bool
    GetDPoPSigningAlgValuesSupported(ctx context.Context) []string
    GetDPoPNonceEnabled(ctx context.Context) bool
    GetDPoPNonceLifespan(ctx context.Context) time.Duration
}
```

- `GetDPoPEnabled` — feature gate; when false, the handler is not registered or short-circuits
- `GetDPoPSigningAlgValuesSupported` — list of accepted JWS algorithms for DPoP proofs (HAIP requires ES256 at minimum)
- `GetDPoPNonceEnabled` — whether the AS requires DPoP nonces (adds replay protection layer)
- `GetDPoPNonceLifespan` — TTL for server-issued nonces

Config keys in `driver/config/`:
- `KeyDPoPEnabled` → `bool`
- `KeyDPoPSigningAlgValues` → `[]string` (default: `["ES256"]`)
- `KeyDPoPNonceEnabled` → `bool` (default: `false`)
- `KeyDPoPNonceLifespan` → `time.Duration` (default: `5m`)

## Storage Interface

```go
type DPoPNonceStorage interface {
    // IsJTIUsed checks if a DPoP proof JTI has been seen before (replay detection)
    IsJTIUsed(ctx context.Context, jti string) (bool, error)

    // MarkJTIUsed records a JTI as used with an expiry time for cleanup
    MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error

    // CreateDPoPNonce generates a fresh server nonce for the DPoP-Nonce header
    CreateDPoPNonce(ctx context.Context) (string, error)

    // ValidateDPoPNonce checks if a nonce value is valid (not expired, not reused)
    ValidateDPoPNonce(ctx context.Context, nonce string) (bool, error)
}
```

## Database Table

### `hydra_oauth2_dpop_jti`

| Column | Type | Description |
|---|---|---|
| `jti` | `VARCHAR(255)` PK | The `jti` claim from the DPoP proof JWT |
| `nid` | `UUID` NOT NULL | Network ID (multi-tenancy) |
| `used_at` | `TIMESTAMP` NOT NULL | When the JTI was first seen |
| `expires_at` | `TIMESTAMP` NOT NULL | TTL for cleanup — rows past this time can be purged |

Index: `idx_dpop_jti_expires_at` on `(nid, expires_at)` for efficient cleanup queries.

## Factory

`fosite/compose/compose_dpop.go`:

```go
func DPoPFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
    return &dpop.DPoPHandler{
        Config:     config.(dpop.DPoPConfigProvider),
        NonceStore: storage.(dpop.DPoPNonceStorage),
    }
}
```

Registered in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyDPoPEnabled`.

## Error Codes

- **`invalid_dpop_proof`** — DPoP proof JWT has an invalid signature, unsupported algorithm, malformed claims, replayed `jti`, incorrect `htm`/`htu`, or stale `iat`. Maps to a new `fosite.RFC6749Error` constant.
- **`use_dpop_nonce`** — DPoP nonce is required but the proof does not contain a valid `nonce` claim. Response MUST include a `DPoP-Nonce` header with a fresh nonce value. Maps to a new `fosite.RFC6749Error` constant.

Both errors use HTTP 400 status code per RFC 9449.

## Discovery Metadata

In `oauth2/handler.go` → `oidcConfiguration` struct, add:

```go
DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
```

Populated in `discoverOidcConfiguration()` when `GetDPoPEnabled(ctx)` returns true. Value comes from `GetDPoPSigningAlgValuesSupported(ctx)`.

## HAIP Requirements

- ES256 MUST be included in `dpop_signing_alg_values_supported`
- When `KeyHAIPEnforced` is true, the DPoP handler should be enabled and ES256 must be in the supported algorithms list
- The DPoP handler validates the proof's signing algorithm against the configured `dpop_signing_alg_values_supported` list

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — Token endpoint lifecycle, `TokenEndpointHandler` interface, `Compose` factory pattern
- [03-issuer-integration-boundary.md](../03-issuer-integration-boundary.md) — DPoP `jkt` confirmation chain from AS to Credential Issuer via introspection
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Isolated handler directory, additive compose factory, DB migration strategy
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Properties 12–14 (DPoP binding, proof validation, nonce exchange)
