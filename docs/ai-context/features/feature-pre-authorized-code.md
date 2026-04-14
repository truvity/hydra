# Feature: Pre-Authorized Code Grant Type

## Purpose

Steering document for implementing the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) in the Hydra AS fork. This grant allows Wallets to exchange a pre-authorized code for an access token without going through the authorization endpoint — the credential issuance preparation happens before the OAuth flow.

## Location

- Handler: `fosite/handler/preauth/handler.go`
- Storage interface: `fosite/handler/preauth/storage.go`
- Tests: `fosite/handler/preauth/handler_test.go`
- Factory: `fosite/compose/compose_preauth.go` → `PreAuthorizedCodeFactory`
- Config keys: `driver/config/` → `KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`

## Handler Design

### Struct

```go
type PreAuthorizedCodeHandler struct {
    Config   PreAuthorizedCodeConfigProvider
    Storage  PreAuthorizedCodeStorage
    Strategy CoreStrategy  // for issuing access tokens (HMAC or JWT)
}
```

### `TokenEndpointHandler` Interface Implementation

**`CanHandleTokenEndpointRequest(ctx, requester)`**
- Returns `true` when `requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code")`
- This is a grant-type-specific handler, unlike DPoP which is cross-cutting

**`CanSkipClientAuth(ctx, requester)`**
- Returns `true` when `Config.GetPreAuthorizedCodeAnonymousAccess(ctx)` is true
- This enables the Pre-Authorized Code flow without client authentication, as specified by `pre-authorized_grant_anonymous_access_supported` in AS metadata
- When anonymous access is disabled, standard client authentication is required

**`HandleTokenEndpointRequest(ctx, requester)`**
1. Extract `pre-authorized_code` from the request form (`requester.GetRequestForm().Get("pre-authorized_code")`)
2. Call `Storage.GetPreAuthorizedCodeSession(ctx, code)` to load the stored grant data
3. If not found: return `ErrInvalidGrant` ("pre-authorized code not found")
4. Check `redeemed` flag — if already redeemed: return `ErrInvalidGrant` ("pre-authorized code already redeemed")
5. Check `expires_at` — if expired: return `ErrInvalidGrant` ("pre-authorized code expired")
6. If `tx_code_hash` is set on the stored data (transaction code required):
   - Extract `tx_code` from the request form
   - If `tx_code` is missing: return `ErrInvalidRequest` ("tx_code required but not provided")
   - Hash the provided `tx_code` and compare with stored `tx_code_hash`
   - If mismatch: return `ErrInvalidGrant` ("tx_code does not match")
7. If `tx_code_hash` is NOT set on the stored data but `tx_code` is present in the request: return `ErrInvalidRequest` ("tx_code provided but not expected")
8. Call `Storage.InvalidatePreAuthorizedCode(ctx, code)` to mark as redeemed (single-use enforcement)
9. Populate the requester session with data from the stored grant (scopes, audience, `authorization_details`)

**`PopulateTokenEndpointResponse(ctx, requester, responder)`**
1. Issue access token via `Strategy.GenerateAccessToken(ctx, requester)`
2. Set the access token on the response
3. Set `authorization_details` with `credential_identifiers` in response extras from the stored session data:
   ```go
   responder.SetExtra("authorization_details", session.Extra["authorization_details"])
   ```
4. Optionally issue a refresh token if the client is authorized for the `refresh_token` grant type

## Storage Interface

```go
type PreAuthorizedCodeStorage interface {
    // GetPreAuthorizedCodeSession retrieves the stored grant data for a pre-authorized code.
    // Returns the data or an error if the code is not found.
    GetPreAuthorizedCodeSession(ctx context.Context, code string) (*PreAuthorizedCodeData, error)

    // InvalidatePreAuthorizedCode marks a pre-authorized code as redeemed (single-use).
    InvalidatePreAuthorizedCode(ctx context.Context, code string) error
}
```

## Data Model

### `PreAuthorizedCodeData` Struct

```go
type PreAuthorizedCodeData struct {
    Signature                string                 // HMAC signature of the pre-authorized code (PK)
    NID                      uuid.UUID              // Network ID (multi-tenancy)
    RequestID                string                 // Request identifier
    ClientID                 string                 // OAuth 2.0 client ID
    RequestedScope           fosite.Arguments       // Scopes requested
    GrantedScope             fosite.Arguments       // Scopes granted
    AuthorizationDetails     json.RawMessage        // RAR authorization_details array (JSON)
    CredentialConfigurationIDs []string             // Credential configuration IDs from the offer
    TxCodeHash               string                 // Hashed transaction code (nullable — empty if not required)
    TxCodeInputMode          string                 // "numeric" or "text" (nullable)
    TxCodeLength             int                    // Expected length of tx_code (nullable)
    SessionData              json.RawMessage        // Serialized session
    Redeemed                 bool                   // Single-use flag
    RequestedAt              time.Time              // When the code was created
    ExpiresAt                time.Time              // Expiry time
}
```

### Database Table: `hydra_oauth2_preauth_code`

| Column | Type | Description |
|---|---|---|
| `signature` | `VARCHAR(255)` PK | HMAC signature of the pre-authorized code |
| `nid` | `UUID` NOT NULL | Network ID (multi-tenancy) |
| `request_id` | `VARCHAR(255)` NOT NULL | Request identifier |
| `client_id` | `VARCHAR(255)` NOT NULL | OAuth 2.0 client ID (FK → `hydra_client`) |
| `requested_scope` | `JSON` | Scopes requested |
| `granted_scope` | `JSON` | Scopes granted |
| `authorization_details` | `JSON` | RAR authorization_details array |
| `credential_configuration_ids` | `JSON` | Credential configuration IDs from the offer |
| `tx_code_hash` | `VARCHAR(255)` NULL | Hashed transaction code |
| `tx_code_input_mode` | `VARCHAR(10)` NULL | `numeric` or `text` |
| `tx_code_length` | `INT` NULL | Expected length of tx_code |
| `session_data` | `JSON` NOT NULL | Serialized session |
| `redeemed` | `BOOLEAN` NOT NULL DEFAULT FALSE | Single-use flag |
| `requested_at` | `TIMESTAMP` NOT NULL | When the code was created |
| `expires_at` | `TIMESTAMP` NOT NULL | Expiry time |

Indexes:
- `idx_preauth_code_nid_client` on `(nid, client_id)` for lookups
- `idx_preauth_code_expires_at` on `(nid, expires_at)` for cleanup

## Factory

`fosite/compose/compose_preauth.go`:

```go
func PreAuthorizedCodeFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
    return &preauth.PreAuthorizedCodeHandler{
        Config:   config.(preauth.PreAuthorizedCodeConfigProvider),
        Storage:  storage.(preauth.PreAuthorizedCodeStorage),
        Strategy: strategy.(preauth.CoreStrategy),
    }
}
```

Registered in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyPreAuthorizedCodeEnabled`.

## Config Provider

```go
type PreAuthorizedCodeConfigProvider interface {
    GetPreAuthorizedCodeEnabled(ctx context.Context) bool
    GetPreAuthorizedCodeLifespan(ctx context.Context) time.Duration
    GetPreAuthorizedCodeAnonymousAccess(ctx context.Context) bool
}
```

Config keys in `driver/config/`:
- `KeyPreAuthorizedCodeEnabled` → `bool`
- `KeyPreAuthorizedCodeLifespan` → `time.Duration` (default: `30m`)
- `KeyPreAuthorizedCodeAnonymousAccess` → `bool` (default: `false`)

## Error Codes

All errors use the standard `invalid_grant`, `invalid_request`, or `invalid_client` OAuth 2.0 error codes per OIDC4VCI §6.3:

- **`invalid_grant`** — Pre-authorized code not found
- **`invalid_grant`** — Pre-authorized code already redeemed (single-use violation)
- **`invalid_grant`** — Pre-authorized code expired
- **`invalid_request`** — `tx_code` required but not provided
- **`invalid_request`** — `tx_code` provided but not expected by the AS
- **`invalid_grant`** — `tx_code` does not match stored value (wrong code)
- **`invalid_client`** — Client authentication required but not provided (when anonymous access is disabled)

## Admin API: Pre-Authorized Code Creation

The Credential Issuer creates pre-authorized codes via an admin endpoint on the AS. This is a new admin API addition:

- The Credential Issuer (external microservice) calls the AS admin API to create a pre-authorized code
- The admin endpoint stores the grant data in `hydra_oauth2_preauth_code`
- The Credential Issuer includes the pre-authorized code in the Credential Offer sent to the Wallet
- The Wallet then exchanges the code at the token endpoint

This admin endpoint is part of the AS admin API (`oauth2/handler.go` → `SetAdminRoutes`), not the public API. The Credential Issuer is the only consumer.

## Discovery Metadata

In `oauth2/handler.go` → `oidcConfiguration`:

- Add `urn:ietf:params:oauth:grant-type:pre-authorized_code` to `grant_types_supported`
- Add `pre-authorized_grant_anonymous_access_supported: true/false` based on config

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — `TokenEndpointHandler` interface, `CanSkipClientAuth` for anonymous access, `Compose` factory pattern
- [03-issuer-integration-boundary.md](../03-issuer-integration-boundary.md) — Pre-Authorized Code data flow, Credential Issuer creates codes via admin API
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Isolated handler directory, DB migration for `hydra_oauth2_preauth_code`
- [feature-dpop.md](feature-dpop.md) — DPoP handler can bind tokens issued via Pre-Authorized Code grant
- [feature-rar.md](feature-rar.md) — `authorization_details` in token response comes from stored session data
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Properties 1–5 (Pre-authorized code redemption, tx_code validation, anonymous access, single-use, expiry)
