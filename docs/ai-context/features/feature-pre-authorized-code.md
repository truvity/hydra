# Feature: Pre-Authorized Code Grant Type

## Purpose

Steering document for implementing the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) in the Hydra AS fork. This grant allows Wallets to exchange a pre-authorized code for an access token without going through the authorization endpoint — the credential issuance preparation happens before the OAuth flow.

## Spec References

- OID4VCI 1.0 Final — §3.5 (Pre-Authorized Code Flow), §4.1.1 (Credential Offer Parameters), §6.1 (Token Request), §6.1.1 (`authorization_details` in Token Request), §6.2 (Token Response), §6.3 (Token Error Response), §12.3 (AS Metadata), §13.6 (Security Considerations)
- HAIP 1.0 — §4.4.1 (Wallet Attestation / Client Authentication at Token Endpoint)

## Key Design Decisions

### 1. Pre-Authorized Code Is NOT Bound to `client_id`

Per OID4VCI §6.1: "For the Pre-Authorized Code Grant Type, authentication of the Client is OPTIONAL [...] the `client_id` parameter is only needed when a form of Client Authentication that relies on this parameter is used."

Per OID4VCI §13.6.1: The pre-authorized code is "by design, not bound to a certain session" (unlike the authorization code flow with PKCE).

**Design:** The `client_id` field in the admin API and DB is **nullable**. The Credential Issuer may not know which Wallet will scan the QR code at code creation time. Client authentication is orthogonal to code validation — it happens at the token endpoint based on AS configuration (anonymous access vs. Wallet Attestation).

- When `client_id` is set at creation: the handler verifies the authenticated client matches at redemption.
- When `client_id` is NULL: any authenticated client (or anonymous if configured) can redeem the code.

### 2. `authorization_details` Is NOT Stored at Code Creation Time

Per OID4VCI §6.1.1: "The Wallet can use `authorization_details` in the Token Request to request a specific Credential Configuration in both the Authorization Code Flow and the Pre-Authorized Code Flow." This is "particularly useful if the Credential Issuer offered multiple Credential Configurations in the Credential Offer."

**Design (Approach B — Token Hook resolution):** The admin API does NOT accept `authorization_details`. Instead:

1. The Credential Issuer passes `credential_configuration_ids` and `scope` at code creation — the "authorization envelope" defining what's allowed.
2. At the token endpoint, if the Wallet sends `authorization_details`, Hydra validates that each `credential_configuration_id` is in the stored allowed set.
3. If the Wallet doesn't send `authorization_details`, Hydra constructs a default set from all stored `credential_configuration_ids`.
4. The Token Hook fires, calling the Credential Issuer's webhook with the validated `authorization_details`.
5. The Credential Issuer generates `credential_identifiers` for the specific credential instances and returns enriched `authorization_details` via the hook response.
6. Hydra includes the enriched `authorization_details` (with `credential_identifiers`) in the token response.

**Rationale:** This mirrors the authorization code flow where the Consent Node adds `credential_identifiers` at consent time. It lets the Credential Issuer defer instance resolution to the moment of actual token issuance, handles the "Wallet selects a subset" case naturally, and keeps Hydra's role clean (authorization enforcement) vs. the Credential Issuer's role (credential instance resolution).

### 3. Anonymous Access vs. HAIP

Per OID4VCI §12.3: `pre-authorized_grant_anonymous_access_supported` defaults to `false`.

Per HAIP §4.4.1: "Wallets MUST use, and Issuers MUST require, an OAuth2 Client authentication mechanism at OAuth2 Endpoints that support client authentication (such as the PAR and Token Endpoints)."

**Design:** Anonymous access and HAIP enforcement are independently configurable. HAIP does not profile the pre-authorized code flow at all — it's silent on it. However, HAIP unconditionally requires client auth at the token endpoint. If both `KeyHAIPEnforced=true` and `KeyPreAuthorizedCodeAnonymousAccess=true` are set, the system should log a warning at startup (they contradict each other). HAIP effectively forces `pre-authorized_grant_anonymous_access_supported: false`.

### 4. Refresh Tokens in Anonymous Mode

When anonymous access is used (no client), refresh tokens MUST NOT be issued. A refresh token without client binding is a security risk — anyone with the refresh token can obtain new access tokens indefinitely. Refresh token eligibility requires a bound client.

### 5. Single-Use Enforcement: Atomic Invalidation

`InvalidatePreAuthorizedCode` MUST use an atomic `UPDATE ... SET redeemed=true WHERE signature=? AND redeemed=false` and return an error if no rows were affected. This prevents the TOCTOU race between `GetPreAuthorizedCodeSession` (check redeemed=false) and `InvalidatePreAuthorizedCode` (set redeemed=true) when two concurrent requests use the same code.

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
- When anonymous access is disabled, standard client authentication is required (Wallet Attestation under HAIP)

**`HandleTokenEndpointRequest(ctx, requester)`**
1. Extract `pre-authorized_code` from the request form (`requester.GetRequestForm().Get("pre-authorized_code")`)
2. If missing or empty: return `ErrInvalidRequest` ("pre-authorized_code parameter is required")
3. Compute HMAC signature from the raw code using `HMACStrategy.Signature(code)` (splits on `.`, returns second part)
4. Call `Storage.GetPreAuthorizedCodeSession(ctx, signature)` to load the stored grant data
5. If not found: return `ErrInvalidGrant` ("pre-authorized code not found")
6. Check `redeemed` flag — if already redeemed: return `ErrInvalidGrant` ("pre-authorized code already redeemed")
7. Check `expires_at` — if expired: return `ErrInvalidGrant` ("pre-authorized code expired")
8. **Client ID validation** (only when stored `ClientID` is non-empty AND client auth was performed):
   - If the authenticated client's ID does not match stored `ClientID`: return `ErrInvalidGrant` ("client_id mismatch")
9. **Transaction code validation** (see dedicated section below)
10. Call `Storage.InvalidatePreAuthorizedCode(ctx, signature)` — atomic UPDATE, returns error if already redeemed (race condition protection)
11. **`authorization_details` validation from token request** (see dedicated section below)
12. Populate the requester session with data from the stored grant (scopes, audience, `authorization_details` in `Session.Extra`)

**`PopulateTokenEndpointResponse(ctx, requester, responder)`**
1. Return `fosite.ErrUnknownRequest` if grant type is not pre-authorized code (skip cleanly)
2. Issue access token via `Strategy.GenerateAccessToken(ctx, requester)`
3. Set the access token on the response
4. Set `token_type` to `"bearer"` (DPoP handler overrides to `"DPoP"` if DPoP proof is present)
5. Set `expires_in` based on access token lifespan from Configurator
6. If `Session.Extra["authorization_details"]` is present, copy to response extras
7. Optionally issue refresh token (see eligibility rules below)

### Transaction Code (tx_code) Validation

Per OID4VCI §6.3, three cases:

| Stored `tx_code_hash` | Request `tx_code` | Result |
|---|---|---|
| Non-empty | Present, matches | Proceed |
| Non-empty | Present, mismatch | `invalid_grant` ("tx_code does not match") |
| Non-empty | Missing | `invalid_request` ("tx_code required but not provided") |
| Empty | Present | `invalid_request` ("tx_code provided but not expected") |
| Empty | Missing | Proceed (no tx_code validation) |

- SHA-256 for hashing the provided `tx_code`
- Constant-time comparison (`subtle.ConstantTimeCompare`) against stored hash
- SHA-256 on short PINs is brute-forceable if the DB leaks, but acceptable given layered security: the attacker also needs the raw pre-authorized code (not stored — only the HMAC signature is stored), and the code is single-use + short-lived

### `authorization_details` in Token Request

Per OID4VCI §6.1.1, the Wallet MAY send `authorization_details` in the token request to select a subset of offered credential configurations.

**Handler logic (step 11 of `HandleTokenEndpointRequest`):**

1. Parse `authorization_details` from the token request form (if present)
2. For each entry with `type: "openid_credential"`, extract `credential_configuration_id`
3. Validate that every requested `credential_configuration_id` is in the stored `CredentialConfigurationIDs` set
4. If any requested ID is not in the allowed set: return `ErrInvalidRequest` ("requested credential_configuration_id not authorized")
5. Set `Session.Extra["authorization_details"]` to the validated request (without `credential_identifiers` — those come from the Token Hook)
6. If the Wallet did NOT send `authorization_details`: construct a default set from all stored `CredentialConfigurationIDs`, each as `{"type": "openid_credential", "credential_configuration_id": "<id>"}`

The Token Hook then fires, and the Credential Issuer enriches the `authorization_details` with `credential_identifiers`.

### Refresh Token Eligibility

Follows the same pattern as `canIssueRefreshToken` in `fosite/handler/oauth2/flow_authorize_code_token.go`:

1. Client's registered grant types must include `refresh_token`
2. Granted scopes must include one of `Config.GetRefreshTokenScopes(ctx)` (defaults to `["offline", "offline_access"]`), OR `GetRefreshTokenScopes` returns an empty list
3. **Additional rule:** When anonymous access is used (no bound client), refresh tokens MUST NOT be issued

The `scope` parameter on the admin API code creation request determines which scopes are granted, so the Credential Issuer controls refresh token eligibility by including `offline` or `offline_access` in the scope.

## Storage Interface

```go
type PreAuthorizedCodeStorage interface {
    // CreatePreAuthorizedCodeSession stores a new pre-authorized code grant.
    // The signature parameter is the HMAC signature extracted from the raw code.
    CreatePreAuthorizedCodeSession(ctx context.Context, signature string, data *PreAuthorizedCodeData) error

    // GetPreAuthorizedCodeSession retrieves the stored grant data for a pre-authorized code.
    // The signature parameter is the HMAC signature extracted from the raw code.
    // Returns fosite.ErrNotFound if the code does not exist.
    GetPreAuthorizedCodeSession(ctx context.Context, signature string) (*PreAuthorizedCodeData, error)

    // InvalidatePreAuthorizedCode atomically marks a pre-authorized code as redeemed.
    // Uses UPDATE ... WHERE redeemed=false and returns an error if no rows affected
    // (already redeemed by a concurrent request).
    InvalidatePreAuthorizedCode(ctx context.Context, signature string) error
}
```

## Data Model

### `PreAuthorizedCodeData` Struct

```go
type PreAuthorizedCodeData struct {
    Signature                string                 // HMAC signature of the pre-authorized code (PK)
    NID                      uuid.UUID              // Network ID (multi-tenancy)
    RequestID                string                 // Request identifier
    ClientID                 string                 // OAuth 2.0 client ID (nullable — empty if unbound)
    RequestedScope           fosite.Arguments       // Scopes requested
    GrantedScope             fosite.Arguments       // Scopes granted
    CredentialConfigurationIDs []string             // Allowed credential configuration IDs (authorization envelope)
    TxCodeHash               string                 // SHA-256 hash of the transaction code (empty if not required)
    TxCodeInputMode          string                 // "numeric" or "text" (nullable)
    TxCodeLength             int                    // Expected length of tx_code (nullable)
    SessionData              json.RawMessage        // Serialized session
    Redeemed                 bool                   // Single-use flag
    RequestedAt              time.Time              // When the code was created
    ExpiresAt                time.Time              // Expiry time
}
```

**Note:** No `AuthorizationDetails` field. The `authorization_details` are NOT stored at code creation time. They are either constructed from `CredentialConfigurationIDs` at the token endpoint (default set) or validated from the Wallet's token request (subset selection), then enriched with `credential_identifiers` by the Credential Issuer via the Token Hook.

### Database Table: `hydra_oauth2_preauth_code`

| Column | Type | Description |
|---|---|---|
| `signature` | `VARCHAR(255)` PK | HMAC signature of the pre-authorized code |
| `nid` | `UUID` NOT NULL | Network ID (multi-tenancy) |
| `request_id` | `VARCHAR(255)` NOT NULL | Request identifier |
| `client_id` | `VARCHAR(255)` NULL | OAuth 2.0 client ID (nullable — NULL if unbound) |
| `requested_scope` | `JSON` | Scopes requested |
| `granted_scope` | `JSON` | Scopes granted |
| `credential_configuration_ids` | `JSON` NOT NULL | Allowed credential configuration IDs |
| `tx_code_hash` | `VARCHAR(255)` NULL | SHA-256 hash of the transaction code |
| `tx_code_input_mode` | `VARCHAR(10)` NULL | `numeric` or `text` |
| `tx_code_length` | `INT` NULL | Expected length of tx_code |
| `session_data` | `JSON` NOT NULL | Serialized session |
| `redeemed` | `BOOLEAN` NOT NULL DEFAULT FALSE | Single-use flag |
| `requested_at` | `TIMESTAMP` NOT NULL | When the code was created |
| `expires_at` | `TIMESTAMP` NOT NULL | Expiry time |

Indexes:
- `idx_preauth_code_nid` on `(nid)` for tenant-scoped queries
- `idx_preauth_code_expires_at` on `(nid, expires_at)` for cleanup

**Changes from previous design:**
- `client_id` is now NULL (was NOT NULL) — supports unbound codes
- `authorization_details` column removed — not stored at creation time
- `idx_preauth_code_nid_client` replaced with `idx_preauth_code_nid` — client_id is nullable so composite index is less useful

## Admin API Contract

### `POST /admin/oauth2/preauth` — Create Pre-Authorized Code

The Credential Issuer calls this to get a pre-authorized code for inclusion in a Credential Offer.

**Request:**

```json
{
  "client_id": "wallet-app",
  "scope": "UniversityDegree_JWT org.iso.18013.5.1.mDL",
  "credential_configuration_ids": [
    "UniversityDegree_JWT",
    "org.iso.18013.5.1.mDL"
  ],
  "tx_code": "493536",
  "tx_code_input_mode": "numeric",
  "tx_code_length": 6
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `client_id` | string | No | OAuth 2.0 client ID to bind the code to. If omitted, any client (or anonymous) can redeem. If provided, must correspond to a registered client. |
| `scope` | string | No | Space-separated scopes to grant. Controls refresh token eligibility (include `offline`/`offline_access` for refresh tokens). |
| `credential_configuration_ids` | []string | Yes | The credential configuration IDs the Credential Issuer plans to offer. Defines the authorization envelope — the Wallet can request a subset via `authorization_details` at the token endpoint. |
| `tx_code` | string | No | Transaction code in plaintext. The AS computes SHA-256 hash before storage. The plaintext is never stored. |
| `tx_code_input_mode` | string | No | `"numeric"` or `"text"`. Stored for metadata completeness. |
| `tx_code_length` | int | No | Expected length of tx_code. Stored for metadata completeness. |

**What is NOT in the contract:**
- `authorization_details` — not needed at creation time. The Credential Issuer resolves `credential_identifiers` at token exchange time via the Token Hook.
- `credential_identifiers` — same reason. Generated dynamically by the Credential Issuer.

**Response:**

```json
{
  "pre_authorized_code": "oaKazRN8I0IbtZ0C7JuMn5.base64hmac",
  "expires_at": "2026-04-16T15:30:00Z"
}
```

**Processing:**
1. Validate `credential_configuration_ids` is non-empty
2. If `client_id` is provided, validate it corresponds to a registered client (scoped to current NID)
3. Generate pre-authorized code using `HMACStrategy` (same entropy as authorization codes — 32 bytes of randomness)
4. If `tx_code` is provided, compute SHA-256 hash
5. Store via `PreAuthorizedCodeStorage.CreatePreAuthorizedCodeSession`
6. Set `expires_at` = now + `GetPreAuthorizedCodeLifespan(ctx)`
7. Return the raw code and expiry

The Credential Issuer then constructs the Credential Offer independently (Hydra never sees the offer):

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

## Token Endpoint Data Flow

```
Wallet                          Hydra AS                         Credential Issuer
  |                                |                                    |
  |  POST /oauth2/token            |                                    |
  |  grant_type=pre-authorized_code|                                    |
  |  pre-authorized_code=...       |                                    |
  |  tx_code=493536                |                                    |
  |  authorization_details=[...]   |                                    |
  |  DPoP: <proof>                 |                                    |
  |  OAuth-Client-Attestation: ... |                                    |
  |------------------------------->|                                    |
  |                                |                                    |
  |                    1. Validate client auth (Wallet Attestation)      |
  |                    2. Validate pre-auth code (exists, not redeemed,  |
  |                       not expired)                                   |
  |                    3. Validate client_id match (if stored)           |
  |                    4. Validate tx_code (if required)                 |
  |                    5. Atomically mark code redeemed                  |
  |                    6. Validate authorization_details subset          |
  |                       (or construct default from stored config IDs)  |
  |                    7. Set Session.Extra["authorization_details"]     |
  |                                |                                    |
  |                                |  Token Hook webhook                |
  |                                |  (authorization_details in session) |
  |                                |----------------------------------->|
  |                                |                                    |
  |                                |  Enriched authorization_details    |
  |                                |  (with credential_identifiers)     |
  |                                |<-----------------------------------|
  |                                |                                    |
  |                    8. DPoP handler binds token (cnf.jkt)            |
  |                    9. Issue access token                             |
  |                                |                                    |
  |  Token Response                |                                    |
  |  access_token, token_type=DPoP |                                    |
  |  authorization_details=[{      |                                    |
  |    type: openid_credential,    |                                    |
  |    credential_configuration_id,|                                    |
  |    credential_identifiers      |                                    |
  |  }]                            |                                    |
  |<-------------------------------|                                    |
```

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
- `KeyPreAuthorizedCodeEnabled` → `bool` (default: `false`)
- `KeyPreAuthorizedCodeLifespan` → `time.Duration` (default: `30m`)
- `KeyPreAuthorizedCodeAnonymousAccess` → `bool` (default: `false`)

**HAIP interaction:** HAIP is independently configurable (`KeyHAIPEnforced`). HAIP does not mandate or prohibit the Pre-Authorized Code grant type. However, HAIP requires client auth at the token endpoint, which contradicts anonymous access. The system should log a warning at startup if both `KeyHAIPEnforced=true` and `KeyPreAuthorizedCodeAnonymousAccess=true`.

## Error Codes

Per OID4VCI §6.3:

| Error Code | Condition | Hint |
|---|---|---|
| `invalid_request` | `pre-authorized_code` parameter missing | "pre-authorized_code parameter is required" |
| `invalid_request` | `tx_code` required but not provided | "tx_code required but not provided" |
| `invalid_request` | `tx_code` provided but not expected | "tx_code provided but not expected" |
| `invalid_request` | `credential_configuration_id` not in allowed set | "requested credential_configuration_id not authorized" |
| `invalid_grant` | Pre-authorized code not found | "pre-authorized code not found" |
| `invalid_grant` | Pre-authorized code already redeemed | "pre-authorized code already redeemed" |
| `invalid_grant` | Pre-authorized code expired | "pre-authorized code expired" |
| `invalid_grant` | `tx_code` does not match | "tx_code does not match" |
| `invalid_grant` | Authenticated client_id ≠ stored client_id | "client_id mismatch" |
| `invalid_client` | Client auth required but not provided (anonymous disabled) | Handled by Fosite core, not PreAuth handler |

## Discovery Metadata

Deferred to Spec 5 (`oidc4vci-haip-metadata`). This feature provides the config provider methods that Spec 5 calls:

- `GetPreAuthorizedCodeEnabled(ctx)` → include `urn:ietf:params:oauth:grant-type:pre-authorized_code` in `grant_types_supported`
- `GetPreAuthorizedCodeAnonymousAccess(ctx)` → set `pre-authorized_grant_anonymous_access_supported` in AS metadata

## Cross-References

- [00-architecture-overview.md](../00-architecture-overview.md) — Flow 2 sequence diagram, component interaction
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Isolated handler directory, DB migration
- [feature-dpop.md](feature-dpop.md) — DPoP handler binds tokens issued via Pre-Authorized Code grant (cross-cutting, runs after PreAuth handler)
- [feature-rar.md](feature-rar.md) — `authorization_details` type `openid_credential` definition, Token Hook enrichment pattern
- [feature-wallet-attestation.md](feature-wallet-attestation.md) — Client authentication at token endpoint (HAIP mode)
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Properties 1–5
- [Requirements](../../.kiro/specs/oidc4vci-preauth/requirements.md) — Formal acceptance criteria
