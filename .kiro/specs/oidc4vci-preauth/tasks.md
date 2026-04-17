# Implementation Plan: OIDC4VCI Pre-Authorized Code Grant Type

## Overview

Implement the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) for the Hydra AS fork. Tasks follow the dependency chain: config infrastructure and error constants first, then storage interface and data model, database migration and SQL persistence, handler core (HandleTokenEndpointRequest + PopulateTokenEndpointResponse), compose factory and registry wiring, admin API endpoint, HAIP startup warning, and finally feature documentation. The handler lives in `fosite/handler/preauth/` as a `TokenEndpointHandler` and follows the patterns established by Spec 1 (RAR) and Spec 2 (DPoP).

## Tasks

- [x] 1. Config infrastructure and error constants
  - [x] 1.1 Define `PreAuthorizedCodeConfigProvider` interface in `fosite/config.go`
    - Append `PreAuthorizedCodeConfigProvider` interface with methods: `GetPreAuthorizedCodeEnabled(ctx context.Context) bool`, `GetPreAuthorizedCodeLifespan(ctx context.Context) time.Duration`, `GetPreAuthorizedCodeAnonymousAccess(ctx context.Context) bool`
    - Mark with `// OIDC4VCI extension` comment
    - _Requirements: 10.1_

  - [x] 1.2 Embed `PreAuthorizedCodeConfigProvider` in `Configurator` interface in `fosite/fosite.go`
    - Add at end of interface composition list
    - _Requirements: 10.4_

  - [x] 1.3 Add config keys and provider methods in `driver/config/provider.go`
    - Add `KeyPreAuthorizedCodeEnabled = "preauth.enabled"`, `KeyPreAuthorizedCodeLifespan = "preauth.lifespan"`, `KeyPreAuthorizedCodeAnonymousAccess = "preauth.anonymous_access"` constants
    - Implement `GetPreAuthorizedCodeEnabled`, `GetPreAuthorizedCodeLifespan`, `GetPreAuthorizedCodeAnonymousAccess` on `DefaultProvider` using `p.getProvider(ctx)` pattern
    - Defaults: `false`, `30m`, `false`
    - _Requirements: 10.2, 10.3_

  - [x] 1.4 Add config schema properties to `spec/config.json`
    - Add `preauth` object with properties: `enabled` (boolean, default false), `lifespan` (string, default `"30m"`), `anonymous_access` (boolean, default false)
    - Run `scripts/render-schemas.sh` to regenerate derived schemas (`.schema/config.schema.json`)
    - _Requirements: 10.5_

  - [x] 1.5 Add compile-time interface satisfaction check in `fositex/config.go`
    - Add `var _ fosite.PreAuthorizedCodeConfigProvider = (*Config)(nil)`
    - Verifies `fositex.Config` inherits the provider methods from embedded `*config.DefaultProvider`
    - _Requirements: 10.6_

  - [x] 1.6 Create error hint helpers in `fosite/handler/preauth/errors.go`
    - The handler reuses `fosite.ErrInvalidGrant` and `fosite.ErrInvalidRequest` with `.WithHint()` at each call site — no new error code constants needed
    - Add copyright header and package declaration
    - Document the error codes and hints as comments for reference (all 9 error conditions from the design)
    - _Requirements: 12.1, 12.2, 12.3_

- [x] 2. Checkpoint — Ensure config infrastructure compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Storage interface, data model, and CoreStrategy type alias
  - [x] 3.1 Create `PreAuthorizedCodeStorage` interface and `PreAuthorizedCodeData` struct in `fosite/handler/preauth/storage.go`
    - Define `PreAuthorizedCodeStorage` interface with methods: `CreatePreAuthorizedCodeSession(ctx context.Context, signature string, data *PreAuthorizedCodeData) error`, `GetPreAuthorizedCodeSession(ctx context.Context, signature string) (*PreAuthorizedCodeData, error)`, `InvalidatePreAuthorizedCode(ctx context.Context, signature string) error`
    - Define `PreAuthorizedCodeData` struct with all fields from the design: `Signature`, `NID`, `RequestID`, `ClientID`, `RequestedScope`, `GrantedScope`, `CredentialConfigurationIDs`, `TxCodeHash`, `TxCodeInputMode`, `TxCodeLength`, `SessionData`, `Redeemed`, `RequestedAt`, `ExpiresAt` — with Pop struct tags (`db:"column_name"`)
    - Implement `TableName() string` returning `"hydra_oauth2_preauth_code"`
    - Add copyright header
    - _Requirements: 5.1, 6.1, 6.2, 6.3_

  - [x] 3.2 Define `CoreStrategy` type alias in `fosite/handler/preauth/handler.go`
    - Add `type CoreStrategy = oauth2.CoreStrategy` — type alias for `fosite/handler/oauth2.CoreStrategy` which composes `AuthorizeCodeStrategy`, `AccessTokenStrategy`, and `RefreshTokenStrategy`
    - This provides `AuthorizeCodeSignature(ctx, code)` for HMAC signature extraction and `GenerateAuthorizeCode(ctx, nil)` for code generation in the admin API, without fragile type assertions
    - _Requirements: 11.2_

- [-] 4. Database migration and SQL persistence
  - [x] 4.1 Create database migration for `hydra_oauth2_preauth_code` table
    - Create `persistence/sql/migrations/YYYYMMDDHHMMSS_oidc4vci_create_preauth_code.up.sql` with `hydra_oauth2_preauth_code` table: `signature VARCHAR(255) NOT NULL` PK, `nid UUID NOT NULL`, `request_id VARCHAR(255) NOT NULL`, `client_id VARCHAR(255) NULL`, `requested_scope JSON`, `granted_scope JSON`, `credential_configuration_ids JSON NOT NULL`, `tx_code_hash VARCHAR(255) NULL`, `tx_code_input_mode VARCHAR(10) NULL`, `tx_code_length INT NULL`, `session_data JSON NOT NULL`, `redeemed BOOLEAN NOT NULL DEFAULT FALSE`, `requested_at TIMESTAMP NOT NULL`, `expires_at TIMESTAMP NOT NULL`
    - Create indexes: `idx_preauth_code_nid` on `(nid)`, `idx_preauth_code_expires_at` on `(nid, expires_at)`
    - Use `CREATE TABLE IF NOT EXISTS` for idempotency
    - Create corresponding `.down.sql` dropping the table
    - Support PostgreSQL, MySQL, CockroachDB, and SQLite
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

  - [x] 4.2 Add `PreAuthorizedCodeStorage` to `persistence.Persister` aggregate interface and implement on SQL persister
    - Embed `preauth.PreAuthorizedCodeStorage` in the `Persister` interface in `persistence/definitions.go`
    - Create `persistence/sql/persister_preauth.go` implementing all three methods on the SQL persister
    - Implement `CreatePreAuthorizedCodeSession(ctx, signature, data)` — insert row with current NID from `p.NetworkID(ctx)`
    - Implement `GetPreAuthorizedCodeSession(ctx, signature)` — query by `signature` and current `nid`; return `fosite.ErrNotFound` if no row
    - Implement `InvalidatePreAuthorizedCode(ctx, signature)` — execute atomic `UPDATE hydra_oauth2_preauth_code SET redeemed=true WHERE signature=? AND nid=? AND redeemed=false`; check `RowsAffected()` — if 0, return error (already redeemed or not found)
    - Note: The `Persister` interface embedding and SQL implementation must be done together to avoid compilation failures
    - _Requirements: 5.2, 8.1, 8.2, 8.3, 8.4_

  - [x] 4.3 Write property test for storage round-trip (Property 8)
    - **Property 8: Pre-Authorized Code Storage Round-Trip**
    - Test in `persistence/sql/persister_preauth_test.go`
    - Generate random `PreAuthorizedCodeData` structs, call `CreatePreAuthorizedCodeSession` then `GetPreAuthorizedCodeSession`, verify all fields preserved
    - Also verify `InvalidatePreAuthorizedCode` sets `redeemed=true` atomically and returns error on second call
    - **Validates: Requirements 5.1, 8.1, 8.2, 8.3**

- [x] 5. Checkpoint — Ensure migration, persistence, and config compile and tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [-] 6. Handler core — HandleTokenEndpointRequest
  - [x] 6.1 Create `fosite/handler/preauth/handler.go` — `Handler` struct and token endpoint request handling
    - Define `Handler` struct with `Config PreAuthorizedCodeConfigProvider`, `Storage PreAuthorizedCodeStorage`, `Strategy CoreStrategy` fields
    - Add compile-time check: `var _ fosite.TokenEndpointHandler = (*Handler)(nil)`
    - Implement `CanHandleTokenEndpointRequest` — returns `true` when `requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code")`
    - Implement `CanSkipClientAuth` — returns `h.Config.GetPreAuthorizedCodeAnonymousAccess(ctx)`
    - Implement `HandleTokenEndpointRequest` with the full validation chain:
      1. Extract `pre-authorized_code` from request form; if missing → `fosite.ErrInvalidRequest.WithHint("pre-authorized_code parameter is required")`
      2. Compute HMAC signature via `h.Strategy.AuthorizeCodeSignature(ctx, code)`
      3. Load stored grant via `h.Storage.GetPreAuthorizedCodeSession(ctx, signature)`; if not found → `fosite.ErrInvalidGrant.WithHint("pre-authorized code not found")`
      4. Check `Redeemed` flag → `fosite.ErrInvalidGrant.WithHint("pre-authorized code already redeemed")`
      5. Check `ExpiresAt` → `fosite.ErrInvalidGrant.WithHint("pre-authorized code expired")`
      6. Client ID validation: if stored `ClientID` non-empty AND client auth performed, verify match → `fosite.ErrInvalidGrant.WithHint("client_id mismatch")`
      7. Transaction code validation (all 5 cases from design — SHA-256 hash + `subtle.ConstantTimeCompare`)
      8. Atomic invalidation via `h.Storage.InvalidatePreAuthorizedCode(ctx, signature)`
      9. `authorization_details` validation: parse from token request, validate subset against stored `CredentialConfigurationIDs`, or construct default set; reject empty array `[]` per RFC 9396 §2
      10. Deserialize `SessionData` into `*oauth2.Session`, set granted scopes, set `Session.Extra["authorization_details"]`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 13.1, 13.2, 13.3, 13.4, 17.1, 17.2, 17.3, 17.4, 17.5_

  - [x] 6.2 Write property test for valid redemption (Property 1)
    - **Property 1: Pre-Authorized Code Valid Redemption**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate random valid codes with associated `CredentialConfigurationIDs`, verify session contains `authorization_details` matching stored config IDs, response includes `access_token`, `token_type`, and `authorization_details`
    - **Validates: Requirements 1.10, 4.2, 4.3, 4.4, 4.5, 13.1, 13.2, 13.3, 13.4, 17.3**

  - [x] 6.3 Write property test for tx_code validation (Property 2)
    - **Property 2: Pre-Authorized Code tx_code Validation**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate all 5 combinations of stored `TxCodeHash` (empty/non-empty) × request `tx_code` (present/absent/matching/mismatching)
    - Verify correct accept/reject behavior and error codes for each combination
    - Verify SHA-256 hashing and constant-time comparison
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6**

  - [x] 6.4 Write property test for client ID validation (Property 3)
    - **Property 3: Pre-Authorized Code Client ID Validation**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate bound codes (non-empty `ClientID`) × matching/mismatching authenticated clients, and unbound codes (empty `ClientID`) × any client
    - Verify bound codes accept only matching client, unbound codes accept any client
    - **Validates: Requirements 1.11, 1.12**

  - [x] 6.5 Write property test for single-use enforcement (Property 4)
    - **Property 4: Pre-Authorized Code Single-Use Enforcement**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate valid codes, redeem once (should succeed), redeem again (should fail with "pre-authorized code already redeemed")
    - Verify atomic `InvalidatePreAuthorizedCode` prevents double redemption
    - **Validates: Requirements 1.7, 1.9, 8.3**

  - [x] 6.6 Write property test for expiry enforcement (Property 5)
    - **Property 5: Pre-Authorized Code Expiry Enforcement**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate codes with past and future `ExpiresAt` timestamps
    - Verify expired codes are rejected with "pre-authorized code expired", non-expired codes pass expiry check
    - **Validates: Requirements 1.8**

  - [x] 6.7 Write property test for authorization_details subset validation (Property 6)
    - **Property 6: Pre-Authorized Code authorization_details Subset Validation**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate stored `CredentialConfigurationIDs` sets × request `authorization_details` with varying `credential_configuration_id` values (subsets, supersets, disjoint)
    - Verify subset requests accepted, non-subset requests rejected with "requested credential_configuration_id not authorized"
    - Also verify default set construction when Wallet omits `authorization_details`
    - **Validates: Requirements 17.1, 17.2, 17.4, 17.5**

- [-] 7. Handler core — PopulateTokenEndpointResponse
  - [x] 7.1 Implement `PopulateTokenEndpointResponse` in `fosite/handler/preauth/handler.go`
    - Return `fosite.ErrUnknownRequest` when grant type is not pre-authorized code
    - Issue access token via `h.Strategy.GenerateAccessToken(ctx, requester)`
    - Set access token on response via `responder.SetAccessToken(token)`
    - Set `responder.SetTokenType("bearer")` (DPoP handler overrides to `DPoP` if active)
    - Set `expires_in` based on access token lifespan from Configurator
    - If `Session.Extra["authorization_details"]` present, copy to response extras via `responder.SetExtra("authorization_details", authDetails)`
    - Refresh token eligibility: if bound client + client grant types include `refresh_token` + granted scopes include offline scope → issue refresh token via `h.Strategy.GenerateRefreshToken(ctx, requester)`. If anonymous (no bound client) → skip refresh token
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [x] 7.2 Write property test for refresh token prohibition in anonymous mode (Property 7)
    - **Property 7: Pre-Authorized Code Refresh Token Prohibition in Anonymous Mode**
    - Test in `fosite/handler/preauth/handler_test.go`
    - Generate unbound codes (anonymous) × any scope/grant config → verify no refresh token issued
    - Generate bound codes × client with `refresh_token` grant + offline scope → verify refresh token issued
    - Generate bound codes × client without `refresh_token` grant or without offline scope → verify no refresh token
    - **Validates: Requirements 4.6, 4.7**

- [x] 8. Checkpoint — Ensure handler compiles and property tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Compose factory and registry wiring
  - [x] 9.1 Create `fosite/compose/compose_preauth.go` — `PreAuthorizedCodeFactory`
    - Define `PreAuthorizedCodeFactory` following `compose.Factory` signature, returning `*preauth.Handler`
    - Type-assert `config` to `preauth.PreAuthorizedCodeConfigProvider`, `storage` to `preauth.PreAuthorizedCodeStorage`, `strategy` to `preauth.CoreStrategy`
    - _Requirements: 11.1, 11.2_

  - [x] 9.2 Register `PreAuthorizedCodeFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`
    - Gate registration by `m.Config().GetPreAuthorizedCodeEnabled(ctx)`
    - Add `PreAuthorizedCodeStorage()` accessor with lazy initialization, returning `m.Persister()` cast to `preauth.PreAuthorizedCodeStorage`
    - _Requirements: 5.3, 11.3, 11.4_

- [x] 10. Admin API endpoint
  - [x] 10.1 Implement `POST /admin/oauth2/preauth` endpoint in `oauth2/handler.go`
    - Register route in `SetAdminRoutes`, marked with `// OIDC4VCI extension` comment
    - Accept JSON request body with fields: `client_id` (optional), `credential_configuration_ids` (required), `scope` (optional), `tx_code` (optional), `tx_code_input_mode` (optional), `tx_code_length` (optional)
    - Validate `credential_configuration_ids` is non-empty → 400 if missing
    - If `client_id` provided, validate it corresponds to a registered client (scoped to NID) → 400 if not found
    - Generate pre-authorized code via `CoreStrategy.GenerateAuthorizeCode(ctx, nil)` — returns `(token, signature, error)` where `token` is the raw code and `signature` is the DB key
    - If `tx_code` provided, compute SHA-256 hex digest
    - Store via `PreAuthorizedCodeStorage.CreatePreAuthorizedCodeSession(ctx, signature, data)`
    - Set `expires_at = time.Now().Add(config.GetPreAuthorizedCodeLifespan(ctx))`
    - Return 201 with `{"pre_authorized_code": "<raw_code>", "expires_at": "<RFC3339>"}`
    - Add Swagger annotations: `swagger:route POST /admin/oauth2/preauth oAuth2 createPreAuthorizedCode`, `swagger:parameters`, `swagger:model` for request/response types
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8_

- [x] 11. Checkpoint — Ensure admin API, factory, and registry wiring compile and tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. HAIP startup warning
  - [x] 12.1 Add startup warning when `KeyHAIPEnforced=true` and `KeyPreAuthorizedCodeAnonymousAccess=true`
    - Locate the serve command startup logic (likely `cmd/cmd_serve.go` or `driver/registry_sql.go` initialization)
    - Log a warning via `reg.Logger().Warnln(...)` indicating the configuration contradiction: HAIP requires client authentication at the token endpoint, which contradicts anonymous access for pre-authorized codes
    - _Requirements: 16.3_

- [x] 13. Feature documentation
  - [x] 13.1 Create `docs/features/pre-authorized-code.md`
    - Feature overview: Pre-Authorized Code grant type, OID4VCI §3.5 reference, handler design
    - Configuration: `KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess` with defaults
    - Admin API: `POST /admin/oauth2/preauth` request/response format with examples
    - Token exchange flow: step-by-step from Wallet to AS
    - tx_code validation rules: all 5 cases (required+provided match, required+provided mismatch, required+missing, not-required+provided, not-required+missing)
    - authorization_details: subset validation, default set construction, Token Hook enrichment with `credential_identifiers`
    - Error codes per OID4VCI §6.3 with all hints
    - Refresh token eligibility rules (bound client + grant type + offline scope; prohibited in anonymous mode)
    - DPoP interaction: DPoP handler binds token independently if `DPoP` header present
    - Token Hook: full-replacement semantics, Credential Issuer must echo back full `session.access_token` map
    - Introspection path: `ext.authorization_details` via `Session.Extra` propagation
    - HAIP independence: `KeyPreAuthorizedCodeEnabled` is independent of `KeyHAIPEnforced`
    - References: OID4VCI spec sections, design docs
    - _Requirements: 15.1, 15.2_

- [x] 14. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests use `pgregory.net/rapid` and validate universal correctness properties from the design document
- All new files in `fosite/handler/preauth/` are isolated from upstream (no merge conflict risk)
- Config and interface changes touch upstream files — follow `// OIDC4VCI extension` comment convention
- `fositex.Config` embeds `*config.DefaultProvider` so `PreAuthorizedCodeConfigProvider` methods are inherited automatically — verified by compile-time check in task 1.5
- The handler uses `CoreStrategy` (type alias for `oauth2.CoreStrategy`) for both HMAC signature extraction (`AuthorizeCodeSignature`) and token generation (`GenerateAccessToken`, `GenerateRefreshToken`, `GenerateAuthorizeCode`) — no fragile type assertions needed
- The Token Hook fires for all grant types including pre-authorized code — no handler code needed for hook integration, but the handler must set `Session.Extra["authorization_details"]` before the hook runs
- The Token Hook uses full-replacement semantics — the Credential Issuer's webhook must return the complete `session.access_token` map including `authorization_details` with `credential_identifiers` added
- Discovery metadata (`pre-authorized_grant_anonymous_access_supported`, `grant_types_supported`) is deferred to Spec 5 (oidc4vci-haip-metadata) — Requirements 14.1, 14.2 are not tasked here
- Requirements 16.1 and 16.2 are notes about HAIP independence — no implementation tasks needed beyond the startup warning (task 12.1)
