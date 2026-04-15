# Implementation Plan: OIDC4VCI RAR & Consent Extensions

## Overview

Implement Rich Authorization Requests (RFC 9396) handler, consent flow extensions for `authorization_details` propagation, `issuer_state` support, config infrastructure, discovery metadata, and session propagation. Tasks follow the dependency chain: error constants and config first, then handler core, consent extensions, session propagation, factory wiring, and finally documentation.

## Tasks

- [x] 1. Error constant and config infrastructure
  - [x] 1.1 Create `ErrInvalidAuthorizationDetails` in `fosite/handler/rar/errors.go`
    - Define `var ErrInvalidAuthorizationDetails = &fosite.RFC6749Error{...}` with `ErrorField: "invalid_authorization_details"`, `CodeField: http.StatusBadRequest`
    - Add copyright header
    - _Requirements: 12.1, 12.2_

  - [x] 1.2 Define `RARConfigProvider` and `HAIPConfigProvider` interfaces in `fosite/config.go`
    - Append `RARConfigProvider` interface with `GetRAREnabled(ctx context.Context) bool` and `GetRARTypesSupported(ctx context.Context) []string`
    - Append `HAIPConfigProvider` interface with `GetHAIPEnforced(ctx context.Context) bool`
    - Mark with `// OIDC4VCI extension` comments
    - _Requirements: 9.1, 10.1_

  - [x] 1.3 Embed `RARConfigProvider` and `HAIPConfigProvider` in `Configurator` interface in `fosite/fosite.go`
    - Add at end of interface composition list
    - _Requirements: 9.4, 10.4_

  - [x] 1.4 Add config keys and provider methods in `driver/config/provider.go`
    - Add `KeyRAREnabled = "rar.enabled"`, `KeyRARTypesSupported = "rar.types_supported"`, `KeyHAIPEnforced = "haip.enforced"` constants
    - Implement `GetRAREnabled`, `GetRARTypesSupported`, `GetHAIPEnforced` on `DefaultProvider` using `p.getProvider(ctx)` pattern
    - _Requirements: 9.2, 9.3, 10.2, 10.3_

  - [x] 1.5 Add config schema properties to `spec/config.json`
    - Add `rar.enabled` (boolean, default false), `rar.types_supported` (array of strings, default `["openid_credential"]`), `haip.enforced` (boolean, default false)
    - Run `scripts/render-schemas.sh` to regenerate derived schemas
    - _Requirements: 9.5, 10.5_

  - [x] 1.6 Add compile-time interface satisfaction checks
    - Add `var _ RARConfigProvider = (*fositex.Config)(nil)` in `fositex/config.go` or a test file
    - Add `var _ HAIPConfigProvider = (*fositex.Config)(nil)` similarly
    - This verifies `fositex.Config` inherits the provider methods from embedded `*config.DefaultProvider`
    - _Requirements: 9.4, 10.4_

- [x] 2. Checkpoint — Ensure config infrastructure compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. RAR handler core implementation
  - [x] 3.1 Create `fosite/handler/rar/handler.go` — `RARHandler` struct and authorize/PAR methods
    - Define `RARHandler` struct with `Config RARConfigProvider`
    - Implement `HandleAuthorizeEndpointRequest` and `HandlePushedAuthorizeEndpointRequest` using shared `validateAuthorizationDetails` helper
    - Validation: parse JSON array, check `type` in `GetRARTypesSupported()`, check `credential_configuration_id` for `openid_credential` type
    - Return `nil` when `authorization_details` is absent (not responsible)
    - Store validated raw JSON in request form for downstream consumption
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9_

  - [x] 3.2 Create `fosite/handler/rar/token_handler.go` — token endpoint methods
    - Implement `CanHandleTokenEndpointRequest` — returns `true` when `authorization_details` is in the token request form
    - Implement `CanSkipClientAuth` — always returns `false`
    - Implement `HandleTokenEndpointRequest` — parse token request `authorization_details`, extract `credential_configuration_id` values, validate subset against authorized set in `session.Extra["authorization_details"]`
    - Implement `PopulateTokenEndpointResponse` — copy `session.Extra["authorization_details"]` into response extras; return `fosite.ErrUnknownRequest` when not present; log warning when `credential_identifiers` missing for `openid_credential` entries
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 3.4_

  - [x] 3.3 Write property test for RAR parsing and validation (Property 1)
    - **Property 1: RAR Parsing and Validation**
    - Test in `fosite/handler/rar/handler_test.go`
    - Use `pgregory.net/rapid` generators for valid/invalid `authorization_details` payloads
    - Verify identical validation behavior for authorize and PAR endpoints
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 12.2**

  - [x] 3.4 Write property test for token request subset validation (Property 2)
    - **Property 2: RAR Token Request Subset Validation**
    - Test in `fosite/handler/rar/handler_test.go`
    - Use generators for `credential_configuration_id` sets (subsets and non-subsets)
    - Verify `CanHandleTokenEndpointRequest` returns `false` when no `authorization_details` in request
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

  - [x] 3.5 Write property test for token response propagation (Property 4)
    - **Property 4: Token Response Contains authorization_details**
    - Test in `fosite/handler/rar/handler_test.go`
    - Verify `PopulateTokenEndpointResponse` copies session data to response extras regardless of token request content
    - **Validates: Requirements 3.1, 3.2, 3.3**

  - [x] 3.6 Write property test for credential_identifiers warning log (Property 9)
    - **Property 9: credential_identifiers Warning Log**
    - Test in `fosite/handler/rar/handler_test.go`
    - Verify warning logged when `openid_credential` entries lack `credential_identifiers`; response still produced
    - **Validates: Requirements 3.4**

- [x] 4. Consent type extensions and database migration
  - [x] 4.1 Add `AuthorizationDetails` and `IssuerState` fields to consent types in `flow/consent_types.go`
    - Add `AuthorizationDetails sqlxx.JSONRawMessage` (`db:"authorization_details"`) and `IssuerState string` (`db:"issuer_state"`) to `OAuth2ConsentRequest` at end of struct
    - Add `AuthorizationDetails sqlxx.JSONRawMessage` (`db:"consent_authorization_details"`) to `AcceptOAuth2ConsentRequest` at end of struct — note the different `db` tag to distinguish from the request-side column
    - Mark with `// OIDC4VCI extension` comments
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [x] 4.2 Create database migration for `hydra_oauth2_flow` table
    - Create `persistence/sql/migrations/YYYYMMDDHHMMSS_oidc4vci_consent_rar.up.sql` adding `authorization_details`, `issuer_state`, `consent_authorization_details` columns
    - Create corresponding `.down.sql` dropping those columns
    - Support PostgreSQL, MySQL, CockroachDB, and SQLite
    - _Requirements: 5.5_

  - [x] 4.3 Verify and update persistence SQL layer for new columns
    - Check `persistence/sql/persister_consent.go` for hand-written INSERT/UPDATE/SELECT queries on `hydra_oauth2_flow`
    - If queries use explicit column lists (not Pop auto-mapping), add `authorization_details`, `issuer_state`, and `consent_authorization_details` to the relevant queries
    - If Pop auto-mapping handles it via `db` struct tags, verify with a test that the new columns are read/written correctly
    - _Requirements: 5.1, 5.2, 5.3, 5.5_

- [x] 5. Consent API handler changes
  - [x] 5.1 Modify consent challenge creation to populate `AuthorizationDetails` and `IssuerState`
    - Locate the consent challenge creation code — likely in `consent/strategy_default.go` or the consent strategy implementation (search for where `OAuth2ConsentRequest` is built from the authorization session)
    - When building `OAuth2ConsentRequest`, read `authorization_details` from the request form (stored by RAR handler) and populate `OAuth2ConsentRequest.AuthorizationDetails`
    - Read `issuer_state` from the request form and populate `OAuth2ConsentRequest.IssuerState`
    - _Requirements: 4.1, 6.1, 6.2, 6.3_

  - [x] 5.2 Modify consent accept processing to merge `authorization_details` into session
    - Locate the consent accept processing code — likely in `consent/strategy_default.go` (search for where `AcceptOAuth2ConsentRequest` is processed and session is built)
    - When processing `AcceptOAuth2ConsentRequest`, read `AcceptOAuth2ConsentRequest.AuthorizationDetails`
    - If non-nil and non-empty: unmarshal JSON into `[]interface{}` and set `session.Extra["authorization_details"]`
    - _Requirements: 4.2, 4.3, 8.1_

  - [x] 5.3 Write property test for RAR round-trip persistence (Property 3)
    - **Property 3: RAR Round-Trip Persistence**
    - Test in `flow/consent_rar_test.go`
    - Verify `authorization_details` stored during authorization is retrievable in consent challenge and enriched data persists in session after consent accept
    - **Validates: Requirements 1.9, 4.1, 4.2, 4.3, 8.1**

  - [x] 5.4 Write property test for issuer_state round-trip (Property 6)
    - **Property 6: issuer_state Round-Trip**
    - Test in `flow/consent_rar_test.go`
    - Verify `issuer_state` from authorization/PAR request is preserved identically in `OAuth2ConsentRequest.IssuerState`
    - **Validates: Requirements 6.1, 6.2**

  - [x] 5.5 Write property test for consent enrichment (Property 7)
    - **Property 7: Consent Node Can Enrich authorization_details**
    - Test in `flow/consent_rar_test.go`
    - Verify enriched `authorization_details` (with `credential_identifiers`) from consent accept flows into `Session.Extra` and token response
    - **Validates: Requirements 4.2, 4.3, 8.1, 8.3, 8.4**

- [x] 6. Checkpoint — Ensure consent flow and handler tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Compose factory and registry wiring
  - [x] 7.1 Create `fosite/compose/compose_rar.go` — `RARFactory`
    - Define `RARFactory` following `compose.Factory` signature, returning `*rar.RARHandler`
    - Type-assert `config` to `rar.RARConfigProvider`
    - _Requirements: 11.1_

  - [x] 7.2 Register `RARFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`
    - Gate registration by `m.Config().GetRAREnabled(ctx)`
    - _Requirements: 11.2, 11.3_

- [x] 8. fositex.Config PushedAuthorizeEndpointHandler registration
  - [x] 8.1 Investigate existing PAR handler registration mechanism
    - Examine how the existing `PushedAuthorizeHandlerFactory` / `par.PushedAuthorizeHandler` is registered at runtime
    - Check if `fositex.Config` already satisfies `PushedAuthorizeRequestHandlersProvider` via a different path
    - Check if PAR works without `GetPushedAuthorizeEndpointHandlers` on `fositex.Config` (it may use `fosite.Config` defaults or a separate registration)
    - Document findings
    - _Requirements: 11.3 (handler registration for PAR endpoint)_
    - **Investigation Findings (Task 8.1):**
      1. **`PushedAuthorizeHandlerFactory` is NOT in `fositex.defaultFactories`** — it only appears in `compose.ComposeAllEnabled()` which is used by fosite integration tests, not by Hydra's runtime.
      2. **`fositex.Config` does NOT satisfy `PushedAuthorizeRequestHandlersProvider`** — it has no `pushedAuthorizeEndpointHandlers` field and no `GetPushedAuthorizeEndpointHandlers` method. Neither `fositex.Config` nor `config.DefaultProvider` implement this interface.
      3. **`fositex.Config.LoadDefaultHandlers` does NOT type-assert for `PushedAuthorizeEndpointHandler`** — it only checks for `AuthorizeEndpointHandler`, `TokenEndpointHandler`, `TokenIntrospector`, `RevocationHandler`, and `DeviceEndpointHandler`.
      4. **The PAR HTTP endpoint is NOT wired in Hydra** — `oauth2/handler.go` `SetPublicRoutes()` has no `/oauth2/par` route. `NewPushedAuthorizeResponse` and `NewPushedAuthorizeRequest` are never called from Hydra's HTTP layer (only in fosite-level tests).
      5. **PAR request resolution works** — `fosite/authorize_request_handler.go` → `authorizeRequestFromPAR()` resolves `request_uri` parameters at the authorize endpoint. But the PAR endpoint itself (where `request_uri` is created) is not exposed.
      6. **`fosite.Config` (the default fosite config) satisfies `PushedAuthorizeRequestHandlersProvider`** via its `PushedAuthorizeEndpointHandlers` field and `GetPushedAuthorizeEndpointHandlers` method. But Hydra uses `fositex.Config`, not `fosite.Config`.
      7. **Conclusion: Task 8.2 IS needed** — to register `RARHandler` (and the existing `PushedAuthorizeHandler`) as PAR handlers, `fositex.Config` must: (a) add a `pushedAuthorizeEndpointHandlers` field, (b) add the `PushedAuthorizeEndpointHandler` type assertion in `LoadDefaultHandlers`, (c) implement `GetPushedAuthorizeEndpointHandlers`, and (d) add `PushedAuthorizeHandlerFactory` to `defaultFactories`. However, since the PAR HTTP endpoint itself is not yet wired, this is infrastructure preparation — the handlers will be registered but won't be invoked until a PAR endpoint route is added (likely in a later spec).

  - [x] 8.2 Conditionally add `PushedAuthorizeEndpointHandler` type assertion to `fositex.Config.LoadDefaultHandlers`
    - 8.1 confirms it IS needed: add `pushedAuthorizeEndpointHandlers` field to `fositex.Config` struct
    - Add `PushedAuthorizeHandlerFactory` to `defaultFactories` (so the existing PAR handler is registered)
    - Add type assertion check for `fosite.PushedAuthorizeEndpointHandler` in the factory loop
    - Implement `GetPushedAuthorizeEndpointHandlers` method on `fositex.Config`
    - Verify existing PAR handler registration is not broken
    - _Requirements: 11.3_

- [x] 9. Discovery metadata
  - [x] 9.1 Add `AuthorizationDetailsTypesSupported` field to `oidcConfiguration` struct in `oauth2/handler.go`
    - Add `AuthorizationDetailsTypesSupported []string` with JSON tag `authorization_details_types_supported,omitempty`
    - Populate in `discoverOidcConfiguration()` when `GetRAREnabled(ctx)` returns true
    - _Requirements: 13.1, 13.2, 13.3_

  - [x] 9.2 Write property test for discovery metadata (Property 10)
    - **Property 10: Discovery Metadata Reflects RAR Configuration**
    - Test in `oauth2/handler_test.go`
    - Verify `authorization_details_types_supported` present when RAR enabled, absent when disabled
    - **Validates: Requirements 13.1, 13.2**

- [x] 10. Scope and RAR independence verification
  - [x] 10.1 Write property test for RAR and scope independence (Property 5)
    - **Property 5: RAR and Scope Independence**
    - Test in `oauth2/rar_scope_test.go`
    - Verify both `authorization_details` and `scope` are preserved independently through consent flow and token response
    - **Validates: Requirements 7.1, 7.2, 7.3**

- [x] 11. Refresh token preservation
  - [x] 11.1 Write property test for refresh token preservation (Property 8)
    - **Property 8: Refresh Token Preserves authorization_details**
    - Test in `oauth2/rar_refresh_test.go`
    - Verify `authorization_details` in `Session.Extra` is preserved across refresh token exchange
    - **Validates: Requirements 8.2**

  - [x] 11.2 Write unit test verifying introspection includes `authorization_details`
    - Test in `oauth2/handler_test.go` or `oauth2/rar_introspection_test.go`
    - Create a token with `authorization_details` in `Session.Extra`, introspect it via the admin handler
    - Verify `authorization_details` appears at `ext.authorization_details` in the introspection response JSON
    - No new production code needed — this verifies existing Hydra introspection behavior with the new session data
    - **Validates: Requirements 8.4**

- [x] 12. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. Feature documentation
  - [x] 13.1 Create `docs/features/rar-consent.md`
    - Feature overview: RAR handler, consent extensions, issuer_state, scope pass-through
    - Configuration: `KeyRAREnabled`, `KeyRARTypesSupported`, `KeyHAIPEnforced` (infrastructure only — enforcement in Spec 5)
    - API surface: affected endpoints, request/response parameters
    - Error codes: `invalid_authorization_details` with all hint variants
    - Consent flow changes: new fields on consent types
    - Session propagation: `Session.Extra["authorization_details"]` lifecycle
    - Introspection: `authorization_details` at `ext.authorization_details` (no code change needed)
    - References: RFC 9396, OIDC4VCI spec
    - _Requirements: 14.1, 14.2_

- [x] 14. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests use `pgregory.net/rapid` and validate universal correctness properties from the design document
- All new files in `fosite/handler/rar/` are isolated from upstream (no merge conflict risk)
- Consent type changes and discovery metadata changes touch upstream files — follow `// OIDC4VCI extension` comment convention
- `fositex.Config` embeds `*config.DefaultProvider` so `RARConfigProvider` and `HAIPConfigProvider` methods are inherited automatically — verified by compile-time checks in task 1.6
- Task 8 (PAR handler registration) is structured as investigate-then-implement — do not blindly add the type assertion without confirming it's needed
- Consent persistence queries in `persistence/sql/persister_consent.go` may need column updates (task 4.3) — verify whether Pop auto-mapping handles the new fields or if hand-written queries need modification
