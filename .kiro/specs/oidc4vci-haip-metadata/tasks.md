# Implementation Plan: HAIP Enforcement, RFC 9207, and Discovery Metadata Extensions

## Overview

Wire the `KeyHAIPEnforced` config flag to override individual feature settings (PAR, PKCE S256, DPoP, RFC 9207 iss), implement RFC 9207 `iss` parameter injection into authorization responses, and extend the discovery metadata endpoint to advertise all OIDC4VCI capabilities. No new Fosite handlers — this spec modifies existing `DefaultProvider` config methods, the two authorize response-writing functions in Fosite core, and the `discoverOidcConfiguration()` function in `oauth2/handler.go`. Tasks follow the dependency chain: config keys and interface first, then HAIP override wiring on DefaultProvider, fositex compile-time checks, RFC 9207 injection, discovery metadata, property tests, and documentation.

## Tasks

- [x] 1. Config keys, interface definition, and schema updates
  - [x] 1.1 Add new config key constants and `AuthResponseIssConfigProvider` interface
    - Add constants to `driver/config/provider.go` in the `// OIDC4VCI extension` section: `KeyAuthResponseIssParameterEnabled = "rfc9207.iss_parameter_enabled"`, `KeyEnforcePushedAuthorize = "oauth2.par.enforced"`, `KeyPushedAuthorizeContextLifespan = "oauth2.par.context_lifespan"`, `KeyPKCEPlainChallengeMethod = "oauth2.pkce.plain_challenge_method"`
    - Define `AuthResponseIssConfigProvider` interface in `fosite/config.go` with method `GetAuthResponseIssParameterEnabled(ctx context.Context) bool`, marked with `// OIDC4VCI extension` comment
    - Embed `AuthResponseIssConfigProvider` in the `Configurator` interface in `fosite/fosite.go` in the `// OIDC4VCI extension` section
    - _Requirements: 5.1, 5.2_

  - [x] 1.2 Add config schema properties to `spec/config.json`
    - Add `rfc9207` object with `iss_parameter_enabled` (boolean, default false)
    - Add `par` object under `oauth2` with `enforced` (boolean, default false) and `context_lifespan` (duration ref, default "5m")
    - Add `plain_challenge_method` (boolean, default false) under `oauth2.pkce`
    - Run `scripts/render-schemas.sh` to regenerate derived schemas
    - _Requirements: 5.1_

- [x] 2. HAIP override wiring on DefaultProvider
  - [x] 2.1 Implement `PushedAuthorizeRequestConfigProvider` methods on `DefaultProvider`
    - Add `GetPushedAuthorizeRequestURIPrefix(ctx)` returning `"urn:ietf:params:oauth:request_uri:"`
    - Add `GetPushedAuthorizeContextLifespan(ctx)` using `KeyPushedAuthorizeContextLifespan` with 5m default
    - Add `EnforcePushedAuthorize(ctx)` using `KeyEnforcePushedAuthorize || KeyHAIPEnforced` OR-override pattern
    - All in `driver/config/provider.go` in the `// OIDC4VCI extension` section
    - _Requirements: 1.1, 1.2_

  - [x] 2.2 Add HAIP override to existing `DefaultProvider` methods
    - Modify `GetEnforcePKCE(ctx)` to return `standalone || KeyHAIPEnforced` (currently reads `KeyPKCEEnforced` only)
    - Add new `GetEnablePKCEPlainChallengeMethod(ctx)` on `DefaultProvider` using `KeyPKCEPlainChallengeMethod` with HAIP inversion: returns `false` when `KeyHAIPEnforced` is true, standalone value otherwise
    - Modify `GetDPoPEnabled(ctx)` to return `standalone || KeyHAIPEnforced`
    - Modify `GetDPoPSigningAlgValuesSupported(ctx)` to ensure `ES256` is included when `KeyHAIPEnforced` is true
    - Add `GetAuthResponseIssParameterEnabled(ctx)` using `KeyAuthResponseIssParameterEnabled || KeyHAIPEnforced` OR-override pattern
    - All in `driver/config/provider.go`
    - _Requirements: 1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 4.1, 4.2, 5.3_

  - [x] 2.3 Update `fositex/config.go` — remove hardcoded overrides and add compile-time checks
    - Remove the hardcoded `GetEnablePKCEPlainChallengeMethod` method on `fositex.Config` (returns `false`) so the `DefaultProvider` method with HAIP logic takes effect via embedding
    - Add compile-time check: `var _ fosite.AuthResponseIssConfigProvider = (*Config)(nil)`
    - Add compile-time check: `var _ fosite.PushedAuthorizeRequestConfigProvider = (*Config)(nil)`
    - _Requirements: 5.4_

- [x] 3. Checkpoint — Ensure config infrastructure compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. RFC 9207 iss parameter injection
  - [x] 4.1 Inject `iss` parameter in `WriteAuthorizeResponse()` in `fosite/authorize_write.go`
    - After the cache-control headers and before the response mode switch, add: if `f.Config.GetAuthResponseIssParameterEnabled(ctx)` then `resp.AddParameter("iss", f.Config.GetIDTokenIssuer(ctx))`
    - This single injection point covers all response modes (query, fragment, form_post) since they all read from `resp.GetParameters()`
    - _Requirements: 6.1, 6.2, 6.3_

  - [x] 4.2 Inject `iss` parameter in `WriteAuthorizeError()` in `fosite/authorize_error.go`
    - Inside the redirect error path (after `errors.Set("state", ar.GetState())`), add: if `f.Config.GetAuthResponseIssParameterEnabled(ctx)` then `errors.Set("iss", f.Config.GetIDTokenIssuer(ctx))`
    - This is placed after the `!ar.IsRedirectURIValid()` early return — non-redirect errors (JSON) do NOT get `iss`
    - Covers all redirect response modes: query, fragment, form_post
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [x] 5. Checkpoint — Ensure RFC 9207 injection compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Discovery metadata extensions
  - [x] 6.1 Add new struct fields to `oidcConfiguration` in `oauth2/handler.go`
    - Add fields in a clearly delimited `// --- OIDC4VCI Extensions (custom fork) ---` section:
      - `PushedAuthorizationRequestEndpoint string` with JSON tag `pushed_authorization_request_endpoint,omitempty`
      - `RequirePushedAuthorizationRequests bool` with JSON tag `require_pushed_authorization_requests,omitempty`
      - `PreAuthorizedGrantAnonymousAccessSupported bool` with JSON tag `pre-authorized_grant_anonymous_access_supported,omitempty`
      - `DPoPSigningAlgValuesSupported []string` with JSON tag `dpop_signing_alg_values_supported,omitempty`
      - `AuthorizationResponseIssParameterSupported bool` with JSON tag `authorization_response_iss_parameter_supported,omitempty`
    - All fields use `omitempty` per RFC 8414 conformance
    - _Requirements: 8.1, 8.2, 9.2, 10.1, 11.1, 14.1, 14.2_

  - [x] 6.2 Add conditional population logic in `discoverOidcConfiguration()`
    - Build dynamic `grantTypes` slice — append `urn:ietf:params:oauth:grant-type:pre-authorized_code` when `GetPreAuthorizedCodeEnabled(ctx)` is true
    - Build dynamic `authMethods` slice — append `attest_jwt_client_auth` when `GetWalletAttestationEnabled(ctx)` is true
    - Build dynamic `codeChallengeMethodsSupported` — restrict to `["S256"]` when `GetHAIPEnforced(ctx)` is true, `["plain", "S256"]` otherwise
    - Set `PushedAuthorizationRequestEndpoint` to `issuerURL + "/oauth2/par"` (always populated)
    - Set `RequirePushedAuthorizationRequests` from `EnforcePushedAuthorize(ctx)`
    - Set `DPoPSigningAlgValuesSupported` from `GetDPoPSigningAlgValuesSupported(ctx)` when `GetDPoPEnabled(ctx)` is true
    - Set `AuthorizationResponseIssParameterSupported` from `GetAuthResponseIssParameterEnabled(ctx)`
    - Set `PreAuthorizedGrantAnonymousAccessSupported` from `GetPreAuthorizedCodeAnonymousAccess(ctx)` when `GetPreAuthorizedCodeEnabled(ctx)` is true
    - Group all new logic in the `// OIDC4VCI extension` section of the function
    - _Requirements: 8.1, 8.2, 8.3, 9.1, 9.2, 9.3, 10.1, 10.2, 11.1, 11.2, 12.1, 12.2, 13.1, 13.2, 14.1, 14.2, 14.3, 15.1, 15.2, 16.1, 16.2_

- [x] 7. Checkpoint — Ensure discovery metadata compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Property-based tests
  - [x]* 8.1 Write property test for HAIP OR-override config methods (Property 1)
    - **Property 1: HAIP OR-Override for Config Methods**
    - Test in `driver/config/provider_haip_test.go`
    - For any pair `(haipEnforced, standaloneValue)`, verify `EnforcePushedAuthorize`, `GetEnforcePKCE`, `GetDPoPEnabled`, `GetAuthResponseIssParameterEnabled` all return `haipEnforced || standaloneValue`
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 1.1, 1.2, 2.1, 2.3, 3.1, 3.3, 4.1, 4.2**

  - [x]* 8.2 Write property test for HAIP PKCE plain method suppression (Property 2)
    - **Property 2: HAIP PKCE Plain Method Suppression**
    - Test in `driver/config/provider_haip_test.go`
    - For any pair `(haipEnforced, standalonePlainEnabled)`, verify `GetEnablePKCEPlainChallengeMethod` returns `!haipEnforced && standalonePlainEnabled`
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 2.2, 2.4**

  - [x]* 8.3 Write property test for HAIP independence of Pre-Auth and Wallet Attestation (Property 3)
    - **Property 3: HAIP Independence of Pre-Auth and Wallet Attestation**
    - Test in `driver/config/provider_haip_test.go`
    - For any pair `(haipEnforced, featureEnabled)`, verify `GetPreAuthorizedCodeEnabled` and `GetWalletAttestationEnabled` return `featureEnabled` regardless of `haipEnforced`
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 15.1, 16.1**

  - [x]* 8.4 Write property test for RFC 9207 iss in success responses (Property 4)
    - **Property 4: RFC 9207 iss in Success Responses**
    - Test in `fosite/authorize_write_test.go`
    - For any random issuer URL and response parameters, when `GetAuthResponseIssParameterEnabled` is true, verify `iss` parameter equals `GetIDTokenIssuer(ctx)`; when false, verify `iss` is absent
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 6.1, 6.2, 6.4**

  - [x]* 8.5 Write property test for RFC 9207 iss in error redirect responses (Property 5)
    - **Property 5: RFC 9207 iss in Error Redirect Responses**
    - Test in `fosite/authorize_error_test.go`
    - For any redirect error with random issuer URL, when `GetAuthResponseIssParameterEnabled` is true, verify error redirect URL contains `iss` parameter matching issuer; when false or non-redirect error, verify `iss` is absent
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4**

  - [x]* 8.6 Write property test for discovery metadata reflecting config state (Property 6)
    - **Property 6: Discovery Metadata Reflects Config State**
    - Test in `oauth2/handler_discovery_test.go`
    - For any combination of feature flags, verify all discovery metadata fields match the expected conditional population logic from the design
    - Verify `omitempty` behavior: disabled features produce absent fields
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 8.1, 8.2, 8.3, 9.1, 9.2, 9.3, 10.1, 10.2, 11.1, 11.2, 12.1, 12.2, 13.1, 13.2, 14.1, 14.3**

  - [x]* 8.7 Write property test for Session.Extra authorization_details round-trip (Property 7)
    - **Property 7: Session.Extra authorization_details Round-Trip**
    - Test in `oauth2/session_roundtrip_test.go`
    - For any valid `authorization_details` JSON array, verify storing in `Session.Extra`, serializing to JSON, and deserializing back produces identical structure
    - Use `pgregory.net/rapid` with minimum 100 iterations
    - **Validates: Requirements 17.1, 17.2**

- [x] 9. Checkpoint — Ensure all property tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Feature documentation
  - [x] 10.1 Create `docs/features/haip-metadata.md`
    - Describe HAIP enforcement behavior: which features are auto-enabled (PAR, PKCE S256, DPoP, RFC 9207 iss) and which are independent (Pre-Auth, Wallet Attestation)
    - Describe RFC 9207 `iss` parameter behavior for both success and error authorization responses
    - List all new discovery metadata fields with conditions, types, and defining RFCs
    - List all relevant configuration keys with types, defaults, and HAIP override behavior
    - Include references to RFC 9126, RFC 9207, RFC 8414, RFC 9449, RFC 9396, and the HAIP specification
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5_

- [x] 11. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests use `pgregory.net/rapid` with minimum 100 iterations per property and validate universal correctness properties from the design document
- RFC 9207 changes touch upstream Fosite files (`fosite/authorize_write.go`, `fosite/authorize_error.go`) — minimal changes, single injection point each
- Discovery metadata changes touch `oauth2/handler.go` (HIGH conflict risk) — all new fields and logic grouped in `// OIDC4VCI extension` section
- HAIP enforcement is config-driven — modifies `DefaultProvider` methods, no new handlers
- The `fositex.Config` hardcoded `GetEnablePKCEPlainChallengeMethod` (returns `false`) must be removed so the `DefaultProvider` method with HAIP logic takes effect via embedding
- `fositex.Config` embeds `*config.DefaultProvider` so new methods (`EnforcePushedAuthorize`, `GetAuthResponseIssParameterEnabled`, etc.) are inherited automatically — verified by compile-time checks in task 2.3
- No new database tables or migrations — all changes are config-driven overrides and response modifications
- Copyright header for new files: `// Copyright © 2026 Ory Corp` + `// SPDX-License-Identifier: Apache-2.0`
