# Implementation Plan: OIDC4VCI AS Capabilities — AI Context Documentation

## Overview

Create a suite of technical documentation files that serve as AI-context steering documents for implementing OIDC4VCI Authorization Server capabilities in the Hydra fork. Each task produces one markdown file. No Go code is written — only documentation referencing code paths, interfaces, and design decisions.

## Tasks

- [x] 1. Create core context document: Hydra Internal Design
  - [x] 1.1 Create `docs/ai-context/01-hydra-internal-design.md`
    - Summarize the request lifecycle: `fosite/access_request_handler.go` → `NewAccessRequest()` iterates `TokenEndpointHandlers`, calls `CanHandleTokenEndpointRequest`, `CanSkipClientAuth`, `HandleTokenEndpointRequest`, then `PopulateTokenEndpointResponse`
    - Document the `AuthorizeEndpointHandler`, `TokenEndpointHandler`, `PushedAuthorizeEndpointHandler`, `RevocationHandler`, `DeviceEndpointHandler` interfaces from `fosite/handler.go`
    - Document the `compose.Factory` pattern from `fosite/compose/compose.go` and how handlers are registered via `Compose()`
    - Document the `Configurator` interface from `fosite/fosite.go` and its provider composition pattern
    - Document the `Session` struct from `oauth2/session.go` (especially `Extra` map for custom claims)
    - Document the consent flow types from `flow/consent_types.go`: `OAuth2ConsentRequest`, `AcceptOAuth2ConsentRequest`, `AcceptOAuth2ConsentRequestSession`
    - Document the token hook mechanism from `oauth2/token_hook.go`: `TokenHookRequest`, `TokenHookResponse`, `executeHookAndUpdateSession`
    - Document the discovery metadata struct `oidcConfiguration` from `oauth2/handler.go` and `discoverOidcConfiguration()`
    - Document the registry pattern from `driver/registry.go` and `oauth2/registry.go`
    - Reference existing handler examples: `fosite/handler/par/`, `fosite/handler/rfc8628/`, `fosite/compose/compose_par.go`
    - _Requirements: All (foundational context for all features)_

- [x] 2. Create core context document: OIDC4VCI AS Requirements Checklist
  - [x] 2.1 Create `docs/ai-context/02-oidc4vci-as-requirements.md`
    - Synthesize AS-specific requirements from `docs/oidc4vci/openid-4-verifiable-credential-issuance-1_0.md` sections: Pre-Authorized Code Flow, authorization_details, Token Endpoint extensions, scope-based credential requests, issuer_state parameter
    - Synthesize AS-specific requirements from `docs/oidc4vci/openid4vc-high-assurance-interoperability-profile-1_0.md` sections: DPoP (RFC 9449), PAR enforcement, PKCE S256, Wallet Attestation, ES256 algorithm support, RFC 9207 iss parameter
    - For each requirement, map to the current Hydra implementation status (supported / partially supported / missing)
    - Gap analysis: identify missing `TokenEndpointHandler` for pre-authorized code, missing DPoP handler, missing RAR parsing, missing `authorization_details` on consent types, missing Wallet Attestation auth method, missing metadata fields
    - Reference specific code paths where gaps exist: `fosite/fosite.go` Configurator missing DPoP/RAR/PreAuth providers, `flow/consent_types.go` missing `AuthorizationDetails` field, `oauth2/handler.go` `oidcConfiguration` missing OIDC4VCI metadata fields
    - _Requirements: 1.1–1.8, 2.1–2.6, 3.1–3.3, 4.1–4.8, 5.1–5.3, 6.1–6.3, 7.1–7.3, 8.1–8.3, 9.1–9.5, 10.1–10.6, 11.1–11.3, 12.1–12.2, 13.1–13.3, 14.1–14.4_

- [x] 3. Create core context document: Issuer Integration Boundary
  - [x] 3.1 Create `docs/ai-context/03-issuer-integration-boundary.md`
    - Define the system boundary: Hydra AS handles OAuth 2.0/OIDC, PAR, DPoP, authorization flows; external Credential Issuer handles VC assembly, signing, Credential Endpoint, Nonce Endpoint, Deferred Credential Endpoint
    - Document that the AS never handles Credential Requests, Credential Endpoints, or Credential Issuer metadata
    - Document how `authorization_details` flows: PAR/Auth request → consent challenge (`OAuth2ConsentRequest`) → consent accept (`AcceptOAuth2ConsentRequest`) → session `Extra` map → token response → introspection
    - Document how `credential_identifiers` are set by the Consent Node (not the AS) and propagated through the session
    - Document how `issuer_state` flows through the authorization request to the consent challenge
    - Document the token hook integration point (`oauth2/token_hook.go`) where external services can modify session data including `authorization_details`
    - Document the introspection endpoint as the mechanism by which the external Credential Issuer validates access tokens and reads `authorization_details` / DPoP binding
    - Document the DPoP `jkt` confirmation claim in the access token that the Credential Issuer validates
    - _Requirements: 2.5, 3.1, 3.2, 5.1, 5.2, 13.1, 13.2, 13.3_

- [x] 4. Create core context document: Fork Maintenance Strategy
  - [x] 4.1 Create `docs/ai-context/04-fork-maintenance-strategy.md`
    - Document branching strategy: custom features on a dedicated branch, upstream Hydra tracked as a remote
    - Document custom package structure to minimize merge conflicts: new handlers in `fosite/handler/preauth/`, `fosite/handler/dpop/`, `fosite/handler/rar/`, `fosite/handler/wallet_attestation/` — isolated from upstream handler directories
    - Document new compose factories in `fosite/compose/compose_preauth.go`, `fosite/compose/compose_dpop.go`, etc. — additive files that don't modify existing compose files
    - Document config key additions in `driver/config/` following the existing `KeyXxx` pattern — additive, not modifying existing keys
    - Document consent type extensions: new fields on `OAuth2ConsentRequest` and `AcceptOAuth2ConsentRequest` in `flow/consent_types.go` — these touch upstream files and need careful merge handling
    - Document discovery metadata extensions in `oauth2/handler.go` `oidcConfiguration` struct — touches upstream file, needs merge handling
    - Document SOPs for upstream merges: rebase custom branch, resolve conflicts in touched files (`flow/consent_types.go`, `oauth2/handler.go`, `fosite/fosite.go`), run full test suite
    - Document database migration strategy for new tables (`hydra_oauth2_preauth_code`, `hydra_oauth2_dpop_jti`)
    - _Requirements: All (operational context for maintaining the fork)_

- [x] 5. Checkpoint — Review core context documents
  - Ensure all four core context documents are complete and consistent. Ask the user if questions arise.

- [x] 6. Create feature steering document: DPoP
  - [x] 6.1 Create `docs/ai-context/features/feature-dpop.md`
    - High-level design: cross-cutting `TokenEndpointHandler` in `fosite/handler/dpop/` that decorates all grant types
    - Injection point: registered via `compose.Factory` pattern, `CanHandleTokenEndpointRequest` returns true when `DPoP` header present
    - `HandleTokenEndpointRequest`: validate DPoP proof JWT (signature, `jti` uniqueness, `htm`, `htu`, `iat`, `nonce`)
    - `PopulateTokenEndpointResponse`: bind access token to DPoP public key (`jkt` confirmation), set `token_type=DPoP`, optionally set `DPoP-Nonce` header
    - Config provider: `DPoPConfigProvider` with `GetDPoPEnabled`, `GetDPoPSigningAlgValuesSupported`, `GetDPoPNonceEnabled`, `GetDPoPNonceLifespan`
    - Storage: `DPoPNonceStorage` for JTI replay detection and nonce management
    - Error codes: `invalid_dpop_proof`, `use_dpop_nonce`
    - Metadata: `dpop_signing_alg_values_supported` in `oidcConfiguration`
    - HAIP requirement: ES256 minimum algorithm
    - _Requirements: 4.1–4.8, 14.1_

- [x] 7. Create feature steering document: PAR Enforcement
  - [x] 7.1 Create `docs/ai-context/features/feature-par.md`
    - Build on existing `fosite/handler/par/` and `fosite/compose/compose_par.go`
    - HAIP enforcement: when `KeyHAIPEnforced` is true, reject direct authorization requests for credential issuance flows that lack `request_uri` from PAR
    - Injection point: extend `PushedAuthorizeRequestConfigProvider.EnforcePushedAuthorize()` or add HAIP-specific check in authorize request handling
    - Document the existing PAR flow: `PushedAuthorizeHandler` stores request, returns `request_uri`, authorize endpoint resolves it
    - Wallet Attestation at PAR endpoint: same client auth rules as token endpoint
    - _Requirements: 7.1–7.3_

- [x] 8. Create feature steering document: Pre-Authorized Code
  - [x] 8.1 Create `docs/ai-context/features/feature-pre-authorized-code.md`
    - New `TokenEndpointHandler` in `fosite/handler/preauth/`
    - Grant type: `urn:ietf:params:oauth:grant-type:pre-authorized_code`
    - `CanHandleTokenEndpointRequest`: true when grant_type matches
    - `CanSkipClientAuth`: true when `pre-authorized_grant_anonymous_access_supported` is enabled
    - `HandleTokenEndpointRequest`: validate `pre-authorized_code` from form, check `tx_code` if required, enforce single-use and expiry
    - `PopulateTokenEndpointResponse`: issue access token, set `authorization_details` with `credential_identifiers` in response extras
    - Storage: `PreAuthorizedCodeStorage` with `GetPreAuthorizedCodeSession`, `InvalidatePreAuthorizedCode`
    - Data model: `hydra_oauth2_preauth_code` table schema
    - Factory: `fosite/compose/compose_preauth.go`
    - Config: `KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`
    - Error codes: `invalid_grant` for invalid/expired/redeemed codes and tx_code mismatches
    - _Requirements: 1.1–1.8_

- [x] 9. Create feature steering document: RAR (Rich Authorization Requests)
  - [x] 9.1 Create `docs/ai-context/features/feature-rar.md`
    - New handler in `fosite/handler/rar/` implementing `AuthorizeEndpointHandler` + `PushedAuthorizeEndpointHandler`
    - Parses `authorization_details` parameter, validates `type=openid_credential`, validates `credential_configuration_id`
    - Does NOT implement `TokenEndpointHandler` — token-side propagation via session data set during consent
    - Consent integration: parsed `authorization_details` added to `OAuth2ConsentRequest`, Consent Node returns `credential_identifiers` in accept response
    - Token response: `authorization_details` array with `credential_identifiers` included in token response extras
    - Token request subset validation: `credential_configuration_id` values in token request must be subset of authorized set
    - Scope and RAR precedence: both processed independently, `authorization_details` takes precedence for overlapping types
    - Config: `KeyRAREnabled`, `KeyRARTypesSupported`
    - _Requirements: 2.1–2.6, 3.1–3.3, 13.1–13.3_

- [x] 10. Create feature steering document: Wallet Attestation
  - [x] 10.1 Create `docs/ai-context/features/feature-wallet-attestation.md`
    - New client authentication method `attest_jwt_client_auth`
    - Location: `fosite/handler/wallet_attestation/` or extension of `fosite/client_authentication.go`
    - Reads `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers
    - Validates attestation JWT signature via `x5c` certificate chain against configured trust anchors
    - Validates PoP JWT
    - Matches `sub` claim to `client_id`
    - Registered as `ClientAuthenticationStrategy` extension
    - Config: `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`
    - Error codes: `invalid_client` for all validation failures
    - Metadata: `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported`
    - _Requirements: 9.1–9.5, 14.2_

- [x] 11. Checkpoint — Review feature steering documents (DPoP, PAR, Pre-Auth, RAR, Wallet Attestation)
  - Ensure all five feature documents are complete and consistent with the core context documents. Ask the user if questions arise.

- [x] 12. Create feature steering document: RFC 9207 Authorization Response Issuer
  - [x] 12.1 Create `docs/ai-context/features/feature-rfc9207-iss.md`
    - Lightweight modification: add `iss` parameter to all authorization responses (success and error)
    - Location: inline in `fosite/authorize_response_writer.go` or a small handler
    - Value: AS Issuer Identifier from `Configurator.GetIDTokenIssuer()` or equivalent
    - Config: `KeyAuthResponseIssParameterEnabled`
    - Metadata: `authorization_response_iss_parameter_supported: true` in `oidcConfiguration`
    - _Requirements: 8.1–8.3_

- [x] 13. Create feature steering document: Metadata Extensions
  - [x] 13.1 Create `docs/ai-context/features/feature-metadata-extensions.md`
    - Location: `oauth2/handler.go` → `discoverOidcConfiguration()` and `oidcConfiguration` struct
    - New fields: `pre_authorized_grant_anonymous_access_supported` (bool), `authorization_details_types_supported` ([]string), `dpop_signing_alg_values_supported` ([]string), `authorization_response_iss_parameter_supported` (bool)
    - New grant type in `grant_types_supported`: `urn:ietf:params:oauth:grant-type:pre-authorized_code`
    - New auth method in `token_endpoint_auth_methods_supported`: `attest_jwt_client_auth`
    - All fields conditionally populated based on config flags
    - Conformance with RFC 8414
    - Document the existing `oidcConfiguration` struct fields and where new fields are added
    - _Requirements: 10.1–10.6, 4.7, 8.3, 9.5, 11.3_

- [x] 14. Final checkpoint — Ensure all documents are complete
  - Ensure all 11 documentation files are created, internally consistent, and cross-reference each other where appropriate. Ask the user if questions arise.

## Notes

- All tasks produce markdown documentation files, not Go code
- Each document should be compact, highly technical, with bullet points and code path references
- No property-based tests are applicable since these are documentation tasks
- Tasks reference specific requirements for traceability
- Checkpoints ensure incremental review of document batches
