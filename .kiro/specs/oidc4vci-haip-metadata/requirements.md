# Requirements Document

## Introduction

This document specifies the capstone requirements for the OIDC4VCI Hydra AS fork: HAIP enforcement wiring, RFC 9207 authorization response issuer identifier, HAIP auto-enable of DPoP, and AS discovery metadata extensions. All foundational infrastructure (RAR, DPoP, Pre-Auth, Wallet Attestation) is already implemented by Specs 1–4. This spec wires the HAIP enforcement flag (`KeyHAIPEnforced`) to override individual feature settings, implements RFC 9207 `iss` parameter injection, and extends the discovery metadata endpoint to advertise all OIDC4VCI capabilities.

The scope is strictly the Authorization Server role. No new Fosite handlers are created — this spec modifies existing config provider methods, authorize response writers, and the discovery metadata function.

## Glossary

- **AS**: Authorization Server — the Hydra instance.
- **HAIP**: High Assurance Interoperability Profile — a security profile requiring PAR, PKCE S256, DPoP, and RFC 9207 `iss`.
- **Discovery_Endpoint**: The Hydra endpoint (`/.well-known/openid-configuration` / `/.well-known/oauth-authorization-server`) that publishes AS metadata.
- **Authorization_Endpoint**: The Hydra endpoint (`/oauth2/auth`) that handles authorization requests.
- **PAR_Endpoint**: The Pushed Authorization Request endpoint (`/oauth2/par`), already implemented in `fosite/handler/par/`.
- **Token_Endpoint**: The Hydra endpoint (`/oauth2/token`) that issues access tokens.
- **DefaultProvider**: The `driver/config.DefaultProvider` struct that implements all config provider interfaces.
- **Configurator**: The `fosite.Configurator` interface composing all config provider interfaces.
- **Fosite**: The embedded OAuth 2.0 library within Hydra.
- **DPoP**: Demonstrating Proof of Possession (RFC 9449) — sender-constrained token binding.
- **PKCE**: Proof Key for Code Exchange (RFC 7636) — authorization code interception prevention.
- **PAR**: Pushed Authorization Requests (RFC 9126) — request integrity and confidentiality.
- **RFC_9207**: Authorization Response Issuer Identifier — `iss` parameter in authorization responses to prevent mix-up attacks.
- **Wallet**: The OAuth 2.0 Client (end-user application) that requests credentials.
- **Consent_Node**: The external Login/Consent application that Hydra delegates user authentication and consent decisions to.
- **Pre-Authorized_Code**: The `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant type for issuer-initiated flows.
- **Wallet_Attestation**: Attestation-based client authentication method (`attest_jwt_client_auth`).
- **RAR**: Rich Authorization Requests (RFC 9396) — the `authorization_details` parameter.

## Requirements

### Requirement 1: HAIP PAR Enforcement Wiring

**User Story:** As a security architect, I want the HAIP enforcement flag to automatically require PAR for all authorization requests, so that request integrity is guaranteed without requiring separate PAR enforcement configuration.

#### Acceptance Criteria

1. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `EnforcePushedAuthorize(ctx)` method SHALL return true regardless of the standalone PAR enforcement setting.
2. WHILE `KeyHAIPEnforced` is false, THE DefaultProvider `EnforcePushedAuthorize(ctx)` method SHALL return the value of the standalone PAR enforcement config key.
3. IF a direct authorization request (not via PAR) is received while `KeyHAIPEnforced` is true, THEN THE Authorization_Endpoint SHALL reject it with an `invalid_request` error via the existing PAR enforcement check in `fosite/authorize_request_handler.go`.

### Requirement 2: HAIP PKCE S256 Enforcement Wiring

**User Story:** As a security architect, I want the HAIP enforcement flag to automatically enforce PKCE with S256 and disable the plain challenge method, so that authorization code interception attacks are prevented without requiring separate PKCE configuration.

#### Acceptance Criteria

1. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `GetEnforcePKCE(ctx)` method SHALL return true regardless of the standalone PKCE enforcement setting.
2. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `GetEnablePKCEPlainChallengeMethod(ctx)` method SHALL return false regardless of the standalone plain challenge method setting.
3. WHILE `KeyHAIPEnforced` is false, THE DefaultProvider `GetEnforcePKCE(ctx)` method SHALL return the value of the standalone `KeyPKCEEnforced` config key.
4. WHILE `KeyHAIPEnforced` is false, THE DefaultProvider `GetEnablePKCEPlainChallengeMethod(ctx)` method SHALL return the value of the standalone plain challenge method config key.

### Requirement 3: HAIP DPoP Auto-Enable Wiring

**User Story:** As a security architect, I want the HAIP enforcement flag to automatically enable DPoP with ES256 support, so that sender-constrained tokens are guaranteed without requiring separate DPoP configuration.

#### Acceptance Criteria

1. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `GetDPoPEnabled(ctx)` method SHALL return true regardless of the standalone `KeyDPoPEnabled` setting.
2. WHILE `KeyHAIPEnforced` is true AND `KeyDPoPSigningAlgValues` is not explicitly configured, THE DefaultProvider `GetDPoPSigningAlgValuesSupported(ctx)` method SHALL return a list containing at least `ES256`.
3. WHILE `KeyHAIPEnforced` is false, THE DefaultProvider `GetDPoPEnabled(ctx)` method SHALL return the value of the standalone `KeyDPoPEnabled` config key.

### Requirement 4: HAIP RFC 9207 Auto-Enable Wiring

**User Story:** As a security architect, I want the HAIP enforcement flag to automatically enable the RFC 9207 `iss` parameter in authorization responses, so that mix-up attack prevention is guaranteed without requiring separate RFC 9207 configuration.

#### Acceptance Criteria

1. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `GetAuthResponseIssParameterEnabled(ctx)` method SHALL return true regardless of the standalone `KeyAuthResponseIssParameterEnabled` setting.
2. WHILE `KeyHAIPEnforced` is false, THE DefaultProvider `GetAuthResponseIssParameterEnabled(ctx)` method SHALL return the value of the standalone `KeyAuthResponseIssParameterEnabled` config key.

### Requirement 5: AuthResponseIssConfigProvider Interface

**User Story:** As a developer, I want a dedicated config provider interface for the RFC 9207 `iss` parameter, so that the feature follows the established single-responsibility config provider pattern.

#### Acceptance Criteria

1. THE Fosite codebase SHALL define an `AuthResponseIssConfigProvider` interface in `fosite/config.go` with a single method `GetAuthResponseIssParameterEnabled(ctx context.Context) bool`.
2. THE `AuthResponseIssConfigProvider` interface SHALL be embedded in the `Configurator` interface in `fosite/fosite.go`.
3. THE `DefaultProvider` in `driver/config/provider.go` SHALL implement `GetAuthResponseIssParameterEnabled(ctx)` using config key `KeyAuthResponseIssParameterEnabled` with HAIP auto-enable fallback.
4. THE `fositex/config.go` file SHALL include a compile-time interface check `var _ fosite.AuthResponseIssConfigProvider = (*Config)(nil)`.

### Requirement 6: RFC 9207 iss Parameter in Success Responses

**User Story:** As a Wallet developer, I want the authorization success response to include an `iss` parameter identifying the AS, so that I can verify the response originated from the expected AS and prevent mix-up attacks.

#### Acceptance Criteria

1. WHEN `GetAuthResponseIssParameterEnabled(ctx)` returns true, THE `WriteAuthorizeResponse()` function in `fosite/authorize_write.go` SHALL add an `iss` parameter to the response parameters before the response mode switch.
2. THE `iss` parameter value SHALL be the AS Issuer Identifier obtained from `Configurator.GetIDTokenIssuer(ctx)`.
3. THE `iss` parameter SHALL appear in all response modes: query, fragment, and form_post.
4. WHEN `GetAuthResponseIssParameterEnabled(ctx)` returns false, THE `WriteAuthorizeResponse()` function SHALL not add an `iss` parameter.

### Requirement 7: RFC 9207 iss Parameter in Error Responses

**User Story:** As a Wallet developer, I want the authorization error response to include an `iss` parameter identifying the AS, so that I can verify error responses also originated from the expected AS.

#### Acceptance Criteria

1. WHEN `GetAuthResponseIssParameterEnabled(ctx)` returns true AND the error is a redirect error, THE `WriteAuthorizeError()` function in `fosite/authorize_error.go` SHALL add an `iss` parameter to the error `url.Values`.
2. THE `iss` parameter value SHALL be the AS Issuer Identifier obtained from `Configurator.GetIDTokenIssuer(ctx)`.
3. WHEN the error is a non-redirect error (rendered as JSON directly to the user-agent), THE `WriteAuthorizeError()` function SHALL not add an `iss` parameter.
4. WHEN `GetAuthResponseIssParameterEnabled(ctx)` returns false, THE `WriteAuthorizeError()` function SHALL not add an `iss` parameter.

### Requirement 8: Discovery Metadata — PAR Fields

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise the PAR endpoint URL and whether PAR is required, so that I can determine whether to use PAR before initiating a flow.

#### Acceptance Criteria

1. THE Discovery_Endpoint SHALL include a `pushed_authorization_request_endpoint` field (string) containing the PAR endpoint URL derived from the issuer URL and the `/oauth2/par` path.
2. THE Discovery_Endpoint SHALL include a `require_pushed_authorization_requests` field (boolean) set to true when `EnforcePushedAuthorize(ctx)` returns true (reflecting both standalone PAR enforcement and HAIP auto-enable).
3. WHEN `EnforcePushedAuthorize(ctx)` returns false, THE `require_pushed_authorization_requests` field SHALL be omitted from the metadata response via `omitempty`.

### Requirement 9: Discovery Metadata — Pre-Authorized Code Fields

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise Pre-Authorized Code grant support and anonymous access capability, so that I can determine whether the AS supports issuer-initiated flows.

#### Acceptance Criteria

1. WHEN `GetPreAuthorizedCodeEnabled(ctx)` returns true, THE Discovery_Endpoint SHALL include `urn:ietf:params:oauth:grant-type:pre-authorized_code` in the `grant_types_supported` array.
2. WHEN `GetPreAuthorizedCodeEnabled(ctx)` returns true, THE Discovery_Endpoint SHALL include a `pre-authorized_grant_anonymous_access_supported` field (boolean) with the value from `GetPreAuthorizedCodeAnonymousAccess(ctx)`.
3. WHEN `GetPreAuthorizedCodeEnabled(ctx)` returns false, THE Discovery_Endpoint SHALL not include the pre-authorized code grant type in `grant_types_supported` and SHALL omit the `pre-authorized_grant_anonymous_access_supported` field.

### Requirement 10: Discovery Metadata — DPoP Fields

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise DPoP signing algorithm support, so that I can determine which algorithms to use for DPoP proofs.

#### Acceptance Criteria

1. WHEN `GetDPoPEnabled(ctx)` returns true, THE Discovery_Endpoint SHALL include a `dpop_signing_alg_values_supported` field (string array) with the value from `GetDPoPSigningAlgValuesSupported(ctx)`.
2. WHEN `GetDPoPEnabled(ctx)` returns false, THE Discovery_Endpoint SHALL omit the `dpop_signing_alg_values_supported` field.

### Requirement 11: Discovery Metadata — RFC 9207 Field

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise RFC 9207 support, so that I can determine whether to validate the `iss` parameter in authorization responses.

#### Acceptance Criteria

1. WHEN `GetAuthResponseIssParameterEnabled(ctx)` returns true, THE Discovery_Endpoint SHALL include an `authorization_response_iss_parameter_supported` field set to true.
2. WHEN `GetAuthResponseIssParameterEnabled(ctx)` returns false, THE Discovery_Endpoint SHALL omit the `authorization_response_iss_parameter_supported` field.

### Requirement 12: Discovery Metadata — Wallet Attestation Field

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise Wallet Attestation client authentication support, so that I can determine whether to use attestation-based authentication.

#### Acceptance Criteria

1. WHEN `GetWalletAttestationEnabled(ctx)` returns true, THE Discovery_Endpoint SHALL include `attest_jwt_client_auth` in the `token_endpoint_auth_methods_supported` array.
2. WHEN `GetWalletAttestationEnabled(ctx)` returns false, THE Discovery_Endpoint SHALL not include `attest_jwt_client_auth` in the `token_endpoint_auth_methods_supported` array.

### Requirement 13: Discovery Metadata — HAIP Code Challenge Methods Restriction

**User Story:** As a Wallet developer, I want the AS discovery metadata to accurately reflect the supported PKCE code challenge methods under HAIP enforcement, so that I know to use S256 exclusively.

#### Acceptance Criteria

1. WHILE `GetHAIPEnforced(ctx)` returns true, THE Discovery_Endpoint SHALL set `code_challenge_methods_supported` to `["S256"]` only, excluding `plain`.
2. WHILE `GetHAIPEnforced(ctx)` returns false, THE Discovery_Endpoint SHALL set `code_challenge_methods_supported` to `["plain", "S256"]`.

### Requirement 14: Discovery Metadata — RFC 8414 Conformance

**User Story:** As a standards-compliant implementer, I want all new discovery metadata fields to conform to RFC 8414 and their respective defining RFCs, so that Wallets and other clients can rely on standard metadata semantics.

#### Acceptance Criteria

1. THE Discovery_Endpoint SHALL use `omitempty` JSON tags on all new boolean and slice fields so that disabled features produce no metadata field (absent rather than false/empty).
2. THE Discovery_Endpoint SHALL use the exact field names specified by their defining RFCs: `pushed_authorization_request_endpoint` (RFC 9126 §5), `require_pushed_authorization_requests` (RFC 9126 §5), `dpop_signing_alg_values_supported` (RFC 9449 §5), `authorization_response_iss_parameter_supported` (RFC 9207 §3), `authorization_details_types_supported` (RFC 9396 §9), `pre-authorized_grant_anonymous_access_supported` (OIDC4VCI §12.3).
3. THE `pushed_authorization_request_endpoint` field SHALL always be populated when the PAR endpoint is available, regardless of whether PAR is enforced.

### Requirement 15: HAIP Independence of Pre-Authorized Code

**User Story:** As an operator, I want the HAIP enforcement flag to not auto-enable the Pre-Authorized Code grant type, so that Pre-Authorized Code support remains independently configurable.

#### Acceptance Criteria

1. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `GetPreAuthorizedCodeEnabled(ctx)` method SHALL return the value of the standalone `KeyPreAuthorizedCodeEnabled` config key without HAIP override.
2. THE Pre-Authorized Code grant type SHALL appear in discovery metadata only when `KeyPreAuthorizedCodeEnabled` is explicitly true.

### Requirement 16: HAIP Independence of Wallet Attestation

**User Story:** As an operator, I want the HAIP enforcement flag to not auto-enable Wallet Attestation, so that Wallet Attestation support remains independently configurable.

#### Acceptance Criteria

1. WHILE `KeyHAIPEnforced` is true, THE DefaultProvider `GetWalletAttestationEnabled(ctx)` method SHALL return the value of the standalone `KeyWalletAttestationEnabled` config key without HAIP override.
2. THE `attest_jwt_client_auth` auth method SHALL appear in discovery metadata only when `KeyWalletAttestationEnabled` is explicitly true.

### Requirement 17: Refresh Token Preserves authorization_details

**User Story:** As a Wallet developer, I want refresh token exchanges to preserve the original `authorization_details` and credential scope bindings, so that refreshed access tokens retain the same credential authorization.

#### Acceptance Criteria

1. WHEN a refresh token is exchanged where the original token was issued with `authorization_details` in `Session.Extra`, THE Token_Endpoint SHALL issue a new access token whose session retains the same `authorization_details` data.
2. THE `credential_identifiers` within each `authorization_details` object SHALL be preserved across refresh token exchanges without mutation.

### Requirement 18: Refresh Token Issuance in Credential Flows

**User Story:** As a Wallet developer, I want refresh tokens to be issued in credential issuance flows when the client is eligible, so that I can refresh credentials without re-authenticating the user.

#### Acceptance Criteria

1. WHEN a credential issuance flow (authorization code or pre-authorized code) completes successfully AND the client is authorized for the `refresh_token` grant type AND the granted scopes include a refresh token scope, THE Token_Endpoint SHALL issue a refresh token alongside the access token.

### Requirement 19: Feature Documentation

**User Story:** As a developer or operator, I want comprehensive documentation of the HAIP enforcement behavior, RFC 9207 implementation, and discovery metadata extensions, so that I can understand and configure the system correctly.

#### Acceptance Criteria

1. THE documentation file `docs/features/haip-metadata.md` SHALL describe HAIP enforcement behavior including which features are auto-enabled (PAR, PKCE S256, DPoP, RFC 9207 iss) and which are independent (Pre-Auth, Wallet Attestation).
2. THE documentation file SHALL describe the RFC 9207 `iss` parameter behavior for both success and error authorization responses.
3. THE documentation file SHALL list all new discovery metadata fields with their conditions, types, and defining RFCs.
4. THE documentation file SHALL list all relevant configuration keys with their types, defaults, and HAIP override behavior.
5. THE documentation file SHALL include references to RFC 9126, RFC 9207, RFC 8414, RFC 9449, RFC 9396, and the HAIP specification.
