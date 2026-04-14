# Requirements Document

## Introduction

This document specifies the foundational OIDC4VCI infrastructure for the Hydra AS fork: Rich Authorization Requests (RFC 9396), consent flow extensions for `authorization_details` propagation, `issuer_state` parameter support, scope-based credential request handling, and HAIP configuration infrastructure. All other OIDC4VCI specs depend on the components built here.

The scope is strictly the Authorization Server role. The Credential Issuer is a separate microservice and is out of scope. This spec covers the RAR handler (`fosite/handler/rar/`), consent type extensions (`flow/consent_types.go`), session propagation, token response extensions, config provider interfaces, compose factory, error constants, and feature documentation.

## Glossary

- **AS**: Authorization Server — the Hydra instance responsible for OAuth 2.0 and OIDC flows.
- **RAR_Handler**: The Fosite handler in `fosite/handler/rar/` that implements `AuthorizeEndpointHandler`, `PushedAuthorizeEndpointHandler`, and `TokenEndpointHandler` for `authorization_details` processing.
- **Authorization_Endpoint**: The Hydra endpoint (`/oauth2/auth`) that handles authorization requests.
- **PAR_Endpoint**: The Pushed Authorization Request endpoint (`/oauth2/par`), already implemented in `fosite/handler/par/`.
- **Token_Endpoint**: The Hydra endpoint (`/oauth2/token`) that issues access tokens and extended response parameters.
- **Discovery_Endpoint**: The Hydra endpoint (`/.well-known/openid-configuration`) that publishes AS metadata.
- **Consent_Node**: The external Login/Consent application that Hydra delegates user authentication and consent decisions to.
- **Wallet**: The OAuth 2.0 Client (end-user application) that requests credentials.
- **Credential_Issuer**: An external microservice that issues Verifiable Credentials. Out of scope for implementation.
- **Fosite**: The embedded OAuth 2.0 library within Hydra that implements handler-based request processing.
- **Session_Extra**: The `map[string]interface{}` field on `oauth2.Session` used to carry custom claims through the token lifecycle.
- **Configurator**: The Fosite interface (`fosite/fosite.go`) that composes all provider interfaces for handler configuration.
- **RARConfigProvider**: The provider interface for RAR feature configuration (`GetRAREnabled`, `GetRARTypesSupported`).
- **HAIPConfigProvider**: The provider interface for HAIP enforcement configuration (`GetHAIPEnforced`).
- **ErrInvalidAuthorizationDetails**: The OAuth extension error code `invalid_authorization_details` defined in RFC 9396 §14.6.

## Requirements

### Requirement 1: RAR Parsing and Validation on Authorization and PAR Endpoints

**User Story:** As a Wallet developer, I want to include an `authorization_details` parameter with type `openid_credential` in authorization and PAR requests, so that I can specify exactly which credential configurations I want issued.

#### Acceptance Criteria

1. WHEN an Authorization Request contains an `authorization_details` parameter, THE RAR_Handler SHALL parse the JSON string as an array of objects and validate each object.
2. WHEN a PAR Request contains an `authorization_details` parameter, THE RAR_Handler SHALL parse and validate the `authorization_details` using the same logic as the Authorization_Endpoint.
3. IF an `authorization_details` object is missing the `type` field, THEN THE RAR_Handler SHALL reject the request with an `invalid_authorization_details` error.
4. WHEN an `authorization_details` object has `type` equal to `openid_credential` (or a value in the configured `GetRARTypesSupported()` list), THE RAR_Handler SHALL validate that the `credential_configuration_id` field is present and non-empty.
5. IF an `authorization_details` object has a `type` value not in the configured `GetRARTypesSupported()` list, THEN THE RAR_Handler SHALL reject the request with an `invalid_authorization_details` error.
6. IF an `authorization_details` object of type `openid_credential` is missing the `credential_configuration_id` field, THEN THE RAR_Handler SHALL reject the request with an `invalid_authorization_details` error.
7. IF the `authorization_details` parameter contains malformed JSON, THEN THE RAR_Handler SHALL reject the request with an `invalid_authorization_details` error.
8. WHEN an Authorization Request or PAR Request does not contain an `authorization_details` parameter, THE RAR_Handler SHALL return nil without modifying the session, responder, or requester.
9. THE RAR_Handler SHALL store the validated `authorization_details` alongside the authorization session for downstream consumption by the consent flow and token endpoint.

### Requirement 2: Token Request Subset Validation

**User Story:** As a Wallet developer, I want to include `authorization_details` in my token request to narrow the set of credentials I want, so that I can request a subset of previously authorized credential configurations.

#### Acceptance Criteria

1. THE RAR_Handler `CanHandleTokenEndpointRequest` SHALL return `true` when the token request form contains an `authorization_details` parameter, enabling subset validation via `HandleTokenEndpointRequest`.
2. WHEN a Token Request contains an `authorization_details` parameter, THE RAR_Handler SHALL parse and validate the `authorization_details` JSON array.
3. WHEN a Token Request contains `authorization_details`, THE RAR_Handler SHALL extract all `credential_configuration_id` values and validate that each is a member of the set previously authorized during the authorization phase (stored in the session).
4. IF a Token Request contains a `credential_configuration_id` not in the previously authorized set, THEN THE RAR_Handler SHALL reject the request with an `invalid_authorization_details` error.
5. WHEN a Token Request does not contain an `authorization_details` parameter, THE RAR_Handler `CanHandleTokenEndpointRequest` SHALL return `false`, and no subset validation SHALL occur. The full authorized set from the session remains unchanged.
6. THE RAR_Handler `CanSkipClientAuth` SHALL return `false` — the RAR handler never bypasses client authentication.

### Requirement 3: Token Response Extensions

**User Story:** As a Wallet developer, I want the token response to include `authorization_details` with `credential_identifiers`, so that I can use those identifiers in subsequent Credential Requests to the Credential Issuer.

#### Acceptance Criteria

1. WHEN `authorization_details` of type `openid_credential` was used in the authorization or token request, THE Token_Endpoint SHALL include an `authorization_details` array in the successful Token Response via response extras.
2. THE Token_Endpoint SHALL propagate `authorization_details` (including `credential_identifiers` set by the Consent_Node or Token Hook) from Session_Extra into the token response extras.
3. WHEN `authorization_details` is present in Session_Extra, THE RAR_Handler `PopulateTokenEndpointResponse` SHALL copy the `authorization_details` value into the access response extras. This method runs regardless of whether the token request itself contained `authorization_details`, because response population is independent of subset validation activation.
4. IF `authorization_details` of type `openid_credential` is present in the Token Response but an entry is missing `credential_identifiers` (or it is empty), THE AS SHALL log a warning. The AS does not set `credential_identifiers` itself — the Consent_Node or Token Hook is responsible for populating them per OIDC4VCI §6.2. The AS propagates whatever the session contains.

### Requirement 4: Authorization Details Flow-Through to Consent Node

**User Story:** As a Login/Consent application developer, I want to receive `authorization_details` data in the consent challenge, so that I can display credential-specific information to the user and make informed consent decisions.

#### Acceptance Criteria

1. WHEN an authorization request contains validated `authorization_details`, THE AS SHALL include the `authorization_details` in the `OAuth2ConsentRequest` payload sent to the Consent_Node.
2. WHEN the Consent_Node accepts the consent request, THE AS SHALL accept an `AuthorizationDetails` field on the `AcceptOAuth2ConsentRequest` containing enriched `authorization_details` (with `credential_identifiers` added by the Consent_Node).
3. THE AS SHALL merge the `authorization_details` from the consent accept response into Session_Extra so the data is available during token issuance, introspection, and refresh token exchange.

### Requirement 5: Consent Type Extensions

**User Story:** As a developer extending the consent flow, I want `AuthorizationDetails` and `IssuerState` fields on the consent types, so that RAR data and issuer context flow through the consent challenge/accept cycle.

#### Acceptance Criteria

1. THE AS SHALL add an `AuthorizationDetails` field of type `sqlxx.JSONRawMessage` to the `OAuth2ConsentRequest` struct in `flow/consent_types.go`, serialized as `json:"authorization_details,omitempty"` and stored as `db:"authorization_details"`.
2. THE AS SHALL add an `AuthorizationDetails` field of type `sqlxx.JSONRawMessage` to the `AcceptOAuth2ConsentRequest` struct in `flow/consent_types.go`, serialized as `json:"authorization_details,omitempty"` and stored as `db:"authorization_details"`.
3. THE AS SHALL add an `IssuerState` field of type `string` to the `OAuth2ConsentRequest` struct in `flow/consent_types.go`, serialized as `json:"issuer_state,omitempty"` and stored as `db:"issuer_state"`.
4. THE AS SHALL add new consent type fields at the end of existing structs before the closing brace, marked with `// OIDC4VCI extension` comments, to minimize upstream merge conflict risk.
5. THE AS SHALL provide a database migration adding `authorization_details` and `issuer_state` columns to the consent request tables. The migration must support PostgreSQL, MySQL, CockroachDB, and SQLite.

### Requirement 6: issuer_state Parameter

**User Story:** As a Credential Issuer operator, I want to pass an `issuer_state` value through the authorization flow, so that I can bind the authorization request to a previously established context such as a Credential Offer.

#### Acceptance Criteria

1. WHEN an Authorization Request or PAR Request contains an `issuer_state` parameter, THE AS SHALL extract the value from the request form and store it alongside the authorization session.
2. THE AS SHALL include the `issuer_state` value in the `OAuth2ConsentRequest` sent to the Consent_Node so the Login/Consent application can use it for context binding.
3. THE AS SHALL treat the `issuer_state` as an opaque, untrusted string and perform no security decisions based on its value without additional validation.

### Requirement 7: Scope-Based Credential Request Support

**User Story:** As a Wallet developer, I want to use standard OAuth 2.0 `scope` values to request credential issuance, so that I can request credentials without using `authorization_details`.

#### Acceptance Criteria

1. WHEN an Authorization Request contains a `scope` value that maps to a credential configuration (as defined in the AS configuration for credential scope mappings), THE AS SHALL treat it as a request to access the Credential Endpoint for that credential type.
2. THE AS SHALL silently ignore unknown scope values related to credential issuance without returning an error.
3. WHEN both `authorization_details` of type `openid_credential` and a `scope` value related to credential issuance are present in the same request, THE AS SHALL process each independently without conflict, with `authorization_details` taking precedence for overlapping credential types at the Credential_Issuer level (the AS passes both through).
4. Note: The concrete configuration mechanism for credential scope mappings (e.g., a `KeyCredentialScopeMappings` config key and provider method) is deferred to the Credential Issuer integration spec. This spec establishes the pass-through behavior only — the AS forwards scope values without interpreting the mapping itself.

### Requirement 8: Session Propagation

**User Story:** As a system integrator, I want `authorization_details` (with `credential_identifiers`) to be available in the token session throughout the token lifecycle, so that introspection, refresh, and token hooks can access the data.

#### Acceptance Criteria

1. THE AS SHALL store the final `authorization_details` (enriched by the Consent_Node with `credential_identifiers`) in `Session.Extra["authorization_details"]` after consent accept processing.
2. WHEN a refresh token is exchanged, THE Token_Endpoint SHALL preserve the `authorization_details` in Session_Extra so the new access token retains the same credential bindings.
3. THE AS SHALL make `authorization_details` in Session_Extra available to the Token Hook (`oauth2/token_hook.go`) so external services can inspect or modify `credential_identifiers` before the token response is finalized.
4. WHEN a token is introspected, THE introspection response SHALL include `authorization_details` from Session_Extra if present. Note: this is handled by existing Hydra introspection code reading `Session.Extra` — no new introspection code is required, but the behavior must be verified.

### Requirement 9: RAR Config Provider and Config Keys

**User Story:** As an AS operator, I want configuration keys to enable/disable RAR and specify supported authorization_details types, so that I can control RAR behavior without code changes.

#### Acceptance Criteria

1. THE AS SHALL define a `RARConfigProvider` interface with methods `GetRAREnabled(ctx context.Context) bool` and `GetRARTypesSupported(ctx context.Context) []string`.
2. THE AS SHALL define config keys `KeyRAREnabled` (boolean, default `false`) and `KeyRARTypesSupported` (string slice, default `["openid_credential"]`) in `driver/config/`.
3. THE AS SHALL implement the `RARConfigProvider` methods on `DefaultProvider` using the standard `p.getProvider(ctx)` pattern for multi-tenant support.
4. THE AS SHALL embed `RARConfigProvider` in the Fosite `Configurator` interface in `fosite/fosite.go`.
5. THE AS SHALL add `rar.enabled` and `rar.types_supported` properties to the JSON schema in `spec/config.json` and run `scripts/render-schemas.sh` to regenerate derived schemas.

### Requirement 10: HAIP Config Infrastructure

**User Story:** As an AS operator, I want a HAIP enforcement configuration key, so that later specs can gate PAR enforcement, PKCE S256 enforcement, and other HAIP-mandated behaviors behind a single config flag.

#### Acceptance Criteria

1. THE AS SHALL define a `HAIPConfigProvider` interface with method `GetHAIPEnforced(ctx context.Context) bool`.
2. THE AS SHALL define config key `KeyHAIPEnforced` (boolean, default `false`) in `driver/config/`.
3. THE AS SHALL implement the `HAIPConfigProvider` method on `DefaultProvider`.
4. THE AS SHALL embed `HAIPConfigProvider` in the Fosite `Configurator` interface in `fosite/fosite.go`.
5. THE AS SHALL add `haip.enforced` property to the JSON schema in `spec/config.json` and run `scripts/render-schemas.sh` to regenerate derived schemas.

### Requirement 11: RAR Compose Factory

**User Story:** As a developer wiring up the Fosite handler pipeline, I want a compose factory for the RAR handler, so that the handler is registered in the authorize, PAR, and token handler lists via the standard factory pattern.

#### Acceptance Criteria

1. THE AS SHALL define an `RARFactory` function in `fosite/compose/compose_rar.go` following the `compose.Factory` signature that returns an `*rar.RARHandler` struct.
2. THE AS SHALL register the `RARFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyRAREnabled`.
3. WHEN the `RARFactory` result is type-asserted by `Compose()`, THE AS SHALL register the handler as `AuthorizeEndpointHandler`, `PushedAuthorizeEndpointHandler`, and `TokenEndpointHandler`.

### Requirement 12: ErrInvalidAuthorizationDetails Error Constant

**User Story:** As a developer implementing RAR validation, I want a dedicated `invalid_authorization_details` error constant in Fosite, so that RFC 9396 §5 error responses use the correct error code.

#### Acceptance Criteria

1. THE AS SHALL define an `ErrInvalidAuthorizationDetails` variable as a `*fosite.RFC6749Error` with `ErrorField` set to `invalid_authorization_details` and `CodeField` set to HTTP 400.
2. THE RAR_Handler SHALL use `ErrInvalidAuthorizationDetails` (with `.WithHint()` and `.WithDebugf()` for context) for all RAR validation failures instead of `ErrInvalidRequest`.

### Requirement 13: Discovery Metadata for RAR

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise supported `authorization_details` types, so that I can determine whether the AS supports RAR before initiating a flow.

#### Acceptance Criteria

1. WHEN RAR is enabled, THE Discovery_Endpoint SHALL include `authorization_details_types_supported` containing the values from `GetRARTypesSupported()` in the AS metadata.
2. WHEN RAR is disabled, THE Discovery_Endpoint SHALL omit the `authorization_details_types_supported` field from the AS metadata.
3. Note: This requirement covers only the `authorization_details_types_supported` metadata field. Other OIDC4VCI and HAIP metadata extensions (e.g., `require_pushed_authorization_requests`, `dpop_signing_alg_values_supported`) are handled in Spec 5 (`oidc4vci-haip-metadata`). The implementation here should be structured so Spec 5 can extend the metadata population logic without conflict.

### Requirement 14: Feature Documentation

**User Story:** As a developer or operator, I want a feature documentation file describing the RAR and consent extensions, so that I can understand the implemented feature, its configuration, API surface, and error codes.

#### Acceptance Criteria

1. THE AS SHALL include a documentation file at `docs/features/rar-consent.md` describing the implemented feature.
2. THE documentation SHALL cover: feature overview, configuration options (`KeyRAREnabled`, `KeyRARTypesSupported`, `KeyHAIPEnforced`), API surface (affected endpoints and request/response parameters), error codes (`invalid_authorization_details`), consent type extensions, session propagation, and references to RFC 9396 and the OIDC4VCI specification. The documentation SHALL clarify that `KeyHAIPEnforced` is infrastructure only in this spec — the config key is defined here but enforcement behavior is wired in Spec 5 (`oidc4vci-haip-metadata`).
