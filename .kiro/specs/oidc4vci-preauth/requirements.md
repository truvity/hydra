# Requirements Document

## Introduction

This document specifies the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) for the Hydra AS fork. This grant allows Wallets to exchange a pre-authorized code for an access token without going through the authorization endpoint — the credential issuance preparation happens before the OAuth flow. The Credential Issuer creates pre-authorized codes via an admin API on the AS, includes them in Credential Offers sent to Wallets, and the Wallets exchange them at the token endpoint.

The scope is strictly the Authorization Server role. The Credential Issuer is a separate microservice and is out of scope. This spec covers the Pre-Authorized Code handler (`fosite/handler/preauth/`), storage interface and SQL persistence, admin API endpoint, compose factory, config provider, error constants, database migration, and feature documentation.

This spec depends on Spec 1 (oidc4vci-rar-consent) which established the config provider interface pattern, factory registration pattern, error constant pattern, `Session.Extra` propagation, `PopulateTokenEndpointResponse` pattern, compile-time interface checks, and persistence pattern. It depends on Spec 2 (oidc4vci-dpop) which established that DPoP token binding is a cross-cutting handler that decorates all grant types independently — the Pre-Auth handler does NOT call DPoP; DPoP's `PopulateTokenEndpointResponse` runs after Pre-Auth's and binds the token if a `DPoP` header is present.

## Glossary

- **AS**: Authorization Server — the Hydra instance responsible for OAuth 2.0 and OIDC flows.
- **PreAuth_Handler**: The Fosite handler in `fosite/handler/preauth/` that implements `TokenEndpointHandler` for the Pre-Authorized Code grant type.
- **Token_Endpoint**: The Hydra endpoint (`/oauth2/token`) that issues access tokens and processes Pre-Authorized Code exchanges.
- **Admin_API**: The Hydra admin API (`/admin/oauth2/preauth`) used by the Credential_Issuer to create pre-authorized codes.
- **Discovery_Endpoint**: The Hydra endpoint (`/.well-known/openid-configuration`) that publishes AS metadata.
- **Credential_Issuer**: An external microservice that issues Verifiable Credentials. It creates pre-authorized codes via the Admin_API and includes them in Credential Offers. Out of scope for implementation.
- **Wallet**: The OAuth 2.0 Client (end-user application) that exchanges pre-authorized codes for access tokens at the Token_Endpoint.
- **Pre-Authorized_Code**: An opaque code created by the Credential_Issuer via the Admin_API, stored in the AS, and exchanged by the Wallet at the Token_Endpoint for an access token. Grant type: `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
- **Transaction_Code**: A one-time code (e.g., PIN sent via SMS/email) that the End-User enters in the Wallet to authorize the Pre-Authorized Code exchange. Validated against a stored hash.
- **PreAuthorizedCodeStorage**: The storage interface for creating, retrieving, and invalidating pre-authorized code sessions, with methods `CreatePreAuthorizedCodeSession`, `GetPreAuthorizedCodeSession`, `InvalidatePreAuthorizedCode`.
- **PreAuthorizedCodeData**: The data model struct representing a stored pre-authorized code grant, including signature, client_id (nullable), credential_configuration_ids, tx_code_hash, session_data, redeemed flag, and expiry. Note: `authorization_details` are NOT stored — they are constructed at runtime from `CredentialConfigurationIDs`.
- **PreAuthorizedCodeConfigProvider**: The provider interface for Pre-Authorized Code feature configuration (`GetPreAuthorizedCodeEnabled`, `GetPreAuthorizedCodeLifespan`, `GetPreAuthorizedCodeAnonymousAccess`).
- **CoreStrategy**: The Fosite strategy interface used by the handler to generate access tokens (HMAC or JWT). Obtained via type assertion from the `strategy` parameter in the compose factory.
- **Configurator**: The Fosite interface (`fosite/fosite.go`) that composes all provider interfaces for handler configuration.
- **Session_Extra**: The `map[string]interface{}` field on `oauth2.Session` used to carry custom claims through the token lifecycle.
- **Persister**: The aggregate persistence interface (`persistence/definitions.go`) that composes all domain storage interfaces, implemented by `persistence/sql/Persister`.
- **DPoP_Handler**: The cross-cutting DPoP handler (`fosite/handler/dpop/`) that independently binds tokens to DPoP keys when a `DPoP` header is present. Runs after the PreAuth_Handler in the `PopulateTokenEndpointResponse` phase.
- **Token_Hook**: The webhook mechanism (`oauth2/token_hook.go`) that fires for all grant types (including Pre-Authorized Code) before the token response is finalized, allowing external services to modify `Session.Extra`.

## Requirements

### Requirement 1: Pre-Authorized Code Grant Type Handler

**User Story:** As a Wallet developer, I want to exchange a pre-authorized code for an access token at the token endpoint, so that I can obtain credentials from the Credential Issuer without going through the authorization endpoint.

#### Acceptance Criteria

1. THE PreAuth_Handler SHALL implement `fosite.TokenEndpointHandler` with compile-time interface check: `var _ fosite.TokenEndpointHandler = (*Handler)(nil)`.
2. THE PreAuth_Handler `CanHandleTokenEndpointRequest` SHALL return `true` when `requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code")` is true, and `false` for all other grant types.
3. WHEN a Token Request with `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` is received, THE PreAuth_Handler `HandleTokenEndpointRequest` SHALL extract the `pre-authorized_code` parameter from the request form.
4. IF the `pre-authorized_code` parameter is missing or empty in the Token Request, THEN THE PreAuth_Handler SHALL reject the request with an `invalid_request` error with hint "pre-authorized_code parameter is required".
5. WHEN a `pre-authorized_code` is provided, THE PreAuth_Handler SHALL compute the HMAC signature from the raw code using `HMACStrategy.Signature(code)` (splits on `.`, returns the second part) and call `PreAuthorizedCodeStorage.GetPreAuthorizedCodeSession(ctx, signature)` to load the stored grant data.
6. IF the pre-authorized code is not found in storage, THEN THE PreAuth_Handler SHALL reject the request with an `invalid_grant` error with hint "pre-authorized code not found".
7. IF the stored PreAuthorizedCodeData has `Redeemed` set to `true`, THEN THE PreAuth_Handler SHALL reject the request with an `invalid_grant` error with hint "pre-authorized code already redeemed".
8. IF the stored PreAuthorizedCodeData has `ExpiresAt` in the past (before `time.Now()`), THEN THE PreAuth_Handler SHALL reject the request with an `invalid_grant` error with hint "pre-authorized code expired".
9. WHEN the pre-authorized code is valid (found, not redeemed, not expired) and tx_code validation passes (see Requirement 2), THE PreAuth_Handler SHALL call `PreAuthorizedCodeStorage.InvalidatePreAuthorizedCode(ctx, code)` to mark the code as redeemed before populating the requester session.
10. WHEN the pre-authorized code is successfully validated, THE PreAuth_Handler SHALL populate the requester session with data from the stored grant: scopes, audience, and `authorization_details` (set in `Session.Extra["authorization_details"]`).
11. WHEN the stored `ClientID` is non-empty AND client authentication was performed, THE PreAuth_Handler SHALL verify that the authenticated client's ID matches the `ClientID` stored in the PreAuthorizedCodeData. IF they do not match, THE handler SHALL reject the request with an `invalid_grant` error with hint "client_id mismatch".
12. WHEN the stored `ClientID` is empty (unbound code), THE PreAuth_Handler SHALL skip client_id matching and allow any authenticated client (or anonymous if configured) to redeem the code.

### Requirement 2: Transaction Code (tx_code) Validation

**User Story:** As a security architect, I want the AS to validate transaction codes per OIDC4VCI §6.3, so that pre-authorized code exchanges are bound to a specific transaction and protected against unauthorized use.

#### Acceptance Criteria

1. WHEN the stored PreAuthorizedCodeData has a non-empty `TxCodeHash` field (transaction code required) and the Token Request includes a `tx_code` parameter, THE PreAuth_Handler SHALL hash the provided `tx_code` and compare it with the stored `TxCodeHash` using constant-time comparison.
2. IF the stored PreAuthorizedCodeData has a non-empty `TxCodeHash` field but the Token Request does not include a `tx_code` parameter, THEN THE PreAuth_Handler SHALL reject the request with an `invalid_request` error with hint "tx_code required but not provided".
3. IF the stored PreAuthorizedCodeData has an empty `TxCodeHash` field (no transaction code required) but the Token Request includes a `tx_code` parameter, THEN THE PreAuth_Handler SHALL reject the request with an `invalid_request` error with hint "tx_code provided but not expected".
4. IF the provided `tx_code` hash does not match the stored `TxCodeHash`, THEN THE PreAuth_Handler SHALL reject the request with an `invalid_grant` error with hint "tx_code does not match".
5. WHEN the stored PreAuthorizedCodeData has an empty `TxCodeHash` field and the Token Request does not include a `tx_code` parameter, THE PreAuth_Handler SHALL proceed without tx_code validation.
6. THE PreAuth_Handler SHALL use SHA-256 for hashing the provided `tx_code` before comparison with the stored `TxCodeHash`. The Admin_API receives the `tx_code` in plaintext from the Credential_Issuer, computes the SHA-256 hash, and stores the hash. The same SHA-256 algorithm is used at the Token_Endpoint to hash the Wallet-provided `tx_code` and compare it against the stored hash using constant-time comparison.

### Requirement 3: Anonymous Access (CanSkipClientAuth)

**User Story:** As a Credential Issuer operator, I want to support pre-authorized code exchange without client authentication when configured, so that Wallets without registered client credentials can still obtain access tokens in issuer-initiated flows.

#### Acceptance Criteria

1. THE PreAuth_Handler `CanSkipClientAuth` SHALL return `true` when `PreAuthorizedCodeConfigProvider.GetPreAuthorizedCodeAnonymousAccess(ctx)` returns `true`.
2. THE PreAuth_Handler `CanSkipClientAuth` SHALL return `false` when `PreAuthorizedCodeConfigProvider.GetPreAuthorizedCodeAnonymousAccess(ctx)` returns `false`, requiring standard client authentication.
3. WHEN anonymous access is disabled and the Token Request does not include valid client authentication, THE Fosite core SHALL reject the request with an `invalid_client` error (this is handled by the Fosite request lifecycle, not by the PreAuth_Handler directly).

### Requirement 4: Token Response Population

**User Story:** As a Wallet developer, I want the token response to include an access token and `authorization_details` with `credential_identifiers`, so that I can use those identifiers in subsequent Credential Requests to the Credential Issuer.

#### Acceptance Criteria

1. THE PreAuth_Handler `PopulateTokenEndpointResponse` SHALL return `fosite.ErrUnknownRequest` when the grant type is not `urn:ietf:params:oauth:grant-type:pre-authorized_code`, so the response writer skips the handler cleanly.
2. WHEN the grant type is `urn:ietf:params:oauth:grant-type:pre-authorized_code`, THE PreAuth_Handler SHALL issue an access token via `CoreStrategy.GenerateAccessToken(ctx, requester)` and set it on the response via `responder.SetAccessToken()`.
3. WHEN the grant type is `urn:ietf:params:oauth:grant-type:pre-authorized_code`, THE PreAuth_Handler SHALL set the token type on the response via `responder.SetTokenType("bearer")`. Note: if DPoP is active, the DPoP_Handler's `PopulateTokenEndpointResponse` runs after and overrides this to `DPoP`.
4. WHEN `Session.Extra["authorization_details"]` is present, THE PreAuth_Handler SHALL copy it into the access response extras via `responder.SetExtra("authorization_details", authDetails)`.
5. WHEN the access token is issued, THE PreAuth_Handler SHALL set the `expires_in` response parameter based on the access token lifespan from the Configurator.
6. WHEN the client associated with the pre-authorized code is eligible for a refresh token, THE PreAuth_Handler SHALL issue a refresh token alongside the access token via `CoreStrategy.RefreshTokenStrategy().GenerateRefreshToken(ctx, requester)`. Refresh token eligibility requires BOTH: (a) the client's registered grant types include `refresh_token`, AND (b) the granted scopes include one of `Config.GetRefreshTokenScopes(ctx)` (defaults to `["offline", "offline_access"]`), OR `GetRefreshTokenScopes` returns an empty list (meaning all exchanges get refresh tokens). The `scope` parameter on the admin API code creation request (Requirement 9) determines which scopes are granted, so the Credential Issuer controls refresh token eligibility by including `offline` or `offline_access` in the scope. This follows the same pattern as `canIssueRefreshToken` in `fosite/handler/oauth2/flow_authorize_code_token.go`.
7. WHEN anonymous access is used (no bound client), THE PreAuth_Handler SHALL NOT issue a refresh token regardless of scope or client grant type configuration. A refresh token without client binding is a security risk — anyone with the refresh token can obtain new access tokens indefinitely.

### Requirement 5: PreAuthorizedCodeStorage Interface

**User Story:** As a developer implementing the Pre-Authorized Code handler, I want a storage interface for creating, retrieving, and invalidating pre-authorized code sessions, so that the handler and admin API can manage pre-authorized code lifecycle.

#### Acceptance Criteria

1. THE AS SHALL define a `PreAuthorizedCodeStorage` interface in `fosite/handler/preauth/storage.go` with methods: `CreatePreAuthorizedCodeSession(ctx context.Context, signature string, data *PreAuthorizedCodeData) error`, `GetPreAuthorizedCodeSession(ctx context.Context, signature string) (*PreAuthorizedCodeData, error)`, `InvalidatePreAuthorizedCode(ctx context.Context, signature string) error`. Note: The `signature` parameter is the HMAC signature extracted from the raw pre-authorized code. The handler is responsible for computing the signature from the raw code (using `HMACStrategy.Signature(code)` which splits on `.` and returns the second part) before calling storage methods. This follows the same pattern as the authorization code flow where `AuthorizeCodeStrategy().AuthorizeCodeSignature(ctx, code)` extracts the signature used as the DB lookup key. The raw pre-authorized code has the format `base64(key).base64(sig)` and the signature portion is the DB primary key.
2. THE AS SHALL add `PreAuthorizedCodeStorage` to the `persistence.Persister` aggregate interface in `persistence/definitions.go` so the SQL persister implements it.
3. THE AS SHALL add a `PreAuthorizedCodeStorage()` accessor on `RegistrySQL` in `driver/registry_sql.go` with lazy initialization pattern, returning the `Persister` cast to `preauth.PreAuthorizedCodeStorage`.

### Requirement 6: PreAuthorizedCodeData Model

**User Story:** As a developer, I want a data model representing the stored pre-authorized code grant, so that all grant data is structured and persisted consistently.

#### Acceptance Criteria

1. THE AS SHALL define a `PreAuthorizedCodeData` struct in `fosite/handler/preauth/` with fields: `Signature` (string, PK — HMAC signature of the pre-authorized code), `NID` (uuid.UUID — network ID for multi-tenancy), `RequestID` (string), `ClientID` (string, nullable — empty if unbound; when set, the handler verifies the authenticated client matches at redemption), `RequestedScope` (fosite.Arguments), `GrantedScope` (fosite.Arguments), `CredentialConfigurationIDs` ([]string — credential configuration IDs from the offer; defines the authorization envelope), `TxCodeHash` (string — SHA-256 hash of the transaction code, empty if not required), `TxCodeInputMode` (string — "numeric" or "text", nullable), `TxCodeLength` (int — expected length of tx_code, nullable), `SessionData` (json.RawMessage — serialized session), `Redeemed` (bool — single-use flag), `RequestedAt` (time.Time), `ExpiresAt` (time.Time). Note: No `AuthorizationDetails` field. The `authorization_details` are NOT stored at code creation time — they are constructed at the token endpoint from `CredentialConfigurationIDs` (default set) or validated from the Wallet's token request (subset selection), then enriched with `credential_identifiers` by the Credential Issuer via the Token Hook.
2. THE `PreAuthorizedCodeData` struct SHALL implement `TableName() string` returning `"hydra_oauth2_preauth_code"` for Pop ORM compatibility.
3. THE `PreAuthorizedCodeData` struct SHALL use Pop struct tags (`db:"column_name"`) for all fields.

### Requirement 7: Database Migration

**User Story:** As an AS operator, I want a database table for pre-authorized code grant data, so that pre-authorized codes are persisted across AS restarts and in multi-instance deployments.

#### Acceptance Criteria

1. THE AS SHALL create a database migration adding the `hydra_oauth2_preauth_code` table with columns: `signature` (VARCHAR(255), NOT NULL, PK), `nid` (UUID, NOT NULL), `request_id` (VARCHAR(255), NOT NULL), `client_id` (VARCHAR(255), NULL — nullable for unbound codes), `requested_scope` (JSON), `granted_scope` (JSON), `credential_configuration_ids` (JSON, NOT NULL — the authorization envelope, always required), `tx_code_hash` (VARCHAR(255), NULL), `tx_code_input_mode` (VARCHAR(10), NULL), `tx_code_length` (INT, NULL), `session_data` (JSON, NOT NULL), `redeemed` (BOOLEAN, NOT NULL, DEFAULT FALSE), `requested_at` (TIMESTAMP, NOT NULL), `expires_at` (TIMESTAMP, NOT NULL).
2. THE migration SHALL create an index `idx_preauth_code_nid` on `(nid)` for tenant-scoped queries.
3. THE migration SHALL create an index `idx_preauth_code_expires_at` on `(nid, expires_at)` for cleanup queries.
4. THE migration SHALL use `CREATE TABLE IF NOT EXISTS` for idempotency.
5. THE migration SHALL support PostgreSQL, MySQL, CockroachDB, and SQLite.
6. THE migration SHALL follow the naming convention `YYYYMMDDHHMMSS_oidc4vci_create_preauth_code.up.sql` / `.down.sql` in `persistence/sql/migrations/`.
7. THE down migration SHALL drop the `hydra_oauth2_preauth_code` table cleanly.

### Requirement 8: SQL Persistence Implementation

**User Story:** As a developer, I want the `PreAuthorizedCodeStorage` interface implemented on the SQL persister, so that pre-authorized code lifecycle management works with the database.

#### Acceptance Criteria

1. THE AS SHALL implement `CreatePreAuthorizedCodeSession` on `persistence/sql/Persister` by inserting a row into `hydra_oauth2_preauth_code` with the provided data and the current network ID (`nid`).
2. THE AS SHALL implement `GetPreAuthorizedCodeSession` on `persistence/sql/Persister` by querying `hydra_oauth2_preauth_code` for the given code signature and the current network ID (`nid`). IF the code is not found, THE method SHALL return `fosite.ErrNotFound`.
3. THE AS SHALL implement `InvalidatePreAuthorizedCode` on `persistence/sql/Persister` by executing an atomic `UPDATE hydra_oauth2_preauth_code SET redeemed=true WHERE signature=? AND nid=? AND redeemed=false`. IF no rows were affected (code already redeemed by a concurrent request or not found), THE method SHALL return an error indicating the code was already redeemed or not found. This atomic WHERE clause prevents the TOCTOU race between `GetPreAuthorizedCodeSession` (check redeemed=false) and `InvalidatePreAuthorizedCode` (set redeemed=true) when two concurrent requests use the same code.
4. THE SQL persistence implementation SHALL be in `persistence/sql/persister_preauth.go`.

### Requirement 9: Admin API for Pre-Authorized Code Creation

**User Story:** As a Credential Issuer operator, I want an admin API endpoint to create pre-authorized codes on the AS, so that I can include them in Credential Offers sent to Wallets.

#### Acceptance Criteria

1. THE AS SHALL provide an admin API endpoint `POST /admin/oauth2/preauth` for creating pre-authorized codes.
2. THE admin endpoint SHALL accept a JSON request body with fields: `client_id` (string, optional — the OAuth 2.0 client ID to bind the code to; if omitted, any client or anonymous can redeem), `credential_configuration_ids` ([]string, required — the credential configuration IDs the Credential Issuer plans to offer; defines the authorization envelope), `scope` (string, optional — space-separated scopes; controls refresh token eligibility by including `offline`/`offline_access`), `tx_code` (string, optional — the transaction code in plaintext; the AS computes the SHA-256 hash before storage; the plaintext is never stored), `tx_code_input_mode` (string, optional — "numeric" or "text"), `tx_code_length` (int, optional — expected length of tx_code). Note: `authorization_details` is NOT in the admin API contract. The Credential Issuer resolves `credential_identifiers` at token exchange time via the Token Hook, not at code creation time.
3. WHEN a valid creation request is received, THE admin endpoint SHALL generate a pre-authorized code (opaque random string with sufficient entropy), compute its HMAC signature for storage, compute the SHA-256 hash of the `tx_code` if provided (storing the hash, not the plaintext), store the grant data via `PreAuthorizedCodeStorage.CreatePreAuthorizedCodeSession`, and return a JSON response with the `pre_authorized_code` value.
4. THE admin endpoint SHALL set the `expires_at` based on `PreAuthorizedCodeConfigProvider.GetPreAuthorizedCodeLifespan(ctx)` added to the current time.
5. IF `client_id` is provided in the request and does not correspond to a registered OAuth 2.0 client, THEN THE admin endpoint SHALL reject the request with an HTTP 400 error. IF `client_id` is omitted, THE admin endpoint SHALL create an unbound code (any client or anonymous can redeem).
6. IF `credential_configuration_ids` is missing or empty, THEN THE admin endpoint SHALL reject the request with an HTTP 400 error.
7. THE admin endpoint SHALL be registered in `oauth2/handler.go` → `SetAdminRoutes`, keeping changes to this upstream file minimal and clearly marked with `// OIDC4VCI extension` comments.
8. THE admin endpoint SHALL include Swagger annotations (`swagger:route`, `swagger:parameters`, `swagger:model`) for OpenAPI spec generation.

### Requirement 10: PreAuthorizedCodeConfigProvider and Config Keys

**User Story:** As an AS operator, I want configuration keys to enable/disable the Pre-Authorized Code grant type and control its behavior, so that I can manage the feature without code changes.

#### Acceptance Criteria

1. THE AS SHALL define a `PreAuthorizedCodeConfigProvider` interface in `fosite/config.go` with methods: `GetPreAuthorizedCodeEnabled(ctx context.Context) bool`, `GetPreAuthorizedCodeLifespan(ctx context.Context) time.Duration`, `GetPreAuthorizedCodeAnonymousAccess(ctx context.Context) bool`.
2. THE AS SHALL define config keys `KeyPreAuthorizedCodeEnabled` (boolean, default `false`), `KeyPreAuthorizedCodeLifespan` (duration, default `30m`), and `KeyPreAuthorizedCodeAnonymousAccess` (boolean, default `false`) in `driver/config/provider.go`.
3. THE AS SHALL implement the `PreAuthorizedCodeConfigProvider` methods on `DefaultProvider` using the standard `p.getProvider(ctx)` pattern for multi-tenant support.
4. THE AS SHALL embed `PreAuthorizedCodeConfigProvider` in the Fosite `Configurator` interface in `fosite/fosite.go`.
5. THE AS SHALL add `preauth.enabled`, `preauth.lifespan`, and `preauth.anonymous_access` properties to the JSON schema in `spec/config.json` and run `scripts/render-schemas.sh` to regenerate derived schemas.
6. THE AS SHALL verify that `fositex.Config` satisfies `PreAuthorizedCodeConfigProvider` via a compile-time interface check in `fositex/config.go`. Since `fositex.Config` embeds `*config.DefaultProvider`, the methods are inherited automatically, but the compile-time check ensures this contract is not accidentally broken.

### Requirement 11: Compose Factory

**User Story:** As a developer wiring up the Fosite handler pipeline, I want a compose factory for the Pre-Authorized Code handler, so that the handler is registered in the token handler list via the standard factory pattern.

#### Acceptance Criteria

1. THE AS SHALL define a `PreAuthorizedCodeFactory` function in `fosite/compose/compose_preauth.go` following the `compose.Factory` signature that returns a `*preauth.Handler` struct with `Config`, `Storage`, and `Strategy` fields.
2. THE factory SHALL type-assert the `config` parameter to `preauth.PreAuthorizedCodeConfigProvider`, the `storage` parameter to `preauth.PreAuthorizedCodeStorage`, and the `strategy` parameter to the `CoreStrategy` interface needed for access token generation.
3. THE AS SHALL register the `PreAuthorizedCodeFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyPreAuthorizedCodeEnabled`.
4. WHEN the `PreAuthorizedCodeFactory` result is type-asserted by `Compose()`, THE AS SHALL register the handler as `TokenEndpointHandler`.

### Requirement 12: Error Constants

**User Story:** As a developer implementing Pre-Authorized Code validation, I want dedicated error variables following the established pattern, so that error responses use the correct OAuth 2.0 error codes per OIDC4VCI §6.3.

#### Acceptance Criteria

1. THE AS SHALL define error variables in `fosite/handler/preauth/errors.go` using the `*fosite.RFC6749Error` pattern established by Spec 1 and Spec 2.
2. THE error variables SHALL cover: `ErrInvalidGrant` (or reuse `fosite.ErrInvalidGrant`) with appropriate hints for "pre-authorized code not found", "pre-authorized code already redeemed", "pre-authorized code expired", "tx_code does not match", and "client_id mismatch"; `ErrInvalidRequest` (or reuse `fosite.ErrInvalidRequest`) with hints for "tx_code required but not provided", "tx_code provided but not expected", "pre-authorized_code parameter is required", and "requested credential_configuration_id not authorized".
3. THE PreAuth_Handler SHALL chain context via `.WithHint()` and `.WithDebugf()` at each call site, following the pattern established by the RAR and DPoP handlers.

### Requirement 13: Session Construction from Stored Grant Data

**User Story:** As a developer, I want the handler to construct a proper OAuth 2.0 session from the stored pre-authorized code grant data, so that the issued access token carries the correct claims and the session is compatible with introspection, refresh, and token hooks.

#### Acceptance Criteria

1. WHEN a pre-authorized code is successfully validated, THE PreAuth_Handler SHALL deserialize the `SessionData` from the stored PreAuthorizedCodeData into an `oauth2.Session` struct.
2. THE PreAuth_Handler SHALL construct `authorization_details` at runtime: if the Wallet sent `authorization_details` in the token request, validate each `credential_configuration_id` against the stored `CredentialConfigurationIDs` set (subset check per Requirement 17); if the Wallet did NOT send `authorization_details`, construct a default set from all stored `CredentialConfigurationIDs` (each as `{"type": "openid_credential", "credential_configuration_id": "<id>"}`). THE PreAuth_Handler SHALL set the result in `Session.Extra["authorization_details"]` so it flows into the token response, introspection (`ext.authorization_details`), and Token_Hook. The Token Hook then fires, and the Credential Issuer enriches the `authorization_details` with `credential_identifiers`.
3. THE PreAuth_Handler SHALL set the requester's granted scopes from the stored `GrantedScope` field.
4. THE PreAuth_Handler SHALL set the requester's session to the deserialized session, making it available to downstream handlers (including the DPoP_Handler which may add `cnf.jkt` to `Session.Extra`).

### Requirement 14: Discovery Metadata (Deferred to Spec 5)

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise Pre-Authorized Code grant support and anonymous access configuration, so that I can determine whether the AS supports this flow before initiating it.

#### Acceptance Criteria

1. Note: The `pre-authorized_grant_anonymous_access_supported` metadata field and the addition of `urn:ietf:params:oauth:grant-type:pre-authorized_code` to `grant_types_supported` are deferred to Spec 5 (`oidc4vci-haip-metadata`), which aggregates all feature-specific metadata extensions into the `oidcConfiguration` struct in `oauth2/handler.go`. This spec provides the `PreAuthorizedCodeConfigProvider.GetPreAuthorizedCodeEnabled(ctx)` and `GetPreAuthorizedCodeAnonymousAccess(ctx)` methods that Spec 5 will call to populate the metadata fields.
2. WHEN the Pre-Authorized Code grant type is enabled, Spec 5 SHALL include `urn:ietf:params:oauth:grant-type:pre-authorized_code` in `grant_types_supported` and `pre-authorized_grant_anonymous_access_supported` in the AS metadata.

### Requirement 15: Feature Documentation

**User Story:** As a developer or operator, I want a feature documentation file describing the Pre-Authorized Code implementation, so that I can understand the feature, its configuration, admin API, token exchange flow, tx_code validation rules, error codes, and integration with DPoP and RAR.

#### Acceptance Criteria

1. THE AS SHALL include a documentation file at `docs/features/pre-authorized-code.md` describing the implemented feature.
2. THE documentation SHALL cover: feature overview, configuration keys and defaults (`KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`), admin API for code creation (request/response format with examples), token exchange flow (step-by-step), tx_code validation rules (all three cases: required+provided, required+missing, not-required+provided), error codes per OIDC4VCI §6.3, interaction with DPoP (DPoP binds the token independently if DPoP header present), interaction with RAR (`authorization_details` propagation from stored grant data to token response), introspection path (`ext.authorization_details`), Token_Hook availability, and references to OIDC4VCI spec sections and the design docs in `docs/ai-context/`.

### Requirement 16: HAIP Independence (Note)

**User Story:** As an AS operator, I want the Pre-Authorized Code grant type to be independently configurable from HAIP enforcement, so that the two concerns are not conflated.

#### Acceptance Criteria

1. Note: HAIP (High Assurance Interoperability Profile) does NOT mandate the Pre-Authorized Code grant type. HAIP mandates DPoP, PAR, PKCE S256, and RFC 9207 — all of which are separate from the Pre-Authorized Code flow. The `KeyPreAuthorizedCodeEnabled` config key is independent of `KeyHAIPEnforced`. Spec 5 (`oidc4vci-haip-metadata`) SHALL NOT auto-enable Pre-Auth when HAIP is enforced.
2. This spec's `PreAuthorizedCodeConfigProvider` and config keys operate independently. Operators who want both HAIP compliance and Pre-Authorized Code support must enable `KeyPreAuthorizedCodeEnabled` separately.
3. WHEN both `KeyHAIPEnforced` and `KeyPreAuthorizedCodeAnonymousAccess` are `true`, THE AS SHALL log a warning at startup indicating the configuration contradiction — HAIP unconditionally requires client authentication at the token endpoint, which contradicts anonymous access.

### Requirement 17: authorization_details Validation in Token Request

**User Story:** As a Wallet developer, I want to send `authorization_details` in the token request to select a subset of offered credential configurations, so that I can request specific credentials from a multi-credential offer.

#### Acceptance Criteria

1. WHEN the Wallet sends `authorization_details` in the token request form, THE PreAuth_Handler SHALL parse the JSON array and extract `credential_configuration_id` from each entry with `type: "openid_credential"`.
2. THE PreAuth_Handler SHALL validate that every requested `credential_configuration_id` is present in the stored `CredentialConfigurationIDs` set from the PreAuthorizedCodeData. IF any requested ID is not in the allowed set, THE handler SHALL reject the request with an `invalid_request` error with hint "requested credential_configuration_id not authorized".
3. WHEN the Wallet does NOT send `authorization_details` in the token request, THE PreAuth_Handler SHALL construct a default `authorization_details` array from all stored `CredentialConfigurationIDs`, each as `{"type": "openid_credential", "credential_configuration_id": "<id>"}`.
4. THE PreAuth_Handler SHALL set the validated or constructed `authorization_details` in `Session.Extra["authorization_details"]` WITHOUT `credential_identifiers` — those are added by the Credential Issuer via the Token Hook.
5. Per OID4VCI §6.1.1, this validation applies to both the Authorization Code Flow and the Pre-Authorized Code Flow. The Wallet can use `authorization_details` to request a specific Credential Configuration, which is particularly useful when the Credential Issuer offered multiple Credential Configurations in the Credential Offer.
