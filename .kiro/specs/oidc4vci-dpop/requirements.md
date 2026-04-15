# Requirements Document

## Introduction

This document specifies the DPoP (Demonstrating Proof of Possession — RFC 9449) token binding implementation for the Hydra AS fork. DPoP is a cross-cutting mechanism that sender-constrains OAuth 2.0 access tokens by binding them to a client's public key via proof-of-possession at the application level. This is the most complex validation logic in the OIDC4VCI feature set, implementing the full RFC 9449 §4.3 proof validation checklist (12 checks), nonce exchange, JTI replay detection, authorization code binding via `dpop_jkt`, and refresh token DPoP binding for public clients.

The scope is strictly the Authorization Server role. The Credential Issuer validates DPoP proofs against the `cnf.jkt` from introspection independently — that is out of scope. This spec covers the DPoP handler (`fosite/handler/dpop/`), storage interface and SQL persistence, compose factory, config provider, error constants, database migration, and feature documentation.

This spec depends on Spec 1 (oidc4vci-rar-consent) which established the config provider interface pattern, factory registration pattern, error constant pattern, `Session.Extra` propagation, introspection path, `PopulateTokenEndpointResponse` pattern, and compile-time interface checks.

## Glossary

- **AS**: Authorization Server — the Hydra instance responsible for OAuth 2.0 and OIDC flows.
- **DPoP_Handler**: The Fosite handler in `fosite/handler/dpop/` that implements `TokenEndpointHandler` and `PushedAuthorizeEndpointHandler` for DPoP proof validation and token binding.
- **Token_Endpoint**: The Hydra endpoint (`/oauth2/token`) that issues access tokens and processes DPoP proofs.
- **PAR_Endpoint**: The Pushed Authorization Request endpoint (`/oauth2/par`), already implemented in `fosite/handler/par/`.
- **Discovery_Endpoint**: The Hydra endpoint (`/.well-known/openid-configuration`) that publishes AS metadata.
- **DPoP_Proof**: A JWT sent in the `DPoP` HTTP header, signed by the client's private key, proving possession of the corresponding public key per RFC 9449 §4.2.
- **JKT**: JWK Thumbprint — a hash of the client's public key computed per RFC 7638, used as the confirmation claim (`cnf.jkt`) to bind tokens to the key.
- **DPoP_Nonce**: A server-issued opaque value included in the `DPoP-Nonce` HTTP response header. When nonces are enabled, the client must include the nonce in the `nonce` claim of subsequent DPoP proofs.
- **JTI**: The `jti` (JWT ID) claim in a DPoP proof, used for replay detection. Each proof must have a unique `jti`.
- **DPoPNonceStorage**: The storage interface for JTI replay detection and nonce management, with methods `IsJTIUsed`, `MarkJTIUsed`, `CreateDPoPNonce`, `ValidateDPoPNonce`.
- **DPoPConfigProvider**: The provider interface for DPoP feature configuration (`GetDPoPEnabled`, `GetDPoPSigningAlgValuesSupported`, `GetDPoPNonceEnabled`, `GetDPoPNonceLifespan`, `GetDPoPProofMaxAge`, `GetDPoPPARURLs`).
- **Configurator**: The Fosite interface (`fosite/fosite.go`) that composes all provider interfaces for handler configuration.
- **Session_Extra**: The `map[string]interface{}` field on `oauth2.Session` used to carry custom claims through the token lifecycle.
- **Wallet**: The OAuth 2.0 Client (end-user application) that sends DPoP proofs to bind access tokens to its key material.
- **Credential_Issuer**: An external microservice that issues Verifiable Credentials. It validates DPoP proofs against `cnf.jkt` from introspection. Out of scope for implementation.
- **Public_Client**: An OAuth 2.0 client without a client secret or private key registered with the AS (e.g., a mobile Wallet app using `none` or `attest_jwt_client_auth` as its token endpoint auth method).
- **Confidential_Client**: An OAuth 2.0 client with authentication credentials (e.g., `client_secret_post`, `private_key_jwt`).
- **ErrInvalidDPoPProof**: The OAuth extension error code `invalid_dpop_proof` (HTTP 400) returned when a DPoP proof fails validation.
- **ErrUseDPoPNonce**: The OAuth extension error code `use_dpop_nonce` (HTTP 400) returned when a DPoP nonce is required but the proof does not contain a valid nonce. The error response includes a `DPoP-Nonce` header with a fresh nonce value.
- **Persister**: The aggregate persistence interface (`persistence/definitions.go`) that composes all domain storage interfaces, implemented by `persistence/sql/Persister`.

## Requirements

### Requirement 1: DPoP Proof Validation (RFC 9449 §4.3 Checklist)

**User Story:** As a security architect, I want the AS to validate DPoP proof JWTs per the full RFC 9449 §4.3 checklist, so that only well-formed, correctly signed, non-replayed proofs are accepted for token binding.

#### Acceptance Criteria

1. WHEN a Token Request includes a `DPoP` HTTP header, THE DPoP_Handler SHALL verify there is not more than one `DPoP` header field in the request. IF multiple `DPoP` headers are present, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 1).
2. WHEN a Token Request includes a `DPoP` header, THE DPoP_Handler SHALL verify the header value is a single well-formed JWT parseable per RFC 7519. IF the value is not a valid JWT, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 2).
3. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify that all required claims are present: `jti`, `htm`, `htu`, and `iat`. IF any required claim is missing, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 3).
4. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `typ` JOSE Header Parameter has the value `dpop+jwt`. IF the `typ` is missing or has a different value, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 4).
5. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `alg` JOSE Header Parameter indicates a registered asymmetric digital signature algorithm, is not `none`, is not a symmetric algorithm, and is in the configured `GetDPoPSigningAlgValuesSupported()` list. IF the algorithm is unsupported, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 5).
6. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL extract the public key from the `jwk` JOSE Header Parameter and verify the JWT signature using that public key. IF the signature is invalid, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 6).
7. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `jwk` JOSE Header Parameter does not contain private key material (fields `d`, `p`, `q`, `dp`, `dq`, `qi` for RSA; field `d` for EC and OKP). IF private key material is present, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 7).
8. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `htm` claim matches the HTTP method of the request (`POST` for the token endpoint). IF the method does not match, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 8).
9. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `htu` claim matches the expected endpoint URL for the current request context: the token endpoint URL (from `Configurator.GetTokenURLs()`) for token requests, or the PAR endpoint URL for PAR requests. The handler SHALL apply syntax-based and scheme-based URI normalization per RFC 3986 §6.2.2–6.2.3 before comparing. IF the URI does not match, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 9). Note: The mechanism for obtaining the PAR endpoint URL SHALL be determined during the design phase.
10. WHILE DPoP nonces are enabled (`GetDPoPNonceEnabled(ctx) == true`), WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `nonce` claim matches a valid server nonce via `DPoPNonceStorage.ValidateDPoPNonce(ctx, nonce)`. IF the nonce is missing or invalid, THEN THE DPoP_Handler SHALL set the `DPoP-Nonce` response header with a fresh nonce value and reject the request with a `use_dpop_nonce` error (§4.3 check 10).
11. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL verify the `iat` (issued-at) claim is recent, within the configured clock skew tolerance (`GetDPoPProofMaxAge(ctx)` for maximum age, hardcoded reasonable tolerance for future drift). IF the timestamp is too old or in the future beyond tolerance, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error (§4.3 check 11).
12. WHEN a DPoP proof JWT is parsed, THE DPoP_Handler SHALL check `jti` uniqueness via `DPoPNonceStorage.IsJTIUsed(ctx, jti)` and reject replayed proofs with an `invalid_dpop_proof` error. WHEN the `jti` is unique, THE DPoP_Handler SHALL mark it as used via `DPoPNonceStorage.MarkJTIUsed(ctx, jti, expiry)` (§4.3 check 12).

Note: RFC 9449 §4.3 also defines a check for the `ath` (access token hash) claim, which binds a DPoP proof to a specific access token. This check applies only at the resource server (Credential Issuer), not at the token endpoint where the access token has not yet been issued. The `ath` check is therefore out of scope for this handler.

### Requirement 2: DPoP Token Binding and Token Type

**User Story:** As a Wallet developer, I want the AS to bind my access token to my DPoP public key and return `token_type=DPoP`, so that the token is sender-constrained and the Credential Issuer can verify my possession of the private key.

#### Acceptance Criteria

1. WHEN a Token Request includes a valid DPoP proof JWT, THE DPoP_Handler `PopulateTokenEndpointResponse` SHALL extract the public key from the validated proof's `jwk` header, compute the JKT (JWK Thumbprint per RFC 7638), and store it as `session.Extra["cnf"] = map[string]interface{}{"jkt": thumbprint}`.
2. WHEN a DPoP-bound access token is issued, THE DPoP_Handler SHALL set the `token_type` response parameter to `DPoP` via `responder.SetTokenType("DPoP")`.
3. WHEN a Token Request does not include a `DPoP` header, THE DPoP_Handler `PopulateTokenEndpointResponse` SHALL return `fosite.ErrUnknownRequest` so the response writer skips the handler cleanly, leaving the default `Bearer` token type unchanged.
4. THE DPoP_Handler SHALL store the `cnf.jkt` value in Session_Extra so it flows to the introspection response at `ext.cnf.jkt`, enabling the Credential_Issuer to validate DPoP proofs against the bound key.

### Requirement 3: DPoP Nonce Exchange

**User Story:** As a security architect, I want the AS to support DPoP nonce exchange, so that pre-computed DPoP proofs from XSS attacks are rendered unusable.

#### Acceptance Criteria

1. WHILE DPoP nonces are enabled, WHEN a DPoP-bound access token is successfully issued, THE DPoP_Handler SHALL generate a fresh nonce via `DPoPNonceStorage.CreateDPoPNonce(ctx)` and set the `DPoP-Nonce` HTTP response header on the successful token response.
2. WHILE DPoP nonces are enabled, WHEN a DPoP proof is missing the `nonce` claim or contains an invalid nonce, THE DPoP_Handler SHALL set the `DPoP-Nonce` HTTP response header with a fresh nonce value BEFORE returning the `use_dpop_nonce` error, so the HTTP response writer includes the header in the error response.
3. WHILE DPoP nonces are disabled (`GetDPoPNonceEnabled(ctx) == false`), THE DPoP_Handler SHALL not require or validate the `nonce` claim in DPoP proofs, and SHALL not set the `DPoP-Nonce` response header.

### Requirement 4: Authorization Code Binding via `dpop_jkt` (RFC 9449 §10)

**User Story:** As a Wallet developer, I want to bind my authorization code to my DPoP key at PAR time, so that even if the authorization code is intercepted, it cannot be exchanged by an attacker who does not possess my private key.

#### Acceptance Criteria

1. WHEN a PAR Request includes a `dpop_jkt` parameter (the JWK Thumbprint of the client's DPoP public key), THE DPoP_Handler `HandlePushedAuthorizeEndpointRequest` SHALL store the `dpop_jkt` value in the request form so it is persisted as part of the PAR session. When the authorize endpoint resolves the `request_uri`, the PAR session's form data (including `dpop_jkt`) is merged into the authorize request and subsequently carried into the authorization session, making it available at the token endpoint.
2. WHEN a PAR Request includes a `DPoP` header (a DPoP proof JWT), THE DPoP_Handler `HandlePushedAuthorizeEndpointRequest` SHALL validate the proof per the §4.3 checklist (adapted for the PAR endpoint: `htm=POST`, `htu` matching the PAR endpoint URL) and treat the public key's JWK Thumbprint as an implicit `dpop_jkt`.
3. IF both a `dpop_jkt` parameter and a `DPoP` header are present on a PAR Request, THEN THE DPoP_Handler SHALL compute the JWK Thumbprint from the `DPoP` header's public key and verify it matches the `dpop_jkt` parameter value. IF they do not match, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error.
4. WHEN a Token Request includes a DPoP proof and the authorization session contains a stored `dpop_jkt` value, THE DPoP_Handler SHALL compute the JWK Thumbprint from the DPoP proof's public key and verify it matches the stored `dpop_jkt`. IF they do not match, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error.
5. WHEN a PAR Request does not include a `dpop_jkt` parameter or a `DPoP` header, THE DPoP_Handler `HandlePushedAuthorizeEndpointRequest` SHALL return nil without modifying the session (not responsible).

### Requirement 5: Refresh Token DPoP Binding (RFC 9449 §5)

**User Story:** As a security architect, I want refresh tokens issued to public clients to be bound to the DPoP key, so that stolen refresh tokens cannot be used by an attacker without the private key, while confidential clients retain flexibility for key rotation.

#### Acceptance Criteria

1. WHEN the AS issues a refresh token to a Public_Client that presents a valid DPoP proof, THE DPoP_Handler SHALL bind the refresh token to the DPoP public key by storing the JKT in the session associated with the refresh token.
2. WHEN a Public_Client exchanges a refresh token and the original session has a DPoP JKT binding, THE DPoP_Handler SHALL validate that the DPoP proof in the new token request uses the same public key (matching JKT). IF the key does not match, THEN THE DPoP_Handler SHALL reject the request with an `invalid_dpop_proof` error.
3. WHEN the AS issues a refresh token to a Confidential_Client that presents a valid DPoP proof, THE DPoP_Handler SHALL NOT bind the refresh token to the DPoP key. The access token is still DPoP-bound, but the refresh token is sender-constrained via client authentication only.
4. THE DPoP_Handler SHALL detect whether a client is public or confidential by checking the client's token endpoint authentication method. A client using `none` as its token endpoint auth method, or using `attest_jwt_client_auth` (Wallet Attestation), is treated as a Public_Client for DPoP refresh token binding purposes. A client using credential-based methods (`client_secret_post`, `client_secret_basic`, `private_key_jwt`) is treated as a Confidential_Client.

### Requirement 6: DPoP Handler Registration and Interface

**User Story:** As a developer wiring up the Fosite handler pipeline, I want the DPoP handler to be registered as both a `TokenEndpointHandler` and a `PushedAuthorizeEndpointHandler`, so that DPoP proofs are validated on token requests and `dpop_jkt` is extracted at PAR.

#### Acceptance Criteria

1. THE DPoP_Handler `CanHandleTokenEndpointRequest` SHALL return `true` when the HTTP request contains a `DPoP` header, regardless of the grant type being processed.
2. THE DPoP_Handler `CanSkipClientAuth` SHALL always return `false` — DPoP is a token binding mechanism, not a client authentication method.
3. THE DPoP_Handler SHALL implement compile-time interface checks: `var _ fosite.TokenEndpointHandler = (*Handler)(nil)` and `var _ fosite.PushedAuthorizeEndpointHandler = (*Handler)(nil)`.
4. THE AS SHALL define a `DPoPFactory` function in `fosite/compose/compose_dpop.go` following the `compose.Factory` signature that returns a `*dpop.Handler` struct with `Config` and `NonceStore` fields.
5. THE AS SHALL register the `DPoPFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyDPoPEnabled`.
6. WHEN the `DPoPFactory` result is type-asserted by `Compose()`, THE AS SHALL register the handler as both `TokenEndpointHandler` and `PushedAuthorizeEndpointHandler`.

### Requirement 7: DPoP Error Constants

**User Story:** As a developer implementing DPoP validation, I want dedicated error constants for `invalid_dpop_proof` and `use_dpop_nonce`, so that RFC 9449 error responses use the correct error codes.

#### Acceptance Criteria

1. THE AS SHALL define an `ErrInvalidDPoPProof` variable as a `*fosite.RFC6749Error` with `ErrorField` set to `invalid_dpop_proof` and `CodeField` set to HTTP 400.
2. THE AS SHALL define an `ErrUseDPoPNonce` variable as a `*fosite.RFC6749Error` with `ErrorField` set to `use_dpop_nonce` and `CodeField` set to HTTP 400.
3. THE DPoP_Handler SHALL use `ErrInvalidDPoPProof` (with `.WithHint()` and `.WithDebugf()` for context) for all DPoP proof validation failures.
4. THE DPoP_Handler SHALL use `ErrUseDPoPNonce` (with `.WithHint()`) when a DPoP nonce is required but the proof does not contain a valid nonce.

### Requirement 8: DPoPNonceStorage Interface

**User Story:** As a developer implementing DPoP, I want a storage interface for JTI replay detection and nonce management, so that the handler can check JTI uniqueness and manage server nonces.

#### Acceptance Criteria

1. THE AS SHALL define a `DPoPNonceStorage` interface in `fosite/handler/dpop/storage.go` with methods: `IsJTIUsed(ctx context.Context, jti string) (bool, error)`, `MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error`, `CreateDPoPNonce(ctx context.Context) (string, error)`, `ValidateDPoPNonce(ctx context.Context, nonce string) (bool, error)`.
2. THE AS SHALL add `DPoPNonceStorage` to the `persistence.Persister` aggregate interface so the SQL persister implements it.
3. THE AS SHALL add a `DPoPNonceStorage()` accessor on `RegistrySQL` in `driver/registry_sql.go` with lazy initialization pattern, returning the `Persister` cast to `DPoPNonceStorage`.

### Requirement 9: Database Migration for DPoP JTI Table

**User Story:** As an AS operator, I want a database table for DPoP JTI replay detection, so that replayed DPoP proofs are rejected across AS restarts and in multi-instance deployments.

#### Acceptance Criteria

1. THE AS SHALL create a database migration adding the `hydra_oauth2_dpop_jti` table with columns: `jti` (VARCHAR(255), NOT NULL), `nid` (UUID, NOT NULL), `used_at` (TIMESTAMP, NOT NULL), `expires_at` (TIMESTAMP, NOT NULL), with a composite primary key `(jti, nid)` to ensure JTI uniqueness per network (multi-tenancy).
2. THE migration SHALL create an index `idx_dpop_jti_expires_at` on `(nid, expires_at)` for efficient cleanup queries.
3. THE migration SHALL support PostgreSQL, MySQL, CockroachDB, and SQLite.
4. THE migration SHALL follow the naming convention `YYYYMMDDHHMMSS_oidc4vci_create_dpop_jti.up.sql` / `.down.sql` in `persistence/sql/migrations/`.
5. THE down migration SHALL drop the `hydra_oauth2_dpop_jti` table cleanly.

### Requirement 10: SQL Persistence Implementation

**User Story:** As a developer, I want the `DPoPNonceStorage` interface implemented on the SQL persister, so that JTI replay detection and nonce management work with the database.

#### Acceptance Criteria

1. THE AS SHALL implement `IsJTIUsed` on `persistence/sql/Persister` by querying the `hydra_oauth2_dpop_jti` table for the given `jti` and the current network ID (`nid`).
2. THE AS SHALL implement `MarkJTIUsed` on `persistence/sql/Persister` by inserting a row into `hydra_oauth2_dpop_jti` with the `jti`, current `nid`, current timestamp as `used_at`, and the provided `expiry` as `expires_at`.
3. THE AS SHALL implement `CreateDPoPNonce` on `persistence/sql/Persister` by generating a cryptographically random nonce string (at least 128 bits of entropy, base64url-encoded) with a lifespan derived from `GetDPoPNonceLifespan()`. The nonce generation mechanism SHOULD allow `ValidateDPoPNonce` to verify the nonce without a database lookup for each nonce verification. The specific mechanism (e.g., stateless HMAC-based, database-backed, or hybrid) SHALL be determined during the design phase.
4. THE AS SHALL implement `ValidateDPoPNonce` on `persistence/sql/Persister` by verifying the nonce is valid and not expired, using the same mechanism as `CreateDPoPNonce`.

### Requirement 11: DPoP Config Provider and Config Keys

**User Story:** As an AS operator, I want configuration keys to enable/disable DPoP and control its behavior, so that I can manage DPoP settings without code changes.

#### Acceptance Criteria

1. THE AS SHALL define a `DPoPConfigProvider` interface in `fosite/config.go` with methods: `GetDPoPEnabled(ctx context.Context) bool`, `GetDPoPSigningAlgValuesSupported(ctx context.Context) []string`, `GetDPoPNonceEnabled(ctx context.Context) bool`, `GetDPoPNonceLifespan(ctx context.Context) time.Duration`, `GetDPoPProofMaxAge(ctx context.Context) time.Duration`, `GetDPoPPARURLs(ctx context.Context) []string`. The `GetDPoPPARURLs` method provides the PAR endpoint URLs for `htu` validation on PAR requests, mirroring the existing `GetTokenURLs` pattern. It is computed from `PublicURL` and `IssuerURL` (no separate config key needed).
2. THE AS SHALL define config keys `KeyDPoPEnabled` (boolean, default `false`), `KeyDPoPSigningAlgValues` (string slice, default `["ES256"]`), `KeyDPoPNonceEnabled` (boolean, default `false`), `KeyDPoPNonceLifespan` (duration, default `5m`), and `KeyDPoPProofMaxAge` (duration, default `60s` — maximum age for DPoP proof `iat` claim) in `driver/config/`.
3. THE AS SHALL implement the `DPoPConfigProvider` methods on `DefaultProvider` using the standard `p.getProvider(ctx)` pattern for multi-tenant support.
4. THE AS SHALL embed `DPoPConfigProvider` in the Fosite `Configurator` interface in `fosite/fosite.go`.
5. THE AS SHALL add `dpop.enabled`, `dpop.signing_alg_values_supported`, `dpop.nonce_enabled`, `dpop.nonce_lifespan`, and `dpop.proof_max_age` properties to the JSON schema in `spec/config.json`.
6. THE default value for `dpop.signing_alg_values_supported` SHALL include `ES256` to satisfy HAIP requirements.
7. THE AS SHALL verify that `fositex.Config` satisfies `DPoPConfigProvider` via a compile-time interface check (`var _ DPoPConfigProvider = (*Config)(nil)` or equivalent). Since `fositex.Config` embeds `*config.DefaultProvider`, the methods are inherited automatically, but the compile-time check ensures this contract is not accidentally broken.

### Requirement 12: DPoP HTTP Header Access

**User Story:** As a developer implementing the DPoP handler, I want a reliable mechanism to access the raw `DPoP` HTTP header from within a Fosite handler, so that the handler can extract and validate the DPoP proof JWT.

#### Acceptance Criteria

1. THE DPoP_Handler SHALL access the `DPoP` HTTP header value from the request. The mechanism for accessing the raw HTTP header (e.g., via request context, form parameter injection at the endpoint handler level, or a custom interface on the requester) SHALL be determined during the design phase based on how existing Fosite handlers access HTTP headers.
2. THE DPoP_Handler SHALL access the `DPoP` HTTP header on PAR requests using the same mechanism as token requests, adapted for the PAR endpoint context.

### Requirement 13: DPoP-Nonce Response Header Delivery

**User Story:** As a developer implementing the DPoP handler, I want a mechanism to set the `DPoP-Nonce` HTTP response header on both success and error responses, so that the nonce is delivered to the client per RFC 9449 §8.

#### Acceptance Criteria

1. THE DPoP_Handler SHALL have a mechanism to set the `DPoP-Nonce` HTTP response header on error responses (specifically `use_dpop_nonce` errors). The header MUST be present in the HTTP response even though the response body is an error. The mechanism (e.g., custom error type carrying headers, response writer access via context, or header attachment on the error object) SHALL be determined during the design phase.
2. THE DPoP_Handler SHALL set the `DPoP-Nonce` HTTP response header on successful token responses when nonces are enabled, using the same mechanism.

### Requirement 14: Feature Documentation

**User Story:** As a developer or operator, I want a feature documentation file describing the DPoP implementation, so that I can understand the feature, its configuration, proof validation checklist, error codes, nonce exchange flow, and integration with introspection.

#### Acceptance Criteria

1. THE AS SHALL include a documentation file at `docs/features/dpop.md` describing the implemented feature.
2. THE documentation SHALL cover: feature overview, configuration options (`KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`, `KeyDPoPProofMaxAge`), the full RFC 9449 §4.3 proof validation checklist with all 12 checks, error codes (`invalid_dpop_proof`, `use_dpop_nonce`), nonce exchange flow, `dpop_jkt` authorization code binding, refresh token DPoP binding rules (public vs confidential clients), `cnf.jkt` introspection path (`ext.cnf.jkt`), and references to RFC 9449 and the design docs.

### Requirement 15: Discovery Metadata for DPoP (Deferred to Spec 5)

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise `dpop_signing_alg_values_supported`, so that I can determine which DPoP signing algorithms the AS accepts before initiating a flow.

#### Acceptance Criteria

1. Note: The `dpop_signing_alg_values_supported` metadata field is deferred to Spec 5 (`oidc4vci-haip-metadata`), which aggregates all feature-specific metadata extensions into the `oidcConfiguration` struct in `oauth2/handler.go`. This spec provides the `DPoPConfigProvider.GetDPoPSigningAlgValuesSupported(ctx)` method that Spec 5 will call to populate the metadata field.
2. WHEN DPoP is enabled, Spec 5 SHALL include `dpop_signing_alg_values_supported` in the AS metadata, populated from `GetDPoPSigningAlgValuesSupported(ctx)`.
3. WHEN DPoP is disabled, Spec 5 SHALL omit the `dpop_signing_alg_values_supported` field from the AS metadata.

### Requirement 16: HAIP Auto-Enable Behavior (Deferred to Spec 5)

**User Story:** As an AS operator, I want DPoP to be automatically enabled when HAIP enforcement is active, so that HAIP compliance is achieved without manually enabling each feature flag.

#### Acceptance Criteria

1. Note: The HAIP-driven auto-enable of DPoP is deferred to Spec 5 (`oidc4vci-haip-metadata`), which wires `KeyHAIPEnforced` to override individual feature flags. This spec defines the `KeyDPoPEnabled` config key with a standalone default of `false`. Spec 5 will ensure that when `GetHAIPEnforced(ctx)` returns `true`, `GetDPoPEnabled(ctx)` also returns `true` and `ES256` is in the supported algorithms list.
2. This spec's `DPoPConfigProvider` and config keys are designed to be overridable by the HAIP enforcement layer in Spec 5 without modification to the DPoP handler code.
