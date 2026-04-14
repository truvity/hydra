# Requirements Document

## Introduction

This document specifies the Authorization Server (AS) capabilities required to support the OIDC4VCI (OpenID for Verifiable Credential Issuance) specification and the HAIP (High Assurance Interoperability Profile). The scope is strictly limited to the AS role within a Hydra fork. The Credential Issuer is an entirely separate microservice and is out of scope.

The AS must support new grant types, token response extensions, authorization request parameters, sender-constrained tokens, and metadata extensions to enable Wallets to obtain access tokens suitable for credential issuance from an external Credential Issuer.

## Glossary

- **AS**: Authorization Server — the Hydra instance responsible for OAuth 2.0 and OIDC flows.
- **Credential_Issuer**: An external microservice that issues Verifiable Credentials. It is a Resource Server protected by the AS. Out of scope for implementation.
- **Wallet**: The OAuth 2.0 Client (end-user application) that requests credentials. Acts as the RP in OIDC flows.
- **Fosite**: The embedded OAuth 2.0 library within Hydra that implements handler-based request processing.
- **Token_Endpoint**: The Hydra endpoint (`/oauth2/token`) that issues access tokens, refresh tokens, and extended response parameters.
- **Authorization_Endpoint**: The Hydra endpoint (`/oauth2/auth`) that handles authorization requests, including PAR-initiated ones.
- **Discovery_Endpoint**: The Hydra endpoint (`/.well-known/openid-configuration` / `/.well-known/oauth-authorization-server`) that publishes AS metadata.
- **PAR_Endpoint**: The Pushed Authorization Request endpoint, already implemented in Hydra via `fosite/handler/par/`.
- **DPoP**: Demonstrating Proof of Possession — a mechanism (RFC 9449) for sender-constraining access tokens using proof-of-possession keys.
- **RAR**: Rich Authorization Requests — the `authorization_details` parameter defined in RFC 9396.
- **Pre-Authorized_Code**: A new OAuth 2.0 grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) where credential issuance preparation happens before the OAuth flow.
- **Transaction_Code**: A one-time code (e.g., PIN sent via SMS) that binds a Pre-Authorized Code to a specific transaction.
- **Consent_Node**: The external Login/Consent application that Hydra delegates user authentication and consent decisions to.
- **Token_Hook**: The webhook mechanism (`oauth2/token_hook.go`) that allows external services to modify session data during token issuance.
- **Wallet_Attestation**: A signed proof from a Wallet Provider verifying the Wallet's authenticity, used as a client authentication method.

## Requirements

### Requirement 1: Pre-Authorized Code Grant Type

**User Story:** As a Credential Issuer operator, I want the AS to support the Pre-Authorized Code grant type, so that Wallets can exchange a pre-authorized code for an access token without going through the authorization endpoint.

#### Acceptance Criteria

1. WHEN a Token Request with `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` is received, THE Token_Endpoint SHALL accept the `pre-authorized_code` parameter and validate it against stored grant data.
2. WHEN a Token Request includes a `tx_code` parameter, THE Token_Endpoint SHALL validate the Transaction_Code against the value associated with the Pre-Authorized_Code.
3. IF a `tx_code` object was present in the Credential Offer but the Token Request omits the `tx_code` parameter, THEN THE Token_Endpoint SHALL reject the request with an `invalid_grant` error.
4. WHEN the Pre-Authorized_Code is valid and the Transaction_Code (if required) matches, THE Token_Endpoint SHALL issue an access token scoped to the credential configurations indicated in the original offer.
5. WHEN client authentication is not provided in a Pre-Authorized Code flow, THE Token_Endpoint SHALL permit the request if the AS metadata indicates `pre-authorized_grant_anonymous_access_supported` is true.
6. THE Token_Endpoint SHALL reject a Pre-Authorized_Code that has already been redeemed (single-use enforcement).
7. THE Token_Endpoint SHALL reject a Pre-Authorized_Code that has expired.
8. WHEN the Pre-Authorized Code grant type is used, THE Fosite handler SHALL implement `TokenEndpointHandler` with `CanHandleTokenEndpointRequest` returning true for the `urn:ietf:params:oauth:grant-type:pre-authorized_code` grant type.

### Requirement 2: Rich Authorization Requests (RFC 9396)

**User Story:** As a Wallet developer, I want to use the `authorization_details` parameter with type `openid_credential` in authorization and token requests, so that I can specify exactly which credential configurations I want issued.

#### Acceptance Criteria

1. WHEN an Authorization Request or PAR Request contains an `authorization_details` parameter with type `openid_credential`, THE Authorization_Endpoint SHALL parse and validate the `credential_configuration_id` field.
2. WHEN a Token Request contains an `authorization_details` parameter with type `openid_credential`, THE Token_Endpoint SHALL parse and validate it, accepting a subset of previously authorized `credential_configuration_id` values.
3. THE AS SHALL store the validated `authorization_details` alongside the authorization grant so it is available during token issuance.
4. WHEN `authorization_details` of type `openid_credential` was used in the authorization or token request, THE Token_Endpoint SHALL include an `authorization_details` array in the Token Response containing `credential_identifiers` for each authorized credential configuration.
5. THE AS SHALL pass the `authorization_details` data through to the Consent_Node so the Login/Consent application can render credential-specific consent screens.
6. WHEN both `authorization_details` of type `openid_credential` and a `scope` value related to credential issuance are present in the same request, THE AS SHALL process each independently, with `authorization_details` taking precedence for overlapping credential types.

### Requirement 3: Token Response Extensions for Credential Issuance

**User Story:** As a Wallet developer, I want the token response to include `authorization_details` with `credential_identifiers`, so that I can use those identifiers in subsequent Credential Requests to the Credential Issuer.

#### Acceptance Criteria

1. WHEN `authorization_details` was used to request credential issuance, THE Token_Endpoint SHALL include an `authorization_details` array in the successful Token Response.
2. THE Token_Endpoint SHALL include a `credential_identifiers` array (non-empty, containing unique strings) within each `authorization_details` object of type `openid_credential` in the Token Response.
3. WHEN `scope` was used to request credential issuance and the AS supports returning `credential_identifiers`, THE Token_Endpoint SHALL optionally include `authorization_details` with `credential_identifiers` in the Token Response.

### Requirement 4: DPoP (Demonstrating Proof of Possession — RFC 9449)

**User Story:** As a security architect, I want the AS to support DPoP-bound access tokens, so that access tokens are sender-constrained and cannot be replayed by an attacker who intercepts them.

#### Acceptance Criteria

1. WHEN a Token Request includes a `DPoP` header containing a valid DPoP proof JWT, THE Token_Endpoint SHALL bind the issued access token to the public key in the DPoP proof.
2. WHEN a DPoP-bound access token is issued, THE Token_Endpoint SHALL set the `token_type` response parameter to `DPoP`.
3. THE Token_Endpoint SHALL validate the DPoP proof JWT per the full RFC 9449 §4.3 checklist: single `DPoP` header, well-formed JWT, required claims present, `typ` equals `dpop+jwt`, `alg` is asymmetric and not `none`, signature valid, `jwk` contains no private key material, `htm` matches, `htu` matches (with URI normalization), `nonce` (if required), `iat` freshness, and `jti` uniqueness.
4. IF the DPoP proof JWT is invalid or its `jti` has been seen before, THEN THE Token_Endpoint SHALL reject the request with an `invalid_dpop_proof` error.
5. WHEN the AS requires DPoP nonces, THE Token_Endpoint SHALL include a `DPoP-Nonce` HTTP response header, and subsequent DPoP proofs from the Wallet SHALL include the `nonce` claim.
6. IF a DPoP nonce is required but the proof does not contain a valid `nonce` claim, THEN THE Token_Endpoint SHALL respond with a `use_dpop_nonce` error and a new `DPoP-Nonce` header. The error response MUST include the `DPoP-Nonce` HTTP header with a fresh nonce value.
7. THE Discovery_Endpoint SHALL advertise `dpop_signing_alg_values_supported` in the AS metadata.
8. THE AS SHALL support ES256 as a minimum DPoP signing algorithm, per HAIP requirements.
9. WHEN the AS supports both PAR and DPoP, THE PAR_Endpoint SHALL support the `dpop_jkt` authorization request parameter (RFC 9449 §10) and the `DPoP` header on PAR requests (RFC 9449 §10.1). At the Token_Endpoint, the DPoP proof's public key MUST match the `dpop_jkt` bound during authorization. Both mechanisms MUST be supported per RFC 9449 §10.1.
10. WHEN the AS issues a refresh token to a public client that presents a valid DPoP proof, THE Token_Endpoint SHALL bind the refresh token to the DPoP public key. On subsequent refresh token exchanges, the client MUST present a DPoP proof for the same key. Refresh tokens issued to confidential clients are NOT bound to the DPoP key (per RFC 9449 §5).

### Requirement 5: `issuer_state` Parameter on Authorization Endpoint

**User Story:** As a Credential Issuer operator, I want to pass an `issuer_state` value through the authorization flow, so that I can bind the authorization request to a previously established context (e.g., a Credential Offer).

#### Acceptance Criteria

1. WHEN an Authorization Request or PAR Request contains an `issuer_state` parameter, THE Authorization_Endpoint SHALL accept, store, and forward the value through the consent flow.
2. THE AS SHALL make the `issuer_state` value available to the Consent_Node so the Login/Consent application can use it for context binding.
3. THE AS SHALL treat the `issuer_state` as an opaque, untrusted string and not rely on it for security decisions without additional validation.

### Requirement 6: Scope-Based Credential Request Support

**User Story:** As a Wallet developer, I want to use standard OAuth 2.0 `scope` values to request credential issuance, so that I can request credentials without using `authorization_details`.

#### Acceptance Criteria

1. WHEN an Authorization Request contains a `scope` value that maps to a credential configuration in the Credential Issuer metadata, THE Authorization_Endpoint SHALL treat it as a request to access the Credential Endpoint for that credential type.
2. THE AS SHALL ignore unknown scope values related to credential issuance without returning an error.
3. WHEN `scope` is used for credential issuance and the AS supports `credential_identifiers`, THE Token_Endpoint SHALL optionally return `authorization_details` with `credential_identifiers` in the Token Response.

### Requirement 7: PAR Enforcement for HAIP Compliance

**User Story:** As a security architect, I want PAR to be enforced when the Authorization Endpoint is used for credential issuance flows, so that authorization request integrity and confidentiality are guaranteed per HAIP requirements.

#### Acceptance Criteria

1. WHILE the AS is configured for HAIP compliance, THE Authorization_Endpoint SHALL require that authorization requests for credential issuance flows are submitted via PAR (RFC 9126).
2. IF a direct authorization request (not via PAR) is received for a credential issuance flow under HAIP enforcement, THEN THE Authorization_Endpoint SHALL reject it with an `invalid_request` error.
3. THE AS SHALL support the existing PAR implementation in `fosite/handler/par/` as the foundation for this enforcement.

### Requirement 8: RFC 9207 — Authorization Response Issuer Identifier

**User Story:** As a Wallet developer, I want the authorization response to include an `iss` parameter identifying the AS, so that I can verify the response originated from the expected AS and prevent mix-up attacks.

#### Acceptance Criteria

1. THE Authorization_Endpoint SHALL include an `iss` parameter in all successful Authorization Responses, with the value set to the AS Issuer Identifier.
2. THE Authorization_Endpoint SHALL include an `iss` parameter in all error Authorization Responses.
3. THE Discovery_Endpoint SHALL advertise `authorization_response_iss_parameter_supported` as `true` in the AS metadata.

### Requirement 9: Wallet Attestation Client Authentication

**User Story:** As a security architect, I want the AS to support Wallet Attestation-based client authentication, so that Wallets can authenticate at the PAR and Token endpoints using attestations from their Wallet Provider.

#### Acceptance Criteria

1. WHEN a PAR or Token Request includes `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers, THE AS SHALL validate the Wallet Attestation JWT and the Proof of Possession JWT.
2. THE AS SHALL verify the Wallet Attestation signature using the `x5c` JOSE header parameter and validate the certificate chain against configured trust anchors.
3. THE AS SHALL verify that the `sub` claim in the Wallet Attestation matches the `client_id` in the request.
4. IF the Wallet Attestation or its PoP proof is invalid, expired, or from an untrusted provider, THEN THE AS SHALL reject the request with an `invalid_client` error.
5. THE Discovery_Endpoint SHALL advertise `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported` when Wallet Attestation is enabled.

### Requirement 10: AS Metadata Extensions

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise OIDC4VCI-specific capabilities, so that I can determine which features the AS supports before initiating a flow.

#### Acceptance Criteria

1. THE Discovery_Endpoint SHALL include `pre-authorized_grant_anonymous_access_supported` (boolean) in the AS metadata when the Pre-Authorized Code grant type is enabled.
2. THE Discovery_Endpoint SHALL include `urn:ietf:params:oauth:grant-type:pre-authorized_code` in `grant_types_supported` when the Pre-Authorized Code grant type is enabled.
3. THE Discovery_Endpoint SHALL include `authorization_details_types_supported` containing `openid_credential` when RAR is enabled.
4. THE Discovery_Endpoint SHALL advertise `dpop_signing_alg_values_supported` when DPoP is enabled.
5. THE Discovery_Endpoint SHALL advertise `authorization_response_iss_parameter_supported` as `true` when RFC 9207 support is enabled.
6. THE Discovery_Endpoint SHALL conform to RFC 8414 for all metadata parameters.

### Requirement 11: PKCE with S256 Enforcement for HAIP

**User Story:** As a security architect, I want PKCE with S256 to be enforced for all authorization code flows used in credential issuance, so that authorization code interception attacks are prevented per HAIP requirements.

#### Acceptance Criteria

1. WHILE the AS is configured for HAIP compliance, THE Authorization_Endpoint SHALL require PKCE with `code_challenge_method=S256` for all authorization code flows.
2. IF a PKCE code challenge is missing or uses a method other than S256 under HAIP enforcement, THEN THE Authorization_Endpoint SHALL reject the request with an `invalid_request` error.
3. THE Discovery_Endpoint SHALL advertise `code_challenge_methods_supported` containing `S256`.

### Requirement 12: Refresh Token Support for Credential Refresh

**User Story:** As a Wallet developer, I want to obtain refresh tokens during credential issuance flows, so that I can refresh credentials without re-authenticating the user.

#### Acceptance Criteria

1. WHEN a credential issuance flow completes successfully and the client is authorized for refresh tokens, THE Token_Endpoint SHALL issue a refresh token alongside the access token.
2. WHEN a refresh token is exchanged, THE Token_Endpoint SHALL issue a new access token that retains the original `authorization_details` and credential scope bindings.

### Requirement 13: Authorization Details Flow-Through to Consent Node

**User Story:** As a Login/Consent application developer, I want to receive `authorization_details` data in the consent challenge, so that I can display credential-specific information to the user and make informed consent decisions.

#### Acceptance Criteria

1. WHEN an authorization request contains `authorization_details`, THE AS SHALL include the parsed `authorization_details` in the consent challenge payload sent to the Consent_Node.
2. WHEN the Consent_Node accepts the consent request, THE AS SHALL allow the Consent_Node to return modified or enriched `authorization_details` (e.g., adding `credential_identifiers`) via the consent session.
3. THE AS SHALL propagate the final `authorization_details` from the consent response into the token session so it is available during token issuance.

### Requirement 14: ES256 Cryptographic Algorithm Support

**User Story:** As a security architect, I want the AS to support ES256 (P-256 + SHA-256) as a minimum cryptographic algorithm, so that the system meets HAIP interoperability requirements.

#### Acceptance Criteria

1. THE AS SHALL support ES256 for DPoP proof validation.
2. THE AS SHALL support ES256 for Wallet Attestation signature validation.
3. THE AS SHALL support ES256 for request object signature validation (JAR).
4. THE Discovery_Endpoint SHALL include `ES256` in `dpop_signing_alg_values_supported` and `request_object_signing_alg_values_supported`.
