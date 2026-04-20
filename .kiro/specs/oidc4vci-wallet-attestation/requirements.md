# Requirements Document

## Introduction

This document specifies the Wallet Attestation client authentication method (`attest_jwt_client_auth`) for the Hydra AS fork, per draft-ietf-oauth-attestation-based-client-auth-07, OIDC4VCI Appendix E, and HAIP §4.4.1.

Wallet Attestation is a client authentication mechanism where Wallets prove their identity using a signed Client Attestation JWT from their Wallet Provider, combined with a Client Attestation PoP (Proof of Possession) JWT signed by the Wallet instance. This is NOT a `TokenEndpointHandler` or `AuthorizeEndpointHandler` — it is a `ClientAuthenticationStrategy` that plugs into `Fosite.AuthenticateClient()`, which is called for both PAR and Token requests.

The implementation validates two HTTP headers per draft-07 §6.1:
- `OAuth-Client-Attestation` — a JWT conforming to draft-07 §5.1, signed by the Wallet Provider (Client Attester), with `typ: oauth-client-attestation+jwt`, carrying the `cnf` claim binding the Client Instance Key
- `OAuth-Client-Attestation-PoP` — a JWT conforming to draft-07 §5.2, signed by the Wallet instance using the key from `cnf`, with `typ: oauth-client-attestation-pop+jwt`

HAIP §4.4.1 adds profile-specific rules: the Attestation JWT's signing key MUST be validated via `x5c` certificate chain (trust anchor excluded from chain, leaf cert not self-signed), and the `sub` claim MUST be shared across all wallet instances of the same type (not unique per instance).

The scope is strictly the Authorization Server role. This spec covers the Wallet Attestation authenticator (`fosite/handler/wallet_attestation/`), trust anchor configuration, PoP JWT `jti` replay protection, integration into `fositex.Config.GetClientAuthenticationStrategy()`, config provider, error constants, refresh token binding, and feature documentation.

### Normative References

- **draft-ietf-oauth-attestation-based-client-auth-07** — Primary protocol specification for attestation-based client authentication (#[[file:docs/oidc4vci/rfc/oauth2-attestation-based-client-auth-07-draft.md]])
- **OIDC4VCI Appendix E** — Wallet Attestations in JWT format, additional claims (`wallet_name`, `wallet_link`, `status`) (#[[file:docs/oidc4vci/openid-4-verifiable-credential-issuance-1_0.md]])
- **HAIP §4.4.1** — Wallet Attestation profile rules: `x5c` required, trust anchor exclusion, no self-signed certs, shared `sub` (#[[file:docs/oidc4vci/openid4vc-high-assurance-interoperability-profile-1_0.md]])

### Dependency Context

This spec depends on Spec 1 (oidc4vci-rar-consent) which established the config provider interface pattern, error constant pattern, and compile-time interface checks. It depends on Spec 2 (oidc4vci-dpop) which established the DPoP handler — the DPoP handler's `isPublicClient()` function already treats `attest_jwt_client_auth` as a public client for refresh token DPoP binding purposes. This spec has NO code dependencies on Spec 3 (oidc4vci-preauth).

## Glossary

- **AS**: Authorization Server — the Hydra instance responsible for OAuth 2.0 and OIDC flows.
- **Wallet_Attestation_Authenticator**: The authenticator in `fosite/handler/wallet_attestation/` that validates Wallet Attestation headers and returns an authenticated client. It is a `ClientAuthenticationStrategy`, not a handler.
- **Token_Endpoint**: The Hydra endpoint (`/oauth2/token`) that issues access tokens. Calls `Fosite.AuthenticateClient()` which invokes the Wallet_Attestation_Authenticator when the `OAuth-Client-Attestation` header is present.
- **PAR_Endpoint**: The Pushed Authorization Request endpoint (`/oauth2/par`). Calls `Fosite.AuthenticateClient()` using the same client authentication pipeline as the Token_Endpoint.
- **Client_Attestation_JWT**: The JWT sent in the `OAuth-Client-Attestation` HTTP header, signed by the Wallet_Provider. MUST have `typ: oauth-client-attestation+jwt` per draft-07 §5.1. Contains `iss` (Wallet Provider), `sub` (client_id), `exp`, `cnf` (Client Instance Key as JWK), and optionally `iat`, `nbf`. HAIP profile requires `x5c` JOSE header for key resolution.
- **Client_Attestation_PoP_JWT**: The Proof of Possession JWT sent in the `OAuth-Client-Attestation-PoP` HTTP header, signed by the Wallet instance using the key from `cnf`. MUST have `typ: oauth-client-attestation-pop+jwt` per draft-07 §5.2. Contains `iss` (client_id), `aud` (AS issuer), `jti`, `iat`, and optionally `challenge`, `nbf`.
- **Wallet_Provider**: The entity (Client Attester) that issues Client Attestation JWTs to Wallet instances after verifying the Wallet app's integrity (e.g., via iOS DeviceCheck or Android Play Integrity). The Wallet_Provider's signing certificate chains to a configured trust anchor.
- **Wallet**: The OAuth 2.0 Client (end-user application / Client Instance) that authenticates using Wallet Attestation at the PAR_Endpoint and Token_Endpoint. Multiple Wallet instances of the same type share a single `client_id` (the `sub` from the Client_Attestation_JWT) per HAIP §4.4.1 and OIDC4VCI §15.4.4.
- **Wallet_Type_Client_Record**: A pre-registered OAuth 2.0 client record in Hydra's database representing a wallet type (not an individual wallet instance). The `client_id` matches the shared `sub` value from the Wallet Provider's attestations. The operator creates one record per trusted wallet type with `token_endpoint_auth_method=attest_jwt_client_auth`. This record controls grant types, scopes, redirect URIs, and audience restrictions for all instances of that wallet type.
- **Client_Instance_Key**: The asymmetric key pair generated by the Wallet (Client Instance). The public key is embedded in the Client_Attestation_JWT's `cnf` claim and used to sign the Client_Attestation_PoP_JWT. This key distinguishes individual wallet instances within a wallet type — it is the per-instance identity, while the `client_id` is the per-type identity.
- **Trust_Anchor**: A root CA certificate configured on the AS. The Client_Attestation_JWT's `x5c` certificate chain must terminate at a Trust_Anchor for the attestation to be accepted. Per HAIP, the Trust_Anchor itself MUST NOT be included in the `x5c` chain.
- **ClientAuthenticationStrategy**: The function type `func(context.Context, *http.Request, url.Values) (Client, error)` used by `Fosite.AuthenticateClient()` to authenticate clients. Configured via `Configurator.GetClientAuthenticationStrategy()`.
- **DefaultClientAuthenticationStrategy**: The built-in Fosite client authentication logic that handles `client_secret_post`, `client_secret_basic`, `private_key_jwt`, and `none`. The Wallet_Attestation_Authenticator falls back to this when the `OAuth-Client-Attestation` header is absent.
- **WalletAttestationConfigProvider**: The provider interface for Wallet Attestation feature configuration (`GetWalletAttestationEnabled`, `GetWalletAttestationTrustAnchors`).
- **Configurator**: The Fosite interface (`fosite/fosite.go`) that composes all provider interfaces for handler configuration.
- **Persister**: The aggregate persistence interface (`persistence/definitions.go`) that composes all domain storage interfaces, implemented by `persistence/sql/Persister`.
- **Fosite_Instance**: The `*fosite.Fosite` struct that provides `DefaultClientAuthenticationStrategy()` for fallback when Wallet Attestation headers are absent.

## Requirements

### Requirement 1: Client Attestation JWT Validation (draft-07 §5.1, §9)

**User Story:** As a security architect, I want the AS to validate the Client Attestation JWT from the `OAuth-Client-Attestation` header per draft-ietf-oauth-attestation-based-client-auth-07 §5.1 and the verification checklist in §9, so that only Wallets with valid attestations from trusted Wallet Providers are authenticated.

#### Acceptance Criteria

1. WHEN a PAR or Token Request includes an `OAuth-Client-Attestation` HTTP header, THE Wallet_Attestation_Authenticator SHALL parse the header value as a JWT. There MUST be precisely one `OAuth-Client-Attestation` header field per draft-07 §6.2 check 1.
2. IF the `OAuth-Client-Attestation` header value is not a well-formed JWT, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation is not a well-formed JWT".
3. WHEN the Client_Attestation_JWT is parsed, THE Wallet_Attestation_Authenticator SHALL validate the `typ` JOSE header parameter equals `oauth-client-attestation+jwt` per draft-07 §5.1. IF the `typ` is missing or incorrect, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation typ must be oauth-client-attestation+jwt".
4. WHEN the Client_Attestation_JWT is parsed, THE Wallet_Attestation_Authenticator SHALL validate the `alg` JOSE header parameter indicates a registered asymmetric digital signature algorithm per IANA JOSE registry, is not `none`, and is supported by the AS per draft-07 §9 check 4. IF the `alg` is `none`, symmetric, or unsupported, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation uses unsupported signing algorithm".
5. WHEN the Client_Attestation_JWT is parsed, THE Wallet_Attestation_Authenticator SHALL extract the `x5c` JOSE header parameter containing the X.509 certificate chain (DER-encoded, base64-encoded per RFC 7515 §4.1.6). The `x5c` header is REQUIRED by HAIP §4.4.1 for Wallet Attestation key resolution.
6. IF the `x5c` JOSE header parameter is missing or empty, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation is missing the x5c JOSE header".
7. WHEN the `x5c` chain is extracted, THE Wallet_Attestation_Authenticator SHALL build the X.509 certificate chain and validate it against the configured trust anchors from `WalletAttestationConfigProvider.GetWalletAttestationTrustAnchors(ctx)` using Go's `crypto/x509.Certificate.Verify()` with a `x509.CertPool` containing the trust anchors. This satisfies draft-07 §9 check 5 ("signature verifies with the public key of a known and trusted Attester").
8. IF the certificate chain does not terminate at a configured Trust_Anchor, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation certificate chain is not trusted".
9. WHEN the certificate chain is validated, THE Wallet_Attestation_Authenticator SHALL verify the Client_Attestation_JWT signature using the public key from the leaf certificate (first certificate in the `x5c` chain).
10. IF the Client_Attestation_JWT signature is invalid, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation signature verification failed".
11. WHEN the Client_Attestation_JWT signature is verified, THE Wallet_Attestation_Authenticator SHALL validate the `exp` claim per draft-07 §5.1 and §9 check 11. IF the Client_Attestation_JWT is expired (subject to allowable clock skew), THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation is expired".
12. WHEN the Client_Attestation_JWT has an `nbf` claim, THE Wallet_Attestation_Authenticator SHALL validate it per RFC 7519. IF the current time is before `nbf` (subject to allowable clock skew), THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation is not yet valid".
13. WHEN the Client_Attestation_JWT is valid, THE Wallet_Attestation_Authenticator SHALL validate the `iss` claim is present per draft-07 §5.1. The `iss` identifies the Wallet Provider (Client Attester). IF `iss` is missing, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation is missing iss claim".
14. WHEN the Client_Attestation_JWT is valid, THE Wallet_Attestation_Authenticator SHALL extract the `sub` claim and verify it matches the `client_id` from the request form (`form.Get("client_id")`) per draft-07 §6.3 and §9 check 13. IF they do not match, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation sub does not match client_id".
15. WHEN the Client_Attestation_JWT is valid, THE Wallet_Attestation_Authenticator SHALL extract the `cnf` (confirmation) claim per draft-07 §5.1. The `cnf` MUST contain a `jwk` representation of the Client_Instance_Key per RFC 7800.
16. IF the `cnf` claim is missing or does not contain a valid JWK, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation is missing the cnf claim".
17. WHEN the `cnf` claim is extracted, THE Wallet_Attestation_Authenticator SHALL verify that the key in `cnf.jwk` is a public key (not a private key) per draft-07 §9 check 6. IF the key contains private key material (e.g., `d` parameter for EC keys), THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation cnf must contain a public key only".
18. THE Wallet_Attestation_Authenticator SHALL ignore unknown claims in the Client_Attestation_JWT per draft-07 §5.1 rule 1. OIDC4VCI Appendix E defines optional claims (`wallet_name`, `wallet_link`, `status`) that MAY be present but are not validated by the AS.


### Requirement 2: HAIP-Specific X.509 Chain Rules (HAIP §4.4.1)

**User Story:** As a security architect, I want the AS to enforce HAIP-specific rules on the Wallet Attestation certificate chain, so that the chain validation meets the high assurance requirements of the interoperability profile.

#### Acceptance Criteria

1. WHEN the `x5c` certificate chain is validated, THE Wallet_Attestation_Authenticator SHALL verify that the Trust_Anchor certificate itself is NOT included in the `x5c` chain per HAIP §4.4.1 ("trust certificate chain excluding the trust anchor"). IF a Trust_Anchor is found in the `x5c` chain (by comparing certificate bytes), THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Trust anchor must not be included in x5c chain".
2. WHEN the `x5c` certificate chain is validated, THE Wallet_Attestation_Authenticator SHALL verify that the leaf certificate (signing certificate) is NOT self-signed per HAIP §4.4.1 ("The X.509 certificate signing the request MUST NOT be self-signed"). IF the leaf certificate is self-signed (issuer equals subject AND the certificate verifies its own signature), THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Wallet Attestation signing certificate must not be self-signed".

### Requirement 3: Client Attestation PoP JWT Validation (draft-07 §5.2, §9)

**User Story:** As a security architect, I want the AS to validate the Client Attestation PoP JWT from the `OAuth-Client-Attestation-PoP` header per draft-07 §5.2 and the verification checklist in §9, so that the Wallet proves it possesses the private key corresponding to the confirmation key in the attestation.

#### Acceptance Criteria

1. WHEN a request includes an `OAuth-Client-Attestation` header, THE Wallet_Attestation_Authenticator SHALL also require the `OAuth-Client-Attestation-PoP` header. There MUST be precisely one `OAuth-Client-Attestation-PoP` header field per draft-07 §6.2 check 2. IF the PoP header is missing, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "OAuth-Client-Attestation-PoP header is required".
2. WHEN the Client_Attestation_PoP_JWT is parsed, THE Wallet_Attestation_Authenticator SHALL validate the `typ` JOSE header parameter equals `oauth-client-attestation-pop+jwt` per draft-07 §5.2. IF the `typ` is missing or incorrect, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT typ must be oauth-client-attestation-pop+jwt".
3. WHEN the Client_Attestation_PoP_JWT is parsed, THE Wallet_Attestation_Authenticator SHALL validate the `alg` JOSE header parameter indicates a registered asymmetric digital signature algorithm, is not `none`, and is supported by the AS per draft-07 §9 check 4. IF the `alg` is `none`, symmetric, or unsupported, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT uses unsupported signing algorithm".
4. WHEN the Client_Attestation_PoP_JWT is parsed, THE Wallet_Attestation_Authenticator SHALL verify the PoP_JWT signature using the public key from the Client_Attestation_JWT's `cnf` claim per draft-07 §5.2 rule 3 and §9 check 7. IF the signature is invalid, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT signature verification failed".
5. WHEN the Client_Attestation_PoP_JWT signature is verified, THE Wallet_Attestation_Authenticator SHALL validate the `iss` claim equals the `client_id` value AND matches the `sub` claim of the Client_Attestation_JWT per draft-07 §5.2 rule 4. IF `iss` is missing or does not match, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT iss does not match client_id".
6. WHEN the Client_Attestation_PoP_JWT signature is verified, THE Wallet_Attestation_Authenticator SHALL validate the `aud` claim matches the AS Issuer Identifier (from `Configurator.GetIDTokenIssuer(ctx)` or equivalent) per draft-07 §5.2 and §9 check 10. The `aud` value MUST be the RFC 8414 issuer identifier URL of the AS. IF the `aud` does not match, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT aud does not match AS issuer".
7. WHEN the Client_Attestation_PoP_JWT signature is verified, THE Wallet_Attestation_Authenticator SHALL validate the `iat` claim is present (REQUIRED per draft-07 §5.2) and recent per draft-07 §9 check 9. The freshness window SHALL be configurable (default 60 seconds) with a future tolerance for clock skew (default 5 seconds). IF the `iat` is too old or too far in the future, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT iat is not recent".
8. WHEN the Client_Attestation_PoP_JWT signature is verified, THE Wallet_Attestation_Authenticator SHALL validate the `jti` claim is present (REQUIRED per draft-07 §5.2) and unique for replay protection per draft-07 §9 check 12 and §12.1. IF the `jti` has been seen before within the replay detection window, THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT jti has already been used".
9. WHEN the Client_Attestation_PoP_JWT `jti` is unique, THE Wallet_Attestation_Authenticator SHALL mark it as used with an expiry matching the PoP freshness window, so it can be cleaned up after the replay window expires. This implements the sliding window approach recommended in draft-07 §10.6.
10. WHEN the Client_Attestation_PoP_JWT has an `nbf` claim, THE Wallet_Attestation_Authenticator SHALL validate it per RFC 7519. IF the current time is before `nbf` (subject to allowable clock skew), THEN THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "PoP JWT is not yet valid".
11. IT IS RECOMMENDED that the Wallet_Attestation_Authenticator validate the Client_Attestation_JWT prior to validating the Client_Attestation_PoP_JWT per draft-07 §6.1 recommendation.

### Requirement 4: PoP JWT JTI Replay Protection Storage

**User Story:** As a developer implementing Wallet Attestation, I want a storage mechanism for PoP JWT `jti` replay detection using a sliding time window per draft-07 §10.6 and §12.1, so that replayed PoP JWTs are rejected across AS restarts and in multi-instance deployments.

#### Acceptance Criteria

1. THE Wallet_Attestation_Authenticator SHALL reuse the existing `DPoPNonceStorage.IsJTIUsed` and `DPoPNonceStorage.MarkJTIUsed` methods for PoP JWT `jti` replay detection. The DPoP JTI table (`hydra_oauth2_dpop_jti`) stores JTI values with expiry — the same table and methods serve both DPoP proof JTI and Wallet Attestation PoP JTI replay detection. The JTI values are namespaced by their content (DPoP proof JTIs and PoP JTIs are cryptographically random UUIDs per draft-07 §5.2 example, collision is negligible).
2. THE Wallet_Attestation_Authenticator SHALL receive a reference to `DPoPNonceStorage` (or an equivalent JTI storage interface) for `jti` replay detection.
3. THE sliding time window for JTI replay detection SHALL match the PoP freshness window configuration (default 60 seconds). JTI entries older than this window SHALL be eligible for cleanup per draft-07 §10.6.

### Requirement 5: Client Authentication Strategy Integration and Client Model

**User Story:** As a developer wiring up the Fosite pipeline, I want the Wallet Attestation authenticator integrated into `Fosite.AuthenticateClient()` via `GetClientAuthenticationStrategy()`, so that Wallet Attestation is checked on both PAR and Token requests without modifying `fosite/client_authentication.go`.

**Client Model:** Wallet Attestation uses a shared pre-registered client record per wallet type (Wallet_Type_Client_Record). The `sub` claim in the Client_Attestation_JWT identifies the wallet type (e.g., `"https://wallet.example.org"`), not an individual wallet instance — this is mandated by HAIP §4.4.1 and OIDC4VCI §15.4.4 for privacy. The AS operator pre-registers one client record per trusted wallet type with `client_id` matching the `sub` value and `token_endpoint_auth_method` set to `attest_jwt_client_auth`. This record controls grant types, scopes, redirect URIs, and audience restrictions for all instances of that wallet type. Individual wallet instances are distinguished by their Client_Instance_Key (the `cnf.jwk` in the attestation), which is used for DPoP token binding and refresh token binding — not for client lookup.

#### Acceptance Criteria

1. WHEN Wallet Attestation is enabled (`GetWalletAttestationEnabled(ctx) == true`), THE `fositex.Config.GetClientAuthenticationStrategy(ctx)` SHALL return a non-nil `ClientAuthenticationStrategy` function that: (a) checks for the `OAuth-Client-Attestation` HTTP header on the request, (b) if present, delegates to the Wallet_Attestation_Authenticator, (c) if absent, falls back to `Fosite_Instance.DefaultClientAuthenticationStrategy(ctx, r, form)`.
2. WHEN Wallet Attestation is disabled (`GetWalletAttestationEnabled(ctx) == false`), THE `fositex.Config.GetClientAuthenticationStrategy(ctx)` SHALL return `nil`, preserving the existing fallback behavior where `Fosite.AuthenticateClient()` calls `DefaultClientAuthenticationStrategy` directly.
3. THE strategy function returned by `GetClientAuthenticationStrategy` SHALL have access to the Fosite_Instance for fallback. The mechanism for providing this access (closure, struct method, or construction-time injection) SHALL be determined during the design phase to resolve the circular dependency between `fositex.Config` and the `Fosite` instance.
4. THE Wallet_Attestation_Authenticator SHALL extract the `sub` claim from the validated Client_Attestation_JWT and use it as the `client_id` to look up the Wallet_Type_Client_Record via `Fosite.Store.GetClient(ctx, clientID)`. IF no client record exists for the `sub` value, THE authenticator SHALL reject with an `invalid_client` error with hint "No client record found for wallet type. The AS operator must pre-register a client with client_id matching the attestation sub claim."
5. THE Wallet_Type_Client_Record MUST have `token_endpoint_auth_method` set to `attest_jwt_client_auth`. IF the looked-up client has a different `token_endpoint_auth_method`, THE authenticator SHALL reject with an `invalid_client` error with hint "Client is not configured for attestation-based authentication".
6. THE same `ClientAuthenticationStrategy` SHALL apply to both PAR and Token endpoint requests — `Fosite.AuthenticateClient()` is called for both, and no endpoint-specific changes are needed. This satisfies HAIP §4.3 ("Wallets MUST authenticate themselves at the PAR endpoint using the same rules as defined in Section 4.4 for client authentication at the token endpoint").
7. WHEN the `OAuth-Client-Attestation` header is present but Wallet Attestation is disabled, THE strategy function SHALL fall back to the default strategy (which will likely reject the request based on the client's configured `token_endpoint_auth_method`).
8. THE Wallet_Attestation_Authenticator SHALL verify that the `client_id` from the request form (if present) matches the `sub` claim of the Client_Attestation_JWT and the `iss` claim of the Client_Attestation_PoP_JWT per draft-07 §6.3 and §6.4. This three-way match (`form.client_id` == attestation `sub` == PoP `iss`) ensures consistency between the OAuth request and the attestation.

### Requirement 6: Fallback Behavior for Non-Attestation Requests

**User Story:** As a developer, I want requests without Wallet Attestation headers to be handled by the default client authentication strategy, so that existing authentication methods (`client_secret_post`, `client_secret_basic`, `private_key_jwt`, `none`) continue to work when Wallet Attestation is enabled.

#### Acceptance Criteria

1. WHEN a PAR or Token Request does not include an `OAuth-Client-Attestation` header and Wallet Attestation is enabled, THE strategy function SHALL delegate to `Fosite_Instance.DefaultClientAuthenticationStrategy(ctx, r, form)` which handles `client_secret_post`, `client_secret_basic`, `private_key_jwt`, and `none`.
2. WHEN a client is configured with `token_endpoint_auth_method=client_secret_post` and sends a request with `client_secret` in the form body (no `OAuth-Client-Attestation` header), THE strategy function SHALL authenticate the client via the default strategy without any Wallet Attestation validation.
3. WHEN a client is configured with `token_endpoint_auth_method=attest_jwt_client_auth` and sends a request without the `OAuth-Client-Attestation` header, THE default strategy fallback SHALL reject the request because the client's configured auth method does not match any default method. The specific error handling for this case is determined by the default strategy's existing logic.

### Requirement 7: Refresh Token Binding (draft-07 §10.3)

**User Story:** As a security architect, I want refresh tokens issued via Wallet Attestation to be bound to the Client Instance and its key per draft-07 §10.3, so that only the original Wallet instance can use the refresh token.

#### Acceptance Criteria

1. WHEN the AS issues a refresh token in response to a token request authenticated via Wallet Attestation, THE AS SHALL bind the refresh token to the Client Instance and its Client_Instance_Key (the public key from the `cnf` claim of the Client_Attestation_JWT used during the original token request) per draft-07 §10.3.
2. WHEN a Client Instance presents a refresh token for token refresh, THE Client Instance MUST authenticate using the Wallet Attestation mechanism (Client_Attestation_JWT + Client_Attestation_PoP_JWT) per draft-07 §10.3.
3. WHEN a refresh token request is authenticated via Wallet Attestation, THE Wallet_Attestation_Authenticator SHALL verify that the `cnf.jwk` in the current Client_Attestation_JWT matches the Client_Instance_Key that was bound to the refresh token at issuance per draft-07 §10.3 ("The client MUST also use the same key that was present in the cnf claim of the client attestation that was used when the refresh token was issued"). IF the keys do not match, THE Wallet_Attestation_Authenticator SHALL reject the request with an `invalid_client` error with hint "Refresh token is bound to a different client instance key".
4. THE mechanism for storing and comparing the bound Client_Instance_Key (e.g., storing the JWK thumbprint in the session or a dedicated field) SHALL be determined during the design phase.

### Requirement 8: ES256 Algorithm Support (HAIP §7)

**User Story:** As a security architect, I want the AS to support ES256 for both Client Attestation JWT and PoP JWT signature validation, so that the system meets HAIP interoperability requirements.

#### Acceptance Criteria

1. THE Wallet_Attestation_Authenticator SHALL support ES256 (ECDSA with P-256 and SHA-256) for Client_Attestation_JWT signature validation. ES256 is the baseline algorithm required by HAIP §7.
2. THE Wallet_Attestation_Authenticator SHALL support ES256 for Client_Attestation_PoP_JWT signature validation.
3. THE Wallet_Attestation_Authenticator SHALL use `go-jose/v4` (already a dependency from the DPoP spec) for JWT parsing and signature verification.
4. THE set of supported signing algorithms for Client Attestation and PoP JWTs SHALL be configurable via AS metadata fields `client_attestation_signing_alg_values_supported` and `client_attestation_pop_signing_alg_values_supported` per draft-07 §10.1. The default SHALL include at least `ES256`.

### Requirement 9: WalletAttestationConfigProvider and Config Keys

**User Story:** As an AS operator, I want configuration keys to enable/disable Wallet Attestation and configure trust anchors, so that I can manage the feature without code changes.

#### Acceptance Criteria

1. THE AS SHALL define a `WalletAttestationConfigProvider` interface in `fosite/config.go` with methods: `GetWalletAttestationEnabled(ctx context.Context) bool`, `GetWalletAttestationTrustAnchors(ctx context.Context) []*x509.Certificate`.
2. THE AS SHALL define config keys `KeyWalletAttestationEnabled` (boolean, default `false`) and `KeyWalletAttestationTrustAnchors` (string slice of PEM-encoded certificates, default empty) in `driver/config/provider.go`.
3. THE AS SHALL implement the `WalletAttestationConfigProvider` methods on `DefaultProvider` using the standard `p.getProvider(ctx)` pattern for multi-tenant support. The `GetWalletAttestationTrustAnchors` method SHALL parse PEM-encoded certificate strings from the config value into `[]*x509.Certificate` objects. IF a PEM string is malformed, THE method SHALL log a warning and skip the invalid entry.
4. THE AS SHALL embed `WalletAttestationConfigProvider` in the Fosite `Configurator` interface in `fosite/fosite.go`.
5. THE AS SHALL add `wallet_attestation.enabled` and `wallet_attestation.trust_anchors` properties to the JSON schema in `spec/config.json` and run `scripts/render-schemas.sh` to regenerate derived schemas.
6. THE AS SHALL verify that `fositex.Config` satisfies `WalletAttestationConfigProvider` via a compile-time interface check in `fositex/config.go` (`var _ fosite.WalletAttestationConfigProvider = (*Config)(nil)`). Since `fositex.Config` embeds `*config.DefaultProvider`, the methods are inherited automatically, but the compile-time check ensures this contract is not accidentally broken.

### Requirement 10: Error Constants (draft-07 §6.2)

**User Story:** As a developer implementing Wallet Attestation validation, I want dedicated error variables following the established pattern, so that validation failures use appropriate error codes per draft-07 §6.2 and OAuth 2.0 convention.

#### Acceptance Criteria

1. THE AS SHALL define error variables in `fosite/handler/wallet_attestation/errors.go` using the `*fosite.RFC6749Error` pattern established by Spec 1 and Spec 2.
2. THE AS SHALL define `ErrInvalidWalletAttestation` as a `*fosite.RFC6749Error` with `ErrorField` set to `invalid_client` and `CodeField` set to HTTP 401. This is the base error for all Wallet Attestation validation failures per OAuth 2.0 convention for client authentication errors.
3. THE AS SHALL define `ErrInvalidClientAttestation` as a `*fosite.RFC6749Error` with `ErrorField` set to `invalid_client_attestation` and `CodeField` set to HTTP 401 per draft-07 §6.2. This MAY be used as an alternative to `invalid_client` when the AS wants to provide more specific error information about attestation validation failures.
4. THE Wallet_Attestation_Authenticator SHALL chain context via `.WithHint()` and `.WithDebugf()` at each call site, following the pattern established by the DPoP handler. Debug details SHALL only be sent when `GetSendDebugMessagesToClients()` returns true.

### Requirement 11: Wallet Attestation Header Access

**User Story:** As a developer implementing the Wallet Attestation authenticator, I want a reliable mechanism to access the `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` HTTP headers from within the `ClientAuthenticationStrategy` function, so that the authenticator can extract and validate the JWTs.

#### Acceptance Criteria

1. THE `ClientAuthenticationStrategy` function receives the raw `*http.Request` as its second parameter, so THE Wallet_Attestation_Authenticator SHALL access the `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers directly from `r.Header.Get("OAuth-Client-Attestation")` and `r.Header.Get("OAuth-Client-Attestation-PoP")`. No form parameter injection is needed (unlike DPoP, which uses form injection because handlers receive `AccessRequester` not `*http.Request`).
2. Per RFC 9110, header field names are case-insensitive. Go's `http.Header.Get()` handles this automatically via canonical header key formatting.

### Requirement 12: Client Attestation JWT Reuse (draft-07 §10.2)

**User Story:** As a developer, I want the AS to correctly handle reuse of a single Client Attestation JWT across multiple requests with fresh PoP JWTs, so that the implementation aligns with the draft spec's deliberate design for attestation reuse.

#### Acceptance Criteria

1. THE Wallet_Attestation_Authenticator SHALL allow the same Client_Attestation_JWT to be presented in multiple requests, provided each request includes a fresh Client_Attestation_PoP_JWT with a unique `jti` per draft-07 §10.2. The replay protection applies only to the PoP JWT's `jti`, not to the Client_Attestation_JWT itself.
2. THE Wallet_Attestation_Authenticator SHALL NOT cache or store the Client_Attestation_JWT between requests. Each request is validated independently.

### Requirement 13: Discovery Metadata (Deferred to Spec 5)

**User Story:** As a Wallet developer, I want the AS discovery metadata to advertise `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported` and the supported signing algorithms, so that I can determine whether the AS supports Wallet Attestation before initiating a flow.

#### Acceptance Criteria

1. Note: The addition of `attest_jwt_client_auth` to `token_endpoint_auth_methods_supported` is deferred to Spec 5 (`oidc4vci-haip-metadata`), which aggregates all feature-specific metadata extensions into the `oidcConfiguration` struct in `oauth2/handler.go`. This spec provides the `WalletAttestationConfigProvider.GetWalletAttestationEnabled(ctx)` method that Spec 5 will call to conditionally include `attest_jwt_client_auth` in the metadata.
2. WHEN Wallet Attestation is enabled, Spec 5 SHALL include `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported` in the AS metadata per draft-07 §10.1.
3. WHEN Wallet Attestation is enabled, Spec 5 SHALL include `client_attestation_signing_alg_values_supported` and `client_attestation_pop_signing_alg_values_supported` in the AS metadata per draft-07 §10.1 and §13.3. These MUST be present when `token_endpoint_auth_methods_supported` includes `attest_jwt_client_auth`.
4. WHEN Wallet Attestation is disabled, Spec 5 SHALL omit `attest_jwt_client_auth` and the algorithm metadata fields from the metadata.

### Requirement 14: Feature Documentation

**User Story:** As a developer or operator, I want a feature documentation file describing the Wallet Attestation implementation, so that I can understand the feature, its configuration, authentication flow, validation rules, HAIP constraints, error codes, and references.

#### Acceptance Criteria

1. THE AS SHALL include a documentation file at `docs/features/wallet-attestation.md` describing the implemented feature.
2. THE documentation SHALL cover: feature overview, client model (one pre-registered Wallet_Type_Client_Record per wallet type with `client_id` matching attestation `sub`, `token_endpoint_auth_method=attest_jwt_client_auth`), configuration keys and defaults (`KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`), operator setup guide (trust anchor configuration + client record creation per wallet type), authentication flow (Client Attestation JWT + PoP JWT validation sequence per draft-07 §9 verification checklist), validation rules (x5c chain building, trust anchor verification, signature verification, `typ` header validation, claim validation), HAIP-specific constraints (trust anchor not in x5c chain, no self-signed leaf certs, shared `sub` across wallet instances per HAIP §4.4.1), refresh token binding rules (draft-07 §10.3), attestation reuse behavior (draft-07 §10.2), error codes (`invalid_client` and `invalid_client_attestation` with specific hints), integration point (`GetClientAuthenticationStrategy` and fallback to default), and references to draft-ietf-oauth-attestation-based-client-auth-07, HAIP §4.4.1, OIDC4VCI Appendix E, and the design docs in `docs/ai-context/`.

### Requirement 15: HAIP Auto-Enable Behavior (Deferred to Spec 5)

**User Story:** As an AS operator, I want Wallet Attestation to be automatically enabled when HAIP enforcement is active, so that HAIP compliance is achieved without manually enabling each feature flag.

#### Acceptance Criteria

1. Note: The HAIP-driven auto-enable of Wallet Attestation is deferred to Spec 5 (`oidc4vci-haip-metadata`), which wires `KeyHAIPEnforced` to override individual feature flags. This spec defines the `KeyWalletAttestationEnabled` config key with a standalone default of `false`. Spec 5 will ensure that when `GetHAIPEnforced(ctx)` returns `true`, `GetWalletAttestationEnabled(ctx)` also returns `true`.
2. This spec's `WalletAttestationConfigProvider` and config keys are designed to be overridable by the HAIP enforcement layer in Spec 5 without modification to the Wallet Attestation authenticator code.
