# OIDC4VCI AS Requirements Checklist — Gap Analysis

## Purpose

Synthesized checklist of Authorization Server requirements from the OIDC4VCI spec (OpenID for Verifiable Credential Issuance 1.0) and the HAIP spec (High Assurance Interoperability Profile 1.0), mapped against the current Hydra fork implementation. Each row identifies the requirement, its spec source, current implementation status, and the specific code paths where gaps exist.

## Requirements Matrix

### OIDC4VCI Spec Requirements

| ID | Requirement | Source | Hydra Status | Gap Details |
|----|-------------|--------|--------------|-------------|
| V1 | **Pre-Authorized Code Grant Type** — Accept `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code` at Token Endpoint, validate `pre-authorized_code` parameter, enforce single-use and expiry | OIDC4VCI §3.5 (Pre-Authorized Code Flow), §4.1.1 (Credential Offer Parameters — grant parameters within `grants` object), §6.1 (Token Request) | **MISSING** | No handler exists. Need new `TokenEndpointHandler` in `fosite/handler/preauth/`. New factory in `fosite/compose/compose_preauth.go`. New storage interface `PreAuthorizedCodeStorage`. New DB table `hydra_oauth2_preauth_code`. Grant type not in `ComposeAllEnabled()` (`fosite/compose/compose.go`). `Configurator` (`fosite/fosite.go`) missing `PreAuthorizedCodeConfigProvider`. Config keys missing in `driver/config/provider.go`. |
| V2 | **Transaction Code (`tx_code`) validation** — When Pre-Authorized Code requires a `tx_code`, validate it against stored value; reject with `invalid_request` if missing/unexpected, `invalid_grant` if wrong | OIDC4VCI §3.5, §4.1.1 (tx_code object definition), §6.1 (Token Request), §6.3 (Token Error Response) | **MISSING** | Part of V1 handler. `HandleTokenEndpointRequest` must check `tx_code` form param against `tx_code_hash` in `PreAuthorizedCodeData`. Per OIDC4VCI §6.3: missing `tx_code` when expected (or unexpected `tx_code` when not expected) → `invalid_request`; wrong `tx_code` value → `invalid_grant`. No existing code path handles this. |
| V3 | **`authorization_details` parameter (RFC 9396)** — Parse `authorization_details` with `type=openid_credential` on Authorization and PAR endpoints, validate `credential_configuration_id`. Per RFC 9396 §5, validation failures MUST use the `invalid_authorization_details` error code (not `invalid_request`) | OIDC4VCI §5.1.1, RFC 9396 §2, §5 | **MISSING** | No RAR parsing anywhere. Need new `AuthorizeEndpointHandler` + `PushedAuthorizeEndpointHandler` in `fosite/handler/rar/`. New factory in `fosite/compose/compose_rar.go`. `Configurator` missing `RARConfigProvider`. PAR handler (`fosite/handler/par/`) does not parse `authorization_details`. Need new `ErrInvalidAuthorizationDetails` fosite error constant. |
| V4 | **Token Request `authorization_details` subset validation** — Token Request may contain `authorization_details` with `credential_configuration_id` values that must be a subset of previously authorized set. Violations MUST use the `invalid_authorization_details` error code per RFC 9396 §5 | OIDC4VCI §6.2, RFC 9396 §6, §7 | **MISSING** | No token-side RAR validation. Session data from consent must carry authorized `credential_configuration_id` set. Token endpoint must validate subset. Requires session propagation via `Session.Extra` (`oauth2/session.go`). Implementation: add `TokenEndpointHandler` interface to the RAR handler in `fosite/handler/rar/` (see `feature-rar.md` Token Request Subset Validation section). |
| V5 | **Token Response `authorization_details` with `credential_identifiers`** — Include `authorization_details` array in Token Response, each object MUST contain `credential_identifiers` (REQUIRED per spec when `authorization_details` was used in the request) | OIDC4VCI §6.2 (Successful Token Response) | **MISSING** | `PopulateTokenEndpointResponse` in no existing handler sets `authorization_details` on the response. Need response extras propagation. Consent Node sets `credential_identifiers` via `AcceptOAuth2ConsentRequest` → `Session.Extra["authorization_details"]` → token response. Per OIDC4VCI §6.2, `credential_identifiers` is REQUIRED (not optional) within each `authorization_details` object of type `openid_credential` in the Token Response when `authorization_details` was used in the Authorization or Token Request. `AcceptOAuth2ConsentRequest` (`flow/consent_types.go`) missing `AuthorizationDetails` field. |
| V6 | **`issuer_state` parameter on Authorization Endpoint** — Accept, store, and forward `issuer_state` through consent flow to Consent Node | OIDC4VCI §5.1.3 | **MISSING** | No code accepts `issuer_state` from authorize/PAR requests. Need to extract from request form, store alongside authorize request, include in `OAuth2ConsentRequest` (`flow/consent_types.go`) sent to Consent Node. Treat as opaque string. |
| V7 | **Scope-based credential request support** — `scope` values mapping to credential configurations treated as credential issuance requests | OIDC4VCI §5.1.2 | **PARTIAL** | Scope handling exists throughout Hydra (`ScopeStrategyProvider` in `fosite/config.go`, scope validation in authorize handlers). However, no credential-specific scope mapping exists. Unknown credential scopes are not silently ignored — standard scope validation may reject them. Need configuration for credential scope mappings. |
| V8 | **AS metadata: `pre-authorized_grant_anonymous_access_supported`** — Boolean in discovery metadata when Pre-Authorized Code grant is enabled | OIDC4VCI §12.3 | **MISSING** | `oidcConfiguration` struct (`oauth2/handler.go`) has no such field. `discoverOidcConfiguration()` does not populate it. Need new field + conditional population based on config flag. |

### HAIP Spec Requirements

| ID | Requirement | Source | Hydra Status | Gap Details |
|----|-------------|--------|--------------|-------------|
| H1 | **DPoP (RFC 9449) sender-constrained tokens** — Validate `DPoP` header JWT proof per full §4.3 checklist (single header, `typ=dpop+jwt`, asymmetric `alg`, no private key in `jwk`, signature, `htm`, `htu`, `iat`, `jti`, `nonce`), bind access token to public key (`jkt` confirmation), set `token_type=DPoP`, support nonce exchange, support `dpop_jkt` authorization code binding (§10), bind refresh tokens for public clients (§5) | HAIP §4 (FAPI2 Security Profile compliance — DPoP required for sender-constrained tokens), RFC 9449 §4.3, §5, §10, §10.1 | **MISSING** | No DPoP handler exists. Need new `TokenEndpointHandler` + `PushedAuthorizeEndpointHandler` in `fosite/handler/dpop/`. New factory in `fosite/compose/compose_dpop.go`. New storage `DPoPNonceStorage` for JTI replay detection. `Configurator` (`fosite/fosite.go`) missing `DPoPConfigProvider`. Config keys missing in `driver/config/`. Error codes `invalid_dpop_proof` and `use_dpop_nonce` not defined. Handler must also implement PAR-side `dpop_jkt` extraction (§10.1) and refresh token DPoP binding for public clients (§5). |
| H2 | **PAR enforcement (RFC 9126)** — Under HAIP, reject direct authorization requests for credential issuance flows that lack `request_uri` from PAR | HAIP §4 (FAPI2 Security Profile compliance — PAR required where applicable), RFC 9126 | **PARTIAL** | PAR exists in `fosite/handler/par/` with factory in `fosite/compose/compose_par.go`. `PushedAuthorizeRequestConfigProvider` (`fosite/config.go`) has `EnforcePushedAuthorize(ctx) bool`. However, enforcement is global, not per-flow. HAIP requires enforcement specifically for credential issuance flows. Need HAIP-specific config key (`KeyHAIPEnforced`) and conditional enforcement logic in authorize request handling. |
| H3 | **PKCE S256 enforcement** — Under HAIP, require `code_challenge_method=S256` for all authorization code flows; reject `plain` method | HAIP §4 (FAPI2 Security Profile compliance — PKCE S256 required) | **PARTIAL** | PKCE handler exists in `fosite/handler/pkce/`. `EnforcePKCEProvider` and `EnablePKCEPlainChallengeMethodProvider` exist in `fosite/config.go`. `code_challenge_methods_supported` in discovery includes `["plain", "S256"]` (`oauth2/handler.go`). Gap: no S256-only enforcement mode. Under HAIP, `plain` must be rejected. Need `KeyHAIPEnforced` config to override `EnablePKCEPlainChallengeMethod` to `false` and enforce PKCE. |
| H4 | **RFC 9207 `iss` in authorization response** — Include `iss` parameter (AS Issuer Identifier) in all authorization responses (success and error) | HAIP §4 (FAPI2 Security Profile compliance — `iss` in authorization response per RFC 9207), RFC 9207 | **MISSING** | No `iss` parameter added to authorization responses. Need modification to authorize response writer (`fosite/authorize_response_writer.go`) or a lightweight `AuthorizeEndpointHandler`. Value from `Configurator.GetIDTokenIssuer()`. Config key `KeyAuthResponseIssParameterEnabled` missing in `driver/config/`. Metadata field `authorization_response_iss_parameter_supported` missing from `oidcConfiguration` (`oauth2/handler.go`). |
| H5 | **Wallet Attestation client auth (`attest_jwt_client_auth`)** — Validate `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP` headers, verify `x5c` chain against trust anchors, match `sub` to `client_id` | HAIP §4.4.1 (Wallet Attestation), OIDC4VCI Appendix E (Wallet Attestations in JWT format) | **MISSING** | No wallet attestation code exists. Need new `ClientAuthenticationStrategy` in `fosite/handler/wallet_attestation/` or extension of `fosite/client_authentication.go`. `ClientAuthenticationStrategyProvider` exists in `fosite/config.go` but only supports `client_secret_post`, `client_secret_basic`, `private_key_jwt`, `none` (see `discoverOidcConfiguration()` in `oauth2/handler.go`). Config keys `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors` missing. |
| H6 | **ES256 algorithm support** — ES256 as minimum algorithm for DPoP proof validation, Wallet Attestation signature validation, and request object validation | HAIP §7 (Requirements for Digital Signatures — ES256 minimum) | **PARTIAL** | ES256 already in `request_object_signing_alg_values_supported: ["none", "RS256", "ES256"]` (`oauth2/handler.go` → `discoverOidcConfiguration()`). However, ES256 support for DPoP proof validation and Wallet Attestation signature validation does not exist because those handlers don't exist yet (see H1, H5). Once DPoP and Wallet Attestation handlers are built, ES256 must be a supported algorithm. |
| H7 | **Refresh token support for credential refresh** — Issue refresh tokens in credential issuance flows; preserve `authorization_details` on refresh | HAIP §4.4 (Token Endpoint — refresh tokens RECOMMENDED) | **SUPPORTED** | Existing refresh token flow works (`OAuth2RefreshTokenGrantFactory` in `fosite/compose/compose.go`, `fosite/handler/oauth2/`). Refresh token issuance is client-configuration-driven. Gap: `authorization_details` in `Session.Extra` must survive refresh token exchange — this depends on session serialization/deserialization which already preserves `Extra` map. Minimal work needed: verify round-trip preservation. |
| H8 | **`authorization_details` flow-through to Consent Node** — Parsed `authorization_details` included in consent challenge; Consent Node can return enriched `authorization_details` (with `credential_identifiers`) in accept response | OIDC4VCI §5.1.1, §6.2 (credential_identifiers REQUIRED in Token Response) | **MISSING** | `OAuth2ConsentRequest` (`flow/consent_types.go`) has no `AuthorizationDetails` field — only `RequestedScope`, `RequestedAudience`, `Context`, `OpenIDConnectContext`. `AcceptOAuth2ConsentRequest` (`flow/consent_types.go`) has no `AuthorizationDetails` field — only `GrantedScope`, `GrantedAudience`, `Session`, `Context`. Need new `AuthorizationDetails sqlxx.JSONRawMessage` field on both structs. Consent API handlers in `consent/` must propagate the field. Session merge logic must copy `authorization_details` into `Session.Extra`. |
| H9 | **Scope-based credential type identification at Authorization Endpoint** — Under HAIP, the `scope` parameter MUST be used to communicate Credential Type(s) to be issued; scope value MUST map to a specific Credential Type | HAIP §4.3 (Authorization Endpoint), §4.2 (Credential Offer — Issuer MUST include scope for authorization_code grant) | **PARTIAL** | Scope handling exists throughout Hydra. However, HAIP mandates that `scope` is the primary mechanism for credential type identification at the authorization endpoint (not `authorization_details`). The Credential Offer's `authorization_code` grant MUST include a scope value, and the Wallet MUST use it. Need configuration for credential scope mappings and validation that scope values map to known credential configurations. Overlaps with V7 but is a distinct HAIP mandate. |
| H10 | **Wallet authentication at PAR endpoint** — Under HAIP, Wallets MUST authenticate at the PAR endpoint using the same client authentication rules as the Token Endpoint | HAIP §4.3 (Authorization Endpoint — PAR client auth) | **SUPPORTED** | `Fosite.AuthenticateClient()` is called during PAR request processing. When Wallet Attestation (H5) is implemented, the same `ClientAuthenticationStrategy` pipeline applies to both PAR and Token endpoints. No PAR-specific changes needed beyond implementing H5. |

## Gap Summary by Code Path

### `fosite/fosite.go` — `Configurator` interface
- **Missing providers**: `PreAuthorizedCodeConfigProvider`, `DPoPConfigProvider`, `RARConfigProvider`, `HAIPConfigProvider`, `WalletAttestationConfigProvider`
- **Missing handler list provider**: `PushedAuthorizeRequestHandlersProvider` is defined in `fosite/config.go` but not embedded in `Configurator` (PAR handlers registered separately)
- Current provider count: ~40. Adding 5 new providers.

### `fosite/config.go` — Provider interfaces
- **Missing interfaces**: `PreAuthorizedCodeConfigProvider`, `DPoPConfigProvider`, `RARConfigProvider`, `HAIPConfigProvider`, `WalletAttestationConfigProvider`
- Each needs method signatures matching the design doc (e.g., `GetDPoPEnabled(ctx) bool`, `GetDPoPSigningAlgValuesSupported(ctx) []string`)

### `flow/consent_types.go` — Consent flow types
- **`OAuth2ConsentRequest`**: missing `AuthorizationDetails sqlxx.JSONRawMessage` field (for V3, V6, H8)
- **`AcceptOAuth2ConsentRequest`**: missing `AuthorizationDetails sqlxx.JSONRawMessage` field (for V5, H8)
- **`OAuth2ConsentRequest`**: missing `IssuerState string` field (for V6)
- These are upstream-touching files — merge conflicts expected on upstream rebases

### `oauth2/handler.go` — `oidcConfiguration` struct + `discoverOidcConfiguration()`
- **Missing struct fields**:
  - `PreAuthorizedGrantAnonymousAccessSupported bool` → `json:"pre-authorized_grant_anonymous_access_supported"` (V8)
  - `AuthorizationDetailsTypesSupported []string` → `json:"authorization_details_types_supported"` (V3)
  - `DPoPSigningAlgValuesSupported []string` → `json:"dpop_signing_alg_values_supported"` (H1)
  - `AuthorizationResponseIssParameterSupported bool` → `json:"authorization_response_iss_parameter_supported"` (H4)
- **Missing grant type in `GrantTypesSupported`**: `urn:ietf:params:oauth:grant-type:pre-authorized_code` (V1)
- **Missing auth method in `TokenEndpointAuthMethodsSupported`**: `attest_jwt_client_auth` (H5)
- All new fields conditionally populated based on config flags
- This is an upstream-touching file — merge conflicts expected

### `fosite/compose/compose.go` — `ComposeAllEnabled()`
- **Missing factories**: `PreAuthorizedCodeFactory`, `DPoPFactory`, `RARFactory`
- New factory files: `compose_preauth.go`, `compose_dpop.go`, `compose_rar.go`
- `ComposeAllEnabled()` must include new factories (or a separate `ComposeOIDC4VCIEnabled()` function)

### `driver/config/` — Configuration keys
- **Missing config keys** (in `provider.go` or new file):
  - `KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`
  - `KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`
  - `KeyRAREnabled`, `KeyRARTypesSupported`
  - `KeyHAIPEnforced`
  - `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`
  - `KeyAuthResponseIssParameterEnabled`
- Provider methods on `DefaultProvider` for each key

### New handler directories (do not exist yet)
- `fosite/handler/preauth/` — Pre-Authorized Code `TokenEndpointHandler` (V1, V2)
- `fosite/handler/dpop/` — DPoP `TokenEndpointHandler` (H1)
- `fosite/handler/rar/` — RAR `AuthorizeEndpointHandler` + `PushedAuthorizeEndpointHandler` (V3, V4)
- `fosite/handler/wallet_attestation/` — Wallet Attestation `ClientAuthenticationStrategy` (H5)

### New compose factories (do not exist yet)
- `fosite/compose/compose_preauth.go` → `PreAuthorizedCodeFactory`
- `fosite/compose/compose_dpop.go` → `DPoPFactory`
- `fosite/compose/compose_rar.go` → `RARFactory`

### New storage interfaces (do not exist yet)
- `PreAuthorizedCodeStorage` — `GetPreAuthorizedCodeSession`, `InvalidatePreAuthorizedCode`
- `DPoPNonceStorage` — `IsJTIUsed`, `MarkJTIUsed`, `CreateDPoPNonce`, `ValidateDPoPNonce`
- `RARStorage` — store/retrieve `authorization_details` alongside authorize requests

### New database tables (do not exist yet)
- `hydra_oauth2_preauth_code` — Pre-Authorized Code grant data
- `hydra_oauth2_dpop_jti` — DPoP JTI replay cache

## Implementation Priority

1. **RAR + Consent flow-through** (V3, V5, H8) — foundational; all other features depend on `authorization_details` propagation
2. **DPoP** (H1) — cross-cutting; required by HAIP for all token responses
3. **Pre-Authorized Code** (V1, V2) — new grant type; depends on RAR for `authorization_details` in response
4. **PAR enforcement + PKCE S256** (H2, H3) — config-driven enforcement on existing handlers
5. **RFC 9207 `iss`** (H4) — lightweight; small change to authorize response writer
6. **Wallet Attestation** (H5) — new client auth method; independent of other features
7. **Metadata extensions** (V8, H6) — additive fields on `oidcConfiguration`; depends on all features being implemented
