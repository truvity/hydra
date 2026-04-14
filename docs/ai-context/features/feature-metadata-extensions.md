# Feature: AS Discovery Metadata Extensions for OIDC4VCI

## Purpose

Steering document for extending the AS discovery metadata (`/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`) to advertise OIDC4VCI and HAIP capabilities. All changes are in a single file — `oauth2/handler.go` — modifying the `oidcConfiguration` struct and the `discoverOidcConfiguration()` function. All new fields are conditionally populated based on feature-specific config flags.

## Location

- Struct + handler: `oauth2/handler.go` → `oidcConfiguration` struct + `discoverOidcConfiguration()` function
- Config providers: `driver/config/` → various feature-specific providers (each feature owns its config)
- No new files created — this is purely additive modifications to an existing file

## Existing Struct Fields (Reference)

The current `oidcConfiguration` struct in `oauth2/handler.go` includes these fields relevant to the extensions:

```go
type oidcConfiguration struct {
    Issuer                                string   `json:"issuer"`
    AuthURL                               string   `json:"authorization_endpoint"`
    TokenURL                              string   `json:"token_endpoint"`
    JWKsURI                               string   `json:"jwks_uri"`
    GrantTypesSupported                   []string `json:"grant_types_supported"`
    TokenEndpointAuthMethodsSupported     []string `json:"token_endpoint_auth_methods_supported"`
    CodeChallengeMethodsSupported         []string `json:"code_challenge_methods_supported"`
    RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported"`
    // ... other standard OIDC fields ...

    // Experimental VC fields (to be removed):
    CredentialsEndpointDraft00    string                    `json:"credentials_endpoint_draft_00"`
    CredentialsSupportedDraft00   []CredentialSupportedDraft00 `json:"credentials_supported_draft_00"`
}
```

Current hardcoded values in `discoverOidcConfiguration()`:
- `GrantTypesSupported`: `["authorization_code", "implicit", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]`
- `TokenEndpointAuthMethodsSupported`: `["client_secret_post", "client_secret_basic", "private_key_jwt", "none"]`
- `CodeChallengeMethodsSupported`: `["plain", "S256"]`
- `RequestObjectSigningAlgValuesSupported`: `["none", "RS256", "ES256"]`

## New Struct Fields

Add the following fields to `oidcConfiguration`:

```go
// PAR: pushed authorization request endpoint URL (RFC 9126 §5)
// Populated unconditionally when PAR is available (existing feature)
PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`

// PAR: whether the AS accepts authorization requests only via PAR (RFC 9126 §5)
// Populated when PAR enforcement is enabled (HAIP or standalone config)
RequirePushedAuthorizationRequests bool `json:"require_pushed_authorization_requests,omitempty"`

// Pre-Authorized Code grant: anonymous access support
// Populated when Pre-Authorized Code grant is enabled
PreAuthorizedGrantAnonymousAccessSupported bool `json:"pre-authorized_grant_anonymous_access_supported,omitempty"`

// RAR: supported authorization_details types
// Populated when RAR is enabled, value from GetRARTypesSupported(ctx)
AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

// DPoP: supported signing algorithms for DPoP proofs
// Populated when DPoP is enabled, value from GetDPoPSigningAlgValuesSupported(ctx)
DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

// RFC 9207: authorization response includes iss parameter
// Populated when RFC 9207 is enabled
AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`
```

## Modifications to Existing Fields

### `GrantTypesSupported` — Add Pre-Authorized Code grant type

When Pre-Authorized Code grant is enabled (`GetPreAuthorizedCodeEnabled(ctx) == true`), append `urn:ietf:params:oauth:grant-type:pre-authorized_code` to the grant types list:

```go
grantTypes := []string{
    "authorization_code", "implicit", "client_credentials",
    "refresh_token", "urn:ietf:params:oauth:grant-type:device_code",
}
if preAuthProvider.GetPreAuthorizedCodeEnabled(ctx) {
    grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:pre-authorized_code")
}
```

### `TokenEndpointAuthMethodsSupported` — Add Wallet Attestation

When Wallet Attestation is enabled (`GetWalletAttestationEnabled(ctx) == true`), append `attest_jwt_client_auth` to the auth methods list:

```go
authMethods := []string{
    "client_secret_post", "client_secret_basic", "private_key_jwt", "none",
}
if walletAttProvider.GetWalletAttestationEnabled(ctx) {
    authMethods = append(authMethods, "attest_jwt_client_auth")
}
```

### `CodeChallengeMethodsSupported` — HAIP S256-only enforcement

When HAIP is enforced (`GetHAIPEnforced(ctx) == true`), restrict to `["S256"]` only — remove `"plain"`:

```go
codeChallengeMethodsSupported := []string{"plain", "S256"}
if haipProvider.GetHAIPEnforced(ctx) {
    codeChallengeMethodsSupported = []string{"S256"}
}
```

This aligns the advertised metadata with the runtime enforcement behavior (see [feature-par.md](feature-par.md) for HAIP PKCE enforcement details).

## Fields to Keep (Existing Upstream)

### `CredentialsEndpointDraft00` and `CredentialsSupportedDraft00`

These experimental fields exist in the current upstream Hydra codebase. While they conceptually belong to the **Credential Issuer metadata** (`/.well-known/openid-credential-issuer`) rather than the AS metadata (`/.well-known/openid-configuration`), they are an existing upstream feature and removing them would be a breaking change for downstream consumers.

**Decision: Keep these fields as-is.** Do not remove them from the `oidcConfiguration` struct or `discoverOidcConfiguration()`. The OIDC4VCI extensions are additive — they coexist with the existing experimental fields. If upstream removes them in a future release, the fork will pick up that change during a rebase.

## Conditional Population Logic

All new fields are populated conditionally based on config flags. The `discoverOidcConfiguration()` function should check each feature's enabled flag before populating:

```go
func (h *Handler) discoverOidcConfiguration(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    // ... existing key fetch ...

    // Build dynamic lists
    grantTypes := []string{"authorization_code", "implicit", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"}
    authMethods := []string{"client_secret_post", "client_secret_basic", "private_key_jwt", "none"}
    codeChallengeMethodsSupported := []string{"plain", "S256"}

    // PAR metadata (RFC 9126 §5)
    // pushed_authorization_request_endpoint is always populated when PAR is available
    parEndpoint := h.c.GetPushedAuthorizeRequestEndpoint(ctx) // e.g., issuerURL + "/oauth2/par"
    var requirePAR bool
    if parCfg, ok := h.c.(PushedAuthorizeRequestConfigProvider); ok {
        requirePAR = parCfg.EnforcePushedAuthorize(ctx)
    }

    // Pre-Authorized Code grant
    var preAuthAnonymousAccess bool
    if preAuthCfg, ok := h.c.(PreAuthorizedCodeConfigProvider); ok && preAuthCfg.GetPreAuthorizedCodeEnabled(ctx) {
        grantTypes = append(grantTypes, "urn:ietf:params:oauth:grant-type:pre-authorized_code")
        preAuthAnonymousAccess = preAuthCfg.GetPreAuthorizedCodeAnonymousAccess(ctx)
    }

    // Wallet Attestation
    if waCfg, ok := h.c.(WalletAttestationConfigProvider); ok && waCfg.GetWalletAttestationEnabled(ctx) {
        authMethods = append(authMethods, "attest_jwt_client_auth")
    }

    // HAIP enforcement — restrict code challenge methods
    if haipCfg, ok := h.c.(HAIPConfigProvider); ok && haipCfg.GetHAIPEnforced(ctx) {
        codeChallengeMethodsSupported = []string{"S256"}
    }

    // RAR
    var authDetailsTypes []string
    if rarCfg, ok := h.c.(RARConfigProvider); ok && rarCfg.GetRAREnabled(ctx) {
        authDetailsTypes = rarCfg.GetRARTypesSupported(ctx) // e.g., ["openid_credential"]
    }

    // DPoP
    var dpopAlgs []string
    if dpopCfg, ok := h.c.(DPoPConfigProvider); ok && dpopCfg.GetDPoPEnabled(ctx) {
        dpopAlgs = dpopCfg.GetDPoPSigningAlgValuesSupported(ctx) // e.g., ["ES256"]
    }

    // RFC 9207
    var issParamSupported bool
    if issCfg, ok := h.c.(AuthResponseIssConfigProvider); ok {
        issParamSupported = issCfg.GetAuthResponseIssParameterEnabled(ctx)
    }

    h.r.Writer().Write(w, r, &oidcConfiguration{
        // ... existing fields ...
        GrantTypesSupported:                        grantTypes,
        TokenEndpointAuthMethodsSupported:          authMethods,
        CodeChallengeMethodsSupported:              codeChallengeMethodsSupported,
        // ... PAR fields (RFC 9126 §5) ...
        PushedAuthorizationRequestEndpoint:         parEndpoint,
        RequirePushedAuthorizationRequests:         requirePAR,
        // ... new OIDC4VCI fields ...
        PreAuthorizedGrantAnonymousAccessSupported: preAuthAnonymousAccess,
        AuthorizationDetailsTypesSupported:         authDetailsTypes,
        DPoPSigningAlgValuesSupported:              dpopAlgs,
        AuthorizationResponseIssParameterSupported: issParamSupported,
    })
}
```

### `omitempty` Behavior

All new fields use `omitempty` JSON tags:
- `bool` fields with `omitempty`: omitted when `false` — this means disabled features produce no metadata field at all (clean output)
- `[]string` fields with `omitempty`: omitted when `nil` — disabled features produce no metadata field
- This is the correct behavior per RFC 8414: optional metadata parameters should be absent when not applicable

## Config Provider Interfaces

Each feature owns its config provider. The metadata extension code type-asserts `h.c` (the `Configurator`) to each provider interface:

| Provider Interface | Method Used | Feature |
|---|---|---|
| `PreAuthorizedCodeConfigProvider` | `GetPreAuthorizedCodeEnabled(ctx)`, `GetPreAuthorizedCodeAnonymousAccess(ctx)` | Pre-Authorized Code grant |
| `RARConfigProvider` | `GetRAREnabled(ctx)`, `GetRARTypesSupported(ctx)` | RAR |
| `DPoPConfigProvider` | `GetDPoPEnabled(ctx)`, `GetDPoPSigningAlgValuesSupported(ctx)` | DPoP |
| `AuthResponseIssConfigProvider` | `GetAuthResponseIssParameterEnabled(ctx)` | RFC 9207 |
| `WalletAttestationConfigProvider` | `GetWalletAttestationEnabled(ctx)` | Wallet Attestation |
| `HAIPConfigProvider` | `GetHAIPEnforced(ctx)` | HAIP enforcement |

See each feature's steering document for the full config provider definition.

## RFC 8414 Conformance

All metadata parameters conform to RFC 8414 (OAuth 2.0 Authorization Server Metadata):

| Parameter | RFC 8414 Section | Type | Notes |
|---|---|---|---|
| `pushed_authorization_request_endpoint` | RFC 9126 §5 | `string` | OPTIONAL. URL of the PAR endpoint. Already exists as an endpoint in Hydra but not yet advertised in discovery metadata. |
| `require_pushed_authorization_requests` | RFC 9126 §5 | `bool` | OPTIONAL. Default: `false`. Set to `true` when PAR enforcement is enabled (HAIP or standalone). |
| `grant_types_supported` | §2 | `[]string` | OPTIONAL. Default: `["authorization_code", "implicit"]`. We extend with new grant types. |
| `token_endpoint_auth_methods_supported` | §2 | `[]string` | OPTIONAL. Default: `["client_secret_basic"]`. We extend with `attest_jwt_client_auth`. |
| `code_challenge_methods_supported` | §2 | `[]string` | OPTIONAL. Per RFC 7636. We restrict under HAIP. |
| `dpop_signing_alg_values_supported` | RFC 9449 §5 | `[]string` | OPTIONAL. Defined by RFC 9449, not RFC 8414 directly. |
| `authorization_details_types_supported` | RFC 9396 §9 | `[]string` | OPTIONAL. Defined by RFC 9396. |
| `pre-authorized_grant_anonymous_access_supported` | OIDC4VCI §12.3 | `bool` | OPTIONAL. Defined by OIDC4VCI spec. |
| `authorization_response_iss_parameter_supported` | RFC 9207 §3 | `bool` | OPTIONAL. Defined by RFC 9207. |

## Merge Conflict Risk

**High**. `oauth2/handler.go` is an upstream file that is modified by multiple features:
- New struct fields on `oidcConfiguration`
- Modified `discoverOidcConfiguration()` function body
- Existing experimental VC fields are kept as-is (no removal)

Mitigation strategies (see [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md)):
- Group all OIDC4VCI metadata changes in a clearly delimited section of the struct (e.g., after the existing experimental VC fields)
- Use comments to mark the custom section: `// --- OIDC4VCI Extensions (custom fork) ---`
- Keep the conditional population logic in a separate block within `discoverOidcConfiguration()` for easy conflict resolution

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — `oidcConfiguration` struct, `discoverOidcConfiguration()` handler, `Configurator` interface
- [02-oidc4vci-as-requirements.md](../02-oidc4vci-as-requirements.md) — Gap V8 (Pre-Auth metadata), H1 (DPoP metadata), H3 (PKCE S256), H4 (RFC 9207 metadata), H5 (Wallet Attestation metadata)
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Merge conflict handling for `oauth2/handler.go`
- [feature-dpop.md](feature-dpop.md) — `dpop_signing_alg_values_supported` field, `DPoPConfigProvider`
- [feature-pre-authorized-code.md](feature-pre-authorized-code.md) — `pre-authorized_grant_anonymous_access_supported` field, Pre-Authorized Code grant type in `grant_types_supported`
- [feature-rar.md](feature-rar.md) — `authorization_details_types_supported` field, `RARConfigProvider`
- [feature-wallet-attestation.md](feature-wallet-attestation.md) — `attest_jwt_client_auth` in `token_endpoint_auth_methods_supported`
- [feature-rfc9207-iss.md](feature-rfc9207-iss.md) — `authorization_response_iss_parameter_supported` field, `AuthResponseIssConfigProvider`
- [feature-par.md](feature-par.md) — HAIP enforcement context for `code_challenge_methods_supported` restriction
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — §6 (Discovery Metadata Extensions)
- [Requirements doc](../../.kiro/specs/oidc4vci-as-capabilities/requirements.md) — Requirements 10.1–10.6 (AS Metadata Extensions), 4.7 (DPoP metadata), 8.3 (RFC 9207 metadata), 9.5 (Wallet Attestation metadata), 11.3 (PKCE S256 metadata)
