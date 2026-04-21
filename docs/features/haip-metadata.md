# Feature: HAIP Enforcement, RFC 9207, and Discovery Metadata Extensions

## Overview

This is the capstone feature for the OIDC4VCI Hydra AS fork. It wires the `KeyHAIPEnforced` config flag to override individual feature settings (PAR, PKCE S256, DPoP, RFC 9207 `iss`), implements RFC 9207 authorization response issuer identifier injection, and extends the discovery metadata endpoint to advertise all OIDC4VCI capabilities.

No new Fosite handlers are created. This feature modifies existing `DefaultProvider` config methods, the two authorize response-writing functions in Fosite core (`WriteAuthorizeResponse`, `WriteAuthorizeError`), and the `discoverOidcConfiguration()` function in `oauth2/handler.go`.

All foundational infrastructure — RAR (Spec 1), DPoP (Spec 2), Pre-Auth (Spec 3), and Wallet Attestation (Spec 4) — is already implemented. This spec connects them under a single enforcement flag and publishes their capabilities via discovery metadata.

## HAIP Enforcement

When `haip.enforced` is set to `true`, the following features are automatically enabled via OR-override on `DefaultProvider` config methods. Each method returns `true` if either its standalone config key OR `KeyHAIPEnforced` is true.

### Auto-Enabled by HAIP

| Feature | Config Method | Standalone Key | HAIP Behavior |
|---------|--------------|----------------|---------------|
| PAR required | `EnforcePushedAuthorize(ctx)` | `oauth2.par.enforced` | Forced `true` |
| PKCE enforced | `GetEnforcePKCE(ctx)` | `oauth2.pkce.enforced` | Forced `true` |
| PKCE plain method | `GetEnablePKCEPlainChallengeMethod(ctx)` | `oauth2.pkce.plain_challenge_method` | Forced `false` (inverted) |
| DPoP enabled | `GetDPoPEnabled(ctx)` | `dpop.enabled` | Forced `true` |
| DPoP ES256 | `GetDPoPSigningAlgValuesSupported(ctx)` | `dpop.signing_alg_values_supported` | Ensures `ES256` is included |
| RFC 9207 iss | `GetAuthResponseIssParameterEnabled(ctx)` | `rfc9207.iss_parameter_enabled` | Forced `true` |

The override pattern for most methods is:

```go
func (p *DefaultProvider) GetDPoPEnabled(ctx context.Context) bool {
    return p.getProvider(ctx).BoolF(KeyDPoPEnabled, false) ||
           p.getProvider(ctx).BoolF(KeyHAIPEnforced, false)
}
```

For `GetEnablePKCEPlainChallengeMethod`, the logic is inverted — HAIP forces `false`:

```go
func (p *DefaultProvider) GetEnablePKCEPlainChallengeMethod(ctx context.Context) bool {
    if p.getProvider(ctx).BoolF(KeyHAIPEnforced, false) {
        return false
    }
    return p.getProvider(ctx).BoolF(KeyPKCEPlainChallengeMethod, false)
}
```

### NOT Auto-Enabled by HAIP

These features remain independently configurable regardless of HAIP enforcement:

| Feature | Config Method | Standalone Key | Reason |
|---------|--------------|----------------|--------|
| Pre-Authorized Code | `GetPreAuthorizedCodeEnabled(ctx)` | `preauth.enabled` | Not mandated by HAIP |
| Wallet Attestation | `GetWalletAttestationEnabled(ctx)` | `wallet_attestation.enabled` | Not mandated by HAIP |

These methods read only their standalone config key and do not check `KeyHAIPEnforced`.

### Existing Enforcement Paths

The HAIP override works because existing Fosite handlers already read these config values:

- **PAR enforcement** — `fosite/authorize_request_handler.go` calls `EnforcePushedAuthorize(ctx)` and rejects direct authorization requests with `invalid_request` when true.
- **PKCE enforcement** — `fosite/handler/pkce/` calls `GetEnforcePKCE(ctx)` and `GetEnablePKCEPlainChallengeMethod(ctx)`.
- **DPoP** — `fosite/handler/dpop/` calls `GetDPoPEnabled(ctx)` and `GetDPoPSigningAlgValuesSupported(ctx)`.

No handler modifications are needed — the config override is sufficient.


## RFC 9207 Authorization Response Issuer Identifier

RFC 9207 adds an `iss` parameter to authorization responses to prevent mix-up attacks. The value is the AS Issuer Identifier from `GetIDTokenIssuer(ctx)` (configured via `urls.self.issuer`).

### Success Responses

When `GetAuthResponseIssParameterEnabled(ctx)` returns `true`, `WriteAuthorizeResponse()` in `fosite/authorize_write.go` injects the `iss` parameter into the response parameters before the response mode switch:

```go
if f.Config.GetAuthResponseIssParameterEnabled(ctx) {
    resp.AddParameter("iss", f.Config.GetIDTokenIssuer(ctx))
}
```

This single injection point covers all three response modes (query, fragment, form_post) because they all read from `resp.GetParameters()`.

When disabled, no `iss` parameter is added.

### Error Responses

When `GetAuthResponseIssParameterEnabled(ctx)` returns `true` and the error is a redirect error (valid redirect URI), `WriteAuthorizeError()` in `fosite/authorize_error.go` injects `iss` into the error URL parameters:

```go
errors.Set("iss", f.Config.GetIDTokenIssuer(ctx))
```

This is placed inside the redirect error path — after the `!ar.IsRedirectURIValid()` early return that renders JSON directly. Non-redirect errors (invalid redirect URI, missing client) are rendered as JSON to the user-agent and do NOT get `iss` per RFC 9207.

### Summary

| Response Type | `iss` Added? |
|---------------|-------------|
| Success — query redirect | Yes |
| Success — fragment redirect | Yes |
| Success — form_post | Yes |
| Error — redirect (valid redirect URI) | Yes |
| Error — non-redirect (JSON to user-agent) | No |

## Discovery Metadata Extensions

The `discoverOidcConfiguration()` function in `oauth2/handler.go` is extended to advertise all OIDC4VCI capabilities. New fields are added to the `oidcConfiguration` struct in a `// --- OIDC4VCI Extensions (custom fork) ---` section.

All new fields use `omitempty` JSON tags per RFC 8414: optional metadata parameters are absent when not applicable. Boolean fields with `omitempty` are omitted when `false`; slice fields are omitted when `nil`.

### New Metadata Fields

| Field | Type | Condition | Defining RFC |
|-------|------|-----------|-------------|
| `pushed_authorization_request_endpoint` | `string` | Always present (PAR endpoint is always available) | RFC 9126 §5 |
| `require_pushed_authorization_requests` | `bool` | Present (true) when `EnforcePushedAuthorize(ctx)` returns true | RFC 9126 §5 |
| `dpop_signing_alg_values_supported` | `[]string` | Present when `GetDPoPEnabled(ctx)` returns true | RFC 9449 §5 |
| `authorization_response_iss_parameter_supported` | `bool` | Present (true) when `GetAuthResponseIssParameterEnabled(ctx)` returns true | RFC 9207 §3 |
| `pre-authorized_grant_anonymous_access_supported` | `bool` | Present when `GetPreAuthorizedCodeEnabled(ctx)` returns true | OIDC4VCI §12.3 |
| `authorization_details_types_supported` | `[]string` | Present when `GetRAREnabled(ctx)` returns true | RFC 9396 §9 |

### Modified Existing Fields

Three existing arrays become dynamic based on feature flags:

| Field | Modification | Condition |
|-------|-------------|-----------|
| `grant_types_supported` | Appends `urn:ietf:params:oauth:grant-type:pre-authorized_code` | When `GetPreAuthorizedCodeEnabled(ctx)` is true |
| `token_endpoint_auth_methods_supported` | Appends `attest_jwt_client_auth` | When `GetWalletAttestationEnabled(ctx)` is true |
| `code_challenge_methods_supported` | Restricted to `["S256"]` | When `GetHAIPEnforced(ctx)` is true; otherwise `["plain", "S256"]` |

### Conditional Population Logic

```go
// PAR endpoint (always populated)
parEndpoint := urlx.AppendPaths(issuerURL, PushedAuthorizePath).String()
requirePAR := h.c.EnforcePushedAuthorize(ctx)

// DPoP
var dpopAlgs []string
if h.c.GetDPoPEnabled(ctx) {
    dpopAlgs = h.c.GetDPoPSigningAlgValuesSupported(ctx)
}

// RFC 9207
issParamSupported := h.c.GetAuthResponseIssParameterEnabled(ctx)

// Pre-Auth anonymous access
var preAuthAnonymousAccess bool
if h.c.GetPreAuthorizedCodeEnabled(ctx) {
    preAuthAnonymousAccess = h.c.GetPreAuthorizedCodeAnonymousAccess(ctx)
}

// HAIP — restrict code challenge methods
if h.c.GetHAIPEnforced(ctx) {
    codeChallengeMethodsSupported = []string{"S256"}
}
```

## Configuration

### Config Keys

| Key | Type | Default | HAIP Override | Description |
|-----|------|---------|---------------|-------------|
| `haip.enforced` | `bool` | `false` | N/A (source) | Master HAIP enforcement flag |
| `rfc9207.iss_parameter_enabled` | `bool` | `false` | → `true` | RFC 9207 `iss` in authorization responses |
| `oauth2.par.enforced` | `bool` | `false` | → `true` | Require PAR for all authorization requests |
| `oauth2.par.context_lifespan` | `duration` | `5m` | No override | Lifespan of PAR request contexts |
| `oauth2.pkce.enforced` | `bool` | `false` | → `true` | Require PKCE on all authorization code flows |
| `oauth2.pkce.plain_challenge_method` | `bool` | `false` | → `false` | Allow `plain` PKCE challenge method |
| `dpop.enabled` | `bool` | `false` | → `true` | Enable DPoP token binding |
| `dpop.signing_alg_values_supported` | `[]string` | `["ES256"]` | Ensures `ES256` | Supported DPoP proof signing algorithms |
| `preauth.enabled` | `bool` | `false` | No override | Pre-Authorized Code grant type |
| `preauth.anonymous_access` | `bool` | `false` | No override | Allow anonymous Pre-Auth access |
| `wallet_attestation.enabled` | `bool` | `false` | No override | Wallet Attestation client authentication |
| `rar.enabled` | `bool` | `false` | No override | Rich Authorization Requests |
| `rar.types_supported` | `[]string` | `["openid_credential"]` | No override | Supported `authorization_details` type values |

### Example Configuration

Minimal HAIP-enforced setup:

```yaml
haip:
  enforced: true
preauth:
  enabled: true
  anonymous_access: true
wallet_attestation:
  enabled: true
  trust_anchors:
    - |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
rar:
  enabled: true
```

With `haip.enforced: true`, PAR enforcement, PKCE S256, DPoP with ES256, and RFC 9207 `iss` are all automatically active. Pre-Auth, Wallet Attestation, and RAR must be enabled independently.

Standalone configuration (no HAIP):

```yaml
haip:
  enforced: false
oauth2:
  par:
    enforced: true
  pkce:
    enforced: true
    plain_challenge_method: false
dpop:
  enabled: true
  signing_alg_values_supported:
    - ES256
rfc9207:
  iss_parameter_enabled: true
```

## References

- [RFC 9126 — OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)
- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- Design doc: `.kiro/specs/oidc4vci-haip-metadata/design.md`
