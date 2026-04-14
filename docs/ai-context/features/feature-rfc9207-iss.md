# Feature: RFC 9207 — Authorization Response Issuer Identifier

## Purpose

Steering document for implementing RFC 9207 support in the Hydra AS fork. This is one of the simplest features — it adds an `iss` parameter to all authorization responses (success and error) so that Wallets can verify the response originated from the expected AS and prevent mix-up attacks. No new handler package is needed; this is an inline modification to existing response-writing code paths.

## Location

This feature touches two existing files in the Fosite core, plus config and metadata:

- Success responses: `fosite/authorize_write.go` → `Fosite.WriteAuthorizeResponse()`
- Error responses: `fosite/authorize_error.go` → `Fosite.WriteAuthorizeError()`
- Config keys: `driver/config/` → `KeyAuthResponseIssParameterEnabled`
- Metadata: `oauth2/handler.go` → `oidcConfiguration` struct + `discoverOidcConfiguration()`

No new handler directory or compose factory is required.

## Design

### Approach: Inline Modification (Preferred)

The `iss` parameter must appear in **every** authorization response — success and error — regardless of response mode (query, fragment, form_post). The cleanest approach is to inject `iss` directly into the two response-writing functions rather than creating a separate `AuthorizeEndpointHandler`.

**Why not a handler?** An `AuthorizeEndpointHandler.HandleAuthorizeEndpointRequest()` could add `iss` to the `AuthorizeResponder.GetParameters()`, but this only covers success responses. Error responses are written by `WriteAuthorizeError()` which does not go through the handler pipeline — it constructs its own `url.Values` from the RFC 6749 error. Covering both paths requires touching both functions anyway, making a handler an unnecessary abstraction.

### Alternative: Lightweight `AuthorizeEndpointHandler`

If the inline approach creates merge conflicts with upstream, a small `AuthorizeEndpointHandler` can be registered to add `iss` to success responses via `resp.AddParameter("iss", issuer)`. Error responses would still need an inline modification in `WriteAuthorizeError()`. This hybrid approach is acceptable but adds a handler for a single parameter.

## Implementation Details

### Success Responses — `fosite/authorize_write.go`

`Fosite.WriteAuthorizeResponse(ctx, rw, ar, resp)`:

- Before the `switch` on response mode, if `KeyAuthResponseIssParameterEnabled` is true:
  - Get the AS Issuer Identifier via `f.Config.GetIDTokenIssuer(ctx)` (already exists on `Configurator` as `IDTokenIssuerProvider`)
  - Add `iss` to the response parameters: `resp.AddParameter("iss", issuer)`
- This ensures `iss` appears in query parameters, fragment parameters, and form_post fields — all three response modes pick up parameters from `resp.GetParameters()`

```go
// Inject RFC 9207 iss parameter
if issProvider, ok := f.Config.(AuthResponseIssConfigProvider); ok && issProvider.GetAuthResponseIssParameterEnabled(ctx) {
    resp.AddParameter("iss", f.Config.GetIDTokenIssuer(ctx))
}
```

### Error Responses — `fosite/authorize_error.go`

`Fosite.WriteAuthorizeError(ctx, rw, ar, err)`:

- After constructing the `errors` (`url.Values`) from `rfcerr.ToValues()` and setting `state`, if `KeyAuthResponseIssParameterEnabled` is true:
  - Add `iss` to the error values: `errors.Set("iss", f.Config.GetIDTokenIssuer(ctx))`
- This covers query-mode errors, fragment-mode errors, and form_post errors
- **Important**: Only add `iss` when the error is redirected to the client. When `ar.IsRedirectURIValid()` is false, the error is rendered as JSON directly to the user-agent — RFC 9207 does not apply to non-redirect error responses

```go
// Inject RFC 9207 iss parameter (only for redirect errors)
if issProvider, ok := f.Config.(AuthResponseIssConfigProvider); ok && issProvider.GetAuthResponseIssParameterEnabled(ctx) {
    errors.Set("iss", f.Config.GetIDTokenIssuer(ctx))
}
```

### Response Mode Handler Extension

The `ResponseModeHandler` interface (`fosite/response_handler.go`) has its own `WriteAuthorizeResponse()` and `WriteAuthorizeError()` methods for custom response modes. If custom response mode handlers are used, they also need `iss` injection. The preferred approach is to inject `iss` into `resp.GetParameters()` before delegating to the response mode handler, so custom handlers automatically pick it up.

### Value Source

The `iss` value is the AS Issuer Identifier — the same value used in ID Tokens and discovery metadata. It is already available via:

- `Configurator.GetIDTokenIssuer(ctx)` — from `IDTokenIssuerProvider` interface, already part of `Configurator`
- `config.DefaultProvider.IssuerURL(ctx)` — the Hydra config provider method

Both return the same value. Using `GetIDTokenIssuer(ctx)` is preferred since it's already on the `Configurator` interface and doesn't require a type assertion to `DefaultProvider`.

## Config Provider

```go
type AuthResponseIssConfigProvider interface {
    GetAuthResponseIssParameterEnabled(ctx context.Context) bool
}
```

Config key in `driver/config/`:
- `KeyAuthResponseIssParameterEnabled` → `bool` (default: `false`)

### HAIP Auto-Enable

When `KeyHAIPEnforced` is true, the `iss` parameter should be automatically enabled. Implementation options:

1. **Config-level override**: `GetAuthResponseIssParameterEnabled(ctx)` returns `true` if either `KeyAuthResponseIssParameterEnabled` is explicitly true OR `KeyHAIPEnforced` is true
2. **Separate check**: The HAIP config provider sets `KeyAuthResponseIssParameterEnabled` to true as a side effect of HAIP enforcement

Option 1 is simpler and avoids config mutation:

```go
func (p *DefaultProvider) GetAuthResponseIssParameterEnabled(ctx context.Context) bool {
    return p.getProvider(ctx).BoolF(KeyAuthResponseIssParameterEnabled, false) ||
           p.getProvider(ctx).BoolF(KeyHAIPEnforced, false)
}
```

## Error Codes

No new error codes. This feature only adds a parameter to existing responses — it does not introduce new validation or rejection logic.

## Discovery Metadata

In `oauth2/handler.go` → `oidcConfiguration` struct, add:

```go
AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`
```

Populated in `discoverOidcConfiguration()` when `GetAuthResponseIssParameterEnabled(ctx)` returns true:

```go
AuthorizationResponseIssParameterSupported: h.c.GetAuthResponseIssParameterEnabled(ctx),
```

See [feature-metadata-extensions.md](feature-metadata-extensions.md) for the full metadata extensions design.

## Affected Code Paths Summary

| File | Function | Change |
|------|----------|--------|
| `fosite/authorize_write.go` | `WriteAuthorizeResponse()` | Add `iss` to `resp.GetParameters()` before response mode switch |
| `fosite/authorize_error.go` | `WriteAuthorizeError()` | Add `iss` to error `url.Values` for redirect errors |
| `driver/config/` | New key + provider method | `KeyAuthResponseIssParameterEnabled` + `GetAuthResponseIssParameterEnabled(ctx)` |
| `oauth2/handler.go` | `oidcConfiguration` struct | New `AuthorizationResponseIssParameterSupported` field |
| `oauth2/handler.go` | `discoverOidcConfiguration()` | Populate new field conditionally |

## Merge Conflict Risk

- `fosite/authorize_write.go` — **Medium**. Adding a few lines before the response mode switch. Upstream changes to this function are infrequent but possible.
- `fosite/authorize_error.go` — **Medium**. Adding a few lines in the redirect error path. Same risk profile.
- `oauth2/handler.go` — **High** (shared with all metadata extensions). See [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md).

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — `AuthorizeEndpointHandler` interface, `Configurator.GetIDTokenIssuer()`, authorize response lifecycle
- [02-oidc4vci-as-requirements.md](../02-oidc4vci-as-requirements.md) — Gap H4: RFC 9207 `iss` in authorization response
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Merge conflict handling for `fosite/authorize_write.go` and `fosite/authorize_error.go`
- [feature-metadata-extensions.md](feature-metadata-extensions.md) — `authorization_response_iss_parameter_supported` metadata field
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Property 19 (Authorization Response iss Parameter)
- [Requirements doc](../../.kiro/specs/oidc4vci-as-capabilities/requirements.md) — Requirements 8.1–8.3 (RFC 9207 Authorization Response Issuer Identifier)
