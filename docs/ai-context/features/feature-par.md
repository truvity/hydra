# Feature: PAR Enforcement for HAIP Compliance

## Purpose

Steering document for enforcing Pushed Authorization Requests (PAR) under HAIP compliance in the Hydra AS fork. PAR is already implemented — this feature extends it with HAIP-specific enforcement rules, PKCE S256 enforcement, and Wallet Attestation client authentication at the PAR endpoint.

## Existing Implementation

### Handler

- Location: `fosite/handler/par/flow_pushed_authorize.go`
- Struct: `PushedAuthorizeHandler` with `Storage` (`fosite.PARStorageProvider`) and `Config` (`fosite.Configurator`)
- Implements: `fosite.PushedAuthorizeEndpointHandler`
- `HandlePushedAuthorizeEndpointRequest()`: validates response types, redirect URI security, scopes, audience; generates `request_uri` via HMAC random bytes; stores PAR session; sets `request_uri` and `expires_in` on response

### Factory

- Location: `fosite/compose/compose_par.go`
- `PushedAuthorizeHandlerFactory` creates `par.PushedAuthorizeHandler` with storage and config
- Registered in `ComposeAllEnabled()` in `fosite/compose/compose.go`

### Config Provider

- Location: `fosite/config.go` → `PushedAuthorizeRequestConfigProvider`
- Methods:
  - `GetPushedAuthorizeRequestURIPrefix(ctx) string` — default `urn:ietf:params:oauth:request_uri:`
  - `GetPushedAuthorizeContextLifespan(ctx) time.Duration` — TTL for PAR sessions
  - `EnforcePushedAuthorize(ctx) bool` — when true, rejects direct authorize requests without `request_uri`

### PAR Flow (Existing)

1. Wallet POSTs to `/oauth2/par` with authorization parameters + client authentication
2. `PushedAuthorizeHandler.HandlePushedAuthorizeEndpointRequest()` validates the request, generates a `request_uri`, stores the PAR session
3. Response: `{"request_uri": "urn:ietf:params:oauth:request_uri:<random>", "expires_in": <seconds>}`
4. Wallet redirects user to `/oauth2/auth?client_id=<id>&request_uri=<uri>`
5. `authorizeRequestFromPAR()` in `fosite/authorize_request_handler.go` resolves the `request_uri`:
   - Checks if `request_uri` starts with the configured prefix
   - Loads the PAR session from storage via `PARStorage().GetPARSession(ctx, requestURI)`
   - Merges the stored request into the current authorize request (redirect URI, response types, state, response mode)
   - Deletes the PAR session (single-use)
   - Validates `client_id` matches between the PAR and authorize requests

### PAR Enforcement (Existing)

In `fosite/authorize_request_handler.go` → `newAuthorizeRequest()`:

```go
if configProvider, ok := f.Config.(PushedAuthorizeRequestConfigProvider); ok && configProvider.EnforcePushedAuthorize(ctx) {
    return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are enforced but no such request was sent."))
}
```

This check runs when `authorizeRequestFromPAR()` returns `isPAR == false` and enforcement is enabled. It rejects all direct authorize requests.

## HAIP Enforcement

### Injection Point

Two options for HAIP-specific PAR enforcement:

**Option A (Preferred): Extend `EnforcePushedAuthorize()` to check HAIP config**
- In the `fositex.Config` / `driver/config/DefaultProvider` implementation of `EnforcePushedAuthorize(ctx)`:
  - Return `true` if `KeyHAIPEnforced` is true (regardless of the standalone PAR enforcement setting)
  - This leverages the existing enforcement check in `newAuthorizeRequest()` without modifying fosite core code
- Advantage: minimal code change, reuses existing enforcement path
- Disadvantage: enforces PAR globally when HAIP is on (not just for credential issuance flows)

**Option B: Add HAIP-specific check in `newAuthorizeRequest()`**
- After the existing PAR enforcement check, add a new check:
  - If HAIP is enforced AND the request is a credential issuance flow (detected by `authorization_details` type or credential-related scopes), reject non-PAR requests
- Advantage: scoped enforcement — only credential issuance flows require PAR
- Disadvantage: requires modifying `fosite/authorize_request_handler.go` (upstream-touched file)

**Recommendation**: Start with Option A for simplicity. HAIP enforcement is a global policy — if the AS is in HAIP mode, all flows should use PAR.

### Config

- `KeyHAIPEnforced` → `bool` — when true, enables HAIP compliance mode
- Implemented on `HAIPConfigProvider`:
  ```go
  type HAIPConfigProvider interface {
      GetHAIPEnforced(ctx context.Context) bool
  }
  ```
- When `GetHAIPEnforced(ctx)` returns true:
  - `EnforcePushedAuthorize(ctx)` returns true
  - `GetEnablePKCEPlainChallengeMethod(ctx)` returns false (S256 only)
  - `GetEnforcePKCE(ctx)` returns true

## PKCE S256 Enforcement

When HAIP is enforced, PKCE with `code_challenge_method=S256` is mandatory for all authorization code flows:

- `EnforcePKCEProvider.GetEnforcePKCE(ctx)` → returns `true` when HAIP enforced
- `EnablePKCEPlainChallengeMethodProvider.GetEnablePKCEPlainChallengeMethod(ctx)` → returns `false` when HAIP enforced
- The existing PKCE handler (`fosite/handler/pkce/`) already enforces these settings — no new handler code needed
- The config provider methods in `fositex.Config` / `driver/config/DefaultProvider` check `KeyHAIPEnforced` and override the standalone PKCE settings

## Wallet Attestation at PAR

The PAR endpoint uses the same client authentication pipeline as the token endpoint:

- `Fosite.AuthenticateClient()` is called during PAR request processing (in the PAR endpoint handler in `oauth2/handler.go`)
- When Wallet Attestation is enabled, the `ClientAuthenticationStrategy` extension handles `OAuth-Client-Attestation` and `OAuth-Client-Attestation-PoP` headers
- No PAR-specific changes needed — the client auth pipeline is shared
- See [feature-wallet-attestation.md](feature-wallet-attestation.md) for Wallet Attestation details

## DPoP at PAR (`dpop_jkt` Binding — RFC 9449 §10.1)

Per RFC 9449 §10.1, when PAR and DPoP are both supported, the AS MUST support binding the authorization code to a DPoP key via the PAR request. Two mechanisms are supported:

1. **`dpop_jkt` parameter**: The client includes `dpop_jkt` in the PAR request form. The AS stores this value alongside the PAR session.
2. **`DPoP` header on PAR request**: The client includes a `DPoP` header. The DPoP handler validates the proof and treats the public key's JWK Thumbprint as an implicit `dpop_jkt`.
3. **Both present**: If both are present, the AS MUST reject the request if the thumbprints don't match.

The stored `dpop_jkt` is carried forward when the authorize endpoint resolves the `request_uri`, and is validated at the token endpoint against the DPoP proof's public key.

See [feature-dpop.md](feature-dpop.md) for the full `dpop_jkt` design.

## Error Codes

- **`invalid_request`** — Direct authorization request when PAR is enforced (existing error, already implemented)
- **`invalid_request`** — PKCE missing or wrong method under HAIP enforcement (handled by existing PKCE handler)

## Discovery Metadata

Per RFC 9126 §5, the following metadata fields are relevant to PAR:

- `pushed_authorization_request_endpoint` — URL of the PAR endpoint (e.g., `<issuer>/oauth2/par`). This field SHOULD be present in AS metadata when PAR is supported. Currently not advertised by Hydra — needs to be added to `oidcConfiguration` struct. See [feature-metadata-extensions.md](feature-metadata-extensions.md).
- `require_pushed_authorization_requests` — Boolean indicating PAR-only mode. Set to `true` when `EnforcePushedAuthorize(ctx)` returns true (either via standalone config or HAIP enforcement). See [feature-metadata-extensions.md](feature-metadata-extensions.md).

PKCE enforcement under HAIP is reflected in `code_challenge_methods_supported` containing only `S256`.

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — `PushedAuthorizeEndpointHandler` interface, `Compose` factory pattern, `PushedAuthorizeRequestConfigProvider`
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Config key additions, minimal upstream file modifications
- [feature-wallet-attestation.md](feature-wallet-attestation.md) — Client authentication at PAR endpoint
- [feature-dpop.md](feature-dpop.md) — DPoP proofs can accompany PAR requests
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Properties 18, 21 (HAIP PAR enforcement, PKCE S256 enforcement)
