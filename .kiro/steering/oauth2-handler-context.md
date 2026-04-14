---
inclusion: fileMatch
fileMatchPattern: "oauth2/handler.go,oauth2/handler_test.go,oauth2/token_hook.go,oauth2/session.go,oauth2/registry.go"
---

# OAuth2 Handler & Session Context

When working on oauth2 package files, follow these patterns.

## Discovery Metadata (`oauth2/handler.go`)

`oidcConfiguration` struct defines all `/.well-known/openid-configuration` fields. `discoverOidcConfiguration()` populates and serves it.

OIDC4VCI adds these fields (all `omitempty`, conditionally populated):
- `PushedAuthorizationRequestEndpoint` — PAR endpoint URL
- `RequirePushedAuthorizationRequests` — PAR-only mode
- `PreAuthorizedGrantAnonymousAccessSupported` — Pre-Auth anonymous access
- `AuthorizationDetailsTypesSupported` — RAR types (e.g., `["openid_credential"]`)
- `DPoPSigningAlgValuesSupported` — DPoP algorithms
- `AuthorizationResponseIssParameterSupported` — RFC 9207

Also modifies dynamic lists: `GrantTypesSupported`, `TokenEndpointAuthMethodsSupported`, `CodeChallengeMethodsSupported`.

Group all OIDC4VCI additions in a clearly marked section: `// --- OIDC4VCI Extensions (custom fork) ---`

## Session (`oauth2/session.go`)

`Session.Extra` map carries custom claims through the token lifecycle. OIDC4VCI uses:
- `session.Extra["authorization_details"]` — RAR data with credential_identifiers
- `session.Extra["cnf"]` — DPoP confirmation (`{"jkt": "<thumbprint>"}`)

## Token Hook (`oauth2/token_hook.go`)

Called for ALL grant types. Sends full `Session` to webhook. Response can overwrite `Session.Extra`. The `authorization_details` in `Session.Extra` is automatically available to hooks.

## Merge Conflict Warning

`oauth2/handler.go` is HIGH conflict risk — upstream frequently modifies discovery metadata. Add struct fields at end, population logic in a separate block.

## Key References

- #[[file:docs/ai-context/features/feature-metadata-extensions.md]] — Full metadata extensions design
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — Session struct, token hook, discovery metadata
