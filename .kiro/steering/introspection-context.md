---
inclusion: fileMatch
fileMatchPattern: "oauth2/introspector.go,oauth2/handler.go,oauth2/session.go,oauth2/token_hook.go,fosite/introspect.go,fosite/introspection_response_writer.go,fosite/introspection_request_handler.go,fosite/session.go,fosite/handler/oauth2/introspector.go"
---

# Token Introspection Context

When working on introspection-related code, follow these patterns. This document describes how token introspection works end-to-end and how to propagate new parameters into the introspection response.

## Two Introspection Paths

Hydra has two distinct introspection code paths. Understanding both is critical.

### Path 1: Hydra Admin Handler (the one actually used)

`oauth2/handler.go` → `introspectOAuth2Token()` — registered at `POST /admin/oauth2/introspect`.

This handler does NOT use fosite's `WriteIntrospectionResponse`. Instead it:
1. Calls `h.r.OAuth2Provider().IntrospectToken()` to validate the token and get the `AccessRequester`
2. Casts the session to `*oauth2.Session`
3. Directly encodes an `oauth2.Introspection` struct via `json.NewEncoder(w).Encode()`
4. Maps `session.Extra` → `Introspection.Extra` (serialized as `"ext"` in JSON)

### Path 2: Fosite-Level Writer (not used by Hydra's admin endpoint)

`fosite/introspection_response_writer.go` → `Fosite.WriteIntrospectionResponse()` — builds a `map[string]interface{}` response.

This path:
1. Checks if session implements `ExtraClaimsSession`
2. Iterates `GetExtraClaims()` and adds each claim as a top-level JSON field
3. Filters reserved claims: `exp`, `client_id`, `scope`, `iat`, `sub`, `aud`, `username`
4. Non-reserved extra claims become top-level response fields (not nested under `ext`)

This path is used by `Fosite.NewIntrospectionRequest()` which is the fosite-native introspection flow. Hydra's admin handler bypasses this entirely.

## Introspection Response Struct

`oauth2/introspector.go` → `Introspection` struct (swagger model `introspectedOAuth2Token`):

```go
type Introspection struct {
    Active            bool                   `json:"active"`
    Scope             string                 `json:"scope,omitempty"`
    ClientID          string                 `json:"client_id"`
    Subject           string                 `json:"sub"`
    ObfuscatedSubject string                 `json:"obfuscated_subject,omitempty"`
    ExpiresAt         int64                  `json:"exp"`
    IssuedAt          int64                  `json:"iat"`
    NotBefore         int64                  `json:"nbf"`
    Username          string                 `json:"username,omitempty"`
    Audience          []string               `json:"aud"`
    Issuer            string                 `json:"iss"`
    TokenType         string                 `json:"token_type"`
    TokenUse          string                 `json:"token_use"`
    Extra             map[string]interface{} `json:"ext,omitempty"`
}
```

All custom/dynamic data from the consent session lives in `Extra` (JSON key `ext`).

## Data Flow: Consent → Session → Introspection

```
1. Consent Node accepts consent request with:
   AcceptOAuth2ConsentRequestSession.AccessToken (map[string]interface{})

2. Flow stores it:
   flow.SessionAccessToken = session.AccessToken

3. Token issuance builds session:
   oauth2/handler.go → updateSessionWithRequest():
     session.Extra = flow.SessionAccessToken

4. Token stored in DB with serialized session

5. Introspection retrieves token + session from storage:
   fosite/handler/oauth2/introspector.go → CoreValidator.IntrospectToken()
     → GetAccessTokenSession() / GetRefreshTokenSession()
     → accessRequest.Merge(or)  // copies session into the access requester

6. Hydra handler reads session.Extra and puts it in the response:
   oauth2/handler.go → introspectOAuth2Token():
     Extra: session.Extra  →  JSON: "ext": {...}
```

## Token Hook Override

`oauth2/token_hook.go` → `executeHookAndUpdateSession()` can overwrite `session.Extra` entirely before token issuance:

```go
session.Extra = respBody.Session.AccessToken
```

This means the Token Hook can add, remove, or modify any data that will appear in introspection.

## How to Propagate a New Parameter to Introspection

### Option A: Via session.Extra (dynamic, no code change)

If the new parameter should be set per-request by the Consent Node or Token Hook:
1. Consent Node sets it in `AcceptOAuth2ConsentRequestSession.AccessToken["my_param"]`
2. It flows automatically into `session.Extra["my_param"]`
3. It appears in introspection response under `ext.my_param`

No code changes needed. This is how `authorization_details` and `credential_identifiers` are propagated.

### Option B: As a top-level introspection field (requires code change)

If the new parameter needs to be a top-level JSON field (not nested under `ext`):

1. Add the field to `oauth2.Introspection` struct in `oauth2/introspector.go`
2. Populate it in `introspectOAuth2Token()` in `oauth2/handler.go` (around line 1080 where the struct literal is built)
3. Source the value from `session.Extra`, `session.DefaultSession`, or the `AccessRequester`
4. Update swagger annotations on the `Introspection` struct

### Option C: Via fosite ExtraClaimsSession (affects fosite-level path only)

If you need the parameter in fosite's `WriteIntrospectionResponse` path:
1. Ensure the session's `GetExtraClaims()` returns the data
2. The claim name must not collide with reserved names (`exp`, `client_id`, `scope`, `iat`, `sub`, `aud`, `username`)
3. It will appear as a top-level JSON field in the fosite response

Note: This does NOT affect Hydra's admin introspection endpoint (Path 1).

## Fosite Introspection Internals

### Token Validation Chain

`fosite/introspect.go` → `Fosite.IntrospectToken()`:
- Iterates `Config.GetTokenIntrospectionHandlers(ctx)` (registered via `TokenIntrospectionHandlers`)
- Each handler implements `TokenIntrospector.IntrospectToken()`
- Primary handler: `fosite/handler/oauth2/introspector.go` → `CoreValidator`
- `CoreValidator` tries access token first, then refresh token (or vice versa based on `token_type_hint`)
- On success, calls `accessRequest.Merge(or)` to copy the stored request (with session) into the caller's access requester

### ExtraClaimsSession Interface

`fosite/session.go`:
```go
type ExtraClaimsSession interface {
    GetExtraClaims() map[string]interface{}
}
```

Implemented by:
- `fosite.DefaultSession` — returns `s.Extra`
- `oauth2.Session` — returns `s.Extra` (the consent session access token data)
- `fosite/handler/oauth2.JWTSession` — returns a copy of JWT claims

### IntrospectionResponder Interface

`fosite/introspection_request_handler.go`:
- `IsActive() bool`
- `GetAccessRequester() AccessRequester`
- `GetTokenUse() TokenUse`
- `GetAccessTokenType() string`

Concrete: `IntrospectionResponse` struct with `Active`, `AccessRequester`, `TokenUse`, `AccessTokenType`.

## Key Files

| File | Role |
|---|---|
| `oauth2/handler.go` | Admin introspection endpoint handler (`introspectOAuth2Token`) |
| `oauth2/introspector.go` | `Introspection` response struct definition |
| `oauth2/session.go` | `Session` struct with `Extra` map, `GetExtraClaims()` |
| `oauth2/token_hook.go` | Token Hook that can overwrite `session.Extra` |
| `fosite/introspect.go` | `Fosite.IntrospectToken()` — token validation orchestrator |
| `fosite/introspection_response_writer.go` | `WriteIntrospectionResponse()` — fosite-level JSON writer |
| `fosite/introspection_request_handler.go` | `NewIntrospectionRequest()` + `IntrospectionResponse` struct |
| `fosite/session.go` | `ExtraClaimsSession` interface, `DefaultSession` |
| `fosite/handler/oauth2/introspector.go` | `CoreValidator` — token storage lookup and validation |
| `flow/flow.go` | `SessionAccessToken` field — consent session data storage |

## Key References

- #[[file:docs/ai-context/01-hydra-internal-design.md]] — Session struct, Token Hook, Registry pattern
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — Introspection as integration point for Credential Issuer
- #[[file:docs/ai-context/00-architecture-overview.md]] — End-to-end data flow through introspection
