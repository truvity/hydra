---
inclusion: fileMatch
fileMatchPattern: "oauth2/token_hook*,oauth2/refresh_hook*,oauth2/handler.go"
---

# Token Hook Context

How the token hook (`oauth2/token_hook.go`) and refresh token hook (`oauth2/refresh_hook.go`) work. Use this when modifying hook behavior, adding new hook fields, or debugging hook-related issues.

## Call Tree

```
POST /oauth2/token
  → oauth2.Handler.oauth2TokenExchange()
    → fosite.NewAccessRequest()          // parse & validate grant
    → grant-specific session setup       // client_credentials, jwt-bearer, password, or auth_code via updateSessionWithRequest
    → for _, hook := range h.r.AccessRequestHooks() { hook(ctx, accessRequest) }
        ├── oauth2.RefreshTokenHook(reg)  // runs first, only for refresh_token grant
        └── oauth2.TokenHook(reg)         // runs second, for ALL grant types
    → fosite.NewAccessResponse()         // generate tokens using (possibly modified) session
    → fosite.WriteAccessResponse()       // serialize JSON response to client
```

Registration in `driver/registry_sql.go`:

```go
func (m *RegistrySQL) AccessRequestHooks() []oauth2.AccessRequestHook {
    m.arhs = []oauth2.AccessRequestHook{
        oauth2.RefreshTokenHook(m),  // only fires for refresh_token grant
        oauth2.TokenHook(m),         // fires for ALL grants
    }
    return m.arhs
}
```

Both hooks share `executeHookAndUpdateSession()` for the HTTP call and session mutation.

## Configuration

Config key: `oauth2.token_hook` (`config.KeyTokenHook`)
Refresh key: `oauth2.refresh_token_hook` (`config.KeyRefreshTokenHook`)

Two config formats are supported:

**Simple (URL string):**
```yaml
oauth2:
  token_hook: https://my-app.example.com/token-hook
```

**With authentication (`webhook_config` object):**
```yaml
oauth2:
  token_hook:
    url: https://my-app.example.com/token-hook
    auth:
      type: api_key
      config:
        in: header       # "header" or "cookie"
        name: Authorization
        value: "Bearer my-secret"
```

Parsed by `DefaultProvider.getHookConfig()` in `driver/config/provider.go`. Returns `*config.HookConfig` (nil when not configured). The `HookConfig`, `Auth`, and `AuthConfig` types are defined in `driver/config/provider.go`.

## Data Types

### TokenHookRequest (sent TO the hook)

```go
// oauth2/token_hook.go
type TokenHookRequest struct {
    Session *Session `json:"session"`
    Request Request  `json:"request"`
}

type Request struct {
    ClientID        string              `json:"client_id"`
    RequestedScopes []string            `json:"requested_scopes"`
    GrantedScopes   []string            `json:"granted_scopes"`
    GrantedAudience []string            `json:"granted_audience"`
    GrantTypes      []string            `json:"grant_types"`
    Payload         map[string][]string `json:"payload"`
}
```

`Request.Payload` comes from `requester.Sanitize([]string{"assertion"}).GetRequestForm()`. The `Sanitize` method keeps only: `grant_type`, `response_type`, `scope`, `client_id`, plus the explicitly allowed `assertion`. All other form parameters (including `client_secret`) are stripped.

### Session (the full `oauth2.Session` struct)

```go
// oauth2/session.go
type Session struct {
    *openid.DefaultSession `json:"id_token"`   // embeds Claims, Headers, Subject, ExpiresAt, Username
    Extra                  map[string]interface{} `json:"extra"`
    KID                    string                 `json:"kid"`
    ClientID               string                 `json:"client_id"`
    ConsentChallenge       string                 `json:"consent_challenge"`
    ExcludeNotBeforeClaim  bool                   `json:"exclude_not_before_claim"`
    AllowedTopLevelClaims  []string               `json:"allowed_top_level_claims"`
    MirrorTopLevelClaims   bool                   `json:"mirror_top_level_claims"`
}
```

`Session.Extra` is the map that becomes access token extra claims (via `GetExtraClaims()` → `GetJWTClaims()` for JWT strategy, or via introspection for opaque strategy).

`Session.DefaultSession.Claims.Extra` (`IDTokenClaims.Extra`) is the map that becomes ID token extra claims.

### TokenHookResponse (received FROM the hook)

```go
// oauth2/token_hook.go
type TokenHookResponse struct {
    Session flow.AcceptOAuth2ConsentRequestSession `json:"session"`
}

// flow/consent_types.go
type AcceptOAuth2ConsentRequestSession struct {
    AccessToken map[string]interface{} `json:"access_token"`
    IDToken     map[string]interface{} `json:"id_token"`
}
```

### RefreshTokenHookRequest (sent TO the hook for refresh_token grant)

```go
// oauth2/refresh_hook.go
type RefreshTokenHookRequest struct {
    Subject         string    `json:"subject"`
    Session         *Session  `json:"session"`
    Requester       Requester `json:"requester"`
    ClientID        string    `json:"client_id"`
    GrantedScopes   []string  `json:"granted_scopes"`
    GrantedAudience []string  `json:"granted_audience"`
}

type Requester struct {
    ClientID        string   `json:"client_id"`
    GrantedScopes   []string `json:"granted_scopes"`
    GrantedAudience []string `json:"granted_audience"`
    GrantTypes      []string `json:"grant_types"`
}
```

Note: `RefreshTokenHookRequest` has top-level `Subject`, `ClientID`, `GrantedScopes`, `GrantedAudience` fields duplicated from `Requester` for backward compatibility. The response type is the same `TokenHookResponse` (via shared `executeHookAndUpdateSession`).

## How the Hook Mutates Session State

In `executeHookAndUpdateSession()`:

```go
// Overwrite existing session data (extra claims).
session.Extra = respBody.Session.AccessToken
idTokenClaims := session.IDTokenClaims()
idTokenClaims.Extra = respBody.Session.IDToken
```

This is a **full replacement**, not a merge. The hook response `session.access_token` map **completely overwrites** `Session.Extra`. The hook response `session.id_token` map **completely overwrites** `IDTokenClaims.Extra`.

If the hook wants to preserve existing claims, it must read them from the request's `session` field and include them in the response.

## HTTP Protocol

- Method: `POST`
- Content-Type: `application/json; charset=UTF-8`
- Auth header applied via `applyAuth()` if configured (api_key in header or cookie)
- Response body limit: 5 MiB
- Uses retryable HTTP client from registry (`reg.HTTPClient(ctx)`)

### Response Status Codes

| Status | Behavior |
|--------|----------|
| `200 OK` | Decode `TokenHookResponse` from body, overwrite `Session.Extra` and `IDTokenClaims.Extra` |
| `204 No Content` | Token permitted, session unchanged (hook is a no-op) |
| `403 Forbidden` | Token denied → `fosite.ErrAccessDenied` returned to client |
| Any other | Token denied → `fosite.ErrServerError` returned to client |

## Example: Client Credentials Grant

### Hook Request Body

```json
{
  "session": {
    "id_token": {
      "id_token_claims": {
        "jti": "",
        "iss": "https://hydra.example.com/",
        "sub": "",
        "aud": null,
        "nonce": "",
        "exp": "0001-01-01T00:00:00Z",
        "iat": "2026-04-16T10:00:00Z",
        "rat": "0001-01-01T00:00:00Z",
        "auth_time": "0001-01-01T00:00:00Z",
        "at_hash": "",
        "acr": "",
        "amr": null,
        "c_hash": "",
        "ext": {}
      },
      "headers": { "extra": { "kid": "" } },
      "expires_at": {},
      "username": "",
      "subject": "my-client-id"
    },
    "extra": {},
    "kid": "",
    "client_id": "my-client-id",
    "consent_challenge": "",
    "exclude_not_before_claim": false,
    "allowed_top_level_claims": [],
    "mirror_top_level_claims": false
  },
  "request": {
    "client_id": "my-client-id",
    "requested_scopes": ["read", "write"],
    "granted_scopes": ["read", "write"],
    "granted_audience": ["https://api.example.com/"],
    "grant_types": ["client_credentials"],
    "payload": {
      "grant_type": ["client_credentials"],
      "scope": ["read write"]
    }
  }
}
```

### Hook Response Body (200 OK)

```json
{
  "session": {
    "access_token": {
      "department": "engineering",
      "role": "admin"
    },
    "id_token": {}
  }
}
```

### Hook Response Body (204 No Content — no-op)

Empty body. Session is not modified.

## Example: Authorization Code Grant

### Session State BEFORE Hook

After `updateSessionWithRequest()` populates the session from the consent flow:

```
Session.Extra = {"foo": "bar"}                    ← from consent accept (flow.SessionAccessToken)
Session.IDTokenClaims().Extra = {"email": "..."}  ← from consent accept (flow.SessionIDToken)
```

### Hook Request Body

```json
{
  "session": {
    "id_token": {
      "id_token_claims": {
        "jti": "",
        "iss": "https://hydra.example.com/",
        "sub": "user-uuid",
        "aud": ["my-client-id"],
        "nonce": "some-nonce",
        "exp": "0001-01-01T00:00:00Z",
        "iat": "2026-04-16T10:00:00Z",
        "rat": "2026-04-16T09:59:00Z",
        "auth_time": "2026-04-16T09:58:00Z",
        "at_hash": "",
        "acr": "0",
        "amr": [],
        "c_hash": "",
        "ext": { "email": "user@example.com" }
      },
      "headers": { "extra": { "kid": "openid-key-id" } },
      "expires_at": {},
      "username": "",
      "subject": "user-uuid"
    },
    "extra": { "foo": "bar" },
    "kid": "access-token-key-id",
    "client_id": "my-client-id",
    "consent_challenge": "consent-challenge-uuid",
    "exclude_not_before_claim": false,
    "allowed_top_level_claims": [],
    "mirror_top_level_claims": false
  },
  "request": {
    "client_id": "my-client-id",
    "requested_scopes": ["openid", "offline"],
    "granted_scopes": ["openid", "offline"],
    "granted_audience": [],
    "grant_types": ["authorization_code"],
    "payload": {
      "grant_type": ["authorization_code"]
    }
  }
}
```

### Hook Response (adds claims, preserves existing)

```json
{
  "session": {
    "access_token": {
      "foo": "bar",
      "hooked": true
    },
    "id_token": {
      "email": "user@example.com",
      "hooked": true
    }
  }
}
```

### Session State AFTER Hook

```
Session.Extra = {"foo": "bar", "hooked": true}
Session.IDTokenClaims().Extra = {"email": "user@example.com", "hooked": true}
```

Note: the hook must echo back `"foo": "bar"` and `"email": "..."` because the response **replaces** the maps entirely.

## How Session.Extra Flows Into Token Responses

### Opaque Access Token Strategy

With opaque tokens, `Session.Extra` is not embedded in the token itself. It surfaces through:

1. **Introspection** (`/admin/oauth2/introspect`): `ExtraClaimsSession.GetExtraClaims()` returns `Session.Extra`. Each key-value pair is added to the introspection JSON response (except reserved keys: `exp`, `client_id`, `scope`, `iat`, `sub`, `aud`, `username`).

2. **Token response body**: The access token response itself only contains `access_token`, `token_type`, `expires_in`, `scope`, `refresh_token`, `id_token`. The `Session.Extra` claims do NOT appear in the token endpoint response body for opaque tokens.

### JWT Access Token Strategy

With JWT tokens, `Session.Extra` is embedded in the JWT claims via `Session.GetJWTClaims()`:

- Each key in `AllowedTopLevelClaims` that exists in `Session.Extra` becomes a top-level JWT claim
- `client_id` is always a top-level claim
- If `MirrorTopLevelClaims` is true, the full `Session.Extra` map is also placed under the `ext` claim
- Reserved claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id`, `scp`, `ext`) cannot be overridden via `AllowedTopLevelClaims`

### ID Token

`IDTokenClaims.Extra` is merged into the ID token JWT via `IDTokenClaims.ToMap()`. Each key-value pair becomes a top-level claim in the ID token (the `Extra` map entries are spread into the claims map, potentially overriding standard claims except those explicitly set like `sub`, `iss`, `aud`, etc.).

## Introspection Response: Without Hook vs With Hook

### Without Hook (consent set `Session.Extra = {"foo": "bar"}`)

```json
{
  "active": true,
  "sub": "user-uuid",
  "client_id": "my-client-id",
  "scope": "openid offline",
  "iat": 1744797600,
  "exp": 1744801200,
  "foo": "bar"
}
```

### With Hook (hook returned `access_token: {"foo": "bar", "hooked": true}`)

```json
{
  "active": true,
  "sub": "user-uuid",
  "client_id": "my-client-id",
  "scope": "openid offline",
  "iat": 1744797600,
  "exp": 1744801200,
  "foo": "bar",
  "hooked": true
}
```

## Token Endpoint Response: Without Hook vs With Hook

The `/oauth2/token` response body is the same structure regardless of hook — the hook does not add fields to the token endpoint response itself. The difference is in what's inside the access token (JWT strategy) or what introspection returns (opaque strategy).

### Token Endpoint Response (same either way)

```json
{
  "access_token": "ory_at_...",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "openid offline",
  "refresh_token": "ory_rt_...",
  "id_token": "eyJ..."
}
```

The ID token JWT (`id_token` field) will contain the hook-modified claims from `IDTokenClaims.Extra`.

## Refresh Token Hook vs Token Hook

For a `refresh_token` grant, BOTH hooks fire (in order):

1. `RefreshTokenHook` — fires first, only for `refresh_token` grant type. Uses `oauth2.refresh_token_hook` config. Sends `RefreshTokenHookRequest` (includes `subject` and top-level `client_id`/`granted_scopes`/`granted_audience`).
2. `TokenHook` — fires second, for all grant types including `refresh_token`. Uses `oauth2.token_hook` config. Sends `TokenHookRequest`.

Both call `executeHookAndUpdateSession()`, so the second hook sees the session as modified by the first. If both are configured, the token hook's response wins for `Session.Extra` and `IDTokenClaims.Extra` (last write wins).

## Key Implementation Details

- Hook is skipped (returns nil) when `hookConfig == nil` (not configured)
- Hook is skipped when session is not `*oauth2.Session` (defensive type assertion)
- `Sanitize([]string{"assertion"})` keeps `grant_type`, `response_type`, `scope`, `client_id`, and `assertion` in the payload; strips everything else including `client_secret`, `code`, `refresh_token`, `redirect_uri`
- Response body is limited to 5 MiB via `io.LimitReader`
- External latency is tracked via `reqlog.AccumulateExternalLatency`
- The hook runs AFTER grant-specific scope/audience granting but BEFORE `NewAccessResponse()` generates the actual tokens
