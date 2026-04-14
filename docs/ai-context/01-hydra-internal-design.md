# Hydra Internal Design — AI Implementation Context

## 1. Token Endpoint Request Lifecycle

Entry point: `fosite/access_request_handler.go` → `Fosite.NewAccessRequest()`

- Parses HTTP POST form, extracts `grant_type`, `scope`, audience
- Calls `f.AuthenticateClient()` to authenticate the client (may fail; deferred check)
- Iterates `f.Config.GetTokenEndpointHandlers(ctx)` (a `TokenEndpointHandlers` slice):
  1. `loader.CanHandleTokenEndpointRequest(ctx, accessRequest)` — skip if false
  2. `loader.CanSkipClientAuth(ctx, accessRequest)` — if false and client auth failed, return error
  3. `loader.HandleTokenEndpointRequest(ctx, accessRequest)` — validate grant, populate request
- If no handler matched (`found == false`), returns `ErrInvalidRequest`

Response phase: `fosite/access_response_writer.go` → `Fosite.NewAccessResponse()`

- Iterates same `TokenEndpointHandlers` list
- Calls `tk.PopulateTokenEndpointResponse(ctx, requester, response)` on each
- Ignores `ErrUnknownRequest` (handler not responsible)
- Validates that `AccessToken` and `TokenType` are set on the response

## 2. Handler Interfaces (`fosite/handler.go`)

### `AuthorizeEndpointHandler`
```go
HandleAuthorizeEndpointRequest(ctx context.Context, requester AuthorizeRequester, responder AuthorizeResponder) error
```
- Called during `/oauth2/auth` processing
- Must return `nil` if not responsible (do not modify session/responder/requester)
- Any non-nil error aborts the entire authorize flow — unlike `TokenEndpointHandler` which uses `ErrUnknownRequest` to skip

### `TokenEndpointHandler`
```go
PopulateTokenEndpointResponse(ctx, requester AccessRequester, responder AccessResponder) error
HandleTokenEndpointRequest(ctx, requester AccessRequester) error
CanSkipClientAuth(ctx, requester AccessRequester) bool
CanHandleTokenEndpointRequest(ctx, requester AccessRequester) bool
```
- `CanHandleTokenEndpointRequest` → gate by `grant_type` or request properties
- `CanSkipClientAuth` → `true` only for extension grants allowing unauthenticated clients
- `HandleTokenEndpointRequest` → validate grant-specific logic
- `PopulateTokenEndpointResponse` → issue tokens, set response extras

### `PushedAuthorizeEndpointHandler`
```go
HandlePushedAuthorizeEndpointRequest(ctx, requester AuthorizeRequester, responder PushedAuthorizeResponder) error
```
- Handles PAR (RFC 9126) requests at `/oauth2/par`

### `RevocationHandler`
```go
RevokeToken(ctx, token string, tokenType TokenType, client Client) error
```

### `DeviceEndpointHandler`
```go
HandleDeviceEndpointRequest(ctx, requester DeviceRequester, responder DeviceResponder) error
```
- Handles RFC 8628 device authorization

## 3. Compose Factory Pattern (`fosite/compose/compose.go`)

### Factory type
```go
type Factory func(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{}
```

### `Compose()` function
- Creates `Fosite` instance via `fosite.NewOAuth2Provider(storage, config)`
- Iterates factories, calls each, type-asserts result to handler interfaces:
  - `AuthorizeEndpointHandler` → `config.AuthorizeEndpointHandlers.Append(ah)`
  - `TokenEndpointHandler` → `config.TokenEndpointHandlers.Append(th)`
  - `TokenIntrospector` → `config.TokenIntrospectionHandlers.Append(tv)`
  - `RevocationHandler` → `config.RevocationHandlers.Append(rh)`
  - `PushedAuthorizeEndpointHandler` → `config.PushedAuthorizeEndpointHandlers.Append(ph)`
  - `DeviceEndpointHandler` → `config.DeviceEndpointHandlers.Append(dh)`
- Handler lists use `Append()` which deduplicates by `reflect.TypeOf`

### Example: `PushedAuthorizeHandlerFactory` (`fosite/compose/compose_par.go`)
```go
func PushedAuthorizeHandlerFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
    return &par.PushedAuthorizeHandler{
        Storage: storage.(fosite.PARStorageProvider),
        Config:  config,
    }
}
```

### `ComposeAllEnabled()` — full handler registration list
- `OAuth2AuthorizeExplicitFactory`, `OAuth2AuthorizeImplicitFactory`
- `OAuth2ClientCredentialsGrantFactory`, `OAuth2RefreshTokenGrantFactory`
- `OAuth2ResourceOwnerPasswordCredentialsFactory`, `RFC7523AssertionGrantFactory`
- `RFC8628DeviceFactory`, `RFC8628DeviceAuthorizationTokenFactory`
- `OpenIDConnectExplicitFactory`, `OpenIDConnectImplicitFactory`, `OpenIDConnectHybridFactory`, `OpenIDConnectRefreshFactory`, `OpenIDConnectDeviceFactory`
- `OAuth2TokenIntrospectionFactory`, `OAuth2TokenRevocationFactory`
- `OAuth2PKCEFactory`, `PushedAuthorizeHandlerFactory`

## 4. Configurator Interface (`fosite/fosite.go`)

### Composition
`Configurator` composes ~40 provider interfaces:
- **Lifespan providers**: `AccessTokenLifespanProvider`, `RefreshTokenLifespanProvider`, `AuthorizeCodeLifespanProvider`, `IDTokenLifespanProvider`, `DeviceAndUserCodeLifespanProvider`, `VerifiableCredentialsNonceLifespanProvider`
- **Strategy providers**: `ScopeStrategyProvider`, `AudienceStrategyProvider`, `ClientAuthenticationStrategyProvider`, `JWKSFetcherStrategyProvider`
- **Secret providers**: `GlobalSecretProvider`, `RotatedGlobalSecretsProvider`, `HMACHashingProvider`, `GetSecretsHashingProvider`
- **Handler list providers**: `AuthorizeEndpointHandlersProvider`, `TokenEndpointHandlersProvider`, `TokenIntrospectionHandlersProvider`, `RevocationHandlersProvider`, `DeviceEndpointHandlersProvider`
- **Feature flag providers**: `EnforcePKCEProvider`, `EnforcePKCEForPublicClientsProvider`, `EnablePKCEPlainChallengeMethodProvider`, `GrantTypeJWTBearerCanSkipClientAuthProvider`
- **Misc**: `IDTokenIssuerProvider`, `AccessTokenIssuerProvider`, `TokenURLProvider`, `SendDebugMessagesToClientsProvider`, `ResponseModeHandlerExtensionProvider`, `MessageCatalogProvider`, `FormPostHTMLTemplateProvider`

### Extension point
- Add new provider interfaces (e.g., `DPoPConfigProvider`, `PreAuthorizedCodeConfigProvider`) to the `Configurator` interface
- Implement them on `fositex.Config` / `driver/config/DefaultProvider`
- New handlers receive `Configurator` and type-assert to their specific provider

### Key handler list providers
```go
TokenEndpointHandlersProvider       → GetTokenEndpointHandlers(ctx) TokenEndpointHandlers
AuthorizeEndpointHandlersProvider   → GetAuthorizeEndpointHandlers(ctx) AuthorizeEndpointHandlers
PushedAuthorizeRequestHandlersProvider → GetPushedAuthorizeEndpointHandlers(ctx) PushedAuthorizeEndpointHandlers
```

### Note: `PushedAuthorizeRequestConfigProvider` (separate from `Configurator`)
```go
GetPushedAuthorizeRequestURIPrefix(ctx) string
GetPushedAuthorizeContextLifespan(ctx) time.Duration
EnforcePushedAuthorize(ctx) bool
```

## 5. Session (`oauth2/session.go`)

### Struct
```go
type Session struct {
    *openid.DefaultSession        `json:"id_token"`
    Extra                         map[string]interface{} `json:"extra"`
    KID                           string                 `json:"kid"`
    ClientID                      string                 `json:"client_id"`
    ConsentChallenge              string                 `json:"consent_challenge"`
    ExcludeNotBeforeClaim         bool                   `json:"exclude_not_before_claim"`
    AllowedTopLevelClaims         []string               `json:"allowed_top_level_claims"`
    MirrorTopLevelClaims          bool                   `json:"mirror_top_level_claims"`
}
```

### `GetJWTClaims()` — maps `Extra` to JWT access token claims
- Filters `AllowedTopLevelClaims` (removes reserved: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id`, `scp`, `ext`)
- Promotes allowed claims from `Extra` to top-level JWT claims
- If `MirrorTopLevelClaims` is true, also sets `ext` key to the full `Extra` map
- Always sets `client_id` as a top-level claim

### `GetExtraClaims()` — returns mutable `Extra` map
- Used by handlers to read/write custom claims (e.g., `authorization_details`)
- Initializes `Extra` to empty map if nil

### `Clone()` — deep copy via `mohae/deepcopy`

## 6. Consent Flow Types (`flow/consent_types.go`)

### `OAuth2ConsentRequest` — sent to Consent Node as challenge
- Key fields: `Challenge`, `RequestedScope`, `RequestedAudience`, `Subject`, `Client`, `RequestURL`, `OpenIDConnectContext`, `Context`, `ACR`, `AMR`
- Sent to the external Consent Node so it can render consent UI
- Extension point: add `AuthorizationDetails sqlxx.JSONRawMessage` field for RAR

### `AcceptOAuth2ConsentRequest` — returned by Consent Node
- Key fields: `GrantedScope`, `GrantedAudience`, `Session *AcceptOAuth2ConsentRequestSession`, `Remember`, `RememberFor`, `Context`
- Extension point: add `AuthorizationDetails sqlxx.JSONRawMessage` for enriched RAR data (e.g., `credential_identifiers`)

### `AcceptOAuth2ConsentRequestSession` — session data from consent
```go
type AcceptOAuth2ConsentRequestSession struct {
    AccessToken map[string]interface{} `json:"access_token"`
    IDToken     map[string]interface{} `json:"id_token"`
}
```
- `AccessToken` map → merged into `Session.Extra` → flows into access token claims
- `IDToken` map → merged into ID token claims

## 7. Token Hook (`oauth2/token_hook.go`)

### Request/Response types
```go
type TokenHookRequest struct {
    Session *Session `json:"session"`
    Request Request  `json:"request"`  // ClientID, Scopes, GrantTypes, Payload
}

type TokenHookResponse struct {
    Session flow.AcceptOAuth2ConsentRequestSession `json:"session"`
}
```

### `executeHookAndUpdateSession()`
- POSTs `TokenHookRequest` JSON to configured webhook URL
- On `200 OK`: decodes `TokenHookResponse`, overwrites `session.Extra` with `respBody.Session.AccessToken`, overwrites ID token claims with `respBody.Session.IDToken`
- On `204 No Content`: no session modification
- On `403 Forbidden`: returns `ErrAccessDenied`
- On other status: returns `ErrServerError`

### `TokenHook()` — `AccessRequestHook` factory
- Called for **all grant types** via `AccessRequestHooks()` in `driver/registry_sql.go`
- Reads hook config from `reg.Config().TokenHookConfig(ctx)`
- Sends full session + request context to external webhook
- Any data in `session.Extra` (including `authorization_details`) is available to the hook

## 8. Discovery Metadata (`oauth2/handler.go`)

### `oidcConfiguration` struct
- All OIDC discovery fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, etc.
- Grant types: `["authorization_code", "implicit", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]`
- Auth methods: `["client_secret_post", "client_secret_basic", "private_key_jwt", "none"]`
- Code challenge methods: `["plain", "S256"]`
- Request object signing algs: `["none", "RS256", "ES256"]`
- Experimental VC fields (to be replaced): `credentials_endpoint_draft_00`, `credentials_supported_draft_00`

### `discoverOidcConfiguration()` handler
- Serves `GET /.well-known/openid-configuration` and `GET /.well-known/oauth-authorization-server`
- Populates `oidcConfiguration` struct from config values
- Extension point: add new fields for OIDC4VCI metadata (`dpop_signing_alg_values_supported`, `authorization_details_types_supported`, `pre_authorized_grant_anonymous_access_supported`, `authorization_response_iss_parameter_supported`)
- Add new grant type `urn:ietf:params:oauth:grant-type:pre-authorized_code` to `grant_types_supported`
- Add `attest_jwt_client_auth` to `token_endpoint_auth_methods_supported`

## 9. Registry Pattern

### Top-level registry (`driver/registry.go`)
- `registry` interface (unexported) composes all sub-registries:
  - `config.Provider`, `persistence.Provider`, `client.Registry`, `consent.Registry`, `jwk.Registry`, `trust.Registry`, `oauth2.Registry`, `otelx.Provider`, `x.NetworkProvider`, `kratos.Provider`, `fosite.Transactional`

### OAuth2 registry (`oauth2/registry.go`)
```go
type Registry interface {
    OAuth2Storage() x.FositeStorer
    OAuth2Provider() fosite.OAuth2Provider
    AccessTokenJWTSigner() jwk.JWTSigner
    OpenIDConnectRequestValidator() *openid.OpenIDConnectRequestValidator
    AccessRequestHooks() []AccessRequestHook
    OAuth2ProviderConfig() fosite.Configurator
    rfc8628.DeviceRateLimitStrategyProvider
    rfc8628.DeviceCodeStrategyProvider
    rfc8628.UserCodeStrategyProvider
}
```

### Concrete implementation (`driver/registry_sql.go`)
- `RegistrySQL` struct — wires everything together
- `OAuth2Provider()` → returns `fosite.OAuth2Provider` (lazy-initialized)
- `OAuth2Config()` → returns `fositex.Config` (the `Configurator` implementation)
- `ExtraFositeFactories()` → extension point for additional factories
- `AccessRequestHooks()` → returns `[]oauth2.AccessRequestHook` including `TokenHook`
- Storage methods: `AuthorizeCodeStorage()`, `AccessTokenStorage()`, `RefreshTokenStorage()`, `PKCERequestStorage()`, `DeviceAuthStorage()`, etc.
- Extension point: add new storage accessors (e.g., `PreAuthorizedCodeStorage()`, `DPoPNonceStorage()`)

## 10. Existing Handler Examples

### `fosite/handler/par/` — PAR handler
- `flow_pushed_authorize.go` → `PushedAuthorizeHandler` struct
- Implements `PushedAuthorizeEndpointHandler`
- Factory: `fosite/compose/compose_par.go` → `PushedAuthorizeHandlerFactory`
- Registered in `ComposeAllEnabled()`

### `fosite/handler/rfc8628/` — Device flow handler
- `token_handler.go` → implements `TokenEndpointHandler` for `urn:ietf:params:oauth:grant-type:device_code`
- `auth_handler.go` → implements `DeviceEndpointHandler`
- `storage.go` → `DeviceAuthStorage` interface
- `strategy.go` / `strategy_hmacsha.go` → device/user code strategies
- Factory: `RFC8628DeviceFactory` + `RFC8628DeviceAuthorizationTokenFactory`

### `fosite/handler/pkce/` — PKCE handler
- Validates `code_challenge` / `code_verifier` on authorize and token endpoints

### `fosite/handler/verifiable/` — Verifiable Credentials handler
- Decorates token responses (cross-cutting pattern, similar to planned DPoP handler)

### `fosite/compose/compose_par.go` — Factory pattern example
- Minimal factory: creates handler struct, type-asserts storage, passes config
- Return type is `interface{}` — `Compose()` does the type assertion to register
