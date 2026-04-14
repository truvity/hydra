---
inclusion: fileMatch
fileMatchPattern: "fosite/handler/**,fosite/compose/**,fosite/fosite.go,fosite/config.go,fositex/**"
---

# Fosite Handler Implementation Context

When working on Fosite handler code, always follow these patterns derived from the existing codebase.

## Request Lifecycle

Entry: `fosite/access_request_handler.go` → `Fosite.NewAccessRequest()`
- Parses POST form, extracts `grant_type`, `scope`, audience
- Calls `f.AuthenticateClient()` (may defer failure)
- Iterates `TokenEndpointHandlers`:
  1. `CanHandleTokenEndpointRequest()` — skip if false
  2. `CanSkipClientAuth()` — if false and client auth failed, return error
  3. `HandleTokenEndpointRequest()` — validate grant, populate request

Response: `fosite/access_response_writer.go` → `Fosite.NewAccessResponse()`
- Iterates same handlers, calls `PopulateTokenEndpointResponse()`
- Ignores `ErrUnknownRequest` (handler not responsible)

## Handler Interfaces

- `TokenEndpointHandler`: `CanHandleTokenEndpointRequest`, `CanSkipClientAuth`, `HandleTokenEndpointRequest`, `PopulateTokenEndpointResponse`
- `AuthorizeEndpointHandler`: `HandleAuthorizeEndpointRequest` — return nil if not responsible, any error aborts flow
- `PushedAuthorizeEndpointHandler`: `HandlePushedAuthorizeEndpointRequest`

## Factory Pattern

```go
type Factory func(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{}
```

`Compose()` calls each factory, type-asserts result to handler interfaces, appends to handler lists. Handler lists deduplicate by `reflect.TypeOf`.

## Configurator Extension

Add new provider interfaces to `Configurator` in `fosite/fosite.go`. Implement on `fositex.Config` / `driver/config/DefaultProvider`. Handlers receive `Configurator` and type-assert to their specific provider.

## Key References

- #[[file:docs/ai-context/01-hydra-internal-design.md]] — Full internal design documentation
- #[[file:docs/ai-context/00-architecture-overview.md]] — System architecture and data flows
