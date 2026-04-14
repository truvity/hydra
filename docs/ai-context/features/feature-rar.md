# Feature: Rich Authorization Requests (RFC 9396)

## Purpose

Steering document for implementing RAR (`authorization_details`) support in the Hydra AS fork. RAR enables Wallets to specify exactly which credential configurations they want issued, using structured `authorization_details` objects with `type=openid_credential`. The handler parses and validates these on authorize/PAR requests and propagates them through the consent flow into the token response.

## Location

- Handler: `fosite/handler/rar/handler.go`
- Tests: `fosite/handler/rar/handler_test.go`
- Factory: `fosite/compose/compose_rar.go` → `RARFactory`
- Config keys: `driver/config/` → `KeyRAREnabled`, `KeyRARTypesSupported`
- Consent type extensions: `flow/consent_types.go` — new `AuthorizationDetails` field

## Handler Design

### Struct

```go
type RARHandler struct {
    Config RARConfigProvider
}
```

### Interfaces Implemented

- `fosite.AuthorizeEndpointHandler` — validates `authorization_details` on `/oauth2/auth`
- `fosite.PushedAuthorizeEndpointHandler` — validates `authorization_details` on `/oauth2/par`
- `fosite.TokenEndpointHandler` — validates `authorization_details` subset on token requests and propagates `authorization_details` (with `credential_identifiers`) into the token response

### `AuthorizeEndpointHandler` Implementation

**`HandleAuthorizeEndpointRequest(ctx, requester, responder)`**
1. Extract `authorization_details` from `requester.GetRequestForm().Get("authorization_details")`
2. If empty/absent: return `nil` (not responsible — do not modify session/responder/requester)
3. Parse the JSON string as an array of objects: `[]map[string]interface{}`
4. For each object in the array:
   - Validate `type` field exists and equals `"openid_credential"` (or is in `GetRARTypesSupported()`)
   - If `type` is unknown: return `ErrInvalidAuthorizationDetails` ("unsupported authorization_details type")
   - Validate `credential_configuration_id` field is present and non-empty
   - If missing: return `ErrInvalidAuthorizationDetails` ("credential_configuration_id required for openid_credential type")
5. Store the validated `authorization_details` alongside the authorize request (in the session or request form for downstream consumption)

### `PushedAuthorizeEndpointHandler` Implementation

**`HandlePushedAuthorizeEndpointRequest(ctx, requester, responder)`**
- Same validation logic as `HandleAuthorizeEndpointRequest` — parse and validate `authorization_details` from the PAR request form
- The validated data is stored with the PAR session and carried forward when the authorize endpoint resolves the `request_uri`

## Consent Integration

### Flow

1. RAR handler validates `authorization_details` during authorize/PAR processing
2. The validated `authorization_details` is stored alongside the authorization session
3. When the consent challenge is created, `authorization_details` is included in `OAuth2ConsentRequest.AuthorizationDetails`
4. The Consent Node reads `authorization_details` to render credential-specific consent UI
5. The Consent Node returns `AcceptOAuth2ConsentRequest.AuthorizationDetails` — potentially enriched with `credential_identifiers` per credential configuration
6. The AS merges the consent response `authorization_details` into `Session.Extra["authorization_details"]`

### Consent Type Extensions

In `flow/consent_types.go`:

**`OAuth2ConsentRequest`** — add field:
```go
AuthorizationDetails sqlxx.JSONRawMessage `json:"authorization_details,omitempty" db:"authorization_details"`
```

**`AcceptOAuth2ConsentRequest`** — add field:
```go
AuthorizationDetails sqlxx.JSONRawMessage `json:"authorization_details,omitempty" db:"authorization_details"`
```

These are additive struct fields. The `authorization_details` is a raw JSON array, preserving the full structure from the original request (or enriched by the Consent Node).

### Session Propagation

After consent accept, the `authorization_details` from `AcceptOAuth2ConsentRequest.AuthorizationDetails` is merged into `Session.Extra["authorization_details"]`. This happens in the consent flow processing code (likely in `consent/handler.go` or equivalent).

The session `Extra` map carries `authorization_details` through:
- Token issuance → included in token response extras
- Token introspection → available to the Credential Issuer
- Refresh token exchange → preserved across token refreshes
- Token hook → available for external modification

## Token Response

The `authorization_details` array is included in the token response body via response extras. Each object of type `openid_credential` contains:

```json
{
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegree_jwt_vc_json",
      "credential_identifiers": ["cred-id-1", "cred-id-2"]
    }
  ]
}
```

The `credential_identifiers` are set by the Consent Node (or Token Hook), not by the RAR handler itself.

## Token Request Subset Validation

When a token request contains `authorization_details`:

1. Parse the `authorization_details` from the token request form
2. Extract all `credential_configuration_id` values from the token request's `authorization_details`
3. Extract all `credential_configuration_id` values from the authorized set (stored in the session during consent)
4. Validate that the token request set is a **subset** of the authorized set
5. If any `credential_configuration_id` in the token request is not in the authorized set: return `ErrInvalidAuthorizationDetails` ("credential_configuration_id not previously authorized")

This validation is NOT part of the authorize/PAR handler logic — it runs at the token endpoint. The `RARHandler` struct implements `TokenEndpointHandler` in addition to `AuthorizeEndpointHandler` and `PushedAuthorizeEndpointHandler`. The token endpoint methods handle subset validation and response propagation:
- `CanHandleTokenEndpointRequest` returns `true` when `authorization_details` is present in the token request form
- `HandleTokenEndpointRequest` performs the subset validation against the session's authorized set
- `PopulateTokenEndpointResponse` propagates `authorization_details` (with `credential_identifiers`) from `Session.Extra` into the token response extras
- `CanSkipClientAuth` returns `false`

The token endpoint logic can live in a separate file within the same `fosite/handler/rar/` package (e.g., `token_handler.go`). The `RARFactory` returns the single `RARHandler` struct, and `Compose()` type-asserts it to all three handler interfaces for registration.

## Scope and RAR Precedence

- Both `scope` and `authorization_details` are processed independently
- Per OIDC4VCI §5.1.2, if both request the same Credential type, the `authorization_details` version is authoritative — but note this precedence rule is defined for the **Credential Issuer**, not the AS
- The AS does not reject requests that contain both — it processes each mechanism on its own terms and passes both through to the consent flow and token response
- The Credential Issuer applies the precedence rule when consuming the introspection response

## Config Provider

```go
type RARConfigProvider interface {
    GetRAREnabled(ctx context.Context) bool
    GetRARTypesSupported(ctx context.Context) []string
}
```

Config keys in `driver/config/`:
- `KeyRAREnabled` → `bool`
- `KeyRARTypesSupported` → `[]string` (default: `["openid_credential"]`)

## Factory

`fosite/compose/compose_rar.go`:

```go
func RARFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
    return &rar.RARHandler{
        Config: config.(rar.RARConfigProvider),
    }
}
```

Registered in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyRAREnabled`. The `Compose()` function will type-assert the result to `AuthorizeEndpointHandler`, `PushedAuthorizeEndpointHandler`, and `TokenEndpointHandler`, registering it in all three handler lists.

## Error Codes

Per RFC 9396 §5, the AS MUST use the dedicated `invalid_authorization_details` error code (not `invalid_request`) when rejecting invalid `authorization_details`. This is a registered OAuth extension error (RFC 9396 §14.6) applicable at both the authorization endpoint and the token endpoint.

- **`invalid_authorization_details`** — Malformed `authorization_details` JSON (parse failure)
- **`invalid_authorization_details`** — Missing `type` field in authorization_details object
- **`invalid_authorization_details`** — Unknown `type` value (not in `GetRARTypesSupported()`)
- **`invalid_authorization_details`** — Missing `credential_configuration_id` for `openid_credential` type
- **`invalid_authorization_details`** — Invalid `credential_configuration_id` (not recognized)
- **`invalid_authorization_details`** — Token request `credential_configuration_id` subset violation (not previously authorized)

Note: This requires defining a new `fosite.RFC6749Error` constant for `invalid_authorization_details` since it does not exist in upstream fosite.

## Discovery Metadata

In `oauth2/handler.go` → `oidcConfiguration`:

```go
AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`
```

Populated when `GetRAREnabled(ctx)` returns true. Value comes from `GetRARTypesSupported(ctx)`.

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — `AuthorizeEndpointHandler` and `PushedAuthorizeEndpointHandler` interfaces, consent flow types, session `Extra` map
- [03-issuer-integration-boundary.md](../03-issuer-integration-boundary.md) — `authorization_details` end-to-end flow, `credential_identifiers` ownership by Consent Node
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Consent type extensions touch upstream files, merge conflict handling
- [feature-pre-authorized-code.md](feature-pre-authorized-code.md) — Pre-authorized codes carry `authorization_details` from stored grant data
- [feature-par.md](feature-par.md) — RAR validation at PAR endpoint
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Properties 6–11 (RAR parsing, subset validation, round-trip persistence, credential_identifiers, consent flow-through, scope precedence)
