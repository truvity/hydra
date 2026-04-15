# Feature: RAR & Consent Extensions (OIDC4VCI)

## Overview

This feature implements the foundational OIDC4VCI infrastructure for the Hydra AS fork:

- **Rich Authorization Requests (RFC 9396)** — A Fosite handler (`fosite/handler/rar/`) that parses and validates `authorization_details` on authorize, PAR, and token endpoints.
- **Consent flow extensions** — New `AuthorizationDetails` and `IssuerState` fields on consent types, enabling `authorization_details` propagation through the consent challenge/accept cycle.
- **`issuer_state` parameter** — Opaque pass-through from authorization/PAR requests to the Consent Node for Credential Offer context binding.
- **Scope-based credential requests** — The AS processes `scope` and `authorization_details` independently, passing both through without conflict.
- **HAIP config infrastructure** — `KeyHAIPEnforced` config key defined here; enforcement behavior is wired in Spec 5 (`oidc4vci-haip-metadata`).

All other OIDC4VCI specs depend on the components built here. The scope is strictly the Authorization Server role — the Credential Issuer is a separate microservice and is out of scope.

## Why authorization_details? Scopes vs. RAR

Credentials can be requested via standard OAuth 2.0 scopes (e.g., `scope=UniversityDegree_jwt_vc_json`). In that case, the consent screen shows scopes like it always does, the Consent Node grants them, and the flow works without any `authorization_details` round-trip. This is the simplest path and works well for basic credential issuance.

`authorization_details` (RFC 9396) exists because scopes are flat strings. They can't express things like "I want a University Degree credential *from this specific issuer*, *in this specific format*, *with these specific claims*." For simple cases, scopes are fine. For complex cases (multiple credential types, specific configurations, format preferences), `authorization_details` carries the structured data that scopes can't.

The AS supports both mechanisms independently. When both are present in the same request, each is processed without conflict — the AS passes both through to the consent flow and token response.

## The Consent Node and credential_identifiers

Hydra is a "headless" OAuth2 server — it has no UI. It delegates all user-facing decisions (login screens, consent screens) to an external application called the Consent Node (or "Login & Consent Provider"). The Consent Node is a separate application you build and host. It receives consent challenges from Hydra via the admin API, shows the user what they're consenting to, and calls back to accept or reject.

When `authorization_details` is present, the Consent Node receives it in the consent challenge so it can render credential-specific consent UI (e.g., "App X wants to issue you a University Degree credential") instead of just showing scope names.

The OIDC4VCI spec (§6.2) requires the token response to include `credential_identifiers` — opaque strings that the Wallet later uses to request specific credentials from the Credential Issuer. The AS doesn't generate these identifiers. They must enter the OAuth2 flow through an external integration point.

There are three supported paths for getting `credential_identifiers` into the token response:

1. **Consent Node enrichment** — The Consent Node calls the Credential Issuer backend to obtain identifiers, then returns enriched `authorization_details` (with `credential_identifiers` added) in the consent accept response. This couples the Consent Node to the Issuer, which makes sense when the Consent Node is part of the Issuer application (a common OIDC4VCI deployment pattern).

2. **Token Hook** — Hydra's `token_hook` webhook (`oauth2.token_hook` config) fires before the token response is finalized and can modify `Session.Extra`. The Credential Issuer can run a webhook endpoint that adds `credential_identifiers` to the session. This keeps the Consent Node generic and decoupled from the Issuer.

3. **Credential endpoint time** — The Credential Issuer generates identifiers when the Wallet actually calls the credential endpoint, not at token time. In this case, `credential_identifiers` is never in the token response. The OIDC4VCI spec allows this — `credential_identifiers` in the token response is optional.

The AS is agnostic to which path is used. It propagates whatever is in `Session.Extra["authorization_details"]` into the token response. The warning log for missing `credential_identifiers` is informational only — it does not block the response, because path 3 is a valid deployment choice.

## Configuration

### Config Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rar.enabled` (`KeyRAREnabled`) | `bool` | `false` | Enable RAR handler registration in the Fosite pipeline |
| `rar.types_supported` (`KeyRARTypesSupported`) | `[]string` | `["openid_credential"]` | Supported `authorization_details` type values |
| `haip.enforced` (`KeyHAIPEnforced`) | `bool` | `false` | HAIP enforcement flag (infrastructure only — enforcement wired in Spec 5) |

### Provider Interfaces

- **`RARConfigProvider`** (`fosite/config.go`) — `GetRAREnabled(ctx) bool`, `GetRARTypesSupported(ctx) []string`
- **`HAIPConfigProvider`** (`fosite/config.go`) — `GetHAIPEnforced(ctx) bool`

Both are embedded in the Fosite `Configurator` interface and implemented on `driver/config.DefaultProvider`. The `fositex.Config` runtime adapter inherits these methods via its embedded `*config.DefaultProvider`.

### Example Configuration

```yaml
rar:
  enabled: true
  types_supported:
    - openid_credential
haip:
  enforced: false
```

## API Surface

### Affected Endpoints

| Endpoint | Change |
|----------|--------|
| `/oauth2/auth` | Accepts `authorization_details` and `issuer_state` parameters; RAR handler validates `authorization_details` |
| `/oauth2/par` | Same validation as `/oauth2/auth` via `PushedAuthorizeEndpointHandler` |
| `/oauth2/token` | Subset validation when `authorization_details` is in the token request; `authorization_details` included in response extras |
| `/.well-known/openid-configuration` | `authorization_details_types_supported` field when RAR is enabled |
| Admin consent GET | `authorization_details` and `issuer_state` included in `OAuth2ConsentRequest` |
| Admin consent PUT (accept) | Accepts `authorization_details` (with `credential_identifiers`) on `AcceptOAuth2ConsentRequest` |

### Request Parameters

**Authorization / PAR request:**
- `authorization_details` — JSON array of objects, each with a `type` field. For `type=openid_credential`, `credential_configuration_id` is required.
- `issuer_state` — Opaque string from a Credential Offer, forwarded to the Consent Node.

**Token request:**
- `authorization_details` — Optional. When present, the `credential_configuration_id` values must be a subset of the previously authorized set.

### Response Parameters

**Token response:**
- `authorization_details` — Array of authorized `authorization_details` objects (including `credential_identifiers` set by the Consent Node or Token Hook), propagated from `Session.Extra`.

**Discovery response (when RAR enabled):**
- `authorization_details_types_supported` — Array of supported type values from `GetRARTypesSupported()`.

## Error Codes

All RAR validation failures use the `invalid_authorization_details` error code (RFC 9396 §5, §14.6) with HTTP 400. The error constant is defined in `fosite/handler/rar/errors.go`.

| Condition | Hint |
|-----------|------|
| Malformed JSON | `"malformed authorization_details JSON"` |
| Missing `type` field | `"missing type field in authorization_details object"` |
| Unsupported `type` value | `"unsupported authorization_details type: {value}"` |
| Missing `credential_configuration_id` for `openid_credential` | `"credential_configuration_id required for openid_credential type"` |
| Token request `credential_configuration_id` not in authorized set | `"credential_configuration_id not previously authorized: {value}"` |

When `authorization_details` is absent from a request, the handler returns `nil` without error (not responsible).

## Consent Flow Changes

### New Fields

**`OAuth2ConsentRequest`** (`flow/consent_types.go`):
- `AuthorizationDetails` (`sqlxx.JSONRawMessage`, `db:"authorization_details"`) — Raw `authorization_details` from the authorize request
- `IssuerState` (`string`, `db:"issuer_state"`) — Opaque `issuer_state` from the request

**`AcceptOAuth2ConsentRequest`** (`flow/consent_types.go`):
- `AuthorizationDetails` (`sqlxx.JSONRawMessage`, `db:"consent_authorization_details"`) — Enriched `authorization_details` with `credential_identifiers` added by the Consent Node

### Consent Lifecycle

1. RAR handler validates `authorization_details` during authorize/PAR processing and stores it in the request form.
2. Consent challenge creation reads `authorization_details` and `issuer_state` from the request form → populates `OAuth2ConsentRequest`.
3. Consent Node reads `authorization_details` and `issuer_state`, renders credential-specific consent UI.
4. Consent Node returns `AcceptOAuth2ConsentRequest.AuthorizationDetails` enriched with `credential_identifiers`.
5. Consent accept processing unmarshals the enriched `authorization_details` and sets `Session.Extra["authorization_details"]`.

### Database Migration

Migration `persistence/sql/migrations/20260414120000000000_oidc4vci_consent_rar.up.sql` adds columns to `hydra_oauth2_flow`:
- `authorization_details` (JSON, nullable)
- `issuer_state` (VARCHAR, nullable, default empty)
- `consent_authorization_details` (JSON, nullable)

## Session Propagation

### `Session.Extra["authorization_details"]` Lifecycle

1. **Consent accept** — Enriched `authorization_details` (with `credential_identifiers`) is unmarshaled from `AcceptOAuth2ConsentRequest.AuthorizationDetails` into `Session.Extra["authorization_details"]` as `[]interface{}`.
2. **Token issuance** — `PopulateTokenEndpointResponse` copies `Session.Extra["authorization_details"]` into the access response extras.
3. **Token introspection** — Existing Hydra introspection code reads `Session.Extra` → `Introspection.Extra` (see below).
4. **Refresh token exchange** — `Session.Extra` is preserved across serialization/deserialization, so `authorization_details` persists in the new access token session.
5. **Token hook** — `Session.Extra` is sent to the webhook in `oauth2/token_hook.go`, allowing external services to inspect or modify `credential_identifiers`.

### Warning Log

When `authorization_details` of type `openid_credential` is present in the token response but an entry is missing `credential_identifiers` (or has an empty array), the AS logs a warning. The response is still produced — the warning is informational. The AS does not set `credential_identifiers` itself; the Consent Node or Token Hook is responsible.

## Introspection

`authorization_details` is available in the introspection response at `ext.authorization_details`. No code changes are needed — Hydra's admin introspection endpoint (`oauth2/handler.go` → `introspectOAuth2Token`) maps `Session.Extra` → `Introspection.Extra`, which is serialized as `"ext"` in JSON.

Example introspection response (relevant fields):
```json
{
  "active": true,
  "ext": {
    "authorization_details": [
      {
        "type": "openid_credential",
        "credential_configuration_id": "UniversityDegree_jwt_vc_json",
        "credential_identifiers": ["cred-id-1", "cred-id-2"]
      }
    ]
  }
}
```

The Credential Issuer reads `ext.authorization_details` from the introspection response. If a future spec requires `authorization_details` as a top-level introspection field (per RFC 9396 §9), that would require changes to the `Introspection` struct — explicitly out of scope here.

## Scope and RAR Independence

The AS processes `scope` and `authorization_details` independently:
- Requests containing both are accepted without conflict.
- Unknown scope values related to credential issuance are silently ignored.
- `authorization_details` takes precedence for overlapping credential types at the Credential Issuer level (per OIDC4VCI §5.1.2) — the AS passes both through.
- Concrete credential scope mappings are deferred to the Credential Issuer integration spec.

## File Layout

| File | Purpose |
|------|---------|
| `fosite/handler/rar/handler.go` | `RARHandler` struct, authorize/PAR validation |
| `fosite/handler/rar/token_handler.go` | Token endpoint subset validation and response propagation |
| `fosite/handler/rar/errors.go` | `ErrInvalidAuthorizationDetails` constant |
| `fosite/handler/rar/handler_test.go` | Unit and property-based tests |
| `fosite/compose/compose_rar.go` | `RARFactory` compose factory |
| `fosite/config.go` | `RARConfigProvider`, `HAIPConfigProvider` interfaces |
| `driver/config/provider.go` | `KeyRAREnabled`, `KeyRARTypesSupported`, `KeyHAIPEnforced` constants and provider methods |
| `flow/consent_types.go` | `AuthorizationDetails` and `IssuerState` fields on consent types |
| `flow/consent_rar_test.go` | Consent flow property-based tests |
| `oauth2/handler.go` | `authorization_details_types_supported` discovery metadata |
| `persistence/sql/migrations/` | Migration adding consent table columns |

## References

- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) — §5.1 (authorization_details), §6.2 (credential_identifiers)
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)
- Design doc: `.kiro/specs/oidc4vci-rar-consent/design.md`
- AI context: `docs/ai-context/features/feature-rar.md`
