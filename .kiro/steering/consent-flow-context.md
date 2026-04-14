---
inclusion: fileMatch
fileMatchPattern: "flow/**,consent/**"
---

# Consent Flow Context

When working on consent flow types or consent handler code, follow these patterns.

## Consent Types (`flow/consent_types.go`)

- `OAuth2ConsentRequest` — sent to Consent Node as challenge. Key fields: `Challenge`, `RequestedScope`, `RequestedAudience`, `Client`, `Context`, `OpenIDConnectContext`
- `AcceptOAuth2ConsentRequest` — returned by Consent Node. Key fields: `GrantedScope`, `GrantedAudience`, `Session`, `Context`
- `AcceptOAuth2ConsentRequestSession` — `AccessToken map[string]interface{}` merged into `Session.Extra`, `IDToken map[string]interface{}` merged into ID token claims

## OIDC4VCI Extensions

These fields are being added for OIDC4VCI support:
- `OAuth2ConsentRequest.AuthorizationDetails` (`sqlxx.JSONRawMessage`) — RAR data from authorize request
- `AcceptOAuth2ConsentRequest.AuthorizationDetails` (`sqlxx.JSONRawMessage`) — enriched RAR data with `credential_identifiers`
- `OAuth2ConsentRequest.IssuerState` (`string`) — opaque issuer_state from Credential Offer

After consent accept, `authorization_details` is merged into `Session.Extra["authorization_details"]` and flows through to token response and introspection.

## Merge Conflict Warning

`flow/consent_types.go` is an upstream file. Add new fields at the end of structs before the closing brace. Mark with comments: `// OIDC4VCI extension`

## Key References

- #[[file:docs/ai-context/features/feature-rar.md]] — RAR consent integration design
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — authorization_details data flow
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Merge conflict handling
