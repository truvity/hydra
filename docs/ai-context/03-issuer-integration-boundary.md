# Issuer Integration Boundary — AS ↔ Credential Issuer

## Purpose

Defines the system boundary between the Hydra Authorization Server (AS) and the external Credential Issuer microservice. Clarifies what each component owns, how data flows between them, and where integration points exist.

## System Boundary

### Hydra AS Owns
- OAuth 2.0 / OIDC authorization flows (`/oauth2/auth`, `/oauth2/token`, `/oauth2/par`)
- PAR (RFC 9126) — `fosite/handler/par/`
- DPoP proof validation and token binding (RFC 9449) — `fosite/handler/dpop/`
- Pre-Authorized Code grant type — `fosite/handler/preauth/`
- RAR (`authorization_details`) parsing and validation — `fosite/handler/rar/`
- Wallet Attestation client authentication — `fosite/handler/wallet_attestation/`
- Consent flow orchestration (challenge/accept via Consent Node)
- Token issuance (access tokens, refresh tokens, ID tokens)
- Token introspection (`/oauth2/introspect`)
- AS discovery metadata (`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`)

### External Credential Issuer Owns
- Verifiable Credential assembly and signing
- Credential Endpoint (`/credential`)
- Batch Credential Endpoint (`/batch_credential`)
- Nonce Endpoint (`/nonce`)
- Deferred Credential Endpoint (`/deferred_credential`)
- Notification Endpoint (`/notification`)
- Credential Issuer metadata (`/.well-known/openid-credential-issuer`)
- Credential Offer generation (including Pre-Authorized Codes via AS admin API)

### Hard Rule
**The AS NEVER handles Credential Requests, Credential Endpoints, or Credential Issuer metadata.** These belong exclusively to the Credential Issuer. The AS issues access tokens; the Credential Issuer consumes them.

## Data Flow: `authorization_details`

End-to-end flow of `authorization_details` through the system:

1. **PAR / Authorization Request** — Wallet sends `authorization_details` parameter with `type=openid_credential` and `credential_configuration_id`
2. **RAR Handler** (`fosite/handler/rar/`) — Parses and validates the JSON array, checks `type` and `credential_configuration_id` values
3. **Stored alongside authorize request** — Validated `authorization_details` persisted with the authorization session
4. **Consent Challenge** — `OAuth2ConsentRequest.AuthorizationDetails` (`flow/consent_types.go`) carries the parsed data to the Consent Node
5. **Consent Node renders credential-specific UI** — External Login/Consent app reads `authorization_details` to show which credentials are being requested
6. **Consent Accept** — Consent Node returns `AcceptOAuth2ConsentRequest.AuthorizationDetails` with added `credential_identifiers` per credential configuration
7. **Session merge** — `authorization_details` (now enriched with `credential_identifiers`) merged into `Session.Extra["authorization_details"]` (`oauth2/session.go`)
8. **Token Response** — Token endpoint includes `authorization_details` array in the response body (via response extras)
9. **Introspection** — Credential Issuer calls `/oauth2/introspect` with the access token, reads `authorization_details` and `credential_identifiers` from the introspection response

## `credential_identifiers` Ownership

`credential_identifiers` are **set by the Consent Node (or Token Hook), NOT by the AS itself**. The AS propagates them:

- The Consent Node determines which specific credential instances to bind to the authorization, based on the `credential_configuration_id` values and user consent decisions
- The Consent Node returns `credential_identifiers` inside `AcceptOAuth2ConsentRequest.AuthorizationDetails`
- The AS merges them into the session without interpreting or validating their content
- Alternatively, the Token Hook (`oauth2/token_hook.go`) can set or modify `credential_identifiers` in `Session.Extra["authorization_details"]` before the token response is finalized
- The Credential Issuer uses `credential_identifiers` from the introspection response to determine which credentials to issue

## Data Flow: `issuer_state`

1. **Authorize / PAR Request** — Wallet includes `issuer_state` as a form parameter (opaque string from a Credential Offer)
2. **Stored alongside authorize request** — AS extracts `issuer_state` from the request form and persists it with the authorization session
3. **Consent Challenge** — `OAuth2ConsentRequest` includes `issuer_state` so the Consent Node can read it
4. **Consent Node uses for context binding** — The Login/Consent app can use `issuer_state` to correlate the authorization request with a previously issued Credential Offer
5. The AS treats `issuer_state` as opaque and untrusted — no security decisions are based on it without additional validation

## Token Hook Integration (`oauth2/token_hook.go`)

The Token Hook is called for **all grant types** (including Pre-Authorized Code) before the token response is finalized:

- `TokenHookRequest` sends the full `Session` (including `Extra` with `authorization_details`) to the configured webhook URL
- The external webhook can inspect `authorization_details`, `credential_identifiers`, and any other session data
- The webhook response (`TokenHookResponse.Session.AccessToken`) **overwrites** `Session.Extra` — the webhook can modify `credential_identifiers` or add additional claims
- This is the primary extension point for external services to influence token content without modifying AS code

```
TokenHookRequest.Session.Extra["authorization_details"] → webhook reads/modifies →
TokenHookResponse.Session.AccessToken["authorization_details"] → overwrites Session.Extra
```

## Introspection Endpoint

The Credential Issuer validates access tokens by calling the AS introspection endpoint (`/oauth2/introspect`):

- **`authorization_details`** — Available in the introspection response via session extra claims. Contains the `credential_configuration_id` and `credential_identifiers` that the Credential Issuer needs to determine which credentials to issue.
- **DPoP `jkt` confirmation** — Available in the access token claims (set by the DPoP handler). The Credential Issuer validates the DPoP proof from the Wallet against this `jkt` value when receiving a Credential Request.
- **Scopes** — Standard `scope` claim available for scope-based credential requests.
- **Token type** — `DPoP` when the token is DPoP-bound; `Bearer` otherwise.

The introspection endpoint is an **admin endpoint** (`oauth2/handler.go` → `SetAdminRoutes`), meaning only trusted services (like the Credential Issuer) should have access.

## DPoP `jkt` Confirmation

DPoP token binding creates a chain of trust from Wallet to Credential Issuer:

1. **Token Request** — Wallet sends DPoP proof JWT with its public key in the `jwk` header
2. **DPoP Handler** (`fosite/handler/dpop/`) — Validates the proof, extracts the public key, computes `jkt` (JWK Thumbprint per RFC 7638)
3. **Access Token Claims** — `jkt` stored as a confirmation claim (`cnf.jkt`) in the access token session
4. **Credential Request** — Wallet sends a new DPoP proof (bound to the Credential Endpoint URL) alongside the access token
5. **Credential Issuer validates** — Introspects the access token to get `jkt`, validates the Wallet's DPoP proof against it. If the proof's public key doesn't match `jkt`, the request is rejected.

The AS is responsible for steps 1–3. The Credential Issuer is responsible for steps 4–5. The AS never sees the Credential Request.
