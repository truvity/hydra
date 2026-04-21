# OIDC4VCI Implementation — Kiro Spec Prompts

Prompts for creating each implementation spec, in strict execution order.
Create specs one at a time. Each spec must be completed before starting the next (except Spec 4 which can run in parallel with Spec 2 or 3).

## Execution Order

```
Spec 1: oidc4vci-rar-consent (foundational — all others depend on this)
   ↓
Spec 2: oidc4vci-dpop (depends on Spec 1 for config infrastructure)
   ↓                    ↘
Spec 3: oidc4vci-preauth  Spec 4: oidc4vci-wallet-attestation (parallel track)
   ↓                    ↙
Spec 5: oidc4vci-haip-metadata (capstone — depends on all above)
```

---

## Spec 1: `oidc4vci-rar-consent` (IMPLEMENTED `.kiro/specs/oidc4vci-rar-consent`)

### Prompt

```
Create a Kiro spec named "oidc4vci-rar-consent" for implementing Rich Authorization Requests (RFC 9396), consent flow extensions, issuer_state propagation, and scope-based credential request support in the Hydra AS fork.

This is the FOUNDATIONAL spec — all other OIDC4VCI specs depend on the infrastructure built here.

## Scope

This spec covers:
1. RAR handler (`fosite/handler/rar/`) implementing `AuthorizeEndpointHandler`, `PushedAuthorizeEndpointHandler`, and `TokenEndpointHandler`
2. Consent type extensions: `AuthorizationDetails` field on `OAuth2ConsentRequest` and `AcceptOAuth2ConsentRequest` in `flow/consent_types.go`
3. `issuer_state` parameter: accept on authorize/PAR, store, forward to Consent Node via new field on `OAuth2ConsentRequest`
4. Session propagation: merge `authorization_details` (with `credential_identifiers` from Consent Node) into `Session.Extra`
5. Token response: propagate `authorization_details` with `credential_identifiers` into token response extras
6. Token request subset validation: validate `credential_configuration_id` subset at token endpoint
7. RAR config provider interface and config keys (`KeyRAREnabled`, `KeyRARTypesSupported`)
8. RAR compose factory (`fosite/compose/compose_rar.go`)
9. New `ErrInvalidAuthorizationDetails` fosite error constant
10. HAIP config infrastructure: `HAIPConfigProvider` interface and `KeyHAIPEnforced` config key (used by later specs)
11. Scope-based credential request handling (config for credential scope mappings)
12. Feature documentation in `docs/features/` describing what was implemented, configuration options, API surface, error codes, and references to relevant RFCs and design docs

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-rar.md]] — RAR handler design, consent integration, token subset validation, error codes
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — Fosite handler interfaces, compose factory pattern, session struct, consent flow types
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — authorization_details end-to-end data flow, credential_identifiers ownership
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Fork maintenance for upstream-touching files
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements V3, V4, V5, V6, V7, H8, H9
- #[[file:docs/ai-context/00-architecture-overview.md]] — System architecture

## Requirements Covered

From the existing requirements document (.kiro/specs/oidc4vci-as-capabilities/requirements.md):
- Requirement 2: Rich Authorization Requests (2.1–2.6)
- Requirement 3: Token Response Extensions (3.1–3.3)
- Requirement 5: issuer_state Parameter (5.1–5.3)
- Requirement 6: Scope-Based Credential Request (6.1–6.3)
- Requirement 13: Authorization Details Flow-Through to Consent Node (13.1–13.3)

## Correctness Properties

From the existing design document (.kiro/specs/oidc4vci-as-capabilities/design.md):
- Property 6: RAR Parsing and Validation
- Property 7: RAR Token Request Subset Validation
- Property 8: RAR Round-Trip Persistence
- Property 9: Token Response Contains credential_identifiers
- Property 10: RAR Flow-Through to Consent Node
- Property 11: RAR and Scope Precedence
- Property 15: issuer_state Round-Trip
- Property 16: Scope-Based Credential Request
- Property 17: Unknown Scope Tolerance
- Property 23: Consent Node Can Enrich authorization_details

## Implementation Constraints

- Follow Hydra coding guidelines from .kiro/steering/coding-rules.md
- New handler in `fosite/handler/rar/` — isolated from upstream
- Consent type changes in `flow/consent_types.go` — upstream-touching, add fields at end of structs
- Config keys in `driver/config/` — additive
- Factory in `fosite/compose/compose_rar.go` — additive file
- Register factory in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyRAREnabled`
- Use `pgregory.net/rapid` for property-based tests
- As a final task, create `docs/features/rar-consent.md` documenting the implemented feature: what it does, configuration keys and defaults, new endpoints/parameters, error codes, consent flow changes, and references to RFC 9396, OIDC4VCI spec sections, and the design docs in `docs/ai-context/`
```

---

## Spec 2: `oidc4vci-dpop`

### Prompt

```
Create a Kiro spec named "oidc4vci-dpop" for implementing DPoP (Demonstrating Proof of Possession — RFC 9449) token binding in the Hydra AS fork.

## Prerequisites

Spec 1 (oidc4vci-rar-consent) is COMPLETED. It established:
- Config provider interface pattern: define interface in `fosite/config.go`, embed in `Configurator` in `fosite/fosite.go`, implement on `DefaultProvider` in `driver/config/provider.go`, add schema to `spec/config.json`. `fositex.Config` embeds `*config.DefaultProvider` so new provider methods are inherited automatically.
- Factory registration pattern: define factory in `fosite/compose/compose_*.go`, register in `driver/registry_sql.go` via `ExtraFositeFactories()` gated by config flag. `fositex.Config.LoadDefaultHandlers` already handles type assertions for `AuthorizeEndpointHandler`, `TokenEndpointHandler`, `TokenIntrospector`, `RevocationHandler`, `DeviceEndpointHandler`, and `PushedAuthorizeEndpointHandler`.
- Error constant pattern: define as `var Err* = &fosite.RFC6749Error{...}` in handler package `errors.go` file.
- Session.Extra propagation: data stored in `session.Extra` flows to token response (via `responder.SetExtra`), introspection (via `Introspection.Extra` → JSON `"ext"`), refresh token exchange (preserved across serialization), and Token Hook.
- Introspection path: Hydra's admin introspection endpoint maps `session.Extra` → `Introspection.Extra` (JSON key `"ext"`). Custom data like `cnf.jkt` will appear at `ext.cnf.jkt` in the introspection response. Refer to `.kiro/steering/introspection-context.md` for the two introspection paths.
- `PopulateTokenEndpointResponse` pattern: called on ALL registered `TokenEndpointHandler` implementations during response phase regardless of `CanHandleTokenEndpointRequest` result. Must return `fosite.ErrUnknownRequest` when not responsible.
- Compile-time interface checks: `var _ fosite.TokenEndpointHandler = (*Handler)(nil)` in handler files.
- Copyright header: `// Copyright © 2026 Ory Corp` + `// SPDX-License-Identifier: Apache-2.0`

## Scope

This spec covers:
1. DPoP handler (`fosite/handler/dpop/`) implementing `TokenEndpointHandler` and `PushedAuthorizeEndpointHandler`
2. Full RFC 9449 §4.3 proof validation checklist (12 checks) — this is the most complex validation logic in the OIDC4VCI feature set
3. DPoP token binding: compute `jkt` (JWK Thumbprint per RFC 7638), store as `cnf.jkt` in `session.Extra["cnf"]`, set `token_type=DPoP`
4. DPoP nonce exchange: `DPoP-Nonce` response header, `use_dpop_nonce` error with fresh nonce in header
5. JTI replay detection via `DPoPNonceStorage` interface
6. Authorization code binding via `dpop_jkt` parameter (RFC 9449 §10) and DPoP header on PAR requests (§10.1)
7. Refresh token DPoP binding for public clients (RFC 9449 §5) — confidential clients NOT bound
8. DPoP config provider interface and config keys (`KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`)
9. DPoP compose factory (`fosite/compose/compose_dpop.go`)
10. New error constants: `ErrInvalidDPoPProof` (`invalid_dpop_proof`, HTTP 400), `ErrUseDPoPNonce` (`use_dpop_nonce`, HTTP 400)
11. Storage interface `DPoPNonceStorage` with methods: `IsJTIUsed`, `MarkJTIUsed`, `CreateDPoPNonce`, `ValidateDPoPNonce`
12. DB table `hydra_oauth2_dpop_jti` (jti PK, nid UUID, used_at TIMESTAMP, expires_at TIMESTAMP) with index on `(nid, expires_at)`
13. Database migration for `hydra_oauth2_dpop_jti` — additive table, no upstream conflict
14. SQL persistence implementation in `persistence/sql/` — implement `DPoPNonceStorage` on `Persister`
15. Feature documentation in `docs/features/dpop.md` describing what was implemented, configuration options, proof validation checklist, error codes, nonce exchange flow, and references to RFC 9449 and design docs

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-dpop.md]] — Full DPoP handler design, storage interface, PAR integration, refresh token binding, all 12 proof validation checks
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — TokenEndpointHandler interface, compose factory pattern, Session struct
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — DPoP jkt confirmation chain from AS to Credential Issuer via introspection
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — DB migration strategy, isolated handler directory, new table naming
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements H1, H6
- #[[file:docs/ai-context/features/feature-par.md]] — DPoP at PAR endpoint (dpop_jkt binding, §10.1)
- #[[file:docs/oidc4vci/rfc/oauth2-dpop-rfc9449.md]] — Full RFC 9449 text for proof validation checklist details
- #[[file:.kiro/steering/introspection-context.md]] — How session.Extra flows to introspection response (ext.cnf.jkt path)

Also reference the completed RAR spec for implementation patterns:
- #[[file:fosite/handler/rar/handler.go]] — Handler struct pattern, compile-time interface checks, shared validation helper
- #[[file:fosite/handler/rar/token_handler.go]] — TokenEndpointHandler implementation pattern, PopulateTokenEndpointResponse with ErrUnknownRequest
- #[[file:fosite/handler/rar/errors.go]] — Error constant definition pattern
- #[[file:fosite/compose/compose_rar.go]] — Factory pattern
- #[[file:docs/features/rar-consent.md]] — Feature documentation pattern

## Requirements Covered

From the parent requirements document (.kiro/specs/oidc4vci-as-capabilities/requirements.md):
- Requirement 4: DPoP (4.1–4.10)
- Requirement 14: ES256 Algorithm Support (14.1)

## Correctness Properties

From the parent design document (.kiro/specs/oidc4vci-as-capabilities/design.md):
- Property 12: DPoP Binding and Token Type
- Property 13: DPoP Proof Validation (covers all 12 RFC 9449 §4.3 checks)
- Property 14: DPoP Nonce Exchange

Additional properties to define in this spec's design:
- dpop_jkt authorization code binding (RFC 9449 §10)
- Refresh token DPoP binding for public clients vs confidential clients (RFC 9449 §5)
- JTI replay detection
- DPoP-Nonce header presence on error and success responses

## Implementation Constraints

- Cross-cutting handler: `CanHandleTokenEndpointRequest` returns true when `DPoP` header present in the HTTP request (not grant-type specific — decorates all grant types)
- `CanSkipClientAuth` always returns false — DPoP is token binding, not client authentication
- Handler also implements `PushedAuthorizeEndpointHandler` for dpop_jkt extraction at PAR endpoint
- ES256 MUST be in default `dpop_signing_alg_values_supported` list
- New handler in `fosite/handler/dpop/` — isolated from upstream, no merge conflict risk
- New DB table `hydra_oauth2_dpop_jti` with `nid` column for multi-tenancy (additive, no upstream conflict)
- Register factory in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyDPoPEnabled`
- Storage interface `DPoPNonceStorage` must be added to `persistence.Persister` aggregate interface
- New storage accessor `DPoPNonceStorage()` on `RegistrySQL` with lazy initialization pattern
- Use `pgregory.net/rapid` for property-based tests, minimum 100 iterations per property
- The DPoP handler needs access to the HTTP request headers (for the `DPoP` header) — verify how to access raw HTTP headers from `fosite.AccessRequester` (may need to pass via request context or form)
- `DPoP-Nonce` response header must be set BEFORE returning the error, so the HTTP response writer includes it — the handler must have access to the `http.ResponseWriter` or use a mechanism to attach headers to the error response
- As a final task, create `docs/features/dpop.md` documenting the implemented feature: what it does, configuration keys and defaults, DPoP proof validation checklist (all 12 checks), error codes, nonce exchange flow, dpop_jkt binding, refresh token binding rules (public vs confidential clients), introspection path (`ext.cnf.jkt`), and references to RFC 9449 and the design docs in `docs/ai-context/`

## Design Considerations to Address

The design phase should explicitly address these implementation questions:
1. How does the DPoP handler access the raw `DPoP` HTTP header? Fosite handlers receive `AccessRequester` which wraps the parsed form — the raw HTTP request may need to be passed via context or a custom interface.
2. How does the handler set the `DPoP-Nonce` response header? Fosite's error handling writes the response — the handler needs a mechanism to attach headers to error responses (e.g., via a custom error type that carries headers, or via response writer access).
3. Where is the `dpop_jkt` stored during PAR processing so it's available at the token endpoint? It needs to survive the PAR session → authorize request → token request lifecycle.
4. How does the handler detect public vs confidential clients for refresh token binding (RFC 9449 §5)?
5. What JWT library to use for DPoP proof parsing and validation? The project already uses `fosite/token/jwt` — verify it supports the needed operations (parse with explicit key from `jwk` header, validate `typ`, extract claims).
```

---

## Spec 3: `oidc4vci-preauth`

### Prompt

```
Create a Kiro spec named "oidc4vci-preauth" for implementing the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) in the Hydra AS fork.

## Prerequisites

Spec 1 (oidc4vci-rar-consent) is COMPLETED. It established:
- Config provider interface pattern: define interface in `fosite/config.go`, embed in `Configurator` in `fosite/fosite.go`, implement on `DefaultProvider` in `driver/config/provider.go`, add schema to `spec/config.json`, run `scripts/render-schemas.sh`. `fositex.Config` embeds `*config.DefaultProvider` so new provider methods are inherited automatically — add compile-time check in `fositex/config.go`.
- Factory registration pattern: define factory in `fosite/compose/compose_*.go`, register in `driver/registry_sql.go` via `ExtraFositeFactories()` gated by config flag.
- Error constant pattern: define as `var Err* = &fosite.RFC6749Error{...}` in handler package `errors.go` file.
- Session.Extra propagation: data stored in `session.Extra` flows to token response (via `responder.SetExtra`), introspection (via `Introspection.Extra` → JSON `"ext"`), refresh token exchange (preserved across serialization), and Token Hook.
- `PopulateTokenEndpointResponse` pattern: called on ALL registered `TokenEndpointHandler` implementations during response phase regardless of `CanHandleTokenEndpointRequest` result. Must return `fosite.ErrUnknownRequest` when not responsible.
- Compile-time interface checks: `var _ fosite.TokenEndpointHandler = (*Handler)(nil)`.
- Persistence pattern: define storage interface in handler package `storage.go`, embed in `persistence.Persister` aggregate interface (`persistence/definitions.go`), implement on SQL persister in `persistence/sql/persister_*.go`, add storage accessor on `RegistrySQL`.

Spec 2 (oidc4vci-dpop) is COMPLETED. It established:
- DPoP token binding is a cross-cutting handler that decorates all grant types independently. The Pre-Auth handler does NOT call DPoP — DPoP's `PopulateTokenEndpointResponse` runs after Pre-Auth's and binds the token if a `DPoP` header is present.
- HTTP header injection pattern: `InjectDPoPHeader` in `fosite/handler/dpop/inject.go` extracts raw HTTP headers and injects them into the request form before Fosite processes the request.
- DPoP-Nonce delivery via context pointer pattern.
- Stateless HMAC-based nonce generation on the persister.
- DB migration pattern: additive tables with `nid` column, composite PK `(signature, nid)`, `CREATE TABLE IF NOT EXISTS`.

## Scope

This spec covers:
1. Pre-Authorized Code handler (`fosite/handler/preauth/`) implementing `TokenEndpointHandler` — this is a grant-type-specific handler (unlike DPoP which is cross-cutting)
2. Grant type: `urn:ietf:params:oauth:grant-type:pre-authorized_code`
3. `CanHandleTokenEndpointRequest`: returns true only for the pre-authorized_code grant type
4. `CanSkipClientAuth`: returns true when `GetPreAuthorizedCodeAnonymousAccess(ctx)` is true — this is the ONLY handler in the OIDC4VCI feature set that can skip client auth
5. `HandleTokenEndpointRequest`: validate `pre-authorized_code` from form, load stored grant data, check redeemed/expired, validate `tx_code` if required, mark as redeemed
6. `PopulateTokenEndpointResponse`: issue access token via `CoreStrategy`, set `authorization_details` with `credential_identifiers` in response extras from stored session data, optionally issue refresh token
7. Transaction Code (`tx_code`) validation with precise error codes per OIDC4VCI §6.3:
   - Missing `tx_code` when expected → `invalid_request`
   - Unexpected `tx_code` when not expected → `invalid_request`
   - Wrong `tx_code` value → `invalid_grant`
8. Storage interface `PreAuthorizedCodeStorage` with `GetPreAuthorizedCodeSession`, `InvalidatePreAuthorizedCode`, `CreatePreAuthorizedCodeSession` (for admin API)
9. Data model `PreAuthorizedCodeData` with all fields from the design doc
10. DB table `hydra_oauth2_preauth_code` and migration (additive, no upstream conflict)
11. SQL persistence implementation in `persistence/sql/persister_preauth.go`
12. Admin API endpoint `POST /admin/oauth2/preauth` for creating pre-authorized codes — this is how the external Credential Issuer creates codes that Wallets later exchange at the token endpoint
13. Config provider `PreAuthorizedCodeConfigProvider` and keys (`KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`)
14. Compose factory (`fosite/compose/compose_preauth.go`) — note the factory needs a `strategy` parameter (unlike RAR/DPoP which don't issue tokens directly)
15. Feature documentation in `docs/features/pre-authorized-code.md`

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-pre-authorized-code.md]] — Full handler design, storage interface, data model, admin API, error codes, tx_code validation rules
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — TokenEndpointHandler interface, CanSkipClientAuth pattern, compose factory, Session struct
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — Pre-Authorized Code data flow, Credential Issuer creates codes via admin API, Token Hook integration
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — DB migration strategy, isolated handler directory
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements V1, V2, V8
- #[[file:docs/ai-context/00-architecture-overview.md]] — Pre-Authorized Code flow sequence diagram (Flow 2)
- #[[file:.kiro/steering/introspection-context.md]] — How session.Extra flows to introspection response (ext.authorization_details path)

Also reference the completed specs for implementation patterns:
- #[[file:fosite/handler/rar/handler.go]] — Handler struct pattern, compile-time interface checks
- #[[file:fosite/handler/rar/token_handler.go]] — TokenEndpointHandler implementation, PopulateTokenEndpointResponse with ErrUnknownRequest
- #[[file:fosite/handler/dpop/handler.go]] — Handler with storage dependency, DPoPConfigProvider type alias pattern
- #[[file:fosite/handler/dpop/storage.go]] — Storage interface definition pattern
- #[[file:fosite/handler/dpop/errors.go]] — Error constant definition pattern
- #[[file:fosite/compose/compose_dpop.go]] — Factory with storage type assertion
- #[[file:persistence/sql/persister_dpop.go]] — SQL persister implementation pattern
- #[[file:docs/features/rar-consent.md]] — Feature documentation pattern
- #[[file:docs/features/dpop.md]] — Feature documentation pattern

## Requirements Covered

From the parent requirements document (.kiro/specs/oidc4vci-as-capabilities/requirements.md):
- Requirement 1: Pre-Authorized Code Grant Type (1.1–1.8)

## Correctness Properties

From the parent design document (.kiro/specs/oidc4vci-as-capabilities/design.md):
- Property 1: Pre-Authorized Code Valid Redemption
- Property 2: Pre-Authorized Code tx_code Validation
- Property 3: Pre-Authorized Code Anonymous Access
- Property 4: Pre-Authorized Code Single-Use Enforcement
- Property 5: Pre-Authorized Code Expiry Enforcement

Additional properties to define in this spec's design:
- Admin API code creation and retrieval
- `authorization_details` propagation from stored grant data to token response
- Token Hook availability (session.Extra with authorization_details is available to hooks)
- Interaction with DPoP (DPoP binds the token independently if DPoP header present)

## Implementation Constraints

- Grant-type-specific handler: `CanHandleTokenEndpointRequest` returns true ONLY for `urn:ietf:params:oauth:grant-type:pre-authorized_code` — unlike DPoP which is cross-cutting
- `CanSkipClientAuth` returns true when `GetPreAuthorizedCodeAnonymousAccess(ctx)` is true — this is unique among OIDC4VCI handlers
- tx_code error codes per OIDC4VCI §6.3: missing tx_code when expected → `invalid_request`; unexpected tx_code → `invalid_request`; wrong tx_code → `invalid_grant`
- New handler in `fosite/handler/preauth/` — isolated from upstream, no merge conflict risk
- New DB table `hydra_oauth2_preauth_code` with `nid` column for multi-tenancy (additive, no upstream conflict)
- Storage interface `PreAuthorizedCodeStorage` must be added to `persistence.Persister` aggregate interface
- New storage accessor on `RegistrySQL` with lazy initialization pattern
- Admin API endpoint in `oauth2/handler.go` → `SetAdminRoutes` — this touches an upstream file, keep changes minimal and clearly marked
- The factory needs a `strategy` parameter (type-assert to `CoreStrategy`) because this handler issues access tokens directly (unlike RAR which only propagates session data, and DPoP which only decorates responses)
- Register factory in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyPreAuthorizedCodeEnabled`
- Use `pgregory.net/rapid` for property-based tests, minimum 100 iterations per property
- tx_code hashing: use bcrypt or SHA-256 for comparing tx_code against stored hash — the design doc says "hash the provided tx_code and compare with stored tx_code_hash" but doesn't specify the algorithm. The design phase should decide.
- The Pre-Auth handler issues access tokens via `CoreStrategy.GenerateAccessToken` — verify the correct strategy interface and how existing grant handlers (e.g., authorization code, device flow) obtain and use it
- Copyright header: `// Copyright © 2026 Ory Corp` + `// SPDX-License-Identifier: Apache-2.0`
- As a final task, create `docs/features/pre-authorized-code.md` documenting the implemented feature: what it does, configuration keys and defaults, admin API for code creation (request/response format), token exchange flow, tx_code validation rules, error codes, interaction with DPoP and RAR, introspection path (`ext.authorization_details`), and references to OIDC4VCI spec sections and the design docs in `docs/ai-context/`

## Design Considerations to Address

The design phase should explicitly address these implementation questions:
1. What `CoreStrategy` interface does the handler need for issuing access tokens? How do existing grant handlers (authorization code in `fosite/handler/oauth2/`, device flow in `fosite/handler/rfc8628/`) obtain the strategy? The factory likely needs to type-assert the `strategy` parameter.
2. How is the `pre-authorized_code` value generated and stored? The admin API creates the code — is it an HMAC-based signature (like authorization codes) or a random opaque string? The storage lookup uses the code value — is it stored as a signature/hash or plaintext?
3. How does the admin API endpoint authenticate? It's an admin endpoint (`SetAdminRoutes`) so it's protected by the admin API authentication (typically mTLS or API key). No additional auth needed in the handler.
4. How does `authorization_details` from the stored grant data flow into the token response? The handler populates `session.Extra["authorization_details"]` from `PreAuthorizedCodeData.AuthorizationDetails`, then `PopulateTokenEndpointResponse` sets it as a response extra. The RAR handler's `PopulateTokenEndpointResponse` also runs and propagates from session — verify there's no conflict.
5. How does the handler interact with the existing refresh token handler? If the client is authorized for `refresh_token` grant type, should the Pre-Auth handler issue a refresh token, or does the existing refresh token handler handle that?
6. What Swagger annotations are needed for the admin API endpoint?
```
```

---

## Spec 4: `oidc4vci-wallet-attestation`

### Prompt

```
Create a Kiro spec named "oidc4vci-wallet-attestation" for implementing Wallet Attestation client authentication (`attest_jwt_client_auth`) in the Hydra AS fork.

## Prerequisites

Spec 1 (oidc4vci-rar-consent) is COMPLETED. It established:
- Config provider interface pattern: define interface in `fosite/config.go`, embed in `Configurator` in `fosite/fosite.go`, implement on `DefaultProvider` in `driver/config/provider.go`, add schema to `spec/config.json`, run `scripts/render-schemas.sh`. `fositex.Config` embeds `*config.DefaultProvider` so new provider methods are inherited automatically — add compile-time check in `fositex/config.go`.
- Error constant pattern: define as `var Err* = &fosite.RFC6749Error{...}` in handler package `errors.go` file.
- Compile-time interface checks: `var _ SomeInterface = (*ConcreteType)(nil)`.

Specs 2 (DPoP) and 3 (Pre-Auth) are COMPLETED but this spec has NO code dependencies on them. Wallet Attestation is a client authentication method — it runs in the `AuthenticateClient` phase, before any `TokenEndpointHandler` or `PushedAuthorizeEndpointHandler` processes the request. However, note:
- The DPoP handler's `isPublicClient()` in `fosite/handler/dpop/handler.go` already treats `attest_jwt_client_auth` as a public client for refresh token DPoP binding purposes.
- The Pre-Auth handler's `CanSkipClientAuth` returns true for anonymous access — when Wallet Attestation is the auth method, `CanSkipClientAuth` returns false (Wallet Attestation IS authentication, just not credential-based).

## Scope

This spec covers:
1. Wallet Attestation authenticator in `fosite/handler/wallet_attestation/` — this is NOT a `TokenEndpointHandler` or `AuthorizeEndpointHandler`. It's a `ClientAuthenticationStrategy` that plugs into `Fosite.AuthenticateClient()`.
2. `OAuth-Client-Attestation` header validation: parse JWT, extract `x5c` JOSE header, build X.509 certificate chain, validate chain against configured trust anchors, verify JWT signature with leaf cert public key, validate `exp`, extract `sub` (must match `client_id`), extract `cnf` (confirmation key for PoP)
3. `OAuth-Client-Attestation-PoP` header validation: verify signature using key from attestation's `cnf`, validate `aud` (AS issuer identifier), `iat` freshness, `jti` uniqueness (replay protection)
4. HAIP-specific rules: trust anchor MUST NOT be in `x5c` chain, signing cert MUST NOT be self-signed, `sub` shared across wallet instances of same type
5. Integration into `fositex.Config.GetClientAuthenticationStrategy()` — currently returns `nil` (falls back to default). Must return a strategy that checks for Wallet Attestation headers first, then falls back to the default strategy.
6. Config provider `WalletAttestationConfigProvider` and keys (`KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`)
7. Trust anchor loading from PEM-encoded certificates in config
8. ES256 algorithm support for both attestation JWT and PoP JWT signature validation
9. PoP JWT `jti` replay protection (may reuse DPoP's JTI storage or define a separate mechanism)
10. Feature documentation in `docs/features/wallet-attestation.md`

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-wallet-attestation.md]] — Full authentication flow, validation rules, HAIP rules, integration options (standalone handler vs client_authentication.go extension)
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — ClientAuthenticationStrategyProvider, Fosite.AuthenticateClient(), DefaultClientAuthenticationStrategy
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — Wallet as OAuth 2.0 Client, client authentication at PAR and token endpoints
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements H5, H10
- #[[file:docs/ai-context/features/feature-par.md]] — Wallet Attestation at PAR endpoint uses same client auth pipeline
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Fork maintenance for upstream-touching files
- #[[file:.kiro/steering/introspection-context.md]] — Not directly relevant but useful for understanding session flow

Also reference the completed specs for implementation patterns:
- #[[file:fosite/handler/dpop/handler.go]] — `isPublicClient()` function already references `attest_jwt_client_auth`
- #[[file:fosite/handler/dpop/errors.go]] — Error constant definition pattern
- #[[file:fosite/handler/dpop/storage.go]] — Storage interface pattern (if JTI replay protection needs storage)
- #[[file:fositex/config.go]] — `GetClientAuthenticationStrategy()` currently returns nil — this is the integration point
- #[[file:fosite/client_authentication.go]] — `Fosite.AuthenticateClient()` and `DefaultClientAuthenticationStrategy()` — the existing auth pipeline
- #[[file:docs/features/dpop.md]] — Feature documentation pattern
- #[[file:docs/features/pre-authorized-code.md]] — Feature documentation pattern

## Requirements Covered

From the parent requirements document (.kiro/specs/oidc4vci-as-capabilities/requirements.md):
- Requirement 9: Wallet Attestation Client Authentication (9.1–9.5)
- Requirement 14: ES256 Algorithm Support (14.2)

## Correctness Properties

From the parent design document (.kiro/specs/oidc4vci-as-capabilities/design.md):
- Property 20: Wallet Attestation Validation

Additional properties to define in this spec's design:
- Attestation JWT x5c chain validation (chain terminates at trust anchor, trust anchor NOT in chain, leaf cert NOT self-signed)
- PoP JWT signature verification using cnf key from attestation
- PoP JWT `jti` replay protection
- `sub` to `client_id` matching
- Fallback to default authentication when Wallet Attestation headers are absent
- Same authentication behavior at both PAR and Token endpoints

## Implementation Constraints

- This is a CLIENT AUTHENTICATION method, not a token endpoint handler. It plugs into `Fosite.AuthenticateClient()` via `ClientAuthenticationStrategy`, not via the handler pipeline.
- All validation failures return `invalid_client` (OAuth 2.0 convention for client auth failures)
- The same auth pipeline applies to both PAR and Token endpoints — `Fosite.AuthenticateClient()` is called for both. No PAR-specific changes needed.
- Trust anchors loaded from PEM-encoded certificates in config. The config value is a list of PEM strings or file paths — the design phase should decide the format.
- The integration point is `fositex.Config.GetClientAuthenticationStrategy()` which currently returns `nil`. When Wallet Attestation is enabled, it must return a strategy function that: (a) checks for `OAuth-Client-Attestation` header, (b) if present, validates attestation + PoP, (c) if absent, falls back to `Fosite.DefaultClientAuthenticationStrategy()`.
- This requires `fositex.Config.GetClientAuthenticationStrategy()` to have access to the `Fosite` instance (for fallback) or to the default strategy. The design phase must resolve this circular dependency.
- New handler package in `fosite/handler/wallet_attestation/` — isolated from upstream, no merge conflict risk
- The `fositex/config.go` change (returning a non-nil strategy) is an upstream-touching modification — keep it minimal
- `fosite/client_authentication.go` itself should NOT be modified — the strategy override via config is the clean extension point
- PoP JWT `jti` replay protection needs a storage mechanism. Options: (a) reuse DPoP's `DPoPNonceStorage.IsJTIUsed/MarkJTIUsed`, (b) define a separate `WalletAttestationJTIStorage` interface, (c) use an in-memory cache with TTL. The design phase should decide.
- X.509 certificate chain validation uses Go's `crypto/x509` standard library — no new dependencies needed
- JWT parsing uses `go-jose/v4` (already a dependency from DPoP spec)
- Use `pgregory.net/rapid` for property-based tests, minimum 100 iterations per property
- Copyright header: `// Copyright © 2026 Ory Corp` + `// SPDX-License-Identifier: Apache-2.0`
- As a final task, create `docs/features/wallet-attestation.md` documenting the implemented feature: what it does, configuration keys and defaults, authentication flow (attestation JWT + PoP JWT), validation rules (x5c chain, signature, claims), HAIP-specific constraints (trust anchor not in chain, no self-signed certs, shared sub), error codes, and references to HAIP spec, OIDC4VCI Appendix E, and the design docs in `docs/ai-context/`

## Design Considerations to Address

The design phase should explicitly address these implementation questions:
1. How does the `ClientAuthenticationStrategy` function access the `Fosite` instance for fallback to `DefaultClientAuthenticationStrategy`? The strategy is a function `func(context.Context, *http.Request, url.Values) (Client, error)` — it needs a reference to the Fosite instance or the default strategy. Options: (a) closure capturing the Fosite instance, (b) the strategy function is a method on a struct that holds a reference, (c) pass the default strategy as a parameter during construction.
2. How are trust anchors loaded from config? The `KeyWalletAttestationTrustAnchors` config value could be: (a) a list of PEM-encoded certificate strings directly in the config YAML, (b) a list of file paths to PEM files, (c) a directory path containing PEM files. The design should pick one and specify the parsing logic.
3. How does the strategy extract the `client_id` from the request to match against the attestation's `sub`? The `client_id` may be in the form body (`form.Get("client_id")`) or derived from other auth methods. The strategy receives `(ctx, r, form)` so it can read `form.Get("client_id")`.
4. Should PoP JWT `jti` replay protection reuse DPoP's `DPoPNonceStorage` or have its own storage? Reusing DPoP storage is simpler but couples the two features. A separate interface is cleaner but adds another storage dependency. An in-memory TTL cache is simplest but doesn't work in multi-instance deployments.
5. How does the strategy return the authenticated `Client` object? It needs to look up the client by `client_id` from the client store. The strategy function receives the form (which has `client_id`) but needs access to the client store. This is another dependency the strategy needs — likely via the registry or a client manager interface.
6. What happens when Wallet Attestation is enabled but the request uses a different auth method (e.g., `client_secret_post`)? The strategy should check for the `OAuth-Client-Attestation` header first — if absent, fall back to the default strategy which handles `client_secret_post`, `client_secret_basic`, `private_key_jwt`, and `none`.
```

---

## Spec 5: `oidc4vci-haip-metadata`

### Prompt

```
Create a Kiro spec named "oidc4vci-haip-metadata" for implementing HAIP enforcement (PAR + PKCE S256), RFC 9207 authorization response issuer identifier, HAIP auto-enable of DPoP, and AS discovery metadata extensions in the Hydra AS fork.

## Prerequisites

ALL previous specs (1–4) are COMPLETED. This is the capstone spec that wires everything together. Here's what exists:

### From Spec 1 (RAR/Consent):
- `RARConfigProvider` with `GetRAREnabled(ctx)`, `GetRARTypesSupported(ctx)` — in `fosite/config.go`, embedded in `Configurator`
- `HAIPConfigProvider` with `GetHAIPEnforced(ctx)` — infrastructure only, enforcement NOT yet wired
- `authorization_details_types_supported` metadata field already added to `oidcConfiguration` struct and populated in `discoverOidcConfiguration()` when RAR enabled
- Config keys: `KeyRAREnabled`, `KeyRARTypesSupported`, `KeyHAIPEnforced` in `driver/config/provider.go`

### From Spec 2 (DPoP):
- `DPoPConfigProvider` with `GetDPoPEnabled(ctx)`, `GetDPoPSigningAlgValuesSupported(ctx)`, `GetDPoPNonceEnabled(ctx)`, `GetDPoPNonceLifespan(ctx)`, `GetDPoPProofMaxAge(ctx)`, `GetDPoPPARURLs(ctx)` — in `fosite/config.go`, embedded in `Configurator`
- Config keys: `KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, etc. in `driver/config/provider.go`
- Discovery metadata for DPoP (`dpop_signing_alg_values_supported`) NOT yet added — deferred to this spec

### From Spec 3 (Pre-Auth):
- `PreAuthorizedCodeConfigProvider` with `GetPreAuthorizedCodeEnabled(ctx)`, `GetPreAuthorizedCodeLifespan(ctx)`, `GetPreAuthorizedCodeAnonymousAccess(ctx)` — in `fosite/config.go`, embedded in `Configurator`
- Config keys: `KeyPreAuthorizedCodeEnabled`, etc. in `driver/config/provider.go`
- Discovery metadata for Pre-Auth (`pre-authorized_grant_anonymous_access_supported`, grant type in `grant_types_supported`) NOT yet added — deferred to this spec
- Pre-Auth is independent of HAIP — `KeyPreAuthorizedCodeEnabled` is NOT auto-enabled by HAIP

### From Spec 4 (Wallet Attestation):
- `WalletAttestationConfigProvider` with `GetWalletAttestationEnabled(ctx)`, `GetWalletAttestationTrustAnchors(ctx)` — in `fosite/config.go`, embedded in `Configurator`
- Config keys: `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors` in `driver/config/provider.go`
- Discovery metadata for Wallet Attestation (`attest_jwt_client_auth` in `token_endpoint_auth_methods_supported`) NOT yet added — deferred to this spec
- Wallet Attestation authenticator integrated via `fositex.Config.GetClientAuthenticationStrategy()` with `SetFositeInstance()` for fallback
- Refresh token binding via `RefreshBindingHandler` storing `wallet_attestation_cnf_jkt` in session

### Existing Hydra infrastructure:
- PAR handler in `fosite/handler/par/` with `PushedAuthorizeRequestConfigProvider.EnforcePushedAuthorize(ctx)` — already exists
- PKCE handler in `fosite/handler/pkce/` with `EnforcePKCEProvider.GetEnforcePKCE(ctx)` and `EnablePKCEPlainChallengeMethodProvider.GetEnablePKCEPlainChallengeMethod(ctx)` — already exists
- `oidcConfiguration` struct in `oauth2/handler.go` with `discoverOidcConfiguration()` — already has `authorization_details_types_supported` from Spec 1
- `fositex.Config` implements all config providers via embedded `*config.DefaultProvider`

## Scope

This spec covers:

### HAIP Enforcement (config-driven, no new handlers)
1. Wire `KeyHAIPEnforced` to override PAR enforcement: when `GetHAIPEnforced(ctx)` returns true, `EnforcePushedAuthorize(ctx)` returns true
2. Wire `KeyHAIPEnforced` to override PKCE enforcement: when `GetHAIPEnforced(ctx)` returns true, `GetEnforcePKCE(ctx)` returns true and `GetEnablePKCEPlainChallengeMethod(ctx)` returns false (S256 only)
3. Wire `KeyHAIPEnforced` to auto-enable DPoP: when `GetHAIPEnforced(ctx)` returns true, `GetDPoPEnabled(ctx)` returns true and ES256 is in `GetDPoPSigningAlgValuesSupported(ctx)`
4. Wire `KeyHAIPEnforced` to auto-enable RFC 9207 `iss` parameter
5. Note: `KeyHAIPEnforced` does NOT auto-enable Pre-Auth (Pre-Auth is independent of HAIP)
6. Note: `KeyHAIPEnforced` does NOT auto-enable Wallet Attestation (Wallet Attestation is independently configured)

### RFC 9207 Authorization Response Issuer Identifier
7. Add `iss` parameter to success responses in `fosite/authorize_write.go` → `WriteAuthorizeResponse()`
8. Add `iss` parameter to error responses in `fosite/authorize_error.go` → `WriteAuthorizeError()`
9. Config key `KeyAuthResponseIssParameterEnabled` with HAIP auto-enable
10. Config provider `AuthResponseIssConfigProvider` with `GetAuthResponseIssParameterEnabled(ctx) bool`
11. Value from `Configurator.GetIDTokenIssuer(ctx)` (already exists on Configurator)

### Discovery Metadata Extensions (all in `oauth2/handler.go`)
12. New struct fields on `oidcConfiguration`:
    - `pushed_authorization_request_endpoint` (string) — PAR endpoint URL
    - `require_pushed_authorization_requests` (bool) — PAR enforcement
    - `pre-authorized_grant_anonymous_access_supported` (bool) — Pre-Auth anonymous access
    - `dpop_signing_alg_values_supported` ([]string) — DPoP algorithms
    - `authorization_response_iss_parameter_supported` (bool) — RFC 9207
    - Note: `authorization_details_types_supported` already exists from Spec 1
13. Modifications to existing dynamic lists in `discoverOidcConfiguration()`:
    - `grant_types_supported` += `urn:ietf:params:oauth:grant-type:pre-authorized_code` when Pre-Auth enabled
    - `token_endpoint_auth_methods_supported` += `attest_jwt_client_auth` when Wallet Attestation enabled
    - `code_challenge_methods_supported` → `["S256"]` only when HAIP enforced (remove `"plain"`)
14. All new fields conditionally populated based on feature config flags with `omitempty` JSON tags
15. Conformance with RFC 8414

### Refresh Token Verification
16. Verify `authorization_details` survives refresh token exchange (existing behavior from Spec 1, just needs verification test)
17. Verify refresh tokens are issued in credential flows when client is eligible (existing behavior from Spec 3)

### Feature Documentation
18. `docs/features/haip-metadata.md` covering all of the above

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-metadata-extensions.md]] — Full metadata extensions design, conditional population logic, RFC 8414 conformance, `omitempty` behavior
- #[[file:docs/ai-context/features/feature-rfc9207-iss.md]] — RFC 9207 implementation, inline modification approach, affected code paths, HAIP auto-enable pattern
- #[[file:docs/ai-context/features/feature-par.md]] — HAIP PAR enforcement, PKCE S256 enforcement, config integration options (Option A preferred: extend `EnforcePushedAuthorize()`)
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — oidcConfiguration struct, discoverOidcConfiguration(), Configurator interface, PushedAuthorizeRequestConfigProvider
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Merge conflict handling for upstream-touching files
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements H2, H3, H4, V8

Also reference the completed feature docs for what each feature provides:
- #[[file:docs/features/rar-consent.md]] — RAR config, metadata field already added
- #[[file:docs/features/dpop.md]] — DPoP config, metadata field deferred to this spec
- #[[file:docs/features/pre-authorized-code.md]] — Pre-Auth config, metadata fields deferred to this spec, HAIP independence
- #[[file:docs/features/wallet-attestation.md]] — Wallet Attestation config, metadata field deferred to this spec

And the actual implementation files for the config providers:
- #[[file:fositex/config.go]] — All config provider compile-time checks, `GetClientAuthenticationStrategy()`, `SetFositeInstance()`
- #[[file:driver/config/provider.go]] — All `Key*` constants and `Get*` methods
- #[[file:oauth2/handler.go]] — `oidcConfiguration` struct, `discoverOidcConfiguration()`, existing RAR metadata population pattern

## Requirements Covered

From the parent requirements document (.kiro/specs/oidc4vci-as-capabilities/requirements.md):
- Requirement 7: PAR Enforcement for HAIP (7.1–7.3)
- Requirement 8: RFC 9207 Authorization Response Issuer Identifier (8.1–8.3)
- Requirement 10: AS Metadata Extensions (10.1–10.6)
- Requirement 11: PKCE S256 Enforcement for HAIP (11.1–11.3)
- Requirement 12: Refresh Token Support (12.1–12.2) — verify authorization_details survives refresh

## Correctness Properties

From the parent design document (.kiro/specs/oidc4vci-as-capabilities/design.md):
- Property 18: HAIP PAR Enforcement
- Property 19: Authorization Response iss Parameter
- Property 21: HAIP PKCE S256 Enforcement
- Property 22: Refresh Token Preserves authorization_details
- Property 24: Refresh Token Issuance in Credential Flows

Additional properties to define in this spec's design:
- HAIP auto-enable of DPoP (when HAIP enforced, DPoP is enabled with ES256)
- HAIP auto-enable of RFC 9207 iss parameter
- Discovery metadata reflects all feature flags correctly (each field present/absent based on config)
- `code_challenge_methods_supported` restricted to `["S256"]` under HAIP
- `grant_types_supported` includes pre-auth grant type when enabled
- `token_endpoint_auth_methods_supported` includes `attest_jwt_client_auth` when enabled

## Implementation Constraints

- RFC 9207 changes touch upstream files (`fosite/authorize_write.go`, `fosite/authorize_error.go`) — keep changes minimal, add `iss` parameter injection before the response mode switch
- Metadata changes touch `oauth2/handler.go` (HIGH conflict risk) — group all new struct fields in a clearly marked `// OIDC4VCI extension` section after existing fields; group population logic in a separate block
- HAIP enforcement is config-driven — modify `DefaultProvider` methods to check `KeyHAIPEnforced` and override individual settings. No new handler code needed.
- The HAIP override pattern: `GetDPoPEnabled(ctx)` returns `true` if either `KeyDPoPEnabled` is explicitly true OR `KeyHAIPEnforced` is true. Same pattern for PAR enforcement, PKCE enforcement, and RFC 9207 iss.
- Keep existing experimental VC fields (`CredentialsEndpointDraft00`, `CredentialsSupportedDraft00`) as-is — they're upstream
- `AuthResponseIssConfigProvider` is a new config provider interface — follow the established pattern (define in `fosite/config.go`, embed in `Configurator`, implement on `DefaultProvider`, compile-time check in `fositex/config.go`)
- The `iss` value comes from `Configurator.GetIDTokenIssuer(ctx)` which already exists — no new config key for the value itself
- `pushed_authorization_request_endpoint` URL is computed from config (e.g., `IssuerURL + "/oauth2/par"`) — verify how the PAR endpoint URL is derived
- Use `pgregory.net/rapid` for property-based tests, minimum 100 iterations per property
- Copyright header: `// Copyright © 2026 Ory Corp` + `// SPDX-License-Identifier: Apache-2.0`
- As a final task, create `docs/features/haip-metadata.md` documenting: HAIP enforcement behavior (what it auto-enables), RFC 9207 iss parameter (success + error responses), all new discovery metadata fields with their conditions, configuration keys and defaults, and references to RFC 9126, RFC 9207, RFC 8414, RFC 9449, RFC 9396, HAIP spec

## Design Considerations to Address

The design phase should explicitly address these implementation questions:
1. How to implement the HAIP override pattern on `DefaultProvider`? Option A (preferred per feature-par.md): each `Get*` method checks `KeyHAIPEnforced` as a fallback. E.g., `GetDPoPEnabled(ctx)` returns `p.getProvider(ctx).Bool(KeyDPoPEnabled) || p.getProvider(ctx).Bool(KeyHAIPEnforced)`. This is simple and doesn't require config mutation.
2. How to compute `pushed_authorization_request_endpoint` for metadata? The PAR endpoint is at `/oauth2/par` — derive from `IssuerURL` or `PublicURL`. Check if there's an existing method or if a new one is needed.
3. Should `require_pushed_authorization_requests` reflect the HAIP override or only the standalone `EnforcePushedAuthorize` config? If HAIP is enforced, PAR is required — the metadata should reflect this.
4. How to inject `iss` into authorize error responses? `WriteAuthorizeError` constructs `url.Values` from the error — the `iss` parameter needs to be added to these values before the redirect. Only for redirect errors — non-redirect errors (rendered as JSON) don't get `iss`.
5. Should the `AuthResponseIssConfigProvider` be a separate interface or merged into `HAIPConfigProvider`? A separate interface is cleaner (single responsibility) and follows the pattern of other providers.
6. How to handle the `code_challenge_methods_supported` restriction under HAIP? The existing `discoverOidcConfiguration()` hardcodes `["plain", "S256"]`. Under HAIP, this should be `["S256"]` only. The population logic needs to check `GetHAIPEnforced(ctx)` and conditionally exclude `"plain"`.
```
