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

## Spec 1: `oidc4vci-rar-consent`

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

Spec 1 (oidc4vci-rar-consent) MUST be completed first. It provides:
- Config infrastructure (provider interface pattern, `HAIPConfigProvider`)
- Session.Extra propagation patterns established

## Scope

This spec covers:
1. DPoP handler (`fosite/handler/dpop/`) implementing `TokenEndpointHandler` and `PushedAuthorizeEndpointHandler`
2. Full RFC 9449 §4.3 proof validation checklist (12 checks)
3. DPoP token binding: compute `jkt` (JWK Thumbprint per RFC 7638), store as `cnf.jkt` in session, set `token_type=DPoP`
4. DPoP nonce exchange: `DPoP-Nonce` header, `use_dpop_nonce` error
5. JTI replay detection via `DPoPNonceStorage`
6. Authorization code binding via `dpop_jkt` parameter (RFC 9449 §10) and DPoP header on PAR requests (§10.1)
7. Refresh token DPoP binding for public clients (RFC 9449 §5)
8. DPoP config provider interface and config keys (`KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`)
9. DPoP compose factory (`fosite/compose/compose_dpop.go`)
10. New error constants: `ErrInvalidDPoPProof`, `ErrUseDPoPNonce`
11. Storage interface `DPoPNonceStorage` and DB table `hydra_oauth2_dpop_jti`
12. Database migration for `hydra_oauth2_dpop_jti`
13. SQL persistence implementation in `persistence/sql/`
14. Feature documentation in `docs/features/` describing what was implemented, configuration options, proof validation checklist, error codes, nonce exchange flow, and references to RFC 9449 and design docs

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-dpop.md]] — Full DPoP handler design, storage interface, PAR integration, refresh token binding
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — TokenEndpointHandler interface, compose factory pattern
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — DPoP jkt confirmation chain
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — DB migration strategy, isolated handler directory
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements H1, H6
- #[[file:docs/ai-context/features/feature-par.md]] — DPoP at PAR endpoint (dpop_jkt binding)

## Requirements Covered

- Requirement 4: DPoP (4.1–4.10)
- Requirement 14: ES256 Algorithm Support (14.1)

## Correctness Properties

- Property 12: DPoP Binding and Token Type
- Property 13: DPoP Proof Validation
- Property 14: DPoP Nonce Exchange

## Implementation Constraints

- Cross-cutting handler: `CanHandleTokenEndpointRequest` returns true when `DPoP` header present (not grant-type specific)
- `CanSkipClientAuth` always returns false
- Handler also implements `PushedAuthorizeEndpointHandler` for dpop_jkt extraction
- ES256 MUST be in default `dpop_signing_alg_values_supported`
- New handler in `fosite/handler/dpop/` — isolated from upstream
- New DB table `hydra_oauth2_dpop_jti` with `nid` column for multi-tenancy
- Register factory in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyDPoPEnabled`
- Use `pgregory.net/rapid` for property-based tests
- As a final task, create `docs/features/dpop.md` documenting the implemented feature: what it does, configuration keys and defaults, DPoP proof validation checklist, error codes, nonce exchange, dpop_jkt binding, refresh token binding rules, and references to RFC 9449 and the design docs in `docs/ai-context/`
```

---

## Spec 3: `oidc4vci-preauth`

### Prompt

```
Create a Kiro spec named "oidc4vci-preauth" for implementing the Pre-Authorized Code grant type (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) in the Hydra AS fork.

## Prerequisites

Spec 1 (oidc4vci-rar-consent) MUST be completed first. It provides:
- `authorization_details` session propagation and token response extras
- Config infrastructure patterns

Spec 2 (oidc4vci-dpop) SHOULD be completed first (DPoP can bind tokens issued via this grant), but is not strictly required — the Pre-Auth handler does not call DPoP directly; DPoP decorates the response independently.

## Scope

This spec covers:
1. Pre-Authorized Code handler (`fosite/handler/preauth/`) implementing `TokenEndpointHandler`
2. Grant type: `urn:ietf:params:oauth:grant-type:pre-authorized_code`
3. `HandleTokenEndpointRequest`: validate `pre-authorized_code`, check `tx_code` (if required), enforce single-use and expiry
4. `PopulateTokenEndpointResponse`: issue access token, set `authorization_details` with `credential_identifiers` in response extras
5. `CanSkipClientAuth`: true when anonymous access is enabled
6. Transaction Code (`tx_code`) validation with proper error codes per OIDC4VCI §6.3
7. Storage interface `PreAuthorizedCodeStorage` and data model `PreAuthorizedCodeData`
8. DB table `hydra_oauth2_preauth_code` and migration
9. SQL persistence implementation in `persistence/sql/`
10. Admin API endpoint for creating pre-authorized codes (`POST /admin/oauth2/preauth`)
11. Config provider and keys (`KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`)
12. Compose factory (`fosite/compose/compose_preauth.go`)
13. Feature documentation in `docs/features/` describing what was implemented, configuration options, admin API, grant flow, tx_code validation, error codes, and references to OIDC4VCI spec and design docs

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-pre-authorized-code.md]] — Full handler design, storage interface, data model, admin API, error codes
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — TokenEndpointHandler interface, CanSkipClientAuth pattern, compose factory
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — Pre-Authorized Code data flow, Credential Issuer creates codes via admin API
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — DB migration strategy
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements V1, V2, V8
- #[[file:docs/ai-context/00-architecture-overview.md]] — Pre-Authorized Code flow sequence diagram

## Requirements Covered

- Requirement 1: Pre-Authorized Code Grant Type (1.1–1.8)

## Correctness Properties

- Property 1: Pre-Authorized Code Valid Redemption
- Property 2: Pre-Authorized Code tx_code Validation
- Property 3: Pre-Authorized Code Anonymous Access
- Property 4: Pre-Authorized Code Single-Use Enforcement
- Property 5: Pre-Authorized Code Expiry Enforcement

## Implementation Constraints

- Grant-type-specific handler: `CanHandleTokenEndpointRequest` returns true only for `urn:ietf:params:oauth:grant-type:pre-authorized_code`
- `CanSkipClientAuth` returns true when `GetPreAuthorizedCodeAnonymousAccess(ctx)` is true
- tx_code error codes per OIDC4VCI §6.3: missing tx_code when expected → `invalid_request`; unexpected tx_code → `invalid_request`; wrong tx_code → `invalid_grant`
- New handler in `fosite/handler/preauth/` — isolated from upstream
- New DB table `hydra_oauth2_preauth_code` with `nid` column for multi-tenancy
- Admin API endpoint in `oauth2/handler.go` → `SetAdminRoutes`
- Register factory in `driver/registry_sql.go` via `ExtraFositeFactories()`, gated by `KeyPreAuthorizedCodeEnabled`
- Use `pgregory.net/rapid` for property-based tests
- As a final task, create `docs/features/pre-authorized-code.md` documenting the implemented feature: what it does, configuration keys and defaults, admin API for code creation, token exchange flow, tx_code validation rules, error codes, and references to OIDC4VCI spec sections and the design docs in `docs/ai-context/`
```

---

## Spec 4: `oidc4vci-wallet-attestation`

### Prompt

```
Create a Kiro spec named "oidc4vci-wallet-attestation" for implementing Wallet Attestation client authentication (`attest_jwt_client_auth`) in the Hydra AS fork.

## Prerequisites

Spec 1 (oidc4vci-rar-consent) MUST be completed first (config infrastructure).
This spec can run IN PARALLEL with Specs 2 or 3 — it has no code dependencies on DPoP or Pre-Auth.

## Scope

This spec covers:
1. Wallet Attestation authenticator (`fosite/handler/wallet_attestation/`) implementing client authentication
2. `OAuth-Client-Attestation` header: parse JWT, validate `x5c` certificate chain against trust anchors, verify signature, validate `exp`, match `sub` to `client_id`, extract `cnf`
3. `OAuth-Client-Attestation-PoP` header: verify signature using key from attestation's `cnf`, validate `aud` (AS issuer), `iat` freshness, `jti` uniqueness
4. HAIP-specific rules: trust anchor NOT in `x5c` chain, signing cert NOT self-signed, `sub` shared across wallet instances
5. Registration as `ClientAuthenticationStrategy` extension
6. Config provider and keys (`KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`)
7. ES256 algorithm support for both attestation and PoP JWT validation
8. Feature documentation in `docs/features/` describing what was implemented, configuration options, authentication flow, validation rules, HAIP-specific rules, error codes, and references to HAIP spec and design docs

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-wallet-attestation.md]] — Full authentication flow, validation rules, HAIP rules, integration options
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — ClientAuthenticationStrategyProvider, Fosite.AuthenticateClient()
- #[[file:docs/ai-context/03-issuer-integration-boundary.md]] — Wallet as OAuth 2.0 Client
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements H5, H10
- #[[file:docs/ai-context/features/feature-par.md]] — Wallet Attestation at PAR endpoint uses same client auth pipeline

## Requirements Covered

- Requirement 9: Wallet Attestation Client Authentication (9.1–9.5)
- Requirement 14: ES256 Algorithm Support (14.2)

## Correctness Properties

- Property 20: Wallet Attestation Validation

## Implementation Constraints

- All validation failures return `invalid_client` (OAuth 2.0 convention)
- The same auth pipeline applies to both PAR and Token endpoints — no PAR-specific changes needed
- Trust anchors loaded from PEM config
- New handler in `fosite/handler/wallet_attestation/` — isolated from upstream
- May need to extend `fosite/client_authentication.go` (upstream-touching) to add the new auth method check
- Use `pgregory.net/rapid` for property-based tests
- As a final task, create `docs/features/wallet-attestation.md` documenting the implemented feature: what it does, configuration keys and defaults, authentication flow (attestation + PoP), validation rules, HAIP-specific constraints, error codes, and references to HAIP spec, OIDC4VCI Appendix E, and the design docs in `docs/ai-context/`
```

---

## Spec 5: `oidc4vci-haip-metadata`

### Prompt

```
Create a Kiro spec named "oidc4vci-haip-metadata" for implementing HAIP enforcement (PAR + PKCE S256), RFC 9207 authorization response issuer identifier, and AS discovery metadata extensions in the Hydra AS fork.

## Prerequisites

ALL previous specs (1–4) MUST be completed first. This is the capstone spec that:
- Wires HAIP enforcement config to existing PAR and PKCE handlers
- Adds RFC 9207 `iss` to authorize responses
- Aggregates all feature flags into discovery metadata

## Scope

This spec covers:

### HAIP Enforcement
1. `KeyHAIPEnforced` config integration: when true, `EnforcePushedAuthorize()` returns true, `GetEnablePKCEPlainChallengeMethod()` returns false, `GetEnforcePKCE()` returns true
2. No new handlers — config-driven overrides on existing PAR and PKCE handlers

### RFC 9207 Authorization Response Issuer Identifier
3. Add `iss` parameter to success responses in `fosite/authorize_write.go` → `WriteAuthorizeResponse()`
4. Add `iss` parameter to error responses in `fosite/authorize_error.go` → `WriteAuthorizeError()`
5. Config key `KeyAuthResponseIssParameterEnabled` with HAIP auto-enable
6. Value from `Configurator.GetIDTokenIssuer(ctx)`

### Discovery Metadata Extensions
7. New struct fields on `oidcConfiguration` in `oauth2/handler.go`:
   - `pushed_authorization_request_endpoint` (PAR endpoint URL)
   - `require_pushed_authorization_requests` (PAR enforcement)
   - `pre-authorized_grant_anonymous_access_supported` (Pre-Auth)
   - `authorization_details_types_supported` (RAR)
   - `dpop_signing_alg_values_supported` (DPoP)
   - `authorization_response_iss_parameter_supported` (RFC 9207)
8. Modifications to existing dynamic lists:
   - `grant_types_supported` += `urn:ietf:params:oauth:grant-type:pre-authorized_code`
   - `token_endpoint_auth_methods_supported` += `attest_jwt_client_auth`
   - `code_challenge_methods_supported` → `["S256"]` only when HAIP enforced
9. All fields conditionally populated based on feature config flags
10. Conformance with RFC 8414
11. Feature documentation in `docs/features/` describing what was implemented: HAIP enforcement behavior, RFC 9207 iss parameter, all metadata fields added, configuration keys, and references to RFC 9126, RFC 9207, RFC 8414, HAIP spec, and the design docs

## Key Design References

Read these documents for authoritative design details:
- #[[file:docs/ai-context/features/feature-metadata-extensions.md]] — Full metadata extensions design, conditional population logic, RFC 8414 conformance
- #[[file:docs/ai-context/features/feature-rfc9207-iss.md]] — RFC 9207 implementation, inline modification approach, affected code paths
- #[[file:docs/ai-context/features/feature-par.md]] — HAIP PAR enforcement, PKCE S256 enforcement, config integration
- #[[file:docs/ai-context/01-hydra-internal-design.md]] — oidcConfiguration struct, discoverOidcConfiguration(), Configurator interface
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Merge conflict handling for upstream-touching files
- #[[file:docs/ai-context/02-oidc4vci-as-requirements.md]] — Requirements H2, H3, H4, V8

## Requirements Covered

- Requirement 7: PAR Enforcement for HAIP (7.1–7.3)
- Requirement 8: RFC 9207 Authorization Response Issuer Identifier (8.1–8.3)
- Requirement 10: AS Metadata Extensions (10.1–10.6)
- Requirement 11: PKCE S256 Enforcement for HAIP (11.1–11.3)
- Requirement 12: Refresh Token Support (12.1–12.2) — verify authorization_details survives refresh

## Correctness Properties

- Property 18: HAIP PAR Enforcement
- Property 19: Authorization Response iss Parameter
- Property 21: HAIP PKCE S256 Enforcement
- Property 22: Refresh Token Preserves authorization_details
- Property 24: Refresh Token Issuance in Credential Flows

## Implementation Constraints

- RFC 9207 changes touch upstream files (`fosite/authorize_write.go`, `fosite/authorize_error.go`) — keep changes minimal
- Metadata changes touch `oauth2/handler.go` (HIGH conflict risk) — group in marked section
- HAIP enforcement is config-driven — no new handler code, just config provider overrides
- Keep existing experimental VC fields (`CredentialsEndpointDraft00`, `CredentialsSupportedDraft00`) as-is
- Use `pgregory.net/rapid` for property-based tests
- As a final task, create `docs/features/haip-metadata.md` documenting the implemented feature: HAIP enforcement (PAR + PKCE S256), RFC 9207 iss parameter behavior, all new discovery metadata fields with their conditions, configuration keys and defaults, and references to RFC 9126, RFC 9207, RFC 8414, RFC 9449, RFC 9396, HAIP spec, and the design docs in `docs/ai-context/`
```
