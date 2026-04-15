# Implementation Plan: OIDC4VCI DPoP Token Binding (RFC 9449)

## Overview

Implement DPoP (Demonstrating Proof of Possession — RFC 9449) token binding for the Hydra AS fork. Tasks follow the dependency chain: error constants and config first, then storage interface, handler core (proof validation + PAR + token endpoint), factory and registry wiring, database migration and SQL persistence, endpoint handler changes for DPoP header injection and nonce delivery, and finally feature documentation. The DPoP handler is a cross-cutting `TokenEndpointHandler` that decorates all grant types — it does not own a grant type.

## Tasks

- [x] 1. Error constants and config infrastructure
  - [x] 1.1 Create `ErrInvalidDPoPProof` and `ErrUseDPoPNonce` in `fosite/handler/dpop/errors.go`
    - Define `var ErrInvalidDPoPProof = &fosite.RFC6749Error{...}` with `ErrorField: "invalid_dpop_proof"`, `CodeField: http.StatusBadRequest`, `DescriptionField: "The DPoP proof is invalid."`
    - Define `var ErrUseDPoPNonce = &fosite.RFC6749Error{...}` with `ErrorField: "use_dpop_nonce"`, `CodeField: http.StatusBadRequest`, `DescriptionField: "Authorization server requires nonce in DPoP proof."`
    - Add copyright header
    - _Requirements: 7.1, 7.2_

  - [x] 1.2 Define `DPoPConfigProvider` interface in `fosite/config.go`
    - Append `DPoPConfigProvider` interface with methods: `GetDPoPEnabled(ctx context.Context) bool`, `GetDPoPSigningAlgValuesSupported(ctx context.Context) []string`, `GetDPoPNonceEnabled(ctx context.Context) bool`, `GetDPoPNonceLifespan(ctx context.Context) time.Duration`, `GetDPoPProofMaxAge(ctx context.Context) time.Duration`, `GetDPoPPARURLs(ctx context.Context) []string`
    - Mark with `// OIDC4VCI extension` comment
    - _Requirements: 11.1_

  - [x] 1.3 Embed `DPoPConfigProvider` in `Configurator` interface in `fosite/fosite.go`
    - Add at end of interface composition list
    - _Requirements: 11.4_

  - [x] 1.4 Add config keys and provider methods in `driver/config/provider.go`
    - Add `KeyDPoPEnabled = "dpop.enabled"`, `KeyDPoPSigningAlgValues = "dpop.signing_alg_values_supported"`, `KeyDPoPNonceEnabled = "dpop.nonce_enabled"`, `KeyDPoPNonceLifespan = "dpop.nonce_lifespan"`, `KeyDPoPProofMaxAge = "dpop.proof_max_age"` constants
    - Implement `GetDPoPEnabled`, `GetDPoPSigningAlgValuesSupported`, `GetDPoPNonceEnabled`, `GetDPoPNonceLifespan`, `GetDPoPProofMaxAge`, `GetDPoPPARURLs` on `DefaultProvider` using `p.getProvider(ctx)` pattern
    - `GetDPoPPARURLs` computes URLs from `PublicURL` and `IssuerURL` (no separate config key), mirroring `GetTokenURLs` pattern
    - _Requirements: 11.2, 11.3_

  - [x] 1.5 Add config schema properties to `spec/config.json`
    - Add `dpop` object with properties: `enabled` (boolean, default false), `signing_alg_values_supported` (array of strings, default `["ES256"]`), `nonce_enabled` (boolean, default false), `nonce_lifespan` (string, default `"5m"`), `proof_max_age` (string, default `"60s"`)
    - Run `scripts/render-schemas.sh` to regenerate derived schemas (`.schema/config.schema.json`)
    - _Requirements: 11.5, 11.6_

  - [x] 1.6 Add compile-time interface satisfaction checks in `fositex/config.go`
    - Add `var _ fosite.DPoPConfigProvider = (*Config)(nil)`
    - Verifies `fositex.Config` inherits the provider methods from embedded `*config.DefaultProvider`
    - _Requirements: 11.7_

- [x] 2. Checkpoint — Ensure config infrastructure compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. DPoPNonceStorage interface and InjectDPoPHeader helper
  - [x] 3.1 Create `DPoPNonceStorage` interface in `fosite/handler/dpop/storage.go`
    - Define interface with methods: `IsJTIUsed(ctx context.Context, jti string) (bool, error)`, `MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error`, `CreateDPoPNonce(ctx context.Context) (string, error)`, `ValidateDPoPNonce(ctx context.Context, nonce string) (bool, error)`
    - Add copyright header
    - _Requirements: 8.1_

  - [x] 3.2 Create `InjectDPoPHeader` helper in `fosite/handler/dpop/inject.go`
    - Define exported `InjectDPoPHeader(r *http.Request)` function
    - Extract `DPoP` header values via `r.Header.Values("DPoP")`
    - If multiple values: set `r.PostForm.Set("dpop_proof_error", "multiple_headers")`
    - If exactly one value: set `r.PostForm.Set("dpop_proof", dpopValues[0])`
    - Define exported context key `DPoPNonceContextKey` for nonce delivery via `context.Context`
    - _Requirements: 12.1, 12.2, 13.1, 13.2_


  - [x] 3.3 Write property test for DPoP header injection (Property 10)
    - **Property 10: DPoP Header Injection**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Use `pgregory.net/rapid` generators for HTTP requests with zero, one, or multiple `DPoP` header values
    - Verify: single header → `dpop_proof` set; multiple headers → `dpop_proof_error=multiple_headers`; no header → both unset
    - **Validates: Requirements 12.1, 12.2**

- [x] 4. DPoP handler core — proof validation and PAR handler
  - [x] 4.1 Create `fosite/handler/dpop/handler.go` — `Handler` struct and shared proof validation
    - Define `Handler` struct with `Config DPoPConfigProvider` and `NonceStore DPoPNonceStorage` fields (note: the design uses `DPoPConfigProvider` as a type alias for `fosite.DPoPConfigProvider`, same pattern as RAR handler)
    - Implement `validateDPoPProof` shared helper implementing the full RFC 9449 §4.3 checklist (12 checks):
      1. Single header check via `dpop_proof_error` form parameter
      2. Well-formed JWT parsing via `go-jose/v4`
      3. Required claims presence (`jti`, `htm`, `htu`, `iat`)
      4. `typ` header is `dpop+jwt`
      5. `alg` header is supported asymmetric algorithm from `GetDPoPSigningAlgValuesSupported()`
      6. Signature verification with embedded `jwk` public key
      7. No private key material in `jwk` (check `d`, `p`, `q`, `dp`, `dq`, `qi` fields)
      8. `htm` claim matches `POST`
      9. `htu` claim matches configured endpoint URLs after RFC 3986 normalization
      10. Nonce validation when enabled (via `NonceStore.ValidateDPoPNonce`)
      11. `iat` freshness within `[now - maxAge, now + 5s]`
      12. JTI uniqueness via `NonceStore.IsJTIUsed` / `NonceStore.MarkJTIUsed`
    - Define context keys for passing validated JKT and nonce between handler phases
    - Add `isPublicClient(client fosite.Client) bool` helper checking token endpoint auth method (`none` or `attest_jwt_client_auth` → public)
    - Add compile-time check: `var _ fosite.PushedAuthorizeEndpointHandler = (*Handler)(nil)`
    - _Requirements: 1.1–1.12, 5.4, 7.3, 7.4_

  - [x] 4.2 Implement `HandlePushedAuthorizeEndpointRequest` in `fosite/handler/dpop/handler.go`
    - Read `dpop_jkt` from request form and `dpop_proof` from request form (injected by endpoint handler)
    - If neither present → return `nil` (not responsible)
    - If `dpop_proof` present: validate proof per §4.3 adapted for PAR (`htm=POST`, `htu` from `GetDPoPPARURLs`), compute JKT
    - If both `dpop_jkt` param and `DPoP` header present: verify thumbprints match, reject with `ErrInvalidDPoPProof` on mismatch
    - Store computed JKT as `dpop_jkt` in request form for PAR session persistence
    - If only `dpop_jkt` parameter present: validate non-empty, leave in form
    - _Requirements: 4.1, 4.2, 4.3, 4.5_

  - [x] 4.3 Write property test for DPoP proof validation (Property 1)
    - **Property 1: DPoP Proof Validation (§4.3 Checklist)**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Use `pgregory.net/rapid` generators for valid/invalid DPoP proof JWTs with configurable fields
    - Verify: proofs passing all 12 checks are accepted; proofs violating any single check are rejected with `invalid_dpop_proof`
    - **Validates: Requirements 1.1, 1.3, 1.4, 1.5, 1.7, 1.8, 1.9, 1.11**

  - [x] 4.4 Write property test for DPoP signature verification (Property 2)
    - **Property 2: DPoP Signature Verification**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Use generators for EC P-256 and RSA 2048 key pairs
    - Verify: proof signed with matching private key is accepted; proof signed with different key is rejected with `invalid_dpop_proof`
    - **Validates: Requirements 1.2, 1.6**

  - [x] 4.5 Write property test for dpop_jkt PAR storage (Property 7)
    - **Property 7: dpop_jkt PAR Storage**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Verify: after `HandlePushedAuthorizeEndpointRequest`, request form contains `dpop_jkt` matching the JWK Thumbprint; mismatching thumbprints produce `invalid_dpop_proof`
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.5**

- [x] 5. DPoP token endpoint handler
  - [x] 5.1 Create `fosite/handler/dpop/token_handler.go` — `TokenEndpointHandler` implementation
    - Implement `CanHandleTokenEndpointRequest` — returns `true` when `dpop_proof` or `dpop_proof_error` is in the request form
    - Implement `CanSkipClientAuth` — always returns `false`
    - Implement `HandleTokenEndpointRequest`:
      - Call `validateDPoPProof` with token endpoint URLs from `Config.GetTokenURLs(ctx)`
      - After proof validation: check `dpop_jkt` binding from authorization session (read from session extra or request form), verify JKT match
      - For `grant_type=refresh_token`: check existing DPoP JKT binding from `session.Extra["dpop_jkt_binding"]`, verify JKT match
      - Store validated JKT in request context for `PopulateTokenEndpointResponse`
    - Implement `PopulateTokenEndpointResponse`:
      - Read validated JKT from context (stored by `HandleTokenEndpointRequest`)
      - If no `dpop_proof` in form → return `fosite.ErrUnknownRequest`
      - Store `session.Extra["cnf"] = map[string]interface{}{"jkt": thumbprint}`
      - Set `responder.SetTokenType("DPoP")`
      - For public clients: store `session.Extra["dpop_jkt_binding"] = thumbprint`
      - If nonces enabled: generate fresh nonce, store in context for endpoint handler
    - Add compile-time check: `var _ fosite.TokenEndpointHandler = (*Handler)(nil)`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 4.4, 5.1, 5.2, 5.3, 6.1, 6.2, 6.3_

  - [x] 5.2 Write property test for DPoP token binding (Property 4)
    - **Property 4: DPoP Token Binding (cnf.jkt)**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Verify: after `PopulateTokenEndpointResponse`, session contains `Extra["cnf"]["jkt"]` equal to JWK SHA-256 Thumbprint, and `token_type` is `DPoP`; when no DPoP proof present, returns `fosite.ErrUnknownRequest`
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**

  - [x] 5.3 Write property test for DPoP nonce exchange (Property 5)
    - **Property 5: DPoP Nonce Exchange**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Verify: when nonces enabled, proof accepted only with valid nonce; missing/invalid nonce produces `use_dpop_nonce` with fresh nonce; successful issuance produces fresh nonce for response header
    - **Validates: Requirements 1.10, 3.1, 3.2, 3.3**

  - [x] 5.4 Write property test for dpop_jkt binding at token endpoint (Property 8)
    - **Property 8: dpop_jkt Binding Verification at Token Endpoint**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Verify: when session contains `dpop_jkt`, handler accepts only if proof's JKT matches; mismatch produces `invalid_dpop_proof`
    - **Validates: Requirements 4.4**

  - [x] 5.5 Write property test for refresh token DPoP binding (Property 9)
    - **Property 9: Refresh Token DPoP Binding (Public vs Confidential)**
    - Test in `fosite/handler/dpop/handler_test.go`
    - Use generators for public (`none`, `attest_jwt_client_auth`) and confidential (`client_secret_post`, `private_key_jwt`) auth methods
    - Verify: public clients get `dpop_jkt_binding` stored; confidential clients do not; refresh with wrong key for public client produces `invalid_dpop_proof`
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4**

- [x] 6. Checkpoint — Ensure handler core compiles and property tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Compose factory and registry wiring
  - [x] 7.1 Create `fosite/compose/compose_dpop.go` — `DPoPFactory`
    - Define `DPoPFactory` following `compose.Factory` signature, returning `*dpop.Handler`
    - Type-assert `config` to `dpop.DPoPConfigProvider` and `storage` to `dpop.DPoPNonceStorage`
    - _Requirements: 6.4_

  - [x] 7.2 Register `DPoPFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`
    - Gate registration by `m.Config().GetDPoPEnabled(ctx)`
    - Add `DPoPNonceStorage()` accessor with lazy initialization, returning `m.Persister()` cast to `dpop.DPoPNonceStorage`
    - _Requirements: 6.5, 8.3_

- [x] 8. Database migration and SQL persistence
  - [x] 8.1 Create database migration for `hydra_oauth2_dpop_jti` table
    - Create `persistence/sql/migrations/YYYYMMDDHHMMSS_oidc4vci_create_dpop_jti.up.sql` with `hydra_oauth2_dpop_jti` table: `jti VARCHAR(255) NOT NULL`, `nid UUID NOT NULL`, `used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP`, `expires_at TIMESTAMP NOT NULL`, composite primary key `(jti, nid)`, index `idx_dpop_jti_expires_at` on `(nid, expires_at)`
    - Create corresponding `.down.sql` dropping the table
    - Support PostgreSQL, MySQL, CockroachDB, and SQLite
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [x] 8.2 Add `DPoPNonceStorage` to `persistence.Persister` aggregate interface and implement on SQL persister
    - Embed `dpop.DPoPNonceStorage` in the `Persister` interface in `persistence/definitions.go`
    - Create `persistence/sql/persister_dpop.go` implementing all four methods on the SQL persister
    - Implement `IsJTIUsed(ctx, jti)` — query `hydra_oauth2_dpop_jti` for given `jti` and current `nid`
    - Implement `MarkJTIUsed(ctx, jti, expiry)` — insert row with `jti`, current `nid`, `time.Now()` as `used_at`, `expiry` as `expires_at`; use `INSERT ... ON CONFLICT DO NOTHING` for race condition handling
    - Implement `CreateDPoPNonce(ctx)` — stateless HMAC-SHA256 nonce: `base64url(timestamp_8bytes || random_16bytes || hmac_16bytes)` using global secret accessed via `p.r.Config().GlobalSecret(ctx)` (the persister holds a registry reference `r InternalRegistry` following the existing pattern)
    - Implement `ValidateDPoPNonce(ctx, nonce)` — decode, verify HMAC with `crypto/subtle.ConstantTimeCompare` using `p.r.Config().GlobalSecret(ctx)`, check timestamp against `p.r.Config().GetDPoPNonceLifespan(ctx)`
    - Note: The `DPoPNonceStorage` interface methods don't accept lifespan/secret parameters — the persister accesses these internally via its registry reference, following the same pattern used by other config-dependent persister methods
    - Note: The `Persister` interface embedding and SQL implementation must be done together to avoid compilation failures
    - _Requirements: 8.2, 10.1, 10.2, 10.3, 10.4_

  - [x] 8.3 Write property test for JTI replay detection (Property 3)
    - **Property 3: JTI Replay Detection**
    - Test in `persistence/sql/persister_dpop_test.go`
    - Verify: first `MarkJTIUsed` + `IsJTIUsed` returns `true`; fresh `jti` returns `false`; duplicate insert is idempotent
    - **Validates: Requirements 1.12, 10.1, 10.2**

  - [x] 8.4 Write property test for nonce round-trip integrity (Property 6)
    - **Property 6: Nonce Round-Trip Integrity**
    - Test in `persistence/sql/persister_dpop_test.go`
    - Verify: nonce from `CreateDPoPNonce` validates via `ValidateDPoPNonce`; tampered nonce returns `false`; expired nonce returns `false`
    - **Validates: Requirements 10.3, 10.4**

- [x] 9. Checkpoint — Ensure migration, persistence, and factory compile and tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Endpoint handler changes for DPoP header injection and nonce delivery
  - [x] 10.1 Modify token endpoint handler in `oauth2/handler.go`
    - Before `NewAccessRequest`: initialize `var dpopNonce string`, store `&dpopNonce` in context via `dpop.DPoPNonceContextKey`, call `dpop.InjectDPoPHeader(r)`
    - After `NewAccessResponse` (success path): if `dpopNonce != ""`, set `w.Header().Set("DPoP-Nonce", dpopNonce)`
    - Error path: if `dpopNonce != ""`, set `w.Header().Set("DPoP-Nonce", dpopNonce)` before writing error response
    - _Requirements: 12.1, 13.1, 13.2_

  - [x] 10.2 Modify PAR endpoint handler in `oauth2/handler.go`
    - Before `NewPushedAuthorizeRequest`: call `dpop.InjectDPoPHeader(r)`
    - _Requirements: 12.2_

- [x] 11. Checkpoint — Ensure endpoint handler changes compile and all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Feature documentation
  - [x] 12.1 Create `docs/features/dpop.md`
    - Feature overview: DPoP token binding, RFC 9449 reference, cross-cutting handler design
    - Configuration: `KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`, `KeyDPoPProofMaxAge`
    - Full RFC 9449 §4.3 proof validation checklist with all 12 checks
    - Error codes: `invalid_dpop_proof`, `use_dpop_nonce` with HTTP 400
    - Nonce exchange flow: stateless HMAC-based nonces, `DPoP-Nonce` header on success and error responses
    - `dpop_jkt` authorization code binding: PAR integration, both `dpop_jkt` param and `DPoP` header mechanisms
    - Refresh token DPoP binding rules: public vs confidential clients, `none`/`attest_jwt_client_auth` detection
    - `cnf.jkt` introspection path: `ext.cnf.jkt` via `Session.Extra` propagation
    - References: RFC 9449, design docs, architecture docs
    - _Requirements: 14.1, 14.2_

- [x] 13. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests use `pgregory.net/rapid` and validate universal correctness properties from the design document
- All new files in `fosite/handler/dpop/` are isolated from upstream (no merge conflict risk)
- Config and interface changes touch upstream files — follow `// OIDC4VCI extension` comment convention
- `fositex.Config` embeds `*config.DefaultProvider` so `DPoPConfigProvider` methods are inherited automatically — verified by compile-time check in task 1.6
- The DPoP handler uses `go-jose/v4` (already a transitive dependency) for JWT parsing, signature verification, and JWK Thumbprint computation — no new dependencies needed
- Stateless HMAC-based nonces require no database table — only the JTI replay cache needs a migration
- The `DPoP-Nonce` response header is delivered via a `*string` pointer in the request context, allowing the handler to write the nonce and the endpoint handler to read it after the Fosite call returns
- Tasks marked with `*` are optional and can be skipped for faster MVP
- Requirements 15 and 16 are deferred to Spec 5 (oidc4vci-haip-metadata) — no tasks needed here
