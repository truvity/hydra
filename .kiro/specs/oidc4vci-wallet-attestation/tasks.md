# Implementation Plan: OIDC4VCI Wallet Attestation Client Authentication

## Overview

Implement Wallet Attestation client authentication (`attest_jwt_client_auth`) for the Hydra AS fork per draft-ietf-oauth-attestation-based-client-auth-07, OIDC4VCI Appendix E, and HAIP §4.4.1. Tasks follow the dependency chain: config infrastructure and error constants first, then JTI storage interface, authenticator core (full validation pipeline), strategy integration via `SetFositeInstance` + `GetClientAuthenticationStrategy`, RefreshBindingHandler TokenEndpointHandler, compose factory and registry wiring, and finally feature documentation. The authenticator lives in `fosite/handler/wallet_attestation/` as a `ClientAuthenticationStrategy` — not a handler — and plugs into `Fosite.AuthenticateClient()` via `fositex.Config.GetClientAuthenticationStrategy()`.

## Tasks

- [x] 1. Config infrastructure and error constants
  - [x] 1.1 Define `WalletAttestationConfigProvider` interface in `fosite/config.go`
    - Append `WalletAttestationConfigProvider` interface with methods: `GetWalletAttestationEnabled(ctx context.Context) bool`, `GetWalletAttestationTrustAnchors(ctx context.Context) []*x509.Certificate`
    - Mark with `// OIDC4VCI extension` comment
    - _Requirements: 9.1_

  - [x] 1.2 Embed `WalletAttestationConfigProvider` in `Configurator` interface in `fosite/fosite.go`
    - Add at end of interface composition list with `// OIDC4VCI extension` comment
    - _Requirements: 9.4_

  - [x] 1.3 Add config keys and provider methods in `driver/config/provider.go`
    - Add `KeyWalletAttestationEnabled = "wallet_attestation.enabled"`, `KeyWalletAttestationTrustAnchors = "wallet_attestation.trust_anchors"` constants in the `// OIDC4VCI extension` section
    - Implement `GetWalletAttestationEnabled` on `DefaultProvider` using `p.getProvider(ctx).Bool(...)` pattern, default `false`
    - Implement `GetWalletAttestationTrustAnchors` on `DefaultProvider` — reads `[]string` PEM entries, parses each via `pem.Decode` + `x509.ParseCertificate`, logs and skips malformed entries
    - _Requirements: 9.2, 9.3_

  - [x] 1.4 Add config schema properties to `spec/config.json`
    - Add `wallet_attestation` object with properties: `enabled` (boolean, default false), `trust_anchors` (array of strings, PEM-encoded certificates)
    - Run `scripts/render-schemas.sh` to regenerate derived schemas
    - _Requirements: 9.5_

  - [x] 1.5 Add compile-time interface satisfaction check in `fositex/config.go`
    - Add `var _ fosite.WalletAttestationConfigProvider = (*Config)(nil)` with `// OIDC4VCI extension` comment
    - Verifies `fositex.Config` inherits the provider methods from embedded `*config.DefaultProvider`
    - _Requirements: 9.6_

  - [x] 1.6 Create error constants in `fosite/handler/wallet_attestation/errors.go`
    - Define `var ErrInvalidWalletAttestation = &fosite.RFC6749Error{...}` with `ErrorField: "invalid_client"`, `CodeField: http.StatusUnauthorized`, `DescriptionField: "The wallet attestation is invalid."`
    - Define `var ErrInvalidClientAttestation = &fosite.RFC6749Error{...}` with `ErrorField: "invalid_client_attestation"`, `CodeField: http.StatusUnauthorized`, `DescriptionField: "The client attestation could not be verified."`
    - Add copyright header and package declaration
    - _Requirements: 10.1, 10.2, 10.3_

- [x] 2. Checkpoint — Ensure config infrastructure compiles
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. JTI storage interface and context key
  - [x] 3.1 Create `JTIStorage` interface in `fosite/handler/wallet_attestation/storage.go`
    - Define `JTIStorage` interface with methods: `IsJTIUsed(ctx context.Context, jti string) (bool, error)`, `MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error`
    - This is a subset of `dpop.DPoPNonceStorage` — the same table and methods serve both DPoP and Wallet Attestation PoP JTI replay detection
    - Add copyright header
    - _Requirements: 4.1, 4.2_

  - [x] 3.2 Define context key for cnf.jwk propagation in `fosite/handler/wallet_attestation/authenticator.go`
    - Define `type contextKey string` and `const WalletAttestationCNFContextKey contextKey = "wallet_attestation_cnf_jwk"`
    - The authenticator stores the validated `cnf.jwk` (`*jose.JSONWebKey`) in the context after successful authentication
    - The `RefreshBindingHandler` reads it to compute the JWK thumbprint for session storage and binding checks
    - _Requirements: 7.4_

- [x] 4. Authenticator core — full validation pipeline
  - [x] 4.1 Create `fosite/handler/wallet_attestation/authenticator.go` — `Authenticator` struct and `AuthenticateClient` method
    - Define `Authenticator` struct with `Config WalletAttestationConfigProvider`, `Store fosite.Storage`, `JTIStore JTIStorage`, `IssuerURL func(ctx context.Context) string` fields
    - Implement `AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error)` with the full validation pipeline:
    - **Phase 1 — Client Attestation JWT Validation (draft-07 §5.1, §9):**
      1. Extract `OAuth-Client-Attestation` header via `r.Header.Get(...)`
      2. Parse JWT via `jose.ParseSigned(attestationString)` — reject if malformed
      3. Validate `typ` JOSE header == `oauth-client-attestation+jwt`
      4. Validate `alg` JOSE header: not `none`, not symmetric (`HS*`), supported asymmetric
      5. Extract `x5c` JOSE header — required per HAIP §4.4.1
      6. Decode `x5c` chain: base64-decode each entry, `x509.ParseCertificate()` each
      7. HAIP check: verify leaf cert is not self-signed
      8. HAIP check: verify trust anchor is not in the `x5c` chain
      9. Build `x509.CertPool` with configured trust anchors, call `leafCert.Verify()`
      10. Verify JWT signature using leaf cert's public key
      11. Validate `exp` claim (with clock skew tolerance)
      12. Validate `nbf` claim if present
      13. Validate `iss` claim is present
      14. Extract `sub` claim — this is the `client_id`
      15. Extract `cnf` claim with `jwk` representation
      16. Validate `cnf.jwk` is a public key (no `d` parameter)
      17. If `form.Get("client_id")` is non-empty, verify it matches `sub`
    - **Phase 2 — Client Attestation PoP JWT Validation (draft-07 §5.2, §9):**
      18. Extract `OAuth-Client-Attestation-PoP` header — required
      19. Parse the PoP JWT
      20. Validate `typ` JOSE header == `oauth-client-attestation-pop+jwt`
      21. Validate `alg` JOSE header: same rules as attestation JWT
      22. Verify PoP JWT signature using the public key from `cnf.jwk`
      23. Validate `iss` claim matches `sub` from attestation JWT
      24. Validate `aud` claim matches AS Issuer Identifier
      25. Validate `iat` claim: present, recent (within freshness window), not too far in future
      26. Validate `jti` claim: present, unique via `JTIStore.IsJTIUsed` / `MarkJTIUsed`
      27. Validate `nbf` claim if present
    - **Phase 3 — Client Lookup and Auth Method Check:**
      28. Look up client via `Store.GetClient(ctx, sub)`
      29. Type-assert to `OpenIDConnectClient`, check `GetTokenEndpointAuthMethod() == "attest_jwt_client_auth"`
    - **Phase 4 — Store cnf.jwk in context:**
      30. Store validated `cnf.jwk` in context via `WalletAttestationCNFContextKey` for `RefreshBindingHandler`
      31. Return the client
    - _Requirements: 1.1–1.18, 2.1, 2.2, 3.1–3.11, 4.1–4.3, 5.4, 5.5, 5.8, 8.1–8.3, 11.1, 11.2_

  - [x] 4.2 Write property test for end-to-end Wallet Attestation authentication (Property 1)
    - **Property 1: End-to-end Wallet Attestation Authentication**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate valid Client Attestation JWTs (signed by trusted CA with valid x5c chain, correct typ, non-expired, with valid cnf) and valid PoP JWTs (signed by cnf key, correct typ, matching iss/sub/aud, fresh iat, unique jti)
    - Verify authenticator returns the pre-registered client without error
    - **Validates: Requirements 1.1, 1.3, 1.4, 1.5, 1.7, 1.9, 1.11, 1.13, 1.14, 1.15, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 5.4, 5.5**

  - [x] 4.3 Write property test for X.509 certificate chain validation with HAIP rules (Property 2)
    - **Property 2: X.509 Certificate Chain Validation with HAIP Rules**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate certificate hierarchies: valid chains, chains with trust anchor in x5c, chains with self-signed leaf, chains not terminating at trust anchor
    - Verify correct accept/reject behavior for each case
    - **Validates: Requirements 1.7, 1.8, 2.1, 2.2**

  - [x] 4.4 Write property test for signature verification binding (Property 3)
    - **Property 3: Signature Verification Binds Attestation to Wallet Provider and PoP to Client Instance**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate key pairs, verify attestation signature only with leaf cert's public key, PoP signature only with cnf.jwk key
    - Signing with any other key causes rejection
    - **Validates: Requirements 1.9, 1.10, 3.4**

  - [x] 4.5 Write property test for cross-JWT claim consistency (Property 4)
    - **Property 4: Cross-JWT Claim Consistency**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate combinations of attestation `sub`, PoP `iss`, and form `client_id` (when present)
    - Verify only matching values accepted, any mismatch rejected with `invalid_client`
    - **Validates: Requirements 1.14, 3.5, 5.8**

  - [x] 4.6 Write property test for temporal claim validation (Property 5)
    - **Property 5: Temporal Claim Validation**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate attestation JWTs with various `exp`/`nbf` and PoP JWTs with various `iat`/`nbf`
    - Verify expired attestations rejected, stale/future PoP JWTs rejected, valid temporal combinations accepted
    - **Validates: Requirements 1.11, 1.12, 3.7, 3.10**

  - [x] 4.7 Write property test for PoP JTI replay detection (Property 6)
    - **Property 6: PoP JTI Replay Detection**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate sequences of PoP JWTs, verify first occurrence accepted, subsequent occurrences rejected
    - **Validates: Requirements 3.8, 3.9**

  - [x] 4.8 Write property test for public key only in cnf claim (Property 9)
    - **Property 9: Public Key Only in cnf Claim**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate JWKs with and without private key material (`d` parameter for EC)
    - Verify public keys accepted, private keys rejected
    - **Validates: Requirements 1.17**

  - [x] 4.9 Write property test for attestation JWT reuse with fresh PoP (Property 10)
    - **Property 10: Attestation JWT Reuse with Fresh PoP**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Present same attestation JWT in multiple requests with distinct PoP JWTs (unique jti each)
    - Verify all requests succeed — replay protection applies only to PoP JWT jti
    - **Validates: Requirements 12.1**

  - [x] 4.10 Write property test for unknown claims tolerance (Property 11)
    - **Property 11: Unknown Claims Tolerance**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate valid attestation JWTs with additional unknown claims beyond required set
    - Verify authenticator accepts without error — unknown claims ignored per draft-07 §5.1 rule 1
    - **Validates: Requirements 1.18**

- [x] 5. Checkpoint — Ensure authenticator compiles and property tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Strategy integration and RefreshBindingHandler
  - [x] 6.1 Add `fositeInstance` field and `SetFositeInstance` method to `fositex.Config`
    - Add `fositeInstance *fosite.Fosite` field to `Config` struct
    - Add `SetFositeInstance(f *fosite.Fosite)` method
    - Add lazy-initialized `walletAttestationAuthenticator` field
    - Update `GetClientAuthenticationStrategy(ctx)` to return a non-nil strategy when Wallet Attestation is enabled: if `OAuth-Client-Attestation` header present → delegate to authenticator, else → fallback to `fositeInstance.DefaultClientAuthenticationStrategy`
    - When Wallet Attestation is disabled, continue returning `nil`
    - _Requirements: 5.1, 5.2, 5.3, 5.7, 6.1_

  - [x] 6.2 Wire `SetFositeInstance` in `driver/registry_sql.go`
    - In `OAuth2Provider()`, after `fosite.NewOAuth2Provider(storage, config)`, call `config.SetFositeInstance(m.fop.(*fosite.Fosite))`
    - _Requirements: 5.3_

  - [x] 6.3 Write property test for strategy routing (Property 7)
    - **Property 7: Strategy Routing — Header Presence Determines Authentication Path**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate requests with and without `OAuth-Client-Attestation` header, with Wallet Attestation enabled and disabled
    - Verify: header present + enabled → Wallet Attestation authenticator; header absent + enabled → default strategy; disabled → nil strategy
    - **Validates: Requirements 5.1, 5.2, 5.7, 6.1**

  - [x] 6.4 Create `RefreshBindingHandler` in `fosite/handler/wallet_attestation/`
    - Define `RefreshBindingHandler` struct with `Config WalletAttestationConfigProvider`
    - Add compile-time check: `var _ fosite.TokenEndpointHandler = (*RefreshBindingHandler)(nil)`
    - Implement `CanHandleTokenEndpointRequest` — returns `true` when client's `token_endpoint_auth_method` is `attest_jwt_client_auth`
    - Implement `CanSkipClientAuth` — returns `false`
    - Implement `HandleTokenEndpointRequest` — for `grant_type=refresh_token`, read stored `wallet_attestation_cnf_jkt` from session `Extra`, compare against current request's `cnf.jwk` thumbprint (from context key). If mismatch → `invalid_client` with hint "Refresh token is bound to a different client instance key"
    - Implement `PopulateTokenEndpointResponse` — compute JWK thumbprint (SHA-256, base64url) of current `cnf.jwk` from context, store in `session.Extra["wallet_attestation_cnf_jkt"]`
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 6.5 Write property test for refresh token binding round-trip (Property 8)
    - **Property 8: Refresh Token Binding Round-Trip**
    - Test in `fosite/handler/wallet_attestation/authenticator_test.go`
    - Generate key pairs, verify thumbprint stored in session matches JWK Thumbprint of cnf.jwk
    - On refresh, verify same key accepted, different key rejected
    - **Validates: Requirements 7.1, 7.3**

- [x] 7. Checkpoint — Ensure strategy integration and RefreshBindingHandler compile and tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Compose factory and registry wiring
  - [x] 8.1 Create `fosite/compose/compose_wallet_attestation.go` — `WalletAttestationRefreshBindingFactory`
    - Define `WalletAttestationRefreshBindingFactory` following `compose.Factory` signature, returning `*wallet_attestation.RefreshBindingHandler`
    - Type-assert `config` to `wallet_attestation.WalletAttestationConfigProvider`
    - Note: The `Authenticator` itself is NOT registered via the factory — it is created lazily on `fositex.Config` and used by the strategy function
    - _Requirements: 5.1_

  - [x] 8.2 Register `WalletAttestationRefreshBindingFactory` in `driver/registry_sql.go` via `ExtraFositeFactories()`
    - Gate registration by `m.Config().GetWalletAttestationEnabled(ctx)`
    - Add import for `wallet_attestation` package
    - _Requirements: 5.1_

- [x] 9. Checkpoint — Ensure factory and registry wiring compile and all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Feature documentation
  - [x] 10.1 Create `docs/features/wallet-attestation.md`
    - Feature overview: Wallet Attestation client authentication, draft-07 reference, ClientAuthenticationStrategy design (not a handler)
    - Client model: one pre-registered Wallet_Type_Client_Record per wallet type with `client_id` matching attestation `sub`, `token_endpoint_auth_method=attest_jwt_client_auth`
    - Configuration: `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors` with defaults
    - Operator setup guide: trust anchor configuration + client record creation per wallet type
    - Authentication flow: Client Attestation JWT + PoP JWT validation sequence per draft-07 §9 verification checklist
    - Validation rules: x5c chain building, trust anchor verification, signature verification, typ header validation, claim validation
    - HAIP-specific constraints: trust anchor not in x5c chain, no self-signed leaf certs, shared `sub` across wallet instances per HAIP §4.4.1
    - Refresh token binding rules: draft-07 §10.3, JWK thumbprint stored in session
    - Attestation reuse behavior: draft-07 §10.2, same attestation JWT reusable with fresh PoP JWTs
    - Error codes: `invalid_client` and `invalid_client_attestation` with all specific hints
    - Integration point: `GetClientAuthenticationStrategy` and fallback to default
    - References: draft-ietf-oauth-attestation-based-client-auth-07, HAIP §4.4.1, OIDC4VCI Appendix E, design docs
    - _Requirements: 14.1, 14.2_

- [x] 11. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests use `pgregory.net/rapid` and validate universal correctness properties from the design document
- All new files in `fosite/handler/wallet_attestation/` are isolated from upstream (no merge conflict risk)
- Config and interface changes touch upstream files — follow `// OIDC4VCI extension` comment convention
- `fositex.Config` embeds `*config.DefaultProvider` so `WalletAttestationConfigProvider` methods are inherited automatically — verified by compile-time check in task 1.5
- The authenticator uses `go-jose/v3` (already used by the DPoP handler and fosite's JWT handling) for JWT parsing, signature verification, and JWK Thumbprint computation
- X.509 chain validation uses Go stdlib `crypto/x509.Certificate.Verify()` with a `CertPool` containing configured trust anchors
- JTI replay detection reuses `DPoPNonceStorage.IsJTIUsed/MarkJTIUsed` — same table (`hydra_oauth2_dpop_jti`) serves both DPoP and Wallet Attestation PoP JTIs. No new migration needed.
- The `Authenticator` is NOT registered via the factory pattern — it is created lazily on `fositex.Config` and used by the strategy function. Only the `RefreshBindingHandler` goes through the factory/compose pattern.
- The `SetFositeInstance` lazy setter resolves the circular dependency between `fositex.Config` and the `Fosite` instance for `DefaultClientAuthenticationStrategy` fallback
- Discovery metadata (`attest_jwt_client_auth` in `token_endpoint_auth_methods_supported`, algorithm metadata) is deferred to Spec 5 (oidc4vci-haip-metadata) — Requirements 13.1–13.4 are not tasked here
- HAIP auto-enable behavior (Requirement 15) is deferred to Spec 5
