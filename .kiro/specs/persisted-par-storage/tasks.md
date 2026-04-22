# Implementation Plan: Persisted PAR Storage

## Overview

Replace the in-memory `inMemoryPARStorage` in `driver/registry_par.go` with a SQL-backed implementation. The implementation reuses the existing `OAuth2RequestSQL` model and `createSession`/`findSessionBySignature` infrastructure — the same pattern used for authorization codes, access tokens, refresh tokens, OIDC sessions, and PKCE sessions. A new `sqlTablePAR` constant maps to the `hydra_oauth2_par` table, and the provided source code forms the basis of the persister methods.

## Tasks

- [x] 1. Create database migration for `hydra_oauth2_par` table
  - [x] 1.1 Create up migration `persistence/sql/migrations/20260418120000000000_oidc4vci_create_par_session.up.sql`
    - `CREATE TABLE IF NOT EXISTS hydra_oauth2_par` with the same schema as `hydra_oauth2_code`: `signature` (VARCHAR(255) NOT NULL PK), `request_id` (VARCHAR(40) NOT NULL), `requested_at` (TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP), `client_id` (VARCHAR(255) NOT NULL), `scope` (TEXT NOT NULL), `granted_scope` (TEXT NOT NULL), `form_data` (TEXT NOT NULL), `session_data` (TEXT NOT NULL), `subject` (VARCHAR(255) NOT NULL DEFAULT ''), `active` (BOOLEAN NOT NULL DEFAULT true), `requested_audience` (TEXT NULL DEFAULT ''), `granted_audience` (TEXT NULL DEFAULT ''), `challenge_id` (VARCHAR(40) NULL), `nid` (CHAR(36) NOT NULL), `expires_at` (TIMESTAMP NULL)
    - No foreign key constraints (PAR sessions are short-lived, no cascade needed)
    - Create index `idx_par_nid` on `(nid)`
    - Create index `idx_par_expires_at` on `(nid, expires_at)`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 9.1, 9.3_
  - [x] 1.2 Create down migration `persistence/sql/migrations/20260418120000000000_oidc4vci_create_par_session.down.sql`
    - Drop indexes `idx_par_expires_at`, `idx_par_nid`, then drop table `hydra_oauth2_par`
    - _Requirements: 2.7_

- [x] 2. Implement PAR persister methods using existing OAuth2RequestSQL infrastructure
  - [x] 2.1 Add `sqlTablePAR` constant and implement persister methods in `persistence/sql/persister_par.go`
    - Add `sqlTablePAR tableName = "par"` constant to the existing `const` block in `persister_oauth2.go` (alongside `sqlTableCode`, `sqlTableAccess`, etc.)
    - Create `persistence/sql/persister_par.go` with the provided source code as the basis
    - Implement `CreatePARSession`: delegates to `p.createSession(ctx, requestURI, requester, sqlTablePAR, expiresAt)` with `expiresAt` from `requester.GetSession().GetExpiresAt(fosite.PushedAuthorizeRequestContext)`
    - Implement `GetPARSession`: delegates to `p.findSessionBySignature(ctx, requestURI, &oauth2.Session{}, sqlTablePAR)`, then reconstructs `fosite.AuthorizeRequest` from the returned `fosite.Request` by parsing `response_type`, `redirect_uri`, `state`, `response_mode` from the stored Form data
    - Add `response_type` enrichment from HTTP request context (`ctx.Value(fosite.RequestContextKey)`) — this is missing from the provided code and must be added for consent flow compatibility
    - Remove the `p.l.Infof` debug logging calls from the provided code (tracing spans provide observability)
    - Implement `DeletePARSession`: no-op returning `nil`, with comment explaining consent flow requirement
    - _Requirements: 1.1–1.5, 3.1–3.5, 4.1–4.5, 5.1–5.2, 12.1–12.3_
  - [x] 2.2 Implement `FlushExpiredPARSessions` on `*Persister`
    - `DELETE FROM hydra_oauth2_par WHERE expires_at < CURRENT_TIMESTAMP AND nid = ?`
    - Wrap errors with `sqlcon.HandleError`
    - _Requirements: 6.1, 6.2, 6.3_

- [x] 3. Checkpoint — Verify persister compiles
  - Ensure all persister methods compile and satisfy the `fosite.PARStorage` interface. Ask the user if questions arise.

- [x] 4. Wire interfaces and registry
  - [x] 4.1 Add `fosite.PARStorage` to `persistence.Persister` interface in `persistence/definitions.go`
    - Add `fosite.PARStorage` to the embedded interface list (alongside existing `dpop.DPoPNonceStorage`, `preauth.PreAuthorizedCodeStorage`, etc.)
    - This ensures compile-time verification that `persistence/sql.Persister` implements PAR storage
    - _Requirements: 8.1, 8.2_
  - [x] 4.2 Update `RegistrySQL.PARStorage()` in `driver/registry_par.go`
    - Replace the `inMemoryPARStorage` lazy init with `return m.Persister().(fosite.PARStorage)` (same pattern as `PreAuthorizedCodeStorage()`)
    - Remove the `inMemoryPARStorage` struct, `newInMemoryPARStorage()` function, and all associated code from the file
    - Remove the `parStore fosite.PARStorage` field from `RegistrySQL` in `driver/registry_sql.go`
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [x] 5. Update SQLite schema dump
  - [x] 5.1 Add `hydra_oauth2_par` table and indexes to `internal/testhelpers/sql_schemas/sqlite3_dump.sql`
    - Append the CREATE TABLE and CREATE INDEX statements matching the up migration
    - _Requirements: 10.1_

- [x] 6. Checkpoint — Verify compilation and schema
  - Ensure all code compiles, the `persistence.Persister` interface is satisfied, and the SQLite schema dump is consistent. Ask the user if questions arise.

- [ ] 7. Property-based tests for PAR persistence
  - [ ]* 7.1 Write property test: PAR Session Serialization Round-Trip
    - **Property 1: PAR Session Serialization Round-Trip**
    - **Validates: Requirements 1.4, 1.5, 3.1, 3.2, 3.3, 4.1, 4.4, 12.1, 12.2, 12.3**
    - Use `pgregory.net/rapid` to generate random `AuthorizeRequester` (random Form url.Values, scopes, audience, response types, redirect URIs, state, response mode, `oauth2.Session` with nested `openid.DefaultSession`)
    - `CreatePARSession` then `GetPARSession`, assert field-by-field equivalence
    - Test file: `persistence/sql/persister_par_test.go`
  - [ ]* 7.2 Write property test: Expired Sessions Are Not Returned
    - **Property 2: Expired Sessions Are Not Returned**
    - **Validates: Requirements 4.3**
    - Generate random sessions with past `expires_at`, verify `GetPARSession` returns `fosite.ErrNotFound`
  - [ ]* 7.3 Write property test: Response Type Enrichment from HTTP Context
    - **Property 3: Response Type Enrichment from HTTP Context**
    - **Validates: Requirements 4.5**
    - Generate random stored sessions and random `response_type` values in HTTP context, verify enrichment on returned `AuthorizeRequester`'s Form
  - [ ]* 7.4 Write property test: DeletePARSession Preserves Sessions
    - **Property 4: DeletePARSession Preserves Sessions**
    - **Validates: Requirements 5.1**
    - Generate random sessions, call `DeletePARSession`, verify `GetPARSession` still returns the session
  - [ ]* 7.5 Write property test: Flush Removes Only Expired Sessions
    - **Property 5: Flush Removes Only Expired Sessions**
    - **Validates: Requirements 6.1**
    - Generate mixed expired/non-expired sessions, call `FlushExpiredPARSessions`, verify only expired are removed and non-expired remain

- [x] 8. Verify existing e2e test passes
  - [x] 8.1 Run `TestAuthCodeFlow_PAR_RAR_DPoP` to confirm the SQL-backed implementation preserves existing PAR behavior
    - No test modifications expected — the SQL implementation must be a drop-in replacement
    - _Requirements: 11.1, 11.2_

- [x] 9. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- The provided source code is used as the basis for task 2.1, with additions for response_type enrichment and removal of debug logging
- No custom `PARSessionSQL` model is needed — the existing `OAuth2RequestSQL` model and `createSession`/`findSessionBySignature` infrastructure handles all serialization/deserialization
- The `sqlTablePAR` constant follows the same pattern as `sqlTableCode`, `sqlTableAccess`, etc.
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document using `pgregory.net/rapid`
