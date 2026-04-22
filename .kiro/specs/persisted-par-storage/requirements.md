# Requirements Document

## Introduction

This document specifies the replacement of the in-memory Pushed Authorization Request (PAR) storage in Ory Hydra with a SQL-backed implementation. The current `inMemoryPARStorage` in `driver/registry_par.go` implements `fosite.PARStorage` using a `sync.RWMutex`-protected map, which works for single-instance deployments but fails in multi-replica production environments. When a Wallet sends a PAR request to replica A and the subsequent authorization redirect hits replica B, the PAR session is lost because the in-memory map is not shared across replicas.

The SQL-backed implementation follows the established persistence patterns in Hydra: a new `hydra_oauth2_par` table stores serialized `AuthorizeRequester` data, the `persistence/sql/Persister` implements the storage methods, and `RegistrySQL.PARStorage()` returns the SQL-backed implementation instead of the in-memory store.

Key architectural constraints that shape this design:
- Hydra's consent flow calls `/oauth2/auth` three times per authorization (login redirect → consent redirect → final), and each call re-resolves the `request_uri` via `authorizeRequestFromPAR`. The PAR session must survive all three calls.
- `DeletePARSession` is called by `authorizeRequestFromPAR` after each PAR resolution. The current implementation is a no-op; the SQL implementation must preserve this no-op semantic (sessions expire via TTL).
- `GetPARSession` enriches the stored `AuthorizeRequester` with `response_type` from the current HTTP request context, because subsequent `/oauth2/auth` calls carry `response_type` in the URL but the PAR session's Form may not have it.
- PAR sessions are short-lived (default TTL is 5 minutes) and should be cleaned up via TTL-based expiry.

## Glossary

- **PAR**: Pushed Authorization Request — an OAuth 2.0 extension (RFC 9126) where the client pushes the authorization request parameters to the AS before redirecting the user.
- **PAR_Session**: The stored authorization request data created by `CreatePARSession` and retrieved by `GetPARSession`, containing the serialized `AuthorizeRequester` (Form, Client ID, Session, ResponseTypes, RedirectURI, Scopes, Audience, State, ResponseMode).
- **PARStorage**: The `fosite.PARStorage` interface defined in `fosite/storage.go` with three methods: `CreatePARSession`, `GetPARSession`, `DeletePARSession`.
- **SQL_Persister**: The `persistence/sql/Persister` struct that implements all domain storage interfaces, including the new PAR storage methods.
- **RegistrySQL**: The `driver.RegistrySQL` struct that is the single concrete implementation satisfying all domain registry interfaces. Currently holds a `parStore fosite.PARStorage` field initialized lazily.
- **AuthorizeRequester**: The `fosite.AuthorizeRequester` interface representing a parsed authorization request, containing Form (url.Values), Client, Session, ResponseTypes, RedirectURI, Scopes, Audience, State, and ResponseMode.
- **Consent_Flow**: Hydra's multi-step authorization flow where `/oauth2/auth` is called three times (login → consent → final). Each call re-resolves the `request_uri` via `authorizeRequestFromPAR`.
- **NID**: Network ID — a UUID column present on all Hydra tables for multi-tenancy support.
- **Request_URI**: The opaque URI returned by the PAR endpoint (prefixed with `urn:ietf:params:oauth:request_uri:`) that the client uses in the subsequent authorization request. Used as the lookup key for PAR sessions.
- **OAuth2RequestSQL**: The existing model in `persistence/sql/persister_oauth2.go` that shows how fosite sessions are serialized (Form as `url.Values.Encode()`, Session as JSON, scopes as pipe-delimited strings, client_id as string reference).
- **BasePersister**: The `persistence/sql/BasePersister` struct providing `CreateWithNetwork`, `Connection`, `NetworkID`, and transaction support.

## Requirements

### Requirement 1: PAR Session SQL Data Model

**User Story:** As a developer, I want a data model representing the stored PAR session, so that all authorization request data is structured and persisted consistently in the database.

#### Acceptance Criteria

1. THE SQL_Persister SHALL define a `PARSessionSQL` struct (or equivalent) with fields: `RequestURI` (string, PK — the opaque PAR request URI used as lookup key), `NID` (uuid.UUID — network ID for multi-tenancy), `ClientID` (string — the OAuth 2.0 client ID from the authorization request), `RequestedScope` (string — pipe-delimited requested scopes), `RequestedAudience` (string — pipe-delimited requested audience), `Form` (string — URL-encoded form data from `url.Values.Encode()`), `ResponseTypes` (string — pipe-delimited response types), `RedirectURI` (string — the redirect URI from the authorization request), `State` (string — the OAuth 2.0 state parameter), `ResponseMode` (string — the response mode), `SessionData` ([]byte — JSON-serialized fosite session), `RequestedAt` (time.Time — when the PAR request was made), `ExpiresAt` (time.Time — when the PAR session expires, based on PAR context lifespan).
2. THE `PARSessionSQL` struct SHALL implement `TableName() string` returning `"hydra_oauth2_par"` for Pop ORM compatibility.
3. THE `PARSessionSQL` struct SHALL use Pop struct tags (`db:"column_name"`) for all fields.
4. THE `PARSessionSQL` struct SHALL provide a method to convert to a `fosite.AuthorizeRequester` by deserializing Form (via `url.ParseQuery`), Session (via `json.Unmarshal`), and splitting pipe-delimited scopes, audience, and response types (via `stringsx.Splitx`), and loading the Client from the client store by `ClientID`.
5. THE serialization format SHALL follow the established `OAuth2RequestSQL` pattern: Form as `url.Values.Encode()`, Session as JSON (with optional encryption via `KeyCipher` when `EncryptSessionData` is enabled), scopes and audience as pipe-delimited strings, client_id as a string reference resolved at read time.

### Requirement 2: Database Migration

**User Story:** As an AS operator, I want a database table for PAR session data, so that PAR sessions are persisted across AS restarts and shared across replicas in multi-instance deployments.

#### Acceptance Criteria

1. THE AS SHALL create a database migration adding the `hydra_oauth2_par` table with columns: `request_uri` (VARCHAR(255), NOT NULL, PK — the opaque PAR request URI), `nid` (UUID, NOT NULL), `client_id` (VARCHAR(255), NOT NULL), `requested_scope` (VARCHAR(512), NOT NULL, DEFAULT ''), `requested_audience` (VARCHAR(512), NOT NULL, DEFAULT ''), `form_data` (TEXT, NOT NULL — URL-encoded form data), `response_types` (VARCHAR(255), NOT NULL, DEFAULT ''), `redirect_uri` (TEXT, NOT NULL, DEFAULT ''), `state` (VARCHAR(255), NOT NULL, DEFAULT ''), `response_mode` (VARCHAR(64), NOT NULL, DEFAULT ''), `session_data` (TEXT, NOT NULL — JSON-serialized session), `requested_at` (TIMESTAMP, NOT NULL), `expires_at` (TIMESTAMP, NOT NULL).
2. THE migration SHALL create an index `idx_par_nid` on `(nid)` for tenant-scoped queries.
3. THE migration SHALL create an index `idx_par_expires_at` on `(nid, expires_at)` for TTL-based cleanup queries.
4. THE migration SHALL use `CREATE TABLE IF NOT EXISTS` for idempotency.
5. THE migration SHALL support PostgreSQL, MySQL, CockroachDB, and SQLite.
6. THE migration SHALL follow the naming convention `YYYYMMDDHHMMSS_create_par_session.up.sql` / `.down.sql` in `persistence/sql/migrations/`.
7. THE down migration SHALL drop indexes and the `hydra_oauth2_par` table cleanly.

### Requirement 3: SQL Persistence Implementation — CreatePARSession

**User Story:** As a developer, I want `CreatePARSession` implemented on the SQL persister, so that PAR sessions created at the PAR endpoint are stored in the database and accessible from any replica.

#### Acceptance Criteria

1. WHEN `CreatePARSession` is called with a `requestURI` and `AuthorizeRequester`, THE SQL_Persister SHALL serialize the `AuthorizeRequester` into a `PARSessionSQL` row: Form via `url.Values.Encode()`, Session via `json.Marshal` (with optional encryption when `EncryptSessionData` is enabled), scopes and audience as pipe-delimited strings, client_id from `request.GetClient().GetID()`, response types as pipe-delimited strings, redirect URI as string, state and response mode as strings.
2. THE SQL_Persister SHALL set the `NID` field to the current network ID from `p.NetworkID(ctx)`.
3. THE SQL_Persister SHALL set the `ExpiresAt` field from the session's `PushedAuthorizeRequestContext` expiry time (set by the PAR handler before calling `CreatePARSession`).
4. THE SQL_Persister SHALL insert the row into `hydra_oauth2_par` via Pop ORM.
5. IF a row with the same `request_uri` already exists, THE SQL_Persister SHALL return an appropriate error (duplicate key).

### Requirement 4: SQL Persistence Implementation — GetPARSession

**User Story:** As a developer, I want `GetPARSession` implemented on the SQL persister, so that the authorization endpoint can retrieve PAR sessions from the database regardless of which replica handles the request.

#### Acceptance Criteria

1. WHEN `GetPARSession` is called with a `requestURI`, THE SQL_Persister SHALL query `hydra_oauth2_par` for the row matching the `request_uri` and current network ID (`nid`).
2. IF no matching row is found, THE SQL_Persister SHALL return `fosite.ErrNotFound`.
3. IF the matching row has `expires_at` in the past, THE SQL_Persister SHALL return `fosite.ErrNotFound` (expired sessions are treated as non-existent).
4. THE SQL_Persister SHALL deserialize the row into a `fosite.AuthorizeRequester`: parse Form via `url.ParseQuery`, unmarshal Session from JSON (with optional decryption when `EncryptSessionData` is enabled), split pipe-delimited scopes, audience, and response types, resolve the Client from the client store by `client_id`, and set RedirectURI, State, and ResponseMode.
5. THE SQL_Persister SHALL preserve the `response_type` enrichment behavior from the current in-memory implementation: WHEN the HTTP request context contains a `response_type` form parameter, THE method SHALL set it on the returned `AuthorizeRequester`'s Form, so that subsequent consent flow calls carry the correct response type.

### Requirement 5: SQL Persistence Implementation — DeletePARSession

**User Story:** As a developer, I want `DeletePARSession` to remain a no-op in the SQL implementation, so that the consent flow's multi-call pattern continues to work correctly.

#### Acceptance Criteria

1. THE SQL_Persister `DeletePARSession` SHALL be a no-op (return `nil` without modifying the database), preserving the current behavior where PAR sessions survive across the three `/oauth2/auth` calls in the consent flow.
2. THE SQL_Persister SHALL include a code comment explaining why `DeletePARSession` is a no-op: Hydra's consent flow calls `/oauth2/auth` multiple times (login → consent → final), and each call re-resolves the `request_uri`. The PAR session must survive across these calls. Sessions expire naturally via the `expires_at` TTL.

### Requirement 6: TTL-Based Expired Session Cleanup

**User Story:** As an AS operator, I want expired PAR sessions to be cleaned up automatically, so that the database does not accumulate stale rows indefinitely.

#### Acceptance Criteria

1. THE SQL_Persister SHALL provide a method to delete expired PAR sessions from `hydra_oauth2_par` where `expires_at` is in the past and `nid` matches the current network ID.
2. THE cleanup method SHALL be integrated into Hydra's existing token cleanup/janitor mechanism so that expired PAR sessions are purged alongside other expired OAuth2 data.
3. THE cleanup query SHALL use the `idx_par_expires_at` index on `(nid, expires_at)` for efficient scanning.

### Requirement 7: Registry Wiring — Replace In-Memory with SQL Storage

**User Story:** As a developer, I want `RegistrySQL.PARStorage()` to return the SQL-backed implementation instead of the in-memory store, so that PAR sessions are shared across replicas.

#### Acceptance Criteria

1. THE `RegistrySQL.PARStorage()` method SHALL return the SQL_Persister cast to `fosite.PARStorage` instead of the current `inMemoryPARStorage`.
2. THE `RegistrySQL` SHALL remove the lazy initialization of `inMemoryPARStorage` and the `parStore` field, since the SQL_Persister is always available after `Init()`.
3. THE `inMemoryPARStorage` struct and `newInMemoryPARStorage()` function in `driver/registry_par.go` SHALL be removed, as they are no longer needed.
4. THE `PARStorage()` method SHALL follow the same pattern as other storage accessors on `RegistrySQL` (e.g., `PreAuthorizedCodeStorage()` which returns `m.Persister().(preauth.PreAuthorizedCodeStorage)`).

### Requirement 8: Persister Interface Composition

**User Story:** As a developer, I want the `persistence.Persister` aggregate interface to include PAR storage methods, so that the SQL persister is required to implement them and the type assertion in `RegistrySQL.PARStorage()` is safe.

#### Acceptance Criteria

1. THE `persistence.Persister` interface in `persistence/definitions.go` SHALL compose a PAR storage interface that includes `CreatePARSession`, `GetPARSession`, and `DeletePARSession` methods matching the `fosite.PARStorage` contract.
2. THE composition SHALL ensure that `persistence/sql/Persister` must implement the PAR storage methods at compile time.

### Requirement 9: Multi-Database Support

**User Story:** As an AS operator, I want the PAR session table and queries to work across all supported databases, so that the feature works regardless of the database backend.

#### Acceptance Criteria

1. THE migration SQL SHALL be compatible with PostgreSQL, MySQL, CockroachDB, and SQLite.
2. THE SQL queries in the persistence implementation SHALL use Pop ORM methods (e.g., `Connection.Create`, `Connection.Where().First()`) or raw SQL that is compatible with all four database backends.
3. THE `session_data` column SHALL use TEXT type (not JSON) for maximum cross-database compatibility, since SQLite does not have a native JSON type. JSON validation is handled at the application layer.

### Requirement 10: SQLite Schema Dump Update

**User Story:** As a developer running tests, I want the SQLite schema dump to include the new `hydra_oauth2_par` table, so that test helpers that load the schema dump work correctly.

#### Acceptance Criteria

1. THE SQLite schema dump in `internal/testhelpers/sql_schemas/` SHALL be updated to include the `hydra_oauth2_par` table definition and its indexes.

### Requirement 11: Existing E2E Test Compatibility

**User Story:** As a developer, I want the existing PAR e2e test to pass with the SQL-backed implementation, so that the replacement does not break existing functionality.

#### Acceptance Criteria

1. WHEN the SQL-backed PAR storage replaces the in-memory implementation, THE existing e2e test `TestAuthCodeFlow_PAR_RAR_DPoP` SHALL continue to pass without modification.
2. THE SQL-backed implementation SHALL preserve the same observable behavior as the in-memory implementation: `CreatePARSession` stores the session, `GetPARSession` retrieves it with `response_type` enrichment, `DeletePARSession` is a no-op, and sessions are accessible across the three consent flow calls.

### Requirement 12: Session Data Serialization Round-Trip

**User Story:** As a developer, I want the PAR session serialization to be lossless, so that all authorization request data survives the write-to-DB and read-from-DB cycle without corruption.

#### Acceptance Criteria

1. FOR ALL valid AuthorizeRequester objects, serializing to PARSessionSQL and deserializing back SHALL produce an equivalent AuthorizeRequester (round-trip property): Form values, Client ID, Session data, ResponseTypes, RedirectURI, Scopes, Audience, State, and ResponseMode SHALL all be preserved.
2. THE serialization SHALL handle edge cases: empty scopes (empty string, not nil), empty audience, empty response types, empty state, default response mode, and Form values containing special characters (URL-encoded correctly).
3. THE session JSON serialization SHALL handle the `oauth2.Session` struct including nested `openid.DefaultSession` fields, `Extra` map, and expiry times.
