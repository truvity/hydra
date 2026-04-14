---
inclusion: fileMatch
fileMatchPattern: "persistence/**"
---

# Persistence Layer Context

When working on persistence code, follow these patterns.

## Architecture

- `persistence.Persister` — aggregate interface composing all domain storage interfaces
- `persistence/sql/` — single SQL implementation using Pop ORM (`github.com/ory/pop/v6`)
- Domain packages define their own `Manager`/`Storage` interfaces; `Persister` embeds them all

## Models

- Use Pop struct tags: `db:"column_name"`
- Implement `TableName() string` on model structs
- Use `sqlxx.NullString`, `sqlxx.NullBool` for nullable columns
- Use `BeforeSave(*pop.Connection) error` hooks for pre-persistence logic

## Migrations

- Location: `persistence/sql/migrations/`
- Source: `persistence/sql/src/`
- Naming: `YYYYMMDDHHMMSS_<description>.up.sql` / `.down.sql`
- Support: PostgreSQL, MySQL, CockroachDB, SQLite

## OIDC4VCI New Tables

Two new tables are additive (no upstream conflict):
- `hydra_oauth2_preauth_code` — Pre-Authorized Code grant data (signature PK, nid, client_id, authorization_details, tx_code_hash, session_data, redeemed, expires_at)
- `hydra_oauth2_dpop_jti` — DPoP JTI replay cache (jti PK, nid, used_at, expires_at)

All new tables MUST include `nid` (Network ID) column for multi-tenancy. Use `CREATE TABLE IF NOT EXISTS` for idempotency.

## Key References

- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — DB migration strategy
- #[[file:docs/ai-context/features/feature-pre-authorized-code.md]] — PreAuthorizedCodeData model
- #[[file:docs/ai-context/features/feature-dpop.md]] — DPoP JTI table schema
