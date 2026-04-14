# Fork Maintenance Strategy — OIDC4VCI on Hydra

## Purpose

Standard operating procedures for maintaining OIDC4VCI custom features on the Hydra fork. Covers branching, package structure, merge conflict management, database migrations, and testing.

## Branching Strategy

- **Development branch**: `hydra-oidc4vci-changes` — all OIDC4VCI work lives here
- **Upstream tracking branch**: `upstream-master` (also `master`) — tracks `upstream/master` for reference
- **Upstream remote**: `upstream` → `ory/hydra`
- **Origin remote**: `origin` → the fork repository
- Fork was created from `upstream/master` at commit `c74b7a6a` (14 commits past upstream tag `v26.2.0`)

```
# Remotes (already configured)
git remote -v
# origin    <fork-url> (fetch/push)
# upstream  https://github.com/ory/hydra.git (fetch/push)

# Development happens on hydra-oidc4vci-changes
git checkout hydra-oidc4vci-changes
```

## Versioning and Release Strategy

### Version Scheme

Use a **patched upstream version** scheme that clearly communicates the upstream base and the fork patch level:

```
v<upstream-version>-oidc4vci.<patch>
```

Examples:
- `v26.2.0-oidc4vci.1` — first release based on upstream v26.2.0
- `v26.2.0-oidc4vci.2` — second release (bugfix or feature addition) on same upstream base
- `v26.3.0-oidc4vci.1` — first release after rebasing onto upstream v26.3.0

This scheme:
- Makes the upstream base version immediately visible
- Follows semver pre-release syntax (Go modules treat `-oidc4vci.N` as a pre-release of the upstream version)
- Allows independent patch increments without conflicting with upstream tags
- Sorts correctly with `git tag --sort=-v:refname`

### Current State

```
Upstream base: v26.2.0 + 14 unreleased upstream commits (upstream/master @ c74b7a6a)
Fork branch:   hydra-oidc4vci-changes (currently at same commit, no custom changes yet)
First tag:     v26.2.0-oidc4vci.1 (when first OIDC4VCI feature is ready)
```

Since the fork is based on `upstream/master` (not a tagged release), the base is effectively "v26.2.0 + unreleased". This is fine — the version tag communicates "compatible with v26.2.0 era" and the `-oidc4vci.N` suffix distinguishes it.

### Tagging a Release

```bash
# 1. Ensure all tests pass
go test ./...

# 2. Tag the release
git tag -a v26.2.0-oidc4vci.1 -m "OIDC4VCI: RAR + DPoP + Pre-Authorized Code"

# 3. Push the tag
git push origin v26.2.0-oidc4vci.1

# 4. Build and deploy from the tag
#    (CI/CD pipeline triggers on v*-oidc4vci.* tag pattern)
```

### Incrementing Versions

| Scenario | Action |
|----------|--------|
| New OIDC4VCI feature or bugfix, same upstream base | Bump patch: `v26.2.0-oidc4vci.1` → `v26.2.0-oidc4vci.2` |
| Rebase onto new upstream release (e.g., v26.3.0) | Reset patch, update base: `v26.3.0-oidc4vci.1` |
| Upstream has no new tag but you rebase onto upstream/master | Keep current base version, bump patch: `v26.2.0-oidc4vci.2` → `v26.2.0-oidc4vci.3` |

### Go Module Considerations

The `go.mod` module path is `github.com/ory/hydra/v2`. Since this is a fork:
- If consumers import your fork directly, they use `replace` directives in their `go.mod`
- The tag scheme doesn't affect Go module resolution since the fork has its own remote
- If you change the module path (e.g., to your org), update `go.mod` and all internal imports — this is a large change, only do it if you need to publish the fork as a standalone module

### Release Checklist

```bash
# Pre-release verification
1. git log --oneline upstream/master..hydra-oidc4vci-changes  # review custom commits
2. go test ./...                                               # full test suite
3. go vet ./...                                                # static analysis
4. golangci-lint run                                           # linter (uses .golangci.yml)

# Tag
5. git tag -a v26.2.0-oidc4vci.N -m "<summary of changes>"
6. git push origin v26.2.0-oidc4vci.N

# Post-release
7. Update deployment configs to reference new tag
8. Run smoke tests against deployed instance
9. Verify discovery metadata: curl <issuer>/.well-known/openid-configuration | jq .
```

### Upstream Rebase + Re-tag Workflow

When upstream releases a new version (e.g., `v26.3.0`):

```bash
# 1. Fetch upstream
git fetch upstream --tags

# 2. Rebase onto the new upstream tag (not master, for stability)
git checkout hydra-oidc4vci-changes
git rebase v26.3.0

# 3. Resolve conflicts (see "Files That TOUCH Upstream" section below)

# 4. Run full test suite
go test ./...

# 5. Tag with new base version
git tag -a v26.3.0-oidc4vci.1 -m "Rebase onto v26.3.0 + OIDC4VCI features"

# 6. Force-push rebased branch + push new tag
git push origin hydra-oidc4vci-changes --force-with-lease
git push origin v26.3.0-oidc4vci.1
```

## Custom Package Structure (Isolated, Additive)

These directories and files **do not exist upstream** — they will never cause merge conflicts:

### New Handler Directories
- `fosite/handler/preauth/` — Pre-Authorized Code `TokenEndpointHandler`
- `fosite/handler/dpop/` — DPoP proof validation `TokenEndpointHandler`
- `fosite/handler/rar/` — RAR `AuthorizeEndpointHandler` + `PushedAuthorizeEndpointHandler`
- `fosite/handler/wallet_attestation/` — Wallet Attestation `ClientAuthenticationStrategy`

Each handler directory contains:
- `handler.go` — handler struct and interface implementation
- `storage.go` — storage interface definition
- `handler_test.go` — unit tests and property-based tests

### New Compose Factories
- `fosite/compose/compose_preauth.go` — `PreAuthorizedCodeFactory`
- `fosite/compose/compose_dpop.go` — `DPoPFactory`
- `fosite/compose/compose_rar.go` — `RARFactory`

These are additive files alongside existing factories like `compose_par.go`. No modification to `compose.go` needed if factories are registered via `driver/registry_sql.go` rather than `ComposeAllEnabled()`.

### New Config Keys
- Added in `driver/config/` following the existing `KeyXxx` pattern
- New keys: `KeyPreAuthorizedCodeEnabled`, `KeyPreAuthorizedCodeLifespan`, `KeyPreAuthorizedCodeAnonymousAccess`, `KeyDPoPEnabled`, `KeyDPoPSigningAlgValues`, `KeyDPoPNonceEnabled`, `KeyDPoPNonceLifespan`, `KeyRAREnabled`, `KeyRARTypesSupported`, `KeyHAIPEnforced`, `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`, `KeyAuthResponseIssParameterEnabled`
- Provider methods on `DefaultProvider` — additive, no conflict risk

## Files That TOUCH Upstream (Merge Conflict Risk)

These files exist upstream and will be modified by OIDC4VCI features. They require careful handling during upstream merges:

### `fosite/fosite.go` — `Configurator` interface
- **Change**: Embed new provider interfaces (`PreAuthorizedCodeConfigProvider`, `DPoPConfigProvider`, `RARConfigProvider`, `HAIPConfigProvider`, `WalletAttestationConfigProvider`)
- **Conflict risk**: Medium — upstream may add new providers to the same interface
- **Resolution strategy**: Add our providers at the end of the interface composition list

### `fosite/config.go` — Provider interface definitions
- **Change**: Define new provider interfaces (e.g., `DPoPConfigProvider`, `PreAuthorizedCodeConfigProvider`)
- **Conflict risk**: Low-Medium — upstream may add new interfaces in the same file
- **Resolution strategy**: Our interfaces are self-contained blocks; append at end of file

### `flow/consent_types.go` — Consent flow types
- **Change**: Add `AuthorizationDetails sqlxx.JSONRawMessage` field to `OAuth2ConsentRequest` and `AcceptOAuth2ConsentRequest`; add `IssuerState string` to `OAuth2ConsentRequest`
- **Conflict risk**: Medium — upstream may modify these structs
- **Resolution strategy**: Our fields are additive struct members; add at end of struct before closing brace

### `oauth2/handler.go` — Discovery metadata
- **Change**: Add new fields to `oidcConfiguration` struct (`PreAuthorizedGrantAnonymousAccessSupported`, `AuthorizationDetailsTypesSupported`, `DPoPSigningAlgValuesSupported`, `AuthorizationResponseIssParameterSupported`); populate them in `discoverOidcConfiguration()`
- **Conflict risk**: High — upstream frequently modifies discovery metadata
- **Resolution strategy**: Add struct fields at end; add population logic at end of the struct literal in `discoverOidcConfiguration()`

### `driver/registry_sql.go` — Registry wiring
- **Change**: Add new storage accessors (`PreAuthorizedCodeStorage()`, `DPoPNonceStorage()`), register new factories, add new handler registrations
- **Conflict risk**: Medium — upstream modifies registry wiring
- **Resolution strategy**: Add new methods and registrations in clearly separated blocks with comments

## Upstream Merge SOP

Standard procedure for incorporating upstream changes. Prefer rebasing onto tagged releases rather than `upstream/master` for stability.

```bash
# 1. Fetch latest upstream (including tags)
git fetch upstream --tags

# 2. Check what upstream released
git tag -l 'v*' --sort=-v:refname | head -5

# 3. Rebase onto the target upstream tag (e.g., v26.3.0)
git checkout hydra-oidc4vci-changes
git rebase v26.3.0   # or upstream/master if no new tag

# 4. Resolve conflicts in touched files (see list above)
#    Priority order for conflict resolution:
#    a. fosite/fosite.go — ensure new providers still embedded in Configurator
#    b. fosite/config.go — ensure new provider interfaces still defined
#    c. flow/consent_types.go — ensure AuthorizationDetails fields still present
#    d. oauth2/handler.go — ensure new metadata fields and population logic intact
#    e. driver/registry_sql.go — ensure new storage/factory registrations intact

# 5. Run full test suite
go test ./...

# 6. Verify discovery metadata still correct
#    curl http://localhost:4444/.well-known/openid-configuration | jq .
#    Check: dpop_signing_alg_values_supported, authorization_details_types_supported,
#           pre-authorized_grant_anonymous_access_supported, grant_types_supported includes pre-auth

# 7. Verify consent flow types still serialize correctly
go test ./flow/... -run TestConsent

# 8. Force-push rebased branch
git push origin hydra-oidc4vci-changes --force-with-lease

# 9. Tag with new base version (see Versioning section)
git tag -a v26.3.0-oidc4vci.1 -m "Rebase onto v26.3.0 + OIDC4VCI features"
git push origin v26.3.0-oidc4vci.1
```

### Conflict Resolution Tips
- Keep upstream changes, then re-apply our additions
- Use `git diff v26.2.0..hydra-oidc4vci-changes -- <file>` to see our delta before rebasing
- If a conflict is complex, consider cherry-picking our commits onto a fresh branch from the new upstream tag

## Database Migration Strategy

### New Tables (Additive — No Upstream Conflict Risk)
- `hydra_oauth2_preauth_code` — Pre-Authorized Code grant data (signature, client_id, authorization_details, tx_code_hash, session_data, redeemed, expires_at, etc.)
- `hydra_oauth2_dpop_jti` — DPoP JTI replay cache (jti, nid, used_at, expires_at)

### Migration Framework
- Use Hydra's existing migration framework (Pop/Fizz migrations in `persistence/`)
- Migration files in `persistence/sql/migrations/` following existing naming convention
- Naming: `YYYYMMDDHHMMSS_oidc4vci_<description>.up.sql` / `.down.sql`
- Example: `20240101000000_oidc4vci_create_preauth_code.up.sql`

### Migration Principles
- **Additive only** — new tables, no modifications to existing upstream tables
- Each migration is idempotent where possible (`CREATE TABLE IF NOT EXISTS`)
- Down migrations drop the new tables cleanly
- Multi-tenancy: all new tables include `nid` (Network ID) column, matching Hydra's multi-tenant pattern
- Foreign keys reference `hydra_client` for `client_id` where applicable

### Migration Files
```
persistence/sql/migrations/
├── YYYYMMDDHHMMSS_oidc4vci_create_preauth_code.up.sql
├── YYYYMMDDHHMMSS_oidc4vci_create_preauth_code.down.sql
├── YYYYMMDDHHMMSS_oidc4vci_create_dpop_jti.up.sql
└── YYYYMMDDHHMMSS_oidc4vci_create_dpop_jti.down.sql
```

## Testing Strategy

### Per-Handler Tests
Each new handler has its own test file in its package directory:
- `fosite/handler/preauth/handler_test.go` — Pre-Authorized Code handler tests (Properties 1–5)
- `fosite/handler/dpop/handler_test.go` — DPoP handler tests (Properties 12–14)
- `fosite/handler/rar/handler_test.go` — RAR handler tests (Properties 6–11)
- `fosite/handler/wallet_attestation/handler_test.go` — Wallet Attestation tests (Property 20)

### Integration Tests
- `fosite/integration/` — end-to-end flow tests combining multiple handlers
- Test full authorization code + RAR + DPoP flow
- Test pre-authorized code + DPoP flow
- Test consent flow-through with `authorization_details` enrichment

### Test Commands
```bash
# Run all tests
go test ./...

# Run specific handler tests
go test ./fosite/handler/preauth/...
go test ./fosite/handler/dpop/...
go test ./fosite/handler/rar/...

# Run integration tests
go test ./fosite/integration/...

# Run with verbose output for property-based tests
go test -v ./fosite/handler/preauth/... -run TestProperty
```

### Property-Based Testing
- Library: `pgregory.net/rapid`
- Each correctness property (Properties 1–24 from design doc) maps to one property-based test
- Generators produce random valid/invalid inputs for comprehensive coverage
- Minimum 100 iterations per property test
