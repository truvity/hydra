# ECR Build Pipeline

How to build the Hydra Docker image and push it to Amazon ECR for deployment
in the bar ecosystem.

---

## Toolchain Setup

The Hydra repo includes a self-contained build toolchain via `devbox.json` and
wrapper scripts in `bin/`. No Go module dependency on the bar repo is required.

### Prerequisites

1. **devbox** — Install from [jetify.com/devbox](https://www.jetify.com/devbox)
2. **Git credentials** — SSH key or `gh auth login` for accessing the private
   `github.com/truvity/bar` repo (required by `go run` in wrapper scripts)
3. **AWS SSO login** — For ECR push: `aws sso login --profile <profile>`
4. **GORELEASER_KEY** — GoReleaser Pro license key (stored in `bin/.goreleaser-key`
   or set as env var)

### Enter the Development Environment

```bash
devbox shell
```

This activates the toolchain (Go, AWS CLI, ECR credential helper, jq, gh) and
adds `bin/` to PATH, making `barctl`, `forgectl`, and `goreleaser` available.

### Wrapper Scripts

| Script | Purpose |
|---|---|
| `bin/barctl` | Runs `go run github.com/truvity/bar/bar/cmd/barctl@latest` |
| `bin/forgectl` | Runs `go run github.com/truvity/bar/forgectl/cmd/forgectl@latest` |
| `bin/goreleaser` | Auto-installs GoReleaser Pro via forgectl, loads license key, executes binary |

### Install GoReleaser Pro

```bash
forgectl install
```

This reads `forge.yaml`, downloads the GoReleaser Pro binary to
`bin/.goreleaser-pro`, and generates `forge.lock.yaml` (gitignored).

---

## Local Build Workflow

### Snapshot Build (Local Development)

The existing local dev script continues to work unchanged:

```bash
./build-and-run-oidc4vci-local.sh
```

This runs `goreleaser release --snapshot --clean --skip=sign` and produces
`oryd/hydra:local-amd64` / `oryd/hydra:local-arm64` images. The ECR entry is
automatically skipped when `REGISTRY` is not set.

### Build with ECR Push (Manual)

```bash
export REGISTRY=677224894277.dkr.ecr.eu-central-1.amazonaws.com
aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin $REGISTRY
goreleaser release --snapshot --clean
```

### Full Artifact Build via barctl

```bash
barctl artifacts snapshot ory
```

This orchestrates the full pipeline:
1. Invokes GoReleaser with `REGISTRY` set
2. Builds multi-arch Docker image
3. Pushes to ECR
4. Generates `dist/ory.forge.lock.yaml` with pinned image digest

---

## CI Workflow

The `.github/workflows/ecr-push.yaml` workflow handles automated ECR pushes.

### Triggers

| Trigger | Condition | GoReleaser Mode |
|---|---|---|
| Tag push | `v*-oidc4vci.*` | `release --clean` |
| Manual dispatch | `nightly: true` | `release --nightly --clean` |

### Required Secrets

| Secret | Purpose |
|---|---|
| `ECR_REGISTRY_URL` | ECR registry URL (e.g., `677224894277.dkr.ecr.eu-central-1.amazonaws.com`) |
| `GORELEASER_KEY` | GoReleaser Pro license key |
| `ECR_PUSH_ROLE_ARN` | IAM role ARN for OIDC federation (IRSA) |

### Runner

The workflow runs on `ci-stable` — a self-hosted ARC runner on the bar kernel
Kubernetes cluster with ECR credentials available via IRSA.

### What It Produces

- Docker image pushed to `<REGISTRY>/ory/hydra:<version>`
- On tag push: version tag (e.g., `2.3.0-oidc4vci.1`) + `latest`
- On nightly: nightly version tag (e.g., `2.3.0-oidc4vci.2-abc1234-nightly`)

---

## Lock File Flow

After building, the artifact lock file is used for GitOps deployment:

```
Hydra repo                          Bar repo
─────────────────────────────────   ─────────────────────────────────
barctl artifacts snapshot ory
  → dist/ory.forge.lock.yaml        hydra/deploy/<env>/ory.forge.lock.yaml
                                      ← manual copy
```

1. `barctl artifacts snapshot ory` generates `dist/ory.forge.lock.yaml`
2. Developer manually copies the lock file to the bar repo's deploy directory
3. The lock file pins the exact image digest for reproducible deployment

The lock file is generated in `dist/` (gitignored in Hydra) and committed to
the bar repo for GitOps.

---

## Versioning

### Fork Version Format

```
v<base>-oidc4vci.<fork_release>
```

| Component | Description | Example |
|---|---|---|
| `<base>` | Upstream Ory Hydra semver | `2.3.0` |
| `<fork_release>` | Monotonically increasing integer per base | `1`, `2`, `3` |

Examples:
- `v2.3.0-oidc4vci.1` — first fork release on upstream 2.3.0
- `v2.3.0-oidc4vci.2` — second fork release on upstream 2.3.0
- `v26.1.0-oidc4vci.1` — first fork release on upstream 26.1.0

When rebasing onto a new upstream version, the fork release counter resets to 1.

### Nightly Version Format

GoReleaser's `--nightly` flag produces:
```
<next-version>-<shortcommit>-nightly
```

Example: `2.3.0-oidc4vci.2-abc1234-nightly`

### Snapshot Version

Local snapshot builds use `version_template: "local"`, producing tags like
`local-amd64` and `local-arm64`.

### No monorepo.tag_prefix

Hydra is a standalone repository with its own tag namespace. The
`monorepo.tag_prefix` field (used by bar subprojects) does not apply here.

---

## Troubleshooting

### `GOPRIVATE not set` — go run fails with 404

```
go: module github.com/truvity/bar/...: reading ...: 404 Not Found
```

**Fix:** Ensure you're in a devbox shell (`devbox shell`) or export
`GOPRIVATE=github.com/truvity/*` manually.

### Missing GORELEASER_KEY

```
warning: goreleaser key not found at bin/.goreleaser-key and GORELEASER_KEY not set
```

**Fix:** Either:
- Place the key in `bin/.goreleaser-key` (gitignored)
- Export `GORELEASER_KEY=<key>` in your environment
- In CI, the key comes from `secrets.GORELEASER_KEY`

### ECR Authentication Failure

```
Error: Cannot perform an interactive login from a non TTY device
```

**Fix:** Run `aws sso login` first, then:
```bash
aws ecr get-login-password --region eu-central-1 | docker login --username AWS --password-stdin $REGISTRY
```

### forgectl install fails

```
Error: failed to download goreleaser-pro: ...
```

**Fix:** Check network connectivity and GitHub rate limits. Retry after a few
minutes, or manually download from the goreleaser-pro releases page.

### GoReleaser template evaluation error

```
template: ...: function "REGISTRY" not defined
```

**Fix:** This means the `env` section in `.goreleaser.yml` is missing or
malformed. The `REGISTRY` variable must be declared with the `index .Env` guard.
