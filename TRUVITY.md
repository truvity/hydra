# Truvity fork of Ory Hydra

Everything Truvity-specific about this fork is described here. Upstream's own
files (`README.md`, `.github/workflows/*` other than `truvity-image.yaml`,
`.docker/*`) are left alone on purpose — see
[Keeping the delta small](#keeping-the-delta-small).

## Why this fork exists

Hydra is the OAuth 2.0 / OpenID Connect server behind Truvity's **eudi** (EUDI
wallet) work. That work needs OIDC4VCI and the specs it drags in — RAR (RFC
9396), DPoP (RFC 9449), the pre-authorized code grant, wallet attestation, HAIP
metadata, persistent PAR storage — which upstream `ory/hydra` does not
implement. We carry those changes here until they land upstream.

**Upstreaming to `ory/hydra` is the goal.** Our delta is therefore kept minimal
and cleanly separable: feature commits stay self-contained, we do not reformat
or restructure anything upstream owns, and Truvity infrastructure is confined to
as few files as possible.

### What we added

- **Rich Authorization Requests (RFC 9396)** — `authorization_details` on the
  authorize, PAR and token endpoints, carried through the consent flow
- **DPoP (RFC 9449)** — sender-constrained access tokens, with nonce exchange
- **Pre-authorized code grant** — OIDC4VCI §5.1.4, including anonymous clients
- **Pushed Authorization Requests (RFC 9126)** — persisted, and enforced under
  HAIP
- **HAIP profile enforcement** — DPoP + PAR + PKCE S256 + the RFC 9207 `iss`
  parameter, switched on by one config key
- **Wallet attestation** — `attest_jwt_client_auth` per
  draft-ietf-oauth-attestation-based-client-auth-07
- **Discovery metadata** advertising all of the above

Every one of these is additive: no upstream behaviour is removed or changed, and
each is off unless its config key turns it on.

## Design documentation

The design docs, integration guides, feature write-ups and Kiro specs for this
work live in the **`truvity/bar`** repository, under
[`eudi/docs/hydra-fork/`](https://github.com/truvity/bar/tree/master/eudi/docs/hydra-fork)
— eudi is the consumer of these features and owns their documentation. They were
moved out of this fork on 2026-08-10 (from commit `3b27844d`); `TRUVITY.md` is
the only document the fork itself carries.

What is over there:

| Path                        | Contents                                                                                   |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| `ai-context/`               | Architecture overview, Hydra internals, the OIDC4VCI AS requirement gap analysis, the AS ↔ Credential Issuer boundary, per-feature design notes |
| `features/`                 | What each shipped feature does (DPoP, RAR + consent, pre-authorized code, HAIP metadata, wallet attestation) |
| `integration/`              | OIDC4VCI integration guide, `authorization_details` in the Consent App, secret management and key rotation |
| `kiro/specs/`, `kiro/steering/` | Kiro specs per capability, and the steering rules for editing this fork's Go code       |

The copies of the OIDC4VCI, HAIP and RFC specifications we implement against
stay here, under [`docs/oidc4vci/`](docs/oidc4vci/), because they are what the
code is read against.

## Branch model

| Branch                   | What it is                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `upstream-master`        | Straight mirror of `ory/hydra` `master`. **No Truvity commits ever.** This is what we rebase onto.                                  |
| `hydra-oidc4vci-changes` | **The integration branch.** `upstream-master` plus our OIDC4VCI commits. Feature branches and release tags come off this.           |
| `master`                 | Default branch, an old upstream snapshot. Carries no Truvity commits and is not the integration branch — do not develop against it. |

Feature work branches off `hydra-oidc4vci-changes` and is merged back into it by
PR.

## Versioning

Tags are `v{upstream}-oidc4vci.{n}`:

```
v26.2.0-oidc4vci.1
 └─┬──┘ └────┬────┘
   │         └── Truvity build number on top of that upstream release, from 1
   └── the upstream ory/hydra release this is rebased onto
```

`{n}` restarts at `1` for every new upstream base. Bump `{n}` when our own
changes move; move `{upstream}` when we rebase onto a newer upstream release.

## Container image

`ghcr.io/truvity/hydra:<tag>` — built and pushed by
[`.github/workflows/truvity-image.yaml`](.github/workflows/truvity-image.yaml)
on every pushed tag matching `v*-oidc4vci.*`.

- Multi-arch **linux/amd64 + linux/arm64**. arm64 is mandatory: the fleet's
  arm64 node pools carry an `arch=arm64:NoSchedule` taint, so an amd64-only
  image cannot be scheduled there.
- Built from upstream's own, unmodified `.docker/Dockerfile-distroless-static` —
  the same Dockerfile ory publishes its images from. The two architectures are
  cross-compiled with the Go toolchain and assembled into one manifest, so no
  new Dockerfile and no QEMU.
- Authenticates with the workflow's `GITHUB_TOKEN` (`packages: write`). No PAT,
  no other secret, so it works from a fresh clone of this repo.
- Provenance and SBOM attestations are attached.

To rebuild an existing tag without moving it, run the workflow via
**workflow_dispatch** and pass the tag in the `ref` input.

**This fork publishes an image only — no Helm chart.** The chart lives in
`truvity/bar` (eudi).

## Running locally

`quickstart-oidc4vci.yml` brings up Hydra + PostgreSQL + the login/consent node
+ the mock issuer. The helper script builds the image for your host
architecture (plain `go build` into upstream's
`.docker/Dockerfile-distroless-static`, the same recipe the image workflow uses)
and starts the stack:

```sh
./build-and-run-oidc4vci-local.sh              # build, up, follow logs
SKIP_BUILD=1 ./build-and-run-oidc4vci-local.sh # reuse the existing image
```

Ctrl-C tears the stack down. To expose it publicly (e.g. for the OpenID
conformance suite), export `HYDRA_PUBLIC_URL` and `MOCK_ISSUER_URL` first.

The external end-to-end tests in `test/oidc4vci-external/` run against that
running stack and cover the full flow — PAR, DPoP, RAR, `private_key_jwt` and
`attest_jwt_client_auth` client authentication, credential issuance:

```sh
go test -v -count=1 -timeout=60s ./test/oidc4vci-external/...
```

See `test/oidc4vci-external/README.md` for the environment variables, the
cached test data and the HAIP attester key generator.

## Where our code lives

Almost all of it sits at paths upstream does not use, so it never conflicts:

| Path                                                                                                              | What                                                       |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `fosite/handler/{preauth,dpop,rar,wallet_attestation}/`                                                           | One package per feature: handler, storage interface, tests. |
| `fosite/compose/compose_{preauth,dpop,rar,wallet_attestation}.go`                                                 | Factories, alongside upstream's own `compose_*.go`.        |
| `persistence/sql/persister_{preauth,dpop,par}.go`, `persistence/sql/migrations/*_oidc4vci_*.{up,down}.sql`        | Storage and schema. New tables only, never a change to an upstream table; every table carries `nid`. |
| `driver/registry_par.go`, `driver/dsn_rotating_driver.go`                                                         | Registry wiring kept out of upstream's files where possible. |
| `oauth2/handler_preauth.go`, `oauth2/*_test.go`, `test/oidc4vci/`, `test/oidc4vci-external/`                      | Endpoint additions and our tests.                          |

New migrations are named `<timestamp>_oidc4vci_<what>.{up,down}.sql` so they are
recognisable at a glance and sort after upstream's.

## Files we modify upstream — the conflict list

These exist upstream and carry our edits, so they are where a rebase hurts. Mark
every addition with an `// OIDC4VCI extension` comment, add struct fields at the
**end** of the struct and interface embeddings at the **end** of the
composition, and when a conflict comes up take upstream's version first and
re-apply our block on top.

| File                                  | Risk       | What we add                                                    |
| ------------------------------------- | ---------- | ---------------------------------------------------------------- |
| `oauth2/handler.go`                   | High       | Discovery metadata fields + their population — upstream changes this file often |
| `fosite/fosite.go`                    | Medium     | Our provider interfaces embedded in `Configurator`             |
| `fosite/config.go`, `fositex/config.go` | Medium   | The provider interfaces themselves, and their defaults         |
| `fosite/authorize_write.go`, `fosite/authorize_error.go` | Medium | RFC 9207 `iss` on success and error responses |
| `fosite/client_authentication.go`     | Medium     | `attest_jwt_client_auth` dispatch                              |
| `flow/consent_types.go`, `flow/flow.go` | Medium   | `AuthorizationDetails` and `IssuerState` on the consent request |
| `driver/registry_sql.go`, `driver/config/provider.go` | Medium | Storage accessors, factory registration, config keys |
| `persistence/definitions.go`, `consent/strategy_default.go`, `cmd/server/handler.go` | Low | Table registration and plumbing |
| `.schema/config.schema.json`, `spec/config.json`, `oauth2/.snapshots/*` | Low | Generated — regenerate, never hand-edit |

After a rebase, check the two things that silently break: the discovery document
(`curl <public>/.well-known/openid-configuration | jq`) must still advertise
`dpop_signing_alg_values_supported`, `authorization_details_types_supported`,
`pre-authorized_grant_anonymous_access_supported` and the pre-authorized grant
type; and `go test ./flow/...` must still round-trip the consent fields.

## Rebasing onto a new upstream release

Manual, by hand, on purpose — there is no automation and none is wanted.

```sh
git remote add upstream https://github.com/ory/hydra.git   # once
git fetch upstream --tags

# 1. Advance the upstream mirror to the release you are moving to.
git checkout upstream-master
git reset --hard <upstream-tag-or-commit>      # e.g. v26.3.0
git push --force-with-lease origin upstream-master

# 2. Replay our commits on top of it.
git checkout hydra-oidc4vci-changes
git rebase --onto upstream-master <previous-upstream-base> hydra-oidc4vci-changes
```

Where `<previous-upstream-base>` is the upstream commit the branch was last
rebased onto (`git merge-base` against the old `upstream-master`, so record it
before step 1).

Then:

3. Resolve conflicts. Keep each of our commits doing one thing — do not squash
   them into upstream's history, and do not take the opportunity to reformat.
4. Regenerate what upstream generates if the rebase touched it (config schema,
   SDK) rather than hand-editing the generated output.
5. Build and run the tests that matter to us:
   `go build ./... && go test ./oauth2/... ./client/... ./test/oidc4vci/...`
6. `git push --force-with-lease origin hydra-oidc4vci-changes`.
7. Tag `v{new-upstream}-oidc4vci.1` and push the tag; the image workflow does
   the rest.

## Keeping the delta small

Every file we add or change is a conflict at the next rebase, so:

- Only ever add files at paths upstream will not use. `TRUVITY.md` and
  `.github/workflows/truvity-image.yaml` are named so upstream can never collide
  with them.
- Never edit upstream's workflows (`ci.yaml`, `format.yml`, `cve-scan.yaml`, …).
  They are upstream's and several of them fail on this fork for lack of ory's
  secrets and runners; that is expected and is not something to "fix" here.
- Do not reformat, restructure, or opportunistically clean up upstream code.

### Truvity-owned files in this repo

| Path                                                                                                                       | Purpose                                                                     |
| ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `TRUVITY.md`                                                                                                               | This document — the only prose the fork carries. Design docs live in `truvity/bar`. |
| `.github/workflows/truvity-image.yaml`                                                                                     | GHCR image build. The only Truvity CI.                                      |
| `build-and-run-oidc4vci-local.sh`, `quickstart-oidc4vci.yml`, `contrib/quickstart/oidc4vci/`, `.docker/Dockerfile-oidc4vci` | Local development and demo.                                                 |
| `devbox.json`, `devbox.lock`, `.envrc`                                                                                     | Local toolchain (dev shell).                                                |
| `docs/oidc4vci/`                                                                                                           | Copies of the specs and RFCs the code implements.                           |
| `test/oidc4vci/`, `test/oidc4vci-external/`                                                                                | Our end-to-end tests.                                                       |
| The paths in [Where our code lives](#where-our-code-lives)                                                                 | The features themselves.                                                    |

Everything else belongs to upstream.

There used to be a second, GoReleaser-based CI path here — `ecr-push.yaml`,
`.goreleaser.yaml` (which had displaced upstream's own `.goreleaser.yml`),
`.docker/Dockerfile-goreleaser`, `bin/`, `forge.yaml`, `aws.ini`. It never
produced an image; it was removed and upstream's `.goreleaser.yml` restored. Do
not bring it back: `truvity-image.yaml` builds from upstream's Dockerfile and
needs no toolchain of its own.
