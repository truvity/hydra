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

| Path                                                                                        | Purpose                                                                                                                                                  |
| ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TRUVITY.md`                                                                                | This document.                                                                                                                                           |
| `.github/workflows/truvity-image.yaml`                                                      | GHCR image build. The only Truvity CI.                                                                                                                   |
| `.github/workflows/ecr-push.yaml`                                                           | Older ECR/GoReleaser path. Superseded by the GHCR workflow; it has never produced an image (its `ci-stable` self-hosted runner never picked the job up). |
| `.goreleaser.yaml`, `.docker/Dockerfile-goreleaser`                                         | Used by the ECR path above. Note `.goreleaser.yaml` _replaced_ upstream's `.goreleaser.yml`, which we deleted — watch for that at every rebase.          |
| `.docker/Dockerfile-oidc4vci`, `build-and-run-oidc4vci-local.sh`, `quickstart-oidc4vci.yml` | Local development and demo.                                                                                                                              |
| `devbox.json`, `devbox.lock`, `.envrc`, `forge.yaml`                                        | Local toolchain.                                                                                                                                         |
| `test/oidc4vci/`, `test/oidc4vci-external/`                                                 | Our end-to-end tests.                                                                                                                                    |
| `.kiro/`                                                                                    | Specs and design notes for the OIDC4VCI work.                                                                                                            |

Everything else belongs to upstream.
