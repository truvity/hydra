#!/usr/bin/env bash
#
# Build the Hydra image for the host architecture and run the OIDC4VCI
# quickstart compose stack, streaming container logs to the console.
#
# Usage:
#   ./build-and-run-oidc4vci-local.sh            # build + up + follow logs
#   SKIP_BUILD=1 ./build-and-run-oidc4vci-local.sh  # reuse existing image
#
# Ctrl-C stops log streaming AND tears down the compose stack.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="quickstart-oidc4vci.yml"
IMAGE="oryd/hydra"
LOCAL_TAG="local"

# --- shutdown handling -------------------------------------------------------

shutdown() {
  # Guard against double-invocation (trap fires once, but be safe)
  trap - INT TERM EXIT
  echo
  echo "==> shutting down compose stack"
  docker compose -f "$COMPOSE_FILE" down --remove-orphans
  exit 0
}
trap shutdown INT TERM

# --- preflight ---------------------------------------------------------------

for cmd in docker go; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "error: '$cmd' is required but not installed" >&2
    exit 1
  fi
done

if ! docker info &>/dev/null; then
  echo "error: Docker daemon is not running" >&2
  exit 1
fi

# --- detect host architecture ------------------------------------------------

case "$(uname -m)" in
  x86_64 | amd64) ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)
    echo "error: unsupported host architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

echo "==> host architecture: ${ARCH}"
echo "==> target image:      ${IMAGE}:${LOCAL_TAG}"

# --- build the image ---------------------------------------------------------
#
# Same recipe as .github/workflows/truvity-image.yaml: cross-compile the binary
# with the Go toolchain, then COPY it into upstream's own, unmodified
# .docker/Dockerfile-distroless-static. Host architecture only — the published
# multi-arch manifest is the workflow's job, not this script's.

if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  echo "==> SKIP_BUILD=1, reusing the existing ${IMAGE}:${LOCAL_TAG} image"

  if ! docker image inspect "${IMAGE}:${LOCAL_TAG}" &>/dev/null; then
    echo "error: ${IMAGE}:${LOCAL_TAG} does not exist — run without SKIP_BUILD first" >&2
    exit 1
  fi
else
  echo "==> building hydra for linux/${ARCH}"

  CTX="$(mktemp -d)"

  LDFLAGS="-s -w"
  LDFLAGS="${LDFLAGS} -X github.com/ory/hydra/v2/driver/config.Version=${LOCAL_TAG}"
  LDFLAGS="${LDFLAGS} -X github.com/ory/hydra/v2/driver/config.Commit=$(git rev-parse HEAD)"
  LDFLAGS="${LDFLAGS} -X github.com/ory/hydra/v2/driver/config.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" go build \
    -buildmode=exe \
    -tags=netgo \
    -trimpath \
    -ldflags "${LDFLAGS}" \
    -o "${CTX}/hydra" \
    .

  echo "==> packaging ${IMAGE}:${LOCAL_TAG}"
  docker build \
    --platform "linux/${ARCH}" \
    -f .docker/Dockerfile-distroless-static \
    -t "${IMAGE}:${LOCAL_TAG}" \
    "${CTX}"

  rm -rf "${CTX}"
fi

# --- bring the stack up ------------------------------------------------------

# URLs baked into the containers. Defaults mirror the yaml config.
EFFECTIVE_HYDRA_PUBLIC_URL="${HYDRA_PUBLIC_URL:-http://127.0.0.1:4444}"
EFFECTIVE_MOCK_ISSUER_URL="${MOCK_ISSUER_URL:-http://127.0.0.1:4448}"

echo "==> HYDRA_PUBLIC_URL = ${EFFECTIVE_HYDRA_PUBLIC_URL}"
echo "==> MOCK_ISSUER_URL  = ${EFFECTIVE_MOCK_ISSUER_URL}"
echo "==> starting compose stack (${COMPOSE_FILE})"
docker compose -f "$COMPOSE_FILE" up -d --build --force-recreate

echo
echo "==> services:"
docker compose -f "$COMPOSE_FILE" ps
echo
echo "==> endpoints:"
echo "     public:       ${EFFECTIVE_HYDRA_PUBLIC_URL}"
echo "     admin:        http://127.0.0.1:4445"
echo "     consent:      http://127.0.0.1:3000"
echo "     mock-issuer:  ${EFFECTIVE_MOCK_ISSUER_URL}"
echo
echo "==> streaming logs (Ctrl-C stops the stack and tears it down)"
echo

docker compose -f "$COMPOSE_FILE" logs -f --tail=0 &
LOGS_PID=$!

# Wait for the logs process. When Ctrl-C fires, `wait` returns non-zero and
# the trap runs shutdown(). If logs exit on their own (e.g. all containers
# died), fall through to shutdown as well.
wait "$LOGS_PID" || true
shutdown
