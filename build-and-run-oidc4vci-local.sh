#!/usr/bin/env bash
#
# Build Hydra with GoReleaser (snapshot mode) and run the OIDC4VCI
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

for cmd in docker goreleaser; do
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

ARCH_TAG="${LOCAL_TAG}-${ARCH}"

echo "==> host architecture: ${ARCH}"
echo "==> target image:      ${IMAGE}:${LOCAL_TAG} (from ${IMAGE}:${ARCH_TAG})"

# --- build with goreleaser ---------------------------------------------------

if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  echo "==> SKIP_BUILD=1, skipping goreleaser build"
else
  echo "==> building hydra via goreleaser (snapshot)"
  goreleaser release --snapshot --clean --skip=sign
fi

# --- re-tag arch-specific image to the stable :local tag ---------------------

if ! docker image inspect "${IMAGE}:${ARCH_TAG}" &>/dev/null; then
  echo "error: expected image ${IMAGE}:${ARCH_TAG} not found after build" >&2
  echo "       available tags for ${IMAGE}:" >&2
  docker images "${IMAGE}" --format '         {{.Repository}}:{{.Tag}}' >&2
  exit 1
fi

echo "==> tagging ${IMAGE}:${ARCH_TAG} -> ${IMAGE}:${LOCAL_TAG}"
docker tag "${IMAGE}:${ARCH_TAG}" "${IMAGE}:${LOCAL_TAG}"

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
