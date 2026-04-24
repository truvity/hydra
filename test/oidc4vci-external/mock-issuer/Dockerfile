# syntax=docker/dockerfile:1.7
#
# MockIssuer — standalone OIDC4VCI credential issuer for local E2E testing.
# Self-contained Go module (no hydra dependencies), built from this directory.

FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache deps
COPY go.mod ./
# No go.sum yet (zero external deps) — copy it lazily if it ever exists.
RUN go mod download

# Source
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/mock-issuer .

#########################

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/mock-issuer /usr/bin/mock-issuer

EXPOSE 4448

ENTRYPOINT ["mock-issuer"]
