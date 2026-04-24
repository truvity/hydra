# OIDC4VCI External E2E Tests

End-to-end tests that run **against a live Hydra + mock-issuer stack** (not
in-process). They exercise the full OIDC4VCI authorization code flow including
PAR, DPoP, RAR (`authorization_details`), credential issuance, and wallet
attestation client provisioning.

## Prerequisites

- The OIDC4VCI compose stack must be running. Start it with:

  ```bash
  cd <hydra-repo-root>
  ./build-and-run-oidc4vci-local.sh
  ```

  This builds Hydra via GoReleaser, tags the image, and brings up:
  - **Hydra** (public `:4444`, admin `:4445`)
  - **PostgreSQL** (`:5432`)
  - **Consent Node** (`:3000`) — patched to echo `authorization_details`
  - **Mock Issuer** (`:4448`) — standalone credential issuer stub

- Go 1.25+ on the host (tests run outside Docker).

## Running the tests

```bash
# Against the local stack (default URLs)
go test -v -count=1 -timeout=60s ./test/oidc4vci-external/...

# Against ngrok-exposed stack
HYDRA_PUBLIC_URL=https://your-hydra.ngrok-free.dev \
MOCK_ISSUER_URL=https://your-issuer.ngrok.dev \
go test -v -count=1 -timeout=60s ./test/oidc4vci-external/...
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `HYDRA_PUBLIC_URL` | `http://127.0.0.1:4444` | Hydra public endpoint (must match Hydra's configured issuer URL) |
| `HYDRA_ADMIN_URL` | `http://127.0.0.1:4445` | Hydra admin endpoint |
| `MOCK_ISSUER_URL` | `http://127.0.0.1:4448` | Mock credential issuer endpoint |
| `REFRESH_TESTDATA` | `0` | Set to `1` to force re-creation of all cached test artifacts |

Tests are skipped automatically if Hydra is not reachable. If Hydra is
reachable but its advertised issuer doesn't match `HYDRA_PUBLIC_URL`, the test
fails with a clear message telling you to export the correct URL.

## Test files

| File | What it does |
|---|---|
| `external_test.go` | Discovery, pre-authorized code, PAR + DPoP + consent emulation (uses `client_secret_basic`) |
| `mock_issuer_test.go` | Full auth-code flow with `private_key_jwt`, DPoP, RAR, credential issuance via mock-issuer, wallet-attestation client provisioning |
| `testdata_helpers_test.go` | Caching layer for test artifacts (clients, credential configs, authorization requests, key material) |
| `ext_test.sh` | Standalone bash script for manual DPoP + PAR flow testing (no Go required) |

## Cached test data (`testdata/`)

On first run the tests register OAuth2 clients and credential configurations
with the live Hydra and mock-issuer instances, then persist the results as JSON
files under `testdata/`. Subsequent runs reuse the cached artifacts (checking
that the client still exists in Hydra's database). This avoids re-registering
on every run and keeps key material stable across sessions.

| File | Contents |
|---|---|
| `client_a.json` | `private_key_jwt` client with ES256 signing key, DPoP key, redirect URIs |
| `client_b.json` | Second `private_key_jwt` client (same shape) |
| `client_attester_a.json` | `attest_jwt_client_auth` client (`client_id=haip-wallet-attester-a`) with DPoP key |
| `client_attester_b.json` | Second wallet-attestation client (`client_id=haip-wallet-attester-b`) |
| `credential_config.json` | Mock-issuer credential configuration (`dc+sd-jwt` format) |
| `authorization_request.json` | Last PAR form payload, `request_uri`, PKCE verifier/challenge, state |

All files are `.gitignore`d. Delete them (or set `REFRESH_TESTDATA=1`) to
force regeneration. If the Hydra database is wiped (`docker compose down -v`),
stale caches are detected automatically and the clients are re-created.

## Attester key generator (`gen-attester-jwks.sh`)

Generates a Client Attester key bundle for HAIP conformance testing (wallet
attestation via `attest_jwt_client_auth`).

```bash
./gen-attester-jwks.sh              # writes to ./attester-keys/
OUT=/tmp/keys ./gen-attester-jwks.sh  # override output directory
SUBJECT=my-wallet ./gen-attester-jwks.sh
```

### What it produces

```
attester-keys/
├── ca.key.pem                   # Root CA private key (ES256 / P-256)
├── ca.cert.pem                  # Root CA certificate — paste into Hydra config
├── leaf.key.pem                 # Leaf (attester signing) private key
├── leaf.cert.pem                # Leaf certificate signed by the root CA
├── attester-keys.jwks.json      # JWKS with private key + x5c (leaf only)
└── attester-keys.public.jwks.json  # Same but without "d" (safe to share)
```

### How to use

1. **Run the generator** — it creates a 2-level PKI (root CA → leaf) and a
   JWKS containing the leaf private key with `x5c: [leaf_cert_DER]`. The root
   CA cert is NOT in `x5c` (per HAIP / draft-ietf-oauth-attestation-based-
   client-auth §6: trust anchors must not appear in the chain).

2. **Configure Hydra** — paste the root CA PEM into the quickstart config:

   ```yaml
   wallet_attestation:
     enabled: true
     trust_anchors:
       - |
         -----BEGIN CERTIFICATE-----
         <contents of ca.cert.pem>
         -----END CERTIFICATE-----
   ```

3. **Upload to conformance test** — paste the contents of
   `attester-keys.jwks.json` into the "Client Attester Keys JWKS" field.

4. **Register wallet-type clients** — the external tests do this automatically
   (`haip-wallet-attester-a`, `haip-wallet-attester-b`). For the conformance
   test, use the matching `client_id` as the test's "Client ID" field.

Existing keys are reused on subsequent runs (the script checks for
`ca.key.pem` / `leaf.key.pem`). Delete `attester-keys/` to regenerate from
scratch.

The `attester-keys/` directory is `.gitignore`d.

## Mock issuer (`mock-issuer/`)

A standalone Go service that emulates an OIDC4VCI Credential Issuer. It runs
inside the compose stack (port 4448) and provides:

- `GET /.well-known/openid-credential-issuer` — issuer metadata
- `POST /nonce` — c_nonce endpoint (with `Cache-Control: no-store`)
- `POST /credential` — credential issuance (supports `vc+sd-jwt` and
  `dc+sd-jwt` formats, DPoP-bound access tokens, `credential_identifier`
  resolution)
- Admin CRUD for credential configurations and credential offers

It delegates token validation to Hydra's admin introspection endpoint. See
`mock-issuer/README.md` (if present) or the source for details.

## Relationship to in-tree tests

The in-tree tests at `test/oidc4vci/` use an in-process Hydra registry
(`testhelpers.NewRegistryMemory`) and don't need Docker. They're faster and
cover unit-level behavior. The external tests here complement them by
exercising the full network stack (HTTP, Docker networking, ngrok tunnels,
real PostgreSQL) and validating that configuration, consent-node integration,
and credential issuance work end-to-end.
