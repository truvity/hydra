# Feature: Wallet Attestation Client Authentication

## Purpose

Steering document for implementing Wallet Attestation-based client authentication (`attest_jwt_client_auth`) in the Hydra AS fork. This adds a new client authentication method where Wallets prove their identity using a signed attestation from their Wallet Provider, combined with a Proof of Possession (PoP) JWT.

## Location

- Handler: `fosite/handler/wallet_attestation/handler.go` (or extension of `fosite/client_authentication.go`)
- Tests: `fosite/handler/wallet_attestation/handler_test.go`
- Config keys: `driver/config/` → `KeyWalletAttestationEnabled`, `KeyWalletAttestationTrustAnchors`

## Authentication Flow

### HTTP Headers

Two headers are required on PAR and Token requests:

1. **`OAuth-Client-Attestation`** — The Wallet Attestation JWT, signed by the Wallet Provider
2. **`OAuth-Client-Attestation-PoP`** — The Proof of Possession JWT, signed by the Wallet instance

### Wallet Attestation JWT Validation

The `OAuth-Client-Attestation` header contains a JWT signed by the Wallet Provider:

1. Parse the JWT and extract the `x5c` JOSE header parameter (certificate chain)
2. Build the X.509 certificate chain from `x5c`
3. Validate the certificate chain against configured trust anchors (`GetWalletAttestationTrustAnchors(ctx)`)
   - The chain must terminate at a trusted root certificate
   - HAIP rule: the trust anchor itself MUST NOT be included in the `x5c` chain
   - HAIP rule: the signing certificate MUST NOT be self-signed
4. Verify the JWT signature using the public key from the leaf certificate in the `x5c` chain
5. Validate standard JWT claims:
   - `exp` — must not be expired
   - `iss` — identifies the Wallet Provider
6. Extract `sub` claim — must match the `client_id` in the request
   - HAIP rule: `sub` must be shared by all wallet instances of the same type (not unique per instance)
7. Extract `cnf` (confirmation) claim — contains the public key for PoP validation

### PoP JWT Validation

The `OAuth-Client-Attestation-PoP` header contains a JWT signed by the Wallet instance:

1. Extract the confirmation key from the Wallet Attestation's `cnf` claim
2. Verify the PoP JWT signature using the key from `cnf`
3. Validate claims:
   - `aud` — must match the AS Issuer Identifier (from `Configurator.GetIDTokenIssuer()` or equivalent)
   - `iat` — must be recent (within configurable clock skew)
   - `jti` — must be unique (replay protection)

### HAIP-Specific Rules

- Wallet Attestations MUST NOT be reused across Issuers — the `aud` in the PoP JWT binds the attestation to a specific AS
- `sub` in the Wallet Attestation must be shared by all wallet instances of the same type (not unique per instance)
- The `x5c` trust anchor MUST NOT be included in the certificate chain
- The signing certificate MUST NOT be self-signed
- ES256 must be supported for both Wallet Attestation and PoP JWT signature validation

## Integration Point

### Option A: Standalone Handler Package

Location: `fosite/handler/wallet_attestation/handler.go`

```go
type WalletAttestationAuthenticator struct {
    Config WalletAttestationConfigProvider
}

func (a *WalletAttestationAuthenticator) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
    // 1. Check for OAuth-Client-Attestation header
    // 2. Validate Wallet Attestation JWT
    // 3. Validate PoP JWT
    // 4. Match sub to client_id
    // 5. Return authenticated client
}
```

### Option B: Extension of `fosite/client_authentication.go`

Add a new case in the existing `AuthenticateClient()` method that checks for the `OAuth-Client-Attestation` header and delegates to wallet attestation validation logic.

### Registration

Registered as a `ClientAuthenticationStrategy` extension in the `Configurator`:

- The `ClientAuthenticationStrategyProvider.GetClientAuthenticationStrategy(ctx)` returns a strategy that includes wallet attestation as one of the supported methods
- The strategy is checked during `Fosite.AuthenticateClient()` which is called for both PAR and token requests
- When the `OAuth-Client-Attestation` header is present, the wallet attestation authenticator takes precedence

## Config Provider

```go
type WalletAttestationConfigProvider interface {
    GetWalletAttestationEnabled(ctx context.Context) bool
    GetWalletAttestationTrustAnchors(ctx context.Context) []*x509.Certificate
}
```

Config keys in `driver/config/`:
- `KeyWalletAttestationEnabled` → `bool`
- `KeyWalletAttestationTrustAnchors` → `[]*x509.Certificate` (loaded from PEM files or config)

The trust anchors are the root CA certificates of trusted Wallet Providers. The AS validates that the `x5c` certificate chain in the Wallet Attestation JWT chains to one of these anchors.

## Error Codes

All validation failures return `invalid_client`:

- **`invalid_client`** — Wallet Attestation JWT signature verification failed
- **`invalid_client`** — Certificate chain does not chain to a configured trust anchor
- **`invalid_client`** — `sub` claim does not match `client_id` in the request
- **`invalid_client`** — Wallet Attestation JWT `exp` is in the past (expired)
- **`invalid_client`** — PoP JWT signature verification failed
- **`invalid_client`** — PoP JWT `aud` does not match AS Issuer Identifier
- **`invalid_client`** — PoP JWT `iat` is not recent (stale)
- **`invalid_client`** — PoP JWT `jti` has been seen before (replay)
- **`invalid_client`** — Trust anchor included in `x5c` chain (HAIP violation)
- **`invalid_client`** — Signing certificate is self-signed (HAIP violation)

Using `invalid_client` for all failures follows OAuth 2.0 convention — client authentication errors always use this code. Debug details are only sent when `GetSendDebugMessagesToClients()` returns true.

## Discovery Metadata

In `oauth2/handler.go` → `oidcConfiguration`:

- Add `attest_jwt_client_auth` to the `token_endpoint_auth_methods_supported` array when Wallet Attestation is enabled
- Existing auth methods: `["client_secret_post", "client_secret_basic", "private_key_jwt", "none"]`
- With Wallet Attestation: `["client_secret_post", "client_secret_basic", "private_key_jwt", "none", "attest_jwt_client_auth"]`

## Cross-References

- [01-hydra-internal-design.md](../01-hydra-internal-design.md) — `ClientAuthenticationStrategyProvider`, `Fosite.AuthenticateClient()` in the token endpoint lifecycle
- [03-issuer-integration-boundary.md](../03-issuer-integration-boundary.md) — Wallet as OAuth 2.0 Client, client authentication at PAR and token endpoints
- [04-fork-maintenance-strategy.md](../04-fork-maintenance-strategy.md) — Isolated handler directory, config key additions
- [feature-par.md](feature-par.md) — Wallet Attestation at PAR endpoint uses the same client auth pipeline
- [feature-dpop.md](feature-dpop.md) — DPoP and Wallet Attestation are complementary — DPoP binds tokens, Wallet Attestation authenticates the client
- [Design doc](../../.kiro/specs/oidc4vci-as-capabilities/design.md) — Property 20 (Wallet Attestation validation)
