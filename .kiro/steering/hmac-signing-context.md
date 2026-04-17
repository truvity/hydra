---
inclusion: auto
name: hmac-signing-context
description: HMAC token signing, opaque token generation/validation, authorization code signatures, access token signatures, system secret configuration, key rotation, SignatureHash for DB storage
---

# HMAC Token Signing Context

How Hydra uses HMAC-SHA512/256 to sign opaque tokens (authorization codes, access tokens, refresh tokens, device codes).

## Core Implementation

`fosite/token/hmac/hmacsha.go` — `HMACStrategy` struct.

### Token Format

```
base64url(randomKey).base64url(hmacSignature)
```

- `randomKey`: cryptographically random bytes (default 32, configurable via `GetTokenEntropy()`)
- `hmacSignature`: `HMAC-SHA512/256(randomKey, signingKey)` where `signingKey` is the first 32 bytes of the system secret

With prefixes applied by `HMACSHAStrategy` (prefixed variant):
- Access tokens: `ory_at_<base64key>.<base64sig>`
- Refresh tokens: `ory_rt_<base64key>.<base64sig>`
- Authorization codes: `ory_ac_<base64key>.<base64sig>`

### Generation Flow

1. `HMACStrategy.Generate(ctx)` in `fosite/token/hmac/hmacsha.go`
2. Reads system secret via `Config.GetGlobalSecret(ctx)` — must be ≥32 bytes
3. Generates random token key via `RandomBytes(entropy)` (`crypto/rand`)
4. Computes `HMAC-SHA512/256(tokenKey, signingKey[:32])`
5. Returns `(base64(key).base64(sig), base64(sig), nil)`

### Validation Flow

1. `HMACStrategy.Validate(ctx, token)` in `fosite/token/hmac/hmacsha.go`
2. Tries current secret first, then rotated secrets from `GetRotatedGlobalSecrets(ctx)`
3. Splits token on `.`, decodes both parts from base64
4. Recomputes HMAC and compares with `hmac.Equal()` (constant-time)
5. Returns `fosite.ErrTokenSignatureMismatch` on mismatch (allows trying next rotated key)

### Signature Extraction

`HMACStrategy.Signature(token)` — splits on `.`, returns the second part (base64-encoded signature). This is the DB lookup key.

### HMAC for Arbitrary Strings

`HMACStrategy.GenerateHMACForString(ctx, text)` — used by device flow (`rfc8628`) for user code signatures. Computes HMAC of the raw string bytes (no random key generation).

## Strategy Layers

### Unprefixed: `HMACSHAStrategyUnPrefixed` (`fosite/handler/oauth2/strategy_hmacsha_plain.go`)

Wraps `HMACStrategy` ("Enigma") with token-type-specific lifespan validation:
- `GenerateAccessToken` / `ValidateAccessToken` — checks `fosite.AccessToken` expiry
- `GenerateRefreshToken` / `ValidateRefreshToken` — checks `fosite.RefreshToken` expiry
- `GenerateAuthorizeCode` / `ValidateAuthorizeCode` — checks `fosite.AuthorizeCode` expiry

### Prefixed: `HMACSHAStrategy` (`fosite/handler/oauth2/strategy_hmacsha_prefixed.go`)

Wraps `HMACSHAStrategyUnPrefixed`, adds `ory_at_` / `ory_rt_` / `ory_ac_` prefixes on generate, strips them on validate.

## Signature Hashing for DB Storage

`x.SignatureHash(signature)` in `x/sighash.go` — `SHA512/384` hex digest of the signature string. Applied before DB writes to keep the PK column under 128 chars.

Applied to access tokens only (not auth codes or refresh tokens):
- `CreateAccessTokenSession` → `x.SignatureHash(signature)` before `createSession()`
- `GetAccessTokenSession` → queries by `x.SignatureHash(signature)`, falls back to raw signature for backwards compatibility
- `DeleteAccessTokenSession` → same dual-lookup pattern

Auth codes and refresh tokens store the raw base64 signature directly.

## System Secret Configuration

`driver/config/provider_fosite.go`:
- `GetGlobalSecret(ctx)` — reads `secrets.system` (string list), takes first element, hashes with `x.HashStringSecret()` (SHA256 → 32 bytes)
- `GetRotatedGlobalSecrets(ctx)` — remaining elements of `secrets.system`, each SHA256-hashed
- Minimum secret length: 16 characters (config validation), 32 bytes after hashing (HMAC requirement)

## Registry Wiring

`driver/registry_sql.go`:
- `OAuth2EnigmaStrategy()` → `*hmac.HMACStrategy{Config: m.OAuth2Config()}`
- `OAuth2HMACStrategy()` → `foauth2.NewHMACSHAStrategy(enigma, config)` (prefixed)
- `rfc8628HMACStrategy()` → device code strategy using same Enigma

## When Adding New HMAC-Signed Tokens

1. Use `HMACStrategy.Generate(ctx)` for new opaque token types
2. Store the signature (second part after `.`) as the DB primary key
3. Apply `x.SignatureHash()` if the signature might exceed 128 chars
4. Validate with `HMACStrategy.Validate(ctx, token)` — handles key rotation automatically
5. For non-token HMAC (e.g., user codes), use `GenerateHMACForString(ctx, text)`
