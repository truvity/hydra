# Ory Hydra — Secret Management & Key Rotation Guide

Production deployment and maintenance reference for all cryptographic material
used by Ory Hydra. Assumes the binary/Docker image is built via GoReleaser and
deployed with Pulumi IaC.

---

## 1. Inventory of Secrets

Hydra relies on several distinct categories of secrets. Each serves a different
purpose and has its own rotation characteristics.

### 1.1 System Secret (`secrets.system`)

| Property | Value |
|---|---|
| Config key | `secrets.system` (array of strings) |
| Env var | `SECRETS_SYSTEM` (comma-separated) |
| Min length | 16 characters per entry |
| Internal form | SHA-256 hash → 32-byte key |

The system secret is the most critical secret in a Hydra deployment. It is used
for:

- **HMAC-SHA512/256 signing** of opaque tokens (authorization codes, access
  tokens, refresh tokens, device codes). The first 32 bytes of the SHA-256 hash
  are used as the HMAC key.
- **AES-GCM-256 encryption** of JWK private keys stored in the database
  (`hydra_jwk` table, `keydata` column).
- **AES-GCM-256 encryption** of OAuth 2.0 session data at rest (when
  `oauth2.session.encrypt_at_rest` is `true`, which is the default).
- **Fallback** for cookie secrets and pagination secrets when those are not
  explicitly configured.

The first element of the array is the *active* signing/encryption key. All
remaining elements are *rotated* keys used only for verification and decryption.

### 1.2 Cookie Secret (`secrets.cookie`)

| Property | Value |
|---|---|
| Config key | `secrets.cookie` (array of strings) |
| Env var | `SECRETS_COOKIE` (comma-separated) |
| Fallback | `secrets.system` if not set |

Used to encrypt and authenticate HTTP session cookies (login/consent CSRF
tokens, session cookies). In production, use a dedicated cookie secret separate
from the system secret to limit blast radius.

Rotation follows the same first-is-active, rest-are-rotated pattern.

### 1.3 Pagination Secret (`secrets.pagination`)

| Property | Value |
|---|---|
| Config key | `secrets.pagination` (array of strings) |
| Env var | `SECRETS_PAGINATION` (comma-separated) |
| Fallback | `secrets.system` if not set |

Used to encrypt pagination tokens in list API responses. Lower sensitivity than
the system secret, but should still be unique in production.

### 1.4 OIDC Pairwise Subject Salt (`oidc.subject_identifiers.pairwise.salt`)

| Property | Value |
|---|---|
| Config key | `oidc.subject_identifiers.pairwise.salt` |
| Env var | `OIDC_SUBJECT_IDENTIFIERS_PAIRWISE_SALT` |
| Min length | 8 characters |

A static salt used in `SHA-256(sector_identifier ‖ local_account_id ‖ salt)` to
compute pairwise subject identifiers per the OpenID Connect specification.

**This value must never be rotated.** Changing it permanently breaks the mapping
between internal user IDs and the `sub` claim seen by relying parties.

### 1.5 JSON Web Keys (JWKs)

Hydra auto-generates and stores asymmetric key pairs in the `hydra_jwk` database
table. The private key material is AES-GCM encrypted using the system secret.

| Key Set Name | Purpose |
|---|---|
| `hydra.openid.id-token` | Signs OpenID Connect ID Tokens |
| `hydra.jwt.access-token` | Signs JWT access tokens (when `strategies.access_token=jwt`) |

These keys are exposed via the `/.well-known/jwks.json` endpoint (public keys
only). Additional key sets can be created via the Admin API
(`POST /admin/keys/{set}`).

### 1.6 OAuth 2.0 Client Secrets

Client secrets are hashed with bcrypt (default) or PBKDF2 before storage.
Configured via:

- `oauth2.hashers.algorithm` — `"bcrypt"` (default) or `"pbkdf2"`
- `oauth2.hashers.bcrypt.cost` — bcrypt work factor (default `10`)
- `oauth2.hashers.pbkdf2.iterations` — PBKDF2 iteration count

Client secrets are not reversible and do not depend on the system secret.

### 1.7 TLS Certificates

| Config key | Purpose |
|---|---|
| `serve.tls` | TLS termination for public and admin endpoints |

In most Pulumi deployments, TLS is terminated at the load balancer or ingress
controller, so Hydra's built-in TLS is not used. If you do terminate TLS at
Hydra, manage certificates through your IaC and rotate them before expiry.

### 1.8 HSM Keys (Optional)

When `hsm.enabled=true`, JWK private keys are generated and stored on a PKCS#11
Hardware Security Module instead of the database. The system secret is still
required for HMAC token signing and session encryption, but JWK encryption at
rest is handled by the HSM.

| Config key | Purpose |
|---|---|
| `hsm.library` | Path to PKCS#11 `.so` library |
| `hsm.pin` | Token PIN |
| `hsm.slot` / `hsm.token_label` | Token selection |
| `hsm.key_set_prefix` | Namespace prefix for multi-instance HSM sharing |

### 1.9 Database Connection String (`dsn`)

The DSN contains database credentials. Treat it as a secret. Use Pulumi's
secret management (`pulumi.secret()`) and inject via environment variable.

---

## 2. Secret Lifecycle in Pulumi

### 2.1 Generating Secrets

Generate secrets outside of Hydra and store them in Pulumi's encrypted state or
an external secret manager (AWS Secrets Manager, Vault, etc.).

```typescript
import * as pulumi from "@pulumi/pulumi";
import * as random from "@pulumi/random";

// Generate a 48-character system secret
const systemSecret = new random.RandomPassword("hydra-system-secret", {
  length: 48,
  special: false,
});

// Mark as secret so Pulumi encrypts it in state
const systemSecretValue = pulumi.secret(systemSecret.result);
```

### 2.2 Injecting Secrets into the Container

Pass secrets as environment variables. Never bake them into the Docker image.

```typescript
const hydraContainer = {
  name: "hydra",
  image: "ghcr.io/your-org/hydra:v2.x.x", // built by GoReleaser
  env: [
    { name: "SECRETS_SYSTEM", value: systemSecretValue },
    { name: "SECRETS_COOKIE", value: cookieSecretValue },
    { name: "DSN", value: dsnSecretValue },
    {
      name: "OIDC_SUBJECT_IDENTIFIERS_PAIRWISE_SALT",
      value: pairwiseSaltValue, // set once, never rotate
    },
  ],
};
```

### 2.3 Secret Storage Recommendations

| Approach | Pros | Cons |
|---|---|---|
| Pulumi encrypted state | Simple, no extra infra | Tied to Pulumi state backend |
| AWS Secrets Manager / SSM | Audit trail, fine-grained IAM | Extra API calls at startup |
| HashiCorp Vault | Dynamic secrets, leasing | Operational complexity |

For AWS deployments, a common pattern is to store secrets in Secrets Manager and
reference them in ECS task definitions or Kubernetes ExternalSecrets.

---

## 3. Rotation Procedures

### 3.1 System Secret Rotation

Rotation is zero-downtime. Hydra validates HMAC signatures and decrypts data
against all secrets in the array, but only signs/encrypts with the first.

**Procedure:**

1. Generate a new secret (≥16 characters, recommend ≥32).
2. Prepend it to the `secrets.system` array. The old secret moves to position
   `[1]`.
3. Deploy the updated configuration to all Hydra instances.
4. Existing tokens remain valid — HMAC validation tries the current secret
   first, then falls back to rotated secrets.
5. Existing encrypted JWKs and session data are decrypted with the old key and
   can be re-encrypted on next write.
6. After all tokens signed with the old secret have expired (governed by
   `ttl.access_token`, `ttl.refresh_token`, `ttl.auth_code`), you may remove
   the old secret from the array.

```typescript
// Rotation example: new secret prepended, old secret kept
const secretsSystem = pulumi.secret(
  pulumi.interpolate`${newSecret.result},${oldSecret.result}`
);
```

**When to rotate:**

- Periodically (e.g., every 90 days) as part of security hygiene.
- Immediately if a secret is suspected to be compromised.
- After personnel changes with access to secrets.

**What breaks if you remove an old secret too early:**

- Opaque tokens signed with that secret will fail HMAC validation → users get
  401 errors and must re-authenticate.
- JWK private keys encrypted with that secret become undecryptable → Hydra
  cannot sign ID tokens or JWT access tokens until keys are re-encrypted or
  regenerated.
- Encrypted session data becomes unreadable.

### 3.2 Cookie Secret Rotation

Same array-based rotation as the system secret. Prepend the new secret, keep old
secrets until all active browser sessions have expired or been refreshed.

Cookie sessions are typically short-lived (tied to the login/consent flow), so
old cookie secrets can be removed relatively quickly (hours to days).

### 3.3 JWK Rotation

JWK rotation is independent of system secret rotation. Rotate signing keys when:

- A key is suspected compromised.
- Periodically (e.g., every 6–12 months) per your security policy.
- When changing signing algorithms.

**Procedure:**

1. Generate a new key set via the Admin API:
   ```
   POST /admin/keys/hydra.openid.id-token
   { "alg": "ES256", "use": "sig" }
   ```
   This replaces the key set. The old public key is no longer served at
   `/.well-known/jwks.json`.

2. Relying parties that cache JWKS will fail to validate tokens signed with the
   old key until they refresh their cache. Coordinate with downstream services
   or use a transition period:
   - Add the new key first (via `PUT` with both old and new keys).
   - Wait for caches to refresh (respect `Cache-Control` / `max-age`).
   - Remove the old key.

3. Repeat for `hydra.jwt.access-token` if using JWT access tokens.

**With HSM:** Key rotation is performed through the same Admin API. The HSM
manages the actual key material; Hydra handles the lifecycle.

### 3.4 Pagination Secret Rotation

Low-risk rotation. Prepend the new secret. Old pagination tokens (from in-flight
list API calls) will fail gracefully — clients simply restart pagination.

### 3.5 Database Credentials Rotation

Rotate DSN credentials through your secret manager. For zero-downtime rotation
with PostgreSQL/CockroachDB:

1. Create a new database user with the same grants.
2. Update the DSN in your secret manager.
3. Restart or rolling-update Hydra pods to pick up the new DSN.
4. Drop the old database user.

---

## 4. Encryption at Rest

### 4.1 JWK Encryption

All JWK private keys stored in `hydra_jwk.keydata` are AES-GCM-256 encrypted
using the system secret. This is always enabled and cannot be turned off.

### 4.2 Session Data Encryption

OAuth 2.0 session data (stored in `hydra_oauth2_*` tables) is AES-GCM-256
encrypted when `oauth2.session.encrypt_at_rest` is `true` (the default).

Disabling this (`false`) stores session data as plaintext JSON. This is
acceptable only if your database itself provides encryption at rest and you trust
all database administrators.

### 4.3 Database-Level Encryption

Regardless of Hydra's application-level encryption, enable encryption at rest on
your database:

- **PostgreSQL:** Use `pgcrypto` or rely on filesystem/volume encryption (e.g.,
  AWS RDS encryption, GCP Cloud SQL encryption).
- **CockroachDB:** Encryption at rest is available in the enterprise tier.
- **MySQL:** InnoDB tablespace encryption.

---

## 5. Operational Checklist

### Pre-Deployment

- [ ] Generate unique `secrets.system` (≥32 characters recommended).
- [ ] Generate separate `secrets.cookie` for production.
- [ ] Generate separate `secrets.pagination` for production.
- [ ] Set `oidc.subject_identifiers.pairwise.salt` (if using pairwise subjects)
      and document it as immutable.
- [ ] Store all secrets in Pulumi encrypted state or external secret manager.
- [ ] Verify `oauth2.session.encrypt_at_rest` is `true` (default).
- [ ] Ensure `dev` mode is `false`.
- [ ] Configure database-level encryption at rest.

### Ongoing Maintenance

- [ ] Rotate `secrets.system` every 90 days (or per your policy).
- [ ] Rotate `secrets.cookie` on the same schedule.
- [ ] Rotate JWKs every 6–12 months.
- [ ] Rotate database credentials periodically.
- [ ] Monitor for secret expiry alerts in your secret manager.
- [ ] Never remove old system secrets before all tokens signed with them have
      expired.
- [ ] Audit access to secrets (Pulumi state, secret manager access logs).

### Incident Response (Suspected Secret Compromise)

1. Generate new secrets immediately.
2. Prepend to the respective arrays and deploy.
3. For system secret compromise: force-expire all active tokens by flushing
   OAuth 2.0 sessions (`DELETE /admin/oauth2/tokens`).
4. For JWK compromise: rotate the affected key set via Admin API.
5. Notify relying parties to refresh their JWKS cache.
6. Remove the compromised secret from the array after all tokens have expired.
7. Audit logs for unauthorized access during the exposure window.

---

## 6. Configuration Reference

```yaml
# Minimal production secrets configuration
secrets:
  system:
    - "primary-secret-at-least-32-chars-long-xxxxx"
    # Old secrets kept for rotation:
    # - "previous-secret-xxxxx"
  cookie:
    - "cookie-secret-at-least-32-chars-long-xxxxx"
  pagination:
    - "pagination-secret-at-least-32-chars-xxxxx"

oidc:
  subject_identifiers:
    pairwise:
      salt: "random-immutable-salt-set-once"

oauth2:
  session:
    encrypt_at_rest: true
  hashers:
    algorithm: bcrypt
    bcrypt:
      cost: 12

# Optional HSM configuration
# hsm:
#   enabled: true
#   library: /usr/lib/softhsm/libsofthsm2.so
#   pin: "your-hsm-pin"
#   token_label: "hydra"
```
