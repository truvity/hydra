# OIDC4VCI Integration Guide — Hydra AS + Credential Issuer

## Purpose

This document describes how Ory Hydra (OIDC4VCI fork) integrates with external components to enable Verifiable Credential Issuance. It covers two primary flows — the Pre-Authorized Code flow and the Authorization Code flow — and details the configuration, dependencies, and integration points for each participating component.

## Components Overview

| Component | Role | Responsibility |
|-----------|------|----------------|
| Wallet | OAuth 2.0 Client | Requests credentials, authenticates via Wallet Attestation, sends DPoP proofs, exchanges codes for tokens, presents tokens to the Credential Issuer |
| Hydra AS | Authorization Server | Issues access tokens, validates client authentication, enforces DPoP/PAR/PKCE, orchestrates consent, provides token introspection |
| Credential Issuer Service | Resource Server + Issuer | Assembles and signs Verifiable Credentials, generates Credential Offers, creates Pre-Authorized Codes via Hydra admin API, validates tokens via introspection |
| Login Page / Consent Page (Consent Node) | Login & Consent Provider | Authenticates end-users, renders consent UI (including credential-specific consent), enriches `authorization_details` with `credential_identifiers` |
| Kratos | Identity Provider | Manages user identities, handles authentication (login flows), provides user session data to the Consent Node |

### System Boundary

Hydra AS issues access tokens. The Credential Issuer consumes them. The AS never handles Credential Requests, Credential Endpoints, or Credential Issuer metadata — those belong exclusively to the Credential Issuer.

```mermaid
graph TB
    subgraph HydraAS["Hydra AS (this fork)"]
        subgraph Public["Public Endpoints"]
            PAR["POST /oauth2/par"]
            AUTH["GET /oauth2/auth"]
            TOKEN["POST /oauth2/token"]
            DISC["GET /.well-known/openid-configuration"]
        end
        subgraph Admin["Admin Endpoints"]
            PREAUTH_API["POST /admin/oauth2/preauth"]
            INTROSPECT["POST /admin/oauth2/introspect"]
            CONSENT_API["GET /admin/oauth2/auth/requests"]
        end
        PIPELINE["Fosite Handler Pipeline:<br/>RAR → DPoP → PreAuth → PKCE → AuthCode → WalletAttestation"]
    end

    subgraph CI["Credential Issuer Service"]
        CRED_EP["POST /credential"]
        BATCH_EP["POST /batch_credential"]
        NONCE_EP["POST /nonce"]
        ISSUER_META["GET /.well-known/openid-credential-issuer"]
    end

    subgraph CN["Consent Node (Login + Consent)"]
        LOGIN_UI["Renders login UI (via Kratos)"]
        CONSENT_UI["Renders consent UI"]
        ENRICH["Enriches authorization_details<br/>with credential_identifiers"]
    end

    CI -->|"Admin API"| PREAUTH_API
    CI -->|"Introspect tokens"| INTROSPECT
    CN -->|"Challenge / Accept"| CONSENT_API
```

---

## Flow 1: Pre-Authorized Code Flow

Participants: Wallet, Credential Issuer Service, Hydra AS.

No user-agent redirect, no login page, no consent page. The Credential Issuer prepares everything upfront and the Wallet goes directly to the token endpoint. This is the "issuer-initiated" flow.

### Use Cases

- University issuing a degree credential to a graduate
- Government issuing an identity document after in-person verification
- Employer issuing an employment credential after onboarding

### Sequence

```mermaid
sequenceDiagram
    participant EU as End-User
    participant CI as Credential Issuer
    participant AS as Hydra AS
    participant W as Wallet

    EU->>CI: 1. Provide info (in-person, etc.)

    CI->>AS: 2. POST /admin/oauth2/preauth<br/>{credential_configuration_ids,<br/>client_id?, tx_code?, scope}
    AS-->>CI: pre_authorized_code, expires_at

    CI->>W: 3. Credential Offer (QR/deeplink)<br/>{pre-authorized_code,<br/>tx_code requirements}
    CI->>EU: 4. tx_code via SMS/email

    EU->>W: 5. Enter tx_code in Wallet

    W->>AS: 6. POST /oauth2/token<br/>grant_type=pre-authorized_code<br/>pre-authorized_code, tx_code,<br/>DPoP proof
    Note over AS: Validate code, tx_code, DPoP,<br/>mark redeemed.<br/>Token Hook fires →<br/>Credential Issuer webhook<br/>enriches session.
    AS-->>W: access_token, token_type=DPoP,<br/>authorization_details

    W->>CI: 7. POST /credential<br/>access_token + DPoP proof + key proofs
    CI->>AS: 8. POST /admin/oauth2/introspect
    AS-->>CI: active, cnf.jkt, authorization_details
    Note over CI: Validate DPoP proof vs jkt,<br/>assemble + sign VC
    CI-->>W: Verifiable Credential
```

### Step-by-Step Details

**Step 2 — Credential Issuer creates Pre-Authorized Code:**

The Credential Issuer calls the Hydra admin API to create a code:

```http
POST /admin/oauth2/preauth
Content-Type: application/json

{
  "client_id": "https://wallet.example.org",
  "credential_configuration_ids": ["UniversityDegree_JWT", "org.iso.18013.5.1.mDL"],
  "scope": "UniversityDegree_JWT offline",
  "tx_code": "493536",
  "tx_code_input_mode": "numeric",
  "tx_code_length": 6
}
```

Response:

```json
{
  "pre_authorized_code": "oaKazRN8I0IbtZ0C7JuMn5.base64hmac",
  "expires_at": "2026-04-21T15:30:00Z"
}
```

- `client_id` is optional. If omitted, any client (or anonymous if configured) can redeem the code.
- `tx_code` is sent in plaintext. Hydra hashes it with SHA-256 before storage — the plaintext is never persisted.
- `credential_configuration_ids` defines the authorization envelope — what credentials the Wallet is allowed to request.

**Step 3 — Credential Issuer constructs and sends the Credential Offer:**

The Credential Issuer builds the Credential Offer independently (Hydra never sees it):

```json
{
  "credential_issuer": "https://credential-issuer.example.com",
  "credential_configuration_ids": ["UniversityDegree_JWT", "org.iso.18013.5.1.mDL"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5.base64hmac",
      "tx_code": {
        "length": 6,
        "input_mode": "numeric",
        "description": "Please enter the code sent to your email"
      }
    }
  }
}
```

Delivered via QR code, deep link, or push notification.

**Step 6 — Wallet exchanges code at the token endpoint:**

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
DPoP: <DPoP proof JWT>

grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code
&pre-authorized_code=oaKazRN8I0IbtZ0C7JuMn5.base64hmac
&tx_code=493536
```

Hydra validates: code exists, not redeemed, not expired, client_id matches (if bound), tx_code matches (if required), DPoP proof is valid. The code is atomically marked as redeemed.

The Token Hook fires after validation, sending `Session.Extra` (including `authorization_details`) to the configured webhook. The Credential Issuer's webhook can enrich `authorization_details` with `credential_identifiers`. The hook uses full-replacement semantics — the webhook must return the complete `session.access_token` map.

Token response:

```json
{
  "access_token": "ory_at_...",
  "token_type": "DPoP",
  "expires_in": 3600,
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegree_JWT",
      "credential_identifiers": ["cred-id-1"]
    }
  ]
}
```

**Step 8 — Credential Issuer introspects the token:**

```http
POST /admin/oauth2/introspect
Content-Type: application/x-www-form-urlencoded

token=ory_at_...
```

Response:

```json
{
  "active": true,
  "token_type": "DPoP",
  "ext": {
    "authorization_details": [
      {
        "type": "openid_credential",
        "credential_configuration_id": "UniversityDegree_JWT",
        "credential_identifiers": ["cred-id-1"]
      }
    ],
    "cnf": {
      "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    }
  }
}
```

The Credential Issuer reads `ext.authorization_details` to determine which credentials to issue, and validates the Wallet's DPoP proof against `ext.cnf.jkt`.

---

## Flow 2: Authorization Code Flow

Participants: Wallet, Credential Issuer Service, Hydra AS, Login Page, Consent Page (Consent Node), Kratos.

This is the full interactive flow with user authentication and consent. The Credential Issuer sends a Credential Offer, the Wallet uses PAR + authorization code + DPoP to obtain an access token, then requests credentials.

### Use Cases

- Wallet-initiated credential request where user consent is required
- Credential issuance that requires user authentication (e.g., identity verification)
- Scenarios where the Credential Issuer needs the user to explicitly approve which credentials to issue

### Sequence

```mermaid
sequenceDiagram
    participant W as Wallet
    participant CI as Credential Issuer
    participant AS as Hydra AS
    participant CN as Consent Node
    participant K as Kratos
    participant EU as End-User

    CI->>W: 1. Credential Offer (QR/deeplink)<br/>authorization_code grant,<br/>issuer_state, scope

    W->>CI: 2. Fetch Credential Issuer metadata
    CI-->>W: authorization_servers,<br/>credential_configurations_supported

    W->>AS: 3. GET /.well-known/openid-configuration
    AS-->>W: par_endpoint, token_endpoint,<br/>dpop_signing_alg_values_supported, ...

    W->>AS: 4. POST /oauth2/par<br/>authorization_details, scope,<br/>issuer_state, code_challenge (S256),<br/>redirect_uri, Wallet Attestation + PoP,<br/>DPoP proof (optional)
    Note over AS: Validate Wallet Attestation,<br/>Validate RAR,<br/>Validate PKCE S256,<br/>Extract dpop_jkt,<br/>Store PAR session
    AS-->>W: request_uri, expires_in

    W->>EU: 5. Redirect to /oauth2/auth?<br/>client_id&request_uri
    EU->>AS: 6. GET /oauth2/auth
    Note over AS: Resolve PAR session

    AS->>CN: 7. Login redirect (login challenge)

    CN->>K: 8. Kratos login flow
    K->>EU: Login UI
    EU->>K: Credentials
    K-->>CN: User session

    CN->>AS: 9. Accept login (subject from Kratos)

    AS->>CN: 10. Consent challenge<br/>{authorization_details,<br/>issuer_state, requested_scope,<br/>client info}
    CN->>EU: 11. Consent UI<br/>"Issuer X wants to issue you<br/>a University Degree credential"
    EU->>CN: 12. User accepts

    CN->>AS: 13. Accept consent<br/>{authorization_details with<br/>credential_identifiers,<br/>granted_scope}
    Note over AS: Merge authorization_details<br/>into Session.Extra

    AS->>EU: 14. Redirect: code, state, iss (RFC 9207)
    EU->>W: Authorization code

    W->>AS: 15. POST /oauth2/token<br/>grant_type=authorization_code,<br/>code, code_verifier, DPoP proof,<br/>Wallet Attestation + PoP
    Note over AS: Validate Wallet Attestation,<br/>Validate auth code + PKCE,<br/>Validate DPoP proof,<br/>Verify dpop_jkt binding,<br/>Bind token to DPoP key (cnf.jkt),<br/>Token Hook fires
    AS-->>W: access_token, token_type=DPoP,<br/>authorization_details with<br/>credential_identifiers,<br/>refresh_token, DPoP-Nonce

    W->>CI: 16. POST /credential<br/>access_token + DPoP proof + key proofs
    CI->>AS: 17. POST /admin/oauth2/introspect
    AS-->>CI: active, cnf.jkt, authorization_details
    Note over CI: Validate DPoP proof vs jkt,<br/>assemble + sign VC
    CI-->>W: Verifiable Credential
```

### Step-by-Step Details

**Step 1 — Credential Offer (optional, for issuer-initiated flows):**

The Credential Issuer sends a Credential Offer to the Wallet. For the authorization code flow, the offer includes the `authorization_code` grant and optionally `issuer_state`:

```json
{
  "credential_issuer": "https://credential-issuer.example.com",
  "credential_configuration_ids": ["UniversityDegree_JWT"],
  "grants": {
    "authorization_code": {
      "issuer_state": "eyJhbGciOiJSU0Et..."
    }
  }
}
```

The `issuer_state` is an opaque string that the Wallet forwards to the AS, which passes it through to the Consent Node for Credential Offer context binding.

**Step 4 — PAR request with Wallet Attestation:**

The Wallet authenticates using two HTTP headers:
- `OAuth-Client-Attestation` — JWT signed by the Wallet Provider (with `x5c` certificate chain)
- `OAuth-Client-Attestation-PoP` — Proof of Possession JWT signed by the Wallet instance key

```http
POST /oauth2/par
Content-Type: application/x-www-form-urlencoded
OAuth-Client-Attestation: <attestation JWT>
OAuth-Client-Attestation-PoP: <PoP JWT>
DPoP: <DPoP proof JWT>

response_type=code
&client_id=https://wallet.example.org
&redirect_uri=https://wallet.example.org/callback
&scope=UniversityDegree_JWT offline
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&authorization_details=[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_JWT"}]
&issuer_state=eyJhbGciOiJSU0Et...
```

Hydra validates:
1. Wallet Attestation — `x5c` chain trusted, `sub` matches `client_id`, PoP signature valid
2. RAR — `authorization_details` parsed, `type` and `credential_configuration_id` validated
3. PKCE — `code_challenge_method=S256` (HAIP requirement)
4. DPoP — if `DPoP` header present, proof validated and `dpop_jkt` extracted for authorization code binding

**Steps 7–9 — Login via Kratos:**

The Consent Node receives a login challenge from Hydra. It initiates a Kratos login flow to authenticate the end-user. After successful authentication, Kratos provides a user session. The Consent Node accepts the login challenge with the authenticated subject identifier from Kratos.

**Steps 10–13 — Consent with authorization_details:**

The Consent Node receives a consent challenge containing:

```json
{
  "challenge": "consent-challenge-uuid",
  "requested_scope": ["UniversityDegree_JWT", "offline"],
  "client": { "client_id": "https://wallet.example.org", ... },
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegree_JWT"
    }
  ],
  "issuer_state": "eyJhbGciOiJSU0Et..."
}
```

The Consent Node renders credential-specific consent UI (e.g., "University X wants to issue you a University Degree credential"). After user approval, the Consent Node accepts the consent, optionally enriching `authorization_details` with `credential_identifiers`:

```http
PUT /admin/oauth2/auth/requests/consent/accept?consent_challenge=...
Content-Type: application/json

{
  "grant_scope": ["UniversityDegree_JWT", "offline"],
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegree_JWT",
      "credential_identifiers": ["cred-id-1"]
    }
  ],
  "session": {
    "access_token": {},
    "id_token": {}
  }
}
```

There are three paths for `credential_identifiers` to enter the token response:
1. The Consent Node sets them during consent accept (shown above)
2. The Token Hook webhook enriches them before the token response is finalized
3. The Credential Issuer generates them at credential endpoint time (not in the token response at all)

**Step 14 — Authorization response with `iss` (RFC 9207):**

When HAIP or RFC 9207 is enabled, the authorization response includes the `iss` parameter to prevent mix-up attacks:

```
HTTP/1.1 302 Found
Location: https://wallet.example.org/callback
  ?code=SplxlOBeZQQYbYS6WxSbIA
  &state=af0ifjsldkj
  &iss=https://hydra.example.com/
```

**Step 15 — Token request:**

The Wallet authenticates again with Wallet Attestation headers and includes a DPoP proof:

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
OAuth-Client-Attestation: <attestation JWT>
OAuth-Client-Attestation-PoP: <PoP JWT>
DPoP: <DPoP proof JWT>

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://wallet.example.org/callback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Token response:

```json
{
  "access_token": "ory_at_...",
  "token_type": "DPoP",
  "expires_in": 3600,
  "refresh_token": "ory_rt_...",
  "authorization_details": [
    {
      "type": "openid_credential",
      "credential_configuration_id": "UniversityDegree_JWT",
      "credential_identifiers": ["cred-id-1"]
    }
  ]
}
```

---

## Hydra AS Configuration

### Minimal HAIP-Enforced Configuration

This is the recommended configuration for production OIDC4VCI deployments. Setting `haip.enforced: true` automatically enables PAR enforcement, PKCE S256, DPoP with ES256, and RFC 9207 `iss` parameter.

```yaml
serve:
  public:
    host: 0.0.0.0
    port: 4444
  admin:
    host: 0.0.0.0
    port: 4445

urls:
  self:
    issuer: https://hydra.example.com
    public: https://hydra.example.com
  login: https://consent-app.example.com/login
  consent: https://consent-app.example.com/consent

dsn: postgres://hydra:secret@postgres:5432/hydra?sslmode=disable

# --- OIDC4VCI Configuration ---

haip:
  enforced: true
  # Auto-enables:
  #   oauth2.par.enforced: true
  #   oauth2.pkce.enforced: true
  #   oauth2.pkce.plain_challenge_method: false
  #   dpop.enabled: true (with ES256)
  #   rfc9207.iss_parameter_enabled: true

# Pre-Authorized Code grant (not auto-enabled by HAIP)
preauth:
  enabled: true
  lifespan: 30m
  anonymous_access: false  # Require client authentication

# Wallet Attestation client authentication (not auto-enabled by HAIP)
wallet_attestation:
  enabled: true
  trust_anchors:
    - |
      -----BEGIN CERTIFICATE-----
      MIIBxTCCAWugAwIBAgIUJnZ+av7kFRaCrKlNi4RSgRMlMzcwCg...
      -----END CERTIFICATE-----

# Rich Authorization Requests (not auto-enabled by HAIP)
rar:
  enabled: true
  types_supported:
    - openid_credential

# DPoP fine-tuning (optional, defaults are sensible)
dpop:
  nonce_enabled: true
  nonce_lifespan: 5m
  proof_max_age: 60s

# Token Hook — Credential Issuer webhook for credential_identifiers enrichment
oauth2:
  token_hook:
    url: https://credential-issuer.example.com/token-hook
    auth:
      type: api_key
      config:
        in: header
        name: Authorization
        value: "Bearer my-webhook-secret"
```

### Standalone Configuration (No HAIP)

For deployments that need individual feature control:

```yaml
haip:
  enforced: false

oauth2:
  par:
    enforced: true
  pkce:
    enforced: true
    plain_challenge_method: false

dpop:
  enabled: true
  signing_alg_values_supported:
    - ES256
  nonce_enabled: true

rfc9207:
  iss_parameter_enabled: true

preauth:
  enabled: true
  lifespan: 30m
  anonymous_access: false

wallet_attestation:
  enabled: true
  trust_anchors:
    - |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----

rar:
  enabled: true
  types_supported:
    - openid_credential
```

### Configuration Reference

| Key | Type | Default | HAIP Override | Description |
|-----|------|---------|---------------|-------------|
| `haip.enforced` | bool | `false` | N/A (source) | Master HAIP enforcement flag |
| `preauth.enabled` | bool | `false` | No | Enable Pre-Authorized Code grant type |
| `preauth.lifespan` | duration | `30m` | No | Pre-authorized code validity window |
| `preauth.anonymous_access` | bool | `false` | No | Allow token exchange without client auth |
| `dpop.enabled` | bool | `false` | → `true` | Enable DPoP token binding |
| `dpop.signing_alg_values_supported` | []string | `["ES256"]` | Ensures ES256 | Supported DPoP proof signing algorithms |
| `dpop.nonce_enabled` | bool | `false` | No | Enable DPoP nonce exchange |
| `dpop.nonce_lifespan` | duration | `5m` | No | DPoP nonce validity window |
| `dpop.proof_max_age` | duration | `60s` | No | Maximum age for DPoP proof `iat` claim |
| `rar.enabled` | bool | `false` | No | Enable Rich Authorization Requests |
| `rar.types_supported` | []string | `["openid_credential"]` | No | Supported `authorization_details` type values |
| `wallet_attestation.enabled` | bool | `false` | No | Enable Wallet Attestation client auth |
| `wallet_attestation.trust_anchors` | []string | `[]` | No | PEM-encoded trust anchor certificates |
| `rfc9207.iss_parameter_enabled` | bool | `false` | → `true` | RFC 9207 `iss` in authorization responses |
| `oauth2.par.enforced` | bool | `false` | → `true` | Require PAR for all authorization requests |
| `oauth2.pkce.enforced` | bool | `false` | → `true` | Require PKCE on all auth code flows |
| `oauth2.pkce.plain_challenge_method` | bool | `false` | → `false` | Allow `plain` PKCE method |
| `oauth2.token_hook` | string/object | — | No | Token Hook webhook URL or config |

---

## Credential Issuer Service Integration

The Credential Issuer is a separate microservice that integrates with Hydra through three touchpoints:

### 1. Admin API — Pre-Authorized Code Creation

The Credential Issuer calls `POST /admin/oauth2/preauth` to create pre-authorized codes for inclusion in Credential Offers. This is the only write operation the Credential Issuer performs against Hydra.

Requirements:
- Network access to Hydra's admin port (default 4445)
- Admin API authentication (if configured)
- Knowledge of registered `client_id` values (for bound codes)
- Knowledge of `credential_configuration_id` values matching its Credential Issuer metadata

### 2. Token Introspection — Access Token Validation

The Credential Issuer calls `POST /admin/oauth2/introspect` to validate access tokens presented by Wallets. The introspection response provides:

- `active` — whether the token is valid
- `ext.authorization_details` — which credentials the Wallet is authorized to receive, including `credential_identifiers`
- `ext.cnf.jkt` — the DPoP key thumbprint for sender-constraining validation
- `scope` — granted scopes (for scope-based credential requests)
- `token_type` — `DPoP` or `Bearer`

The Credential Issuer must:
1. Introspect every access token before issuing credentials
2. Validate the Wallet's DPoP proof against `ext.cnf.jkt` from the introspection response
3. Use `ext.authorization_details` to determine which credentials to issue
4. Match `credential_identifiers` to specific credential instances

### 3. Token Hook — Session Enrichment (Optional)

If the Credential Issuer runs a webhook endpoint, Hydra calls it before finalizing every token response. The webhook receives the full session (including `authorization_details`) and can enrich it with `credential_identifiers`.

Token Hook request body (relevant fields):

```json
{
  "session": {
    "extra": {
      "authorization_details": [
        {
          "type": "openid_credential",
          "credential_configuration_id": "UniversityDegree_JWT"
        }
      ]
    }
  },
  "request": {
    "client_id": "https://wallet.example.org",
    "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
  }
}
```

Token Hook response (200 OK):

```json
{
  "session": {
    "access_token": {
      "authorization_details": [
        {
          "type": "openid_credential",
          "credential_configuration_id": "UniversityDegree_JWT",
          "credential_identifiers": ["cred-id-1"]
        }
      ]
    },
    "id_token": {}
  }
}
```

The hook uses full-replacement semantics — `session.access_token` completely overwrites `Session.Extra`. The webhook must return the complete map including any existing claims it wants to preserve.

A `204 No Content` response leaves the session unchanged (no-op). This is valid when the Credential Issuer resolves `credential_identifiers` at credential endpoint time.

### Credential Issuer Metadata

The Credential Issuer serves its own metadata at `/.well-known/openid-credential-issuer`, which references the Hydra AS:

```json
{
  "credential_issuer": "https://credential-issuer.example.com",
  "authorization_servers": ["https://hydra.example.com"],
  "credential_endpoint": "https://credential-issuer.example.com/credential",
  "nonce_endpoint": "https://credential-issuer.example.com/nonce",
  "credential_configurations_supported": {
    "UniversityDegree_JWT": {
      "format": "vc+sd-jwt",
      "scope": "UniversityDegree_JWT",
      "cryptographic_binding_methods_supported": ["jwk"],
      "credential_signing_alg_values_supported": ["ES256"],
      "proof_types_supported": {
        "jwt": {
          "proof_signing_alg_values_supported": ["ES256"]
        }
      }
    }
  }
}
```

The Wallet discovers the AS by reading `authorization_servers` from this metadata, then fetches the AS metadata at `/.well-known/openid-configuration` to learn endpoints and capabilities.

---

## Dependencies and Deployment

### Component Dependencies

```mermaid
graph TD
    W[Wallet] -->|discovery| CI_META["Credential Issuer metadata"]
    W -->|discovery| AS_META["Hydra AS metadata"]
    W -->|PAR, auth, token| AS_PUBLIC["Hydra AS public endpoints"]
    W -->|credential, nonce| CI_EP["Credential Issuer endpoints"]

    AS["Hydra AS"] -->|persistence| DB_H["Database<br/>(PostgreSQL / MySQL / CockroachDB / SQLite)"]
    AS -->|login + consent delegation| CN["Consent Node"]
    AS -.->|optional| HOOK["Token Hook webhook endpoint"]

    CN -->|consent challenge/accept| AS_ADMIN["Hydra AS admin API"]
    CN -->|user authentication| K["Kratos"]
    CN -.->|optional: credential_identifiers| CI_BACK["Credential Issuer backend"]

    CI["Credential Issuer"] -->|pre-auth code creation,<br/>introspection| AS_ADMIN
    CI -.->|optional| HOOK

    K -->|persistence| DB_K["Database<br/>(user identity storage)"]
```

### Client Registration

For Wallet Attestation, register one client per wallet type:

```http
POST /admin/clients
Content-Type: application/json

{
  "client_id": "https://wallet.example.org",
  "token_endpoint_auth_method": "attest_jwt_client_auth",
  "grant_types": [
    "authorization_code",
    "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    "refresh_token"
  ],
  "response_types": ["code"],
  "scope": "openid UniversityDegree_JWT offline",
  "redirect_uris": ["https://wallet.example.org/callback"]
}
```

The `client_id` must match the `sub` value in the Wallet Provider's attestation JWTs. All wallet instances of that type share this single client record.

### Database Migrations

The OIDC4VCI features add two new tables (no modifications to existing upstream tables):

| Table | Purpose |
|-------|---------|
| `hydra_oauth2_preauth_code` | Pre-Authorized Code grant data (signature, client_id, credential_configuration_ids, tx_code_hash, redeemed flag, expiry) |
| `hydra_oauth2_dpop_jti` | DPoP JTI replay detection cache (jti, used_at, expires_at) |

Run `hydra migrate sql` to apply migrations before starting the server.

### Discovery Metadata

With the recommended configuration, `GET /.well-known/openid-configuration` returns (OIDC4VCI-relevant fields):

```json
{
  "issuer": "https://hydra.example.com",
  "authorization_endpoint": "https://hydra.example.com/oauth2/auth",
  "token_endpoint": "https://hydra.example.com/oauth2/token",
  "pushed_authorization_request_endpoint": "https://hydra.example.com/oauth2/par",
  "require_pushed_authorization_requests": true,
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:pre-authorized_code"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_post",
    "client_secret_basic",
    "private_key_jwt",
    "none",
    "attest_jwt_client_auth"
  ],
  "code_challenge_methods_supported": ["S256"],
  "dpop_signing_alg_values_supported": ["ES256"],
  "authorization_details_types_supported": ["openid_credential"],
  "authorization_response_iss_parameter_supported": true,
  "pre-authorized_grant_anonymous_access_supported": false
}
```

---

## Data Flow Summary

Key data elements and how they traverse the system:

| Data Element | Origin | Hydra Storage | Exits Via |
|---|---|---|---|
| `authorization_details` | PAR/Auth request (Wallet) or admin API (Credential Issuer) | Authorize session → Consent challenge → `Session.Extra` | Token response + Introspection (`ext.authorization_details`) |
| `credential_identifiers` | Consent Node accept or Token Hook webhook | `Session.Extra["authorization_details"]` | Token response + Introspection |
| `issuer_state` | PAR/Auth request (from Credential Offer) | Authorize session → Consent challenge | Consent Node reads it (not in token response) |
| DPoP `jkt` | Token request (DPoP proof header) | `Session.Extra["cnf"]["jkt"]` | Introspection (`ext.cnf.jkt`) |
| `token_type: DPoP` | DPoP handler | Token response | Token response |
| Wallet Attestation | PAR/Token request headers | Not stored (validated per-request) | N/A |
| Pre-Authorized Code | Admin API → DB → Token request | `hydra_oauth2_preauth_code` table | Redeemed → access token issued |
| `tx_code` | Token request form param | Validated against `tx_code_hash` in DB | N/A (validated and discarded) |

---

## Security Layers

| Layer | Mechanism | Enforced By | HAIP Required |
|---|---|---|---|
| Request integrity | PAR (RFC 9126) | `oauth2.par.enforced` / HAIP | Yes |
| Code interception prevention | PKCE S256 (RFC 7636) | `oauth2.pkce.enforced` / HAIP | Yes |
| Token sender-constraining | DPoP (RFC 9449) | `dpop.enabled` / HAIP | Yes |
| Client authentication | Wallet Attestation (`attest_jwt_client_auth`) | `wallet_attestation.enabled` | No (recommended) |
| Mix-up attack prevention | `iss` in auth response (RFC 9207) | `rfc9207.iss_parameter_enabled` / HAIP | Yes |
| Replay prevention (Pre-Auth) | Transaction Code (`tx_code`) | `preauth.enabled` | No |
| Replay prevention (DPoP) | JTI uniqueness + optional nonces | `dpop.nonce_enabled` | No (recommended) |

---

## References

- [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VC High Assurance Interoperability Profile 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-sd-jwt-vc-1_0.html)
- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 9126 — OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [draft-ietf-oauth-attestation-based-client-auth-07](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html)
- Feature docs: `docs/features/pre-authorized-code.md`, `docs/features/dpop.md`, `docs/features/rar-consent.md`, `docs/features/wallet-attestation.md`, `docs/features/haip-metadata.md`
- Architecture overview: `docs/ai-context/00-architecture-overview.md`
- Issuer integration boundary: `docs/ai-context/03-issuer-integration-boundary.md`
