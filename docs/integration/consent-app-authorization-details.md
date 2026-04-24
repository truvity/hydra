# Ory Hydra — Handling `authorization_details` in the Consent App

Integration guide for Login & Consent App implementors ("Consent App" below)
who need to support OIDC4VCI or any other OAuth 2.0 flow that uses Rich
Authorization Requests (RFC 9396).

This document describes the *contract* between Hydra and the Consent App for
`authorization_details`. The reference implementation at
[`ory/hydra-login-consent-node`](https://github.com/ory/hydra-login-consent-node)
is a minimal sample — a production Consent App has latitude in how it renders
the UI, stores context, or enriches credentials, but it must honor the contract
below.

---

## 1. Why the Consent App is involved

Hydra is a headless OAuth 2.0 / OpenID Connect server. It delegates every
user-facing decision — login, consent, credential selection — to an external
Consent App via the Admin API. `authorization_details` (RFC 9396) is the
mechanism clients use to express fine-grained authorization requests (e.g.
"issue me a UniversityDegree credential in SD-JWT format"). For the access
token to carry those details, the Consent App must participate:

1. **Receive** `authorization_details` in the consent challenge payload.
2. **Present** them to the user in a meaningful way (or skip consent when safe).
3. **Return** them — optionally enriched — in the consent accept response.

If the Consent App omits step 3, Hydra has no authoritative record of what the
user consented to, and the token response will not contain
`authorization_details`. Every downstream consumer (credential issuer, resource
server, introspection) then loses the context.

---

## 2. End-to-end data flow

```
Client              Hydra                Consent App           User
  |                   |                      |                   |
  |-- PAR with -----> |                      |                   |
  |   auth_details    |                      |                   |
  |                   | [1] stores on flow   |                   |
  |                   |                      |                   |
  |-- /oauth2/auth -> |                      |                   |
  |                   |-- challenge GET ---> |                   |
  |                   |   (auth_details in)  |                   |
  |                   |                      | [2] renders UI -> |
  |                   |                      |                   |-- approve -->
  |                   |                      | [3] accept PUT -> |
  |                   | <---- auth_details --|                   |
  |                   |   (possibly          |                   |
  |                   |    enriched)         |                   |
  |                   | [4] merges into      |                   |
  |                   |    session.Extra     |                   |
  |                   |                      |                   |
  |                   |-- code redirect --------------------------->
  |-- token request ->|                                          |
  |<-- access_token + authorization_details in response --       |
```

**Step annotations**

1. **Hydra stores the request-side `authorization_details`** on the Flow
   (`flow.authorization_details` column). Source is the `authorization_details`
   form/query parameter on `/oauth2/par` or `/oauth2/auth`. See
   `hydra/consent/strategy_default.go` — the field is copied verbatim from the
   request form, no transformation.

2. **Hydra includes `authorization_details` in the consent challenge payload**
   returned by `GET /admin/oauth2/auth/requests/consent?consent_challenge=…`.
   The field is present as a JSON array on the response body. If the request
   did not include `authorization_details`, the field is omitted.

3. **The Consent App accepts consent** with
   `PUT /admin/oauth2/auth/requests/consent/accept` and echoes the
   `authorization_details` back (optionally enriched — see §5). This is the
   authoritative record: what Hydra puts in the token response comes from the
   accept body, not from the original request.

4. **Hydra merges the accept-side `authorization_details` into the session**
   so it ends up in the token response and in introspection output.

---

## 3. What the Consent App MUST do

These are non-negotiable — skipping any of them breaks the feature silently
(no error from Hydra, just missing data in the token response).

### 3.1 Preserve all fields of the consent challenge

When you fetch the consent request (`GET /admin/oauth2/auth/requests/consent`),
you MUST retain the full JSON body. Do not deserialize into a type that drops
unknown fields.

**Common trap: pinned SDKs filter unknown fields.** The TypeScript SDK
`@ory/hydra-client-fetch` generates strongly-typed mappers that silently drop
any field not in the upstream OpenAPI schema. OIDC4VCI extensions
(`authorization_details`, `issuer_state`) are Ory-fork-specific and are *not*
in upstream, so they are dropped on both:

- the inbound mapper (`OAuth2ConsentRequestFromJSONTyped`) — the returned
  object has no `authorization_details` at runtime, even though Hydra sent it,
- the outbound mapper (`AcceptOAuth2ConsentRequestToJSON`) — even if you
  attach `authorization_details` to the accept body, the SDK strips it before
  sending.

Same problem applies to the Go, Python, and Java SDKs — any time the SDK is
pinned to a version older than the Hydra instance it talks to.

**Workaround:** for the two affected endpoints — `GET consent_request` and
`PUT consent/accept` — call Hydra's Admin API with a raw HTTP client and
pass JSON through unmodified. Use the SDK for everything else (login accept,
consent reject, session fields) without restriction.

The stub implementation in this repo does exactly that — see
`hydra-login-consent-node/src/routes/consent.ts`.

### 3.2 Echo `authorization_details` in the accept body

The accept body sent to
`PUT /admin/oauth2/auth/requests/consent/accept?consent_challenge=…`
MUST include `authorization_details` when the consent request carried it.

Minimum payload:

```json
{
  "grant_scope": ["openid", "openid_credential"],
  "grant_access_token_audience": [],
  "authorization_details": <same array Hydra sent, or an enriched version>,
  "session": { "access_token": {}, "id_token": {} }
}
```

Omit the `authorization_details` key when the consent request did not include
one — sending `null` or an empty array can cause Hydra to interpret this as
"the user consented to no authorization details", which is materially different
from "no authorization details were requested".

### 3.3 Respect the `skip` branch

When `consent_request.skip === true` (or the client has `skip_consent: true`),
the Consent App is expected to accept the request without showing UI. The
`authorization_details` echo applies equally in this branch — otherwise the
first skip-eligible consent hides the field forever for remembered sessions.

### 3.4 Do not blindly trust enrichment from the user-agent

`authorization_details` entering the Consent App is bound to the authorize
session. Anything the user-agent could tamper with (query strings in the UI
form, client-side JS) MUST NOT influence what ends up in the accept body. Read
`authorization_details` only from the consent request payload returned by
Hydra's Admin API.

---

## 4. How Hydra uses what you send back

For each entry in the `authorization_details` array you pass to the consent
accept endpoint, Hydra:

- **Stores it** on `flow.consent_authorization_details` (separate column from
  `flow.authorization_details` — the former is the authoritative
  consented-to set; the latter is the historical request).
- **Merges it into `session.Extra["authorization_details"]`** as a JSON array
  of objects.
- **Copies it into the access token response** as the top-level
  `authorization_details` field (via the RAR token handler at
  `hydra/fosite/handler/rar/token_handler.go`).
- **Exposes it via introspection** under `ext.authorization_details` so
  resource servers can read it from `POST /admin/oauth2/introspect`.

Validation you DO NOT need to perform: Hydra's RAR handler validates request
shape (`type`, `credential_configuration_id`, supported types, JSON wellformedness)
at the authorize/PAR endpoint before the consent challenge is ever created. The
Consent App receives only requests that already passed structural validation.

---

## 5. Implementation patterns — pick one

Three common patterns for managing `authorization_details` in a Consent App.
They differ in who generates `credential_identifiers` (required in the token
response per OIDC4VCI §6.2 for credential issuance flows) and who owns the
credential catalog.

### 5.1 Pattern A — Echo-only (client-provided details)

**What it is.** The Consent App echoes the request-side `authorization_details`
back unchanged. No enrichment, no credential lookup.

**When to use.**
- The RAR type doesn't require `credential_identifiers` (non-OIDC4VCI flows).
- The Token Hook (see §5.3) is responsible for credential_identifiers.
- Early development / conformance harness usage.

**Implementation.** One line in the accept body:

```ts
if (consentRequest.authorization_details) {
  acceptBody.authorization_details = consentRequest.authorization_details
}
```

**Trade-off.** For OIDC4VCI credential issuance, the token response will be
missing `credential_identifiers` unless the Token Hook adds them. Most
conformance suites accept this and test the Token Hook path separately.

### 5.2 Pattern B — Consent-time enrichment

**What it is.** The Consent App calls the Credential Issuer (or its own
catalog) to obtain `credential_identifiers` for each `openid_credential` entry
and includes them in the accept body.

**When to use.**
- The Consent App is deployed inside or tightly coupled to the Credential
  Issuer.
- You want to show the user the exact credentials they're about to receive
  (their identifiers, not just their configuration names).
- You want consent-time commitment to a specific credential inventory.

**Pseudocode.**

```ts
const enriched = await Promise.all(
  consentRequest.authorization_details.map(async (entry) => {
    if (entry.type !== "openid_credential") return entry
    const ids = await credentialIssuer.reserveIdentifiers({
      subject: consentRequest.subject,
      configurationId: entry.credential_configuration_id,
    })
    return { ...entry, credential_identifiers: ids }
  }),
)
acceptBody.authorization_details = enriched
```

**Trade-off.** Couples the Consent App to the Credential Issuer's reservation
API. Reservation should be idempotent per consent challenge to avoid leaking
identifiers when consent is denied or the user abandons mid-flow.

### 5.3 Pattern C — Delegate to the Token Hook

**What it is.** The Consent App echoes `authorization_details` unchanged
(Pattern A). A separate Token Hook webhook (`oauth2.token_hook` config) runs
at token-issuance time and enriches
`session.Extra["authorization_details"]` with `credential_identifiers` just
before the response is finalized.

**When to use.**
- The Credential Issuer and the Consent App are owned by different teams.
- You want reservation to happen at the latest possible moment (after the
  access token is about to be minted, so reservation is only made for flows
  that actually complete).
- The Consent App must remain generic across many integrations.

**Implementation.** See the Token Hook contract documented at
`hydra/docs/features/…` and in the config schema under `oauth2.token_hook`.
The hook receives a request with
`session.extra.authorization_details`, mutates it, and returns it. Hydra
then uses the hook's response for the token response and introspection.

**Trade-off.** Adds a second network hop per token request; requires careful
error semantics (hook failures block token issuance).

### 5.4 Combining patterns

Patterns are not mutually exclusive — you can have a Consent App that does
Pattern B for some credential types and delegates to Pattern C for others,
routed off the `type` field. The only hard rule: the *final* state of
`session.Extra["authorization_details"]` at token-response time is what the
client sees. The accept body is just the first writer; the Token Hook, if
configured, runs last.

---

## 6. Implementation checklist

- [ ] `GET /admin/oauth2/auth/requests/consent` is fetched with a raw HTTP
      client that preserves all JSON fields.
- [ ] The Consent App reads `authorization_details` from the consent request
      payload (not from the user-agent's form submission).
- [ ] `authorization_details` is echoed (and optionally enriched) in the
      `PUT /admin/oauth2/auth/requests/consent/accept` body.
- [ ] The field is omitted (not sent as `null` or `[]`) when the consent
      request had no `authorization_details`.
- [ ] The `skip` branch also echoes the field.
- [ ] The accept body is sent with a raw HTTP client (the typed SDK strips
      unknown fields).
- [ ] The reject path does not need to handle `authorization_details`.

---

## 7. End-to-end validation

Once the Consent App is wired up, validate without running a wallet:

```bash
# 1. Register a client that asks for authorization_details.
#    (see contrib/quickstart/oidc4vci for a working example)

# 2. Start a PAR + auth flow manually, accept login via admin API, let
#    the Consent App accept consent via its HTTP UI or its automation
#    branch, and reach the token endpoint.

# 3. Confirm the token response contains authorization_details.
curl -s "$HYDRA_ADMIN/admin/oauth2/introspect" \
  -d "token=$ACCESS_TOKEN" | jq '.ext.authorization_details'

# 4. Confirm the token endpoint returns the same array.
#    (inspect the raw token response body during step 2).
```

If `ext.authorization_details` is null in the introspection output but was
present on the initial request, the break is in the Consent App — most likely
one of:

- The accept body did not include `authorization_details`.
- The accept call went through a typed SDK that stripped the field.
- The consent request was fetched through a typed SDK that never surfaced the
  field, so there was nothing to echo.

See `hydra-login-consent-node/src/routes/consent.ts` in this repo for a
working reference implementation covering all four paths (skip, manual accept,
Pattern A echo, reject).

---

## 8. Related documents

- [OIDC4VCI integration guide](./oidc4vci-integration-guide.md) — overall
  integration story for Credential Issuers.
- [`docs/features/rar-consent.md`](../features/rar-consent.md) — internal
  architecture of RAR support in Hydra.
- [`docs/ai-context/features/feature-rar.md`](../ai-context/features/feature-rar.md)
  — implementation detail for contributors working on Hydra itself.
- [RFC 9396 — OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396).
- [OpenID for Verifiable Credential Issuance §5.1.1, §6.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
