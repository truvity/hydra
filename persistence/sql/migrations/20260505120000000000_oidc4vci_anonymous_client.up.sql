-- SEC-346: Create synthetic anonymous client for pre-authorized code anonymous access.
-- When preauth.anonymous_access is enabled, the token endpoint stores access tokens
-- with this client_id to satisfy the hydra_oauth2_access FK constraint.
--
-- The client is inserted for every existing network. The WHERE NOT EXISTS clause
-- ensures idempotency (re-running the migration does not fail or create duplicates).
--
-- Note: jsonb columns (redirect_uris, grant_types, response_types, audience,
-- allowed_cors_origins, contacts, request_uris, post_logout_redirect_uris) require
-- valid JSON literals. Plain '[]' is valid JSON and accepted by both PostgreSQL
-- jsonb and SQLite/MySQL text columns.

INSERT INTO hydra_client (
    id,
    nid,
    client_name,
    client_secret,
    redirect_uris,
    grant_types,
    response_types,
    scope,
    owner,
    policy_uri,
    tos_uri,
    client_uri,
    logo_uri,
    contacts,
    client_secret_expires_at,
    sector_identifier_uri,
    jwks,
    jwks_uri,
    request_uris,
    token_endpoint_auth_method,
    request_object_signing_alg,
    userinfo_signed_response_alg,
    subject_type,
    allowed_cors_origins,
    audience,
    frontchannel_logout_uri,
    frontchannel_logout_session_required,
    post_logout_redirect_uris,
    backchannel_logout_uri,
    backchannel_logout_session_required,
    metadata,
    token_endpoint_auth_signing_alg,
    registration_access_token_signature,
    access_token_strategy,
    skip_consent
)
SELECT
    '__oidc4vci_anonymous__',
    id,
    'OIDC4VCI Anonymous Client',
    '',
    '[]',
    '["urn:ietf:params:oauth:grant-type:pre-authorized_code"]',
    '[]',
    '',
    'system',
    '',
    '',
    '',
    '',
    '[]',
    0,
    '',
    '{"keys":[]}',
    '',
    '[]',
    'none',
    '',
    '',
    '',
    '[]',
    '[]',
    '',
    false,
    '[]',
    '',
    false,
    '{}',
    '',
    '',
    '',
    true
FROM networks
WHERE NOT EXISTS (
    SELECT 1 FROM hydra_client
    WHERE hydra_client.id = '__oidc4vci_anonymous__' AND hydra_client.nid = networks.id
);
