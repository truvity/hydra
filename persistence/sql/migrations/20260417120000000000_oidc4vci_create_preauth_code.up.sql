-- OIDC4VCI extension: create pre-authorized code grant table
CREATE TABLE IF NOT EXISTS hydra_oauth2_preauth_code (
    signature                    VARCHAR(255) NOT NULL,
    nid                          UUID         NOT NULL,
    request_id                   VARCHAR(255) NOT NULL,
    client_id                    VARCHAR(255) NULL,
    requested_scope              JSON,
    granted_scope                JSON,
    credential_configuration_ids JSON         NOT NULL,
    tx_code_hash                 VARCHAR(255) NULL,
    tx_code_input_mode           VARCHAR(10)  NULL,
    tx_code_length               INT          NULL,
    session_data                 JSON         NOT NULL,
    redeemed                     BOOLEAN      NOT NULL DEFAULT FALSE,
    requested_at                 TIMESTAMP    NOT NULL,
    expires_at                   TIMESTAMP    NOT NULL,
    PRIMARY KEY (signature)
);

CREATE INDEX IF NOT EXISTS idx_preauth_code_nid ON hydra_oauth2_preauth_code (nid);
CREATE INDEX IF NOT EXISTS idx_preauth_code_expires_at ON hydra_oauth2_preauth_code (nid, expires_at);
