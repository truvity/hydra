-- OIDC4VCI extension: create PAR (Pushed Authorization Request) session table
CREATE TABLE IF NOT EXISTS hydra_oauth2_par (
    signature          VARCHAR(255) NOT NULL,
    request_id         VARCHAR(40)  NOT NULL,
    requested_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_id          VARCHAR(255) NOT NULL,
    scope              TEXT         NOT NULL,
    granted_scope      TEXT         NOT NULL,
    form_data          TEXT         NOT NULL,
    session_data       TEXT         NOT NULL,
    subject            VARCHAR(255) NOT NULL DEFAULT '',
    active             BOOLEAN      NOT NULL DEFAULT true,
    requested_audience TEXT         NULL     DEFAULT '',
    granted_audience   TEXT         NULL     DEFAULT '',
    challenge_id       VARCHAR(40)  NULL,
    nid                CHAR(36)     NOT NULL,
    expires_at         TIMESTAMP    NULL,
    PRIMARY KEY (signature)
);

CREATE INDEX IF NOT EXISTS idx_par_nid ON hydra_oauth2_par (nid);
CREATE INDEX IF NOT EXISTS idx_par_expires_at ON hydra_oauth2_par (nid, expires_at);
