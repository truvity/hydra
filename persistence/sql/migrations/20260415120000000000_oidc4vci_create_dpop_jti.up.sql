-- OIDC4VCI extension: create DPoP JTI replay detection table
CREATE TABLE IF NOT EXISTS hydra_oauth2_dpop_jti (
    jti         VARCHAR(255) NOT NULL,
    nid         UUID         NOT NULL,
    used_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP    NOT NULL,
    PRIMARY KEY (jti, nid)
);

CREATE INDEX IF NOT EXISTS idx_dpop_jti_expires_at ON hydra_oauth2_dpop_jti (nid, expires_at);
