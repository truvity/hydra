-- OIDC4VCI extension: drop pre-authorized code grant table
DROP INDEX IF EXISTS idx_preauth_code_expires_at;
DROP INDEX IF EXISTS idx_preauth_code_nid;
DROP TABLE IF EXISTS hydra_oauth2_preauth_code;
