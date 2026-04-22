-- OIDC4VCI extension: drop PAR session table
DROP INDEX IF EXISTS idx_par_expires_at;
DROP INDEX IF EXISTS idx_par_nid;
DROP TABLE IF EXISTS hydra_oauth2_par;
