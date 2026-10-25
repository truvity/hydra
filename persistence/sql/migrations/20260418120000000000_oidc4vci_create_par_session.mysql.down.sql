-- OIDC4VCI extension: drop PAR session table
-- MySQL variant: DROP INDEX IF EXISTS is not supported; dropping the table drops its indexes.
DROP TABLE IF EXISTS hydra_oauth2_par;
