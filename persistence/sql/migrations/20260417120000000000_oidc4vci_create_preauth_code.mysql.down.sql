-- OIDC4VCI extension: drop pre-authorized code grant table
-- MySQL variant: DROP INDEX IF EXISTS is not supported; dropping the table drops its indexes.
DROP TABLE IF EXISTS hydra_oauth2_preauth_code;
