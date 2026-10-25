-- OIDC4VCI extension: drop DPoP JTI replay detection table
-- MySQL variant: DROP INDEX IF EXISTS is not supported; dropping the table drops its indexes.
DROP TABLE IF EXISTS hydra_oauth2_dpop_jti;
