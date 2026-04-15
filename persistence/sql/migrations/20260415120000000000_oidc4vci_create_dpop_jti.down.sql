-- OIDC4VCI extension: drop DPoP JTI replay detection table
DROP INDEX IF EXISTS idx_dpop_jti_expires_at;
DROP TABLE IF EXISTS hydra_oauth2_dpop_jti;
