-- OIDC4VCI extension: add authorization_details, issuer_state, and consent_authorization_details columns to the flow table
ALTER TABLE hydra_oauth2_flow ADD COLUMN authorization_details json NULL;
ALTER TABLE hydra_oauth2_flow ADD COLUMN issuer_state VARCHAR(4096) NULL DEFAULT '';
ALTER TABLE hydra_oauth2_flow ADD COLUMN consent_authorization_details json NULL;
