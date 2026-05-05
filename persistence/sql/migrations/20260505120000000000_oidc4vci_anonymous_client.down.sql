-- SEC-346: Remove synthetic anonymous client for pre-authorized code anonymous access.
DELETE FROM hydra_client WHERE id = '__oidc4vci_anonymous__';
