// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package preauth

// AnonymousClientID is the well-known client ID used for anonymous
// pre-authorized code token issuance. When `preauth.anonymous_access` is
// enabled and a Wallet redeems a code without client authentication, this
// synthetic client is assigned to the access request so that the access token
// can be persisted (hydra_oauth2_access.client_id has a NOT NULL FK to
// hydra_client). The client is provisioned via DB migration.
const AnonymousClientID = "__oidc4vci_anonymous__" // #nosec G101
