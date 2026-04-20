// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/hydra/v2/fosite"
	wallet_attestation "github.com/ory/hydra/v2/fosite/handler/wallet_attestation"
)

// WalletAttestationRefreshBindingFactory creates the Wallet Attestation
// RefreshBindingHandler which stores the Client Instance Key thumbprint in the
// session when a refresh token is issued via Wallet Attestation, and verifies
// it on refresh.
func WalletAttestationRefreshBindingFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
	return &wallet_attestation.RefreshBindingHandler{
		Config: config.(wallet_attestation.WalletAttestationConfigProvider),
	}
}
