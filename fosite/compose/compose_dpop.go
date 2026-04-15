// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/dpop"
)

// DPoPFactory creates the DPoP (RFC 9449) token binding handler.
func DPoPFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
	return &dpop.Handler{
		Config:     config.(dpop.DPoPConfigProvider),
		NonceStore: storage.(dpop.DPoPNonceStorage),
	}
}
