// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/preauth"
)

// PreAuthorizedCodeFactory creates the Pre-Authorized Code (OIDC4VCI) handler.
func PreAuthorizedCodeFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	return &preauth.Handler{
		Config:   config.(preauth.PreAuthorizedCodeConfigProvider),
		Storage:  storage.(preauth.PreAuthorizedCodeStorage),
		Strategy: strategy.(preauth.CoreStrategy),
	}
}
