// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/preauth"
)

// PreAuthorizedCodeFactory creates the Pre-Authorized Code (OIDC4VCI) handler.
func PreAuthorizedCodeFactory(config fosite.Configurator, storage fosite.Storage, strategy interface{}) interface{} {
	// Extract CoreStrategy from CommonStrategyProvider if needed.
	var coreStrategy preauth.CoreStrategy
	switch s := strategy.(type) {
	case *CommonStrategyProvider:
		coreStrategy = s.CoreStrategy
	case preauth.CoreStrategy:
		coreStrategy = s
	default:
		panic("PreAuthorizedCodeFactory: strategy must be *CommonStrategyProvider or preauth.CoreStrategy")
	}

	return &preauth.Handler{
		Config: config.(preauth.PreAuthorizedCodeConfigProvider),
		Storage: storage.(interface {
			preauth.PreAuthorizedCodeStorageProvider
			oauth2.AccessTokenStorageProvider
		}),
		Strategy: coreStrategy,
	}
}
