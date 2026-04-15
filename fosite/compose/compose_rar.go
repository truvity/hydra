// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/rar"
)

// RARFactory creates the Rich Authorization Requests (RFC 9396) handler.
func RARFactory(config fosite.Configurator, storage fosite.Storage, _ interface{}) interface{} {
	return &rar.RARHandler{
		Config: config.(rar.RARConfigProvider),
	}
}
