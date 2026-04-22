// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"github.com/ory/hydra/v2/fosite"
)

// PARStorage returns the SQL-backed PAR session store.
// Implements fosite.PARStorageProvider so that *RegistrySQL can be used
// as fosite.Storage for the PAR handler and authorize request handler.
func (m *RegistrySQL) PARStorage() fosite.PARStorage {
	return m.Persister().(fosite.PARStorage)
}
