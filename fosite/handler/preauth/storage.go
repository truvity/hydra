// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package preauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory/x/sqlxx"
)

// PreAuthorizedCodeStorageProvider provides access to PreAuthorizedCodeStorage.
// This follows the same provider pattern as oauth2.AccessTokenStorageProvider.
type PreAuthorizedCodeStorageProvider interface {
	PreAuthorizedCodeStorage() PreAuthorizedCodeStorage
}

// PreAuthorizedCodeStorage provides lifecycle management for pre-authorized code
// sessions: creation (admin API), retrieval and atomic invalidation (token endpoint).
type PreAuthorizedCodeStorage interface {
	// CreatePreAuthorizedCodeSession inserts a new pre-authorized code grant.
	// Called by the admin API handler after generating the HMAC code.
	CreatePreAuthorizedCodeSession(ctx context.Context, signature string, data *PreAuthorizedCodeData) error

	// GetPreAuthorizedCodeSession loads the stored grant by HMAC signature and
	// current network ID. Returns fosite.ErrNotFound if no matching row exists.
	GetPreAuthorizedCodeSession(ctx context.Context, signature string) (*PreAuthorizedCodeData, error)

	// InvalidatePreAuthorizedCode atomically marks the code as redeemed.
	// Uses UPDATE ... SET redeemed=true WHERE signature=? AND nid=? AND redeemed=false.
	// Returns an error if no rows were affected (already redeemed or not found).
	InvalidatePreAuthorizedCode(ctx context.Context, signature string) error
}

// PreAuthorizedCodeData represents a stored pre-authorized code grant.
// The HMAC signature is the DB primary key; the raw code is never stored.
type PreAuthorizedCodeData struct {
	Signature                  string                      `db:"signature"`
	NID                        uuid.UUID                   `db:"nid"`
	RequestID                  string                      `db:"request_id"`
	ClientID                   string                      `db:"client_id"`
	RequestedScope             sqlxx.StringSliceJSONFormat `db:"requested_scope"`
	GrantedScope               sqlxx.StringSliceJSONFormat `db:"granted_scope"`
	CredentialConfigurationIDs sqlxx.StringSliceJSONFormat `db:"credential_configuration_ids"`
	TxCodeHash                 string                      `db:"tx_code_hash"`
	TxCodeInputMode            string                      `db:"tx_code_input_mode"`
	TxCodeLength               int                         `db:"tx_code_length"`
	SessionData                json.RawMessage             `db:"session_data"`
	Redeemed                   bool                        `db:"redeemed"`
	RequestedAt                time.Time                   `db:"requested_at"`
	ExpiresAt                  time.Time                   `db:"expires_at"`
}

// TableName returns the Pop ORM table name for pre-authorized code grants.
func (d *PreAuthorizedCodeData) TableName() string {
	return "hydra_oauth2_preauth_code"
}
