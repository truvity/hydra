// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package wallet_attestation

import (
	"context"
	"time"
)

// JTIStorage provides JTI replay detection for Wallet Attestation PoP JWTs.
// This is a subset of dpop.DPoPNonceStorage — the same table and methods
// serve both DPoP proof JTI and Wallet Attestation PoP JTI replay detection.
// No new migration is needed; the hydra_oauth2_dpop_jti table stores JTI
// values with expiry for both use cases. Collision between DPoP JTIs and
// PoP JTIs is negligible (both are cryptographically random UUIDs).
type JTIStorage interface {
	// IsJTIUsed checks whether the given jti has already been seen.
	// Returns true if the jti was previously marked as used.
	IsJTIUsed(ctx context.Context, jti string) (bool, error)

	// MarkJTIUsed records the jti as used with the given expiry time.
	// After expiry the entry may be purged and the jti reused.
	MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error
}
