// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"time"
)

// DPoPNonceStorageProvider provides access to DPoPNonceStorage.
// This follows the same provider pattern as oauth2.AccessTokenStorageProvider.
type DPoPNonceStorageProvider interface {
	DPoPNonceStorage() DPoPNonceStorage
}

// DPoPNonceStorage provides JTI replay detection and nonce management for
// DPoP proof validation per RFC 9449.
type DPoPNonceStorage interface {
	// IsJTIUsed checks whether the given jti has already been seen for the
	// current network. Returns true if the jti was previously marked as used.
	IsJTIUsed(ctx context.Context, jti string) (bool, error)

	// MarkJTIUsed records the jti as used with the given expiry time. After
	// expiry the entry may be purged and the jti reused.
	MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error

	// CreateDPoPNonce generates a fresh server nonce for inclusion in the
	// DPoP-Nonce response header. The nonce is stateless (HMAC-based) and
	// can be validated without a database lookup.
	CreateDPoPNonce(ctx context.Context) (string, error)

	// ValidateDPoPNonce verifies that the given nonce is authentic and not
	// expired. Returns true if the nonce is valid.
	ValidateDPoPNonce(ctx context.Context, nonce string) (bool, error)
}
