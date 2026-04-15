// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/internal/testhelpers"
)

// Feature: oidc4vci-dpop, Property 3: JTI Replay Detection
// **Validates: Requirements 1.12, 10.1, 10.2**
func TestProperty3_JTIReplayDetection(t *testing.T) {
	t.Parallel()

	reg := testhelpers.NewRegistryMemory(t)
	p := reg.Persister()
	ctx := t.Context()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a unique JTI string for each property test iteration.
		jti := rapid.StringMatching(`[a-zA-Z0-9_-]{8,64}`).Draw(t, "jti")
		expiry := time.Now().Add(1 * time.Hour)

		// Property: a fresh JTI that has never been marked should not be used.
		used, err := p.IsJTIUsed(ctx, jti)
		require.NoError(t, err)
		require.False(t, used, "fresh jti must not be reported as used")

		// Mark the JTI as used.
		err = p.MarkJTIUsed(ctx, jti, expiry)
		require.NoError(t, err)

		// Property: after marking, IsJTIUsed must return true.
		used, err = p.IsJTIUsed(ctx, jti)
		require.NoError(t, err)
		require.True(t, used, "marked jti must be reported as used")

		// Property: duplicate MarkJTIUsed is idempotent (no error).
		err = p.MarkJTIUsed(ctx, jti, expiry)
		require.NoError(t, err)

		// Still used after duplicate insert.
		used, err = p.IsJTIUsed(ctx, jti)
		require.NoError(t, err)
		require.True(t, used, "jti must remain used after duplicate insert")
	})
}

// Feature: oidc4vci-dpop, Property 6: Nonce Round-Trip Integrity
// **Validates: Requirements 10.3, 10.4**
func TestProperty6_NonceRoundTripIntegrity(t *testing.T) {
	t.Parallel()

	reg := testhelpers.NewRegistryMemory(t)
	p := reg.Persister()
	ctx := t.Context()

	rapid.Check(t, func(t *rapid.T) {
		// Create a fresh nonce.
		nonce, err := p.CreateDPoPNonce(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, nonce)

		// Property: a freshly created nonce must validate successfully.
		valid, err := p.ValidateDPoPNonce(ctx, nonce)
		require.NoError(t, err)
		require.True(t, valid, "freshly created nonce must validate")

		// Property: a tampered nonce must not validate.
		// Decode the nonce, flip a random byte, re-encode.
		raw, err := base64.RawURLEncoding.DecodeString(nonce)
		require.NoError(t, err)
		require.Len(t, raw, 40)

		pos := rapid.IntRange(0, len(raw)-1).Draw(t, "tamper_position")
		tampered := make([]byte, len(raw))
		copy(tampered, raw)
		// Flip a random bit in the chosen byte to guarantee mutation.
		tampered[pos] ^= 0x01

		tamperedNonce := base64.RawURLEncoding.EncodeToString(tampered)
		valid, err = p.ValidateDPoPNonce(ctx, tamperedNonce)
		require.NoError(t, err)
		require.False(t, valid, "tampered nonce must not validate (flipped byte at position %d)", pos)

		// Property: an expired nonce must not validate.
		// Reconstruct a nonce with a timestamp far in the past but a valid HMAC.
		secret, err := reg.Config().GetGlobalSecret(ctx)
		require.NoError(t, err)

		pastTS := make([]byte, 8)
		binary.BigEndian.PutUint64(pastTS, uint64(time.Now().Add(-1*time.Hour).Unix()))

		// Reuse the random bytes from the original nonce.
		randomBytes := raw[8:24]

		// Recompute HMAC over pastTS || randomBytes with the real secret.
		mac := hmac.New(sha256.New, secret)
		mac.Write(pastTS)
		mac.Write(randomBytes)
		sig := mac.Sum(nil)[:16]

		expired := make([]byte, 40)
		copy(expired[0:8], pastTS)
		copy(expired[8:24], randomBytes)
		copy(expired[24:40], sig)

		expiredNonce := base64.RawURLEncoding.EncodeToString(expired)
		valid, err = p.ValidateDPoPNonce(ctx, expiredNonce)
		require.NoError(t, err)
		require.False(t, valid, "expired nonce must not validate")
	})
}
