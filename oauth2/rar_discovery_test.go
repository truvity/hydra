// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-rar-consent, Property 10: Discovery Metadata Reflects RAR Configuration

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// **Validates: Requirements 13.1, 13.2**

func TestProperty10_DiscoveryMetadataPresent_WhenRAREnabled(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		types := rapid.SliceOfN(
			rapid.StringMatching(`[a-zA-Z0-9_]{1,30}`),
			1, 5,
		).Draw(t, "types_supported")

		cfg := oidcConfiguration{
			Issuer:                             "https://example.com",
			AuthorizationDetailsTypesSupported: types,
		}

		data, err := json.Marshal(cfg)
		require.NoError(t, err)

		var raw map[string]json.RawMessage
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		_, exists := raw["authorization_details_types_supported"]
		assert.True(t, exists,
			"authorization_details_types_supported must be present when types are set")

		var decoded []string
		err = json.Unmarshal(raw["authorization_details_types_supported"], &decoded)
		require.NoError(t, err)
		assert.Equal(t, types, decoded,
			"decoded types must match the configured types")
	})
}

func TestProperty10_DiscoveryMetadataAbsent_WhenRARDisabled(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		cfg := oidcConfiguration{
			Issuer:                             "https://example.com",
			AuthorizationDetailsTypesSupported: nil,
		}

		data, err := json.Marshal(cfg)
		require.NoError(t, err)

		var raw map[string]json.RawMessage
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		_, exists := raw["authorization_details_types_supported"]
		assert.False(t, exists,
			"authorization_details_types_supported must be absent when types are nil (RAR disabled)")
	})
}
