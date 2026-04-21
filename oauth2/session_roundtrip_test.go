// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/oauth2"
)

// Feature: oidc4vci-haip-metadata, Property 7: Session.Extra authorization_details Round-Trip
//
// For any valid authorization_details JSON array (containing objects with type,
// credential_configuration_id, and credential_identifiers fields), storing it in
// Session.Extra["authorization_details"], serializing the session to JSON, and
// deserializing it back SHALL produce an identical authorization_details structure.
//
// **Validates: Requirements 17.1, 17.2**
func TestProperty7_SessionExtraAuthorizationDetailsRoundTrip(t *testing.T) {
	t.Parallel()

	// Generator for a single authorization_details object.
	genAuthDetail := rapid.Custom(func(t *rapid.T) map[string]interface{} {
		numIDs := rapid.IntRange(0, 5).Draw(t, "numCredentialIdentifiers")
		credIDs := make([]interface{}, numIDs)
		for i := range numIDs {
			credIDs[i] = rapid.StringMatching(`[a-zA-Z0-9_-]{1,32}`).Draw(t, "credentialIdentifier")
		}

		return map[string]interface{}{
			"type":                        rapid.StringMatching(`[a-zA-Z0-9_-]{1,32}`).Draw(t, "type"),
			"credential_configuration_id": rapid.StringMatching(`[a-zA-Z0-9_-]{1,32}`).Draw(t, "credentialConfigurationId"),
			"credential_identifiers":      credIDs,
		}
	})

	// Generator for an authorization_details array (1–5 elements).
	genAuthDetails := rapid.Custom(func(t *rapid.T) []interface{} {
		n := rapid.IntRange(1, 5).Draw(t, "numDetails")
		details := make([]interface{}, n)
		for i := range n {
			details[i] = genAuthDetail.Draw(t, "authDetail")
		}
		return details
	})

	rapid.Check(t, func(rt *rapid.T) {
		authDetails := genAuthDetails.Draw(rt, "authorizationDetails")

		// Build a minimal session with authorization_details in Extra.
		session := &oauth2.Session{
			Extra: map[string]interface{}{
				"authorization_details": authDetails,
			},
		}

		// Serialize to JSON.
		data, err := json.Marshal(session)
		require.NoError(rt, err, "json.Marshal must succeed")

		// Deserialize back.
		var restored oauth2.Session
		err = json.Unmarshal(data, &restored)
		require.NoError(rt, err, "json.Unmarshal must succeed")

		// Compare the authorization_details round-trip.
		assert.Equal(rt, session.Extra["authorization_details"], restored.Extra["authorization_details"],
			"authorization_details must survive JSON round-trip")
	})
}
