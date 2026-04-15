// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-rar-consent, Property 8: Refresh Token Preserves authorization_details

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/fosite/token/jwt"
)

// --- rapid generators ---

// genCredConfigID generates a random credential_configuration_id string.
func genRefreshCredConfigID() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_]{0,29}`)
}

// genCredentialIdentifier generates a random credential identifier string.
func genCredentialIdentifier() *rapid.Generator[string] {
	return rapid.StringMatching(`cred-[a-z0-9]{4,12}`)
}

// genAuthDetailsEntry generates a single authorization_details object with
// type=openid_credential, a random credential_configuration_id, and optionally
// credential_identifiers (as enriched by the Consent Node).
func genAuthDetailsEntry() *rapid.Generator[map[string]interface{}] {
	return rapid.Custom(func(t *rapid.T) map[string]interface{} {
		obj := map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": genRefreshCredConfigID().Draw(t, "credConfigID"),
		}
		if rapid.Bool().Draw(t, "hasCredIDs") {
			n := rapid.IntRange(1, 4).Draw(t, "numCredIDs")
			credIDs := make([]interface{}, n)
			for i := range credIDs {
				credIDs[i] = genCredentialIdentifier().Draw(t, "credID")
			}
			obj["credential_identifiers"] = credIDs
		}
		if rapid.Bool().Draw(t, "hasLocations") {
			obj["locations"] = []interface{}{"https://issuer.example.com"}
		}
		return obj
	})
}

// genAuthDetailsSlice generates a non-empty authorization_details array for Session.Extra.
func genAuthDetailsSlice() *rapid.Generator[[]interface{}] {
	return rapid.Custom(func(t *rapid.T) []interface{} {
		n := rapid.IntRange(1, 5).Draw(t, "numEntries")
		entries := make([]interface{}, n)
		for i := range entries {
			entries[i] = genAuthDetailsEntry().Draw(t, "entry")
		}
		return entries
	})
}

// --- Property 8 Tests ---

// **Validates: Requirements 8.2**

// TestProperty8_RefreshTokenPreservesAuthorizationDetails verifies that
// authorization_details in Session.Extra is preserved across JSON serialization
// and deserialization — the mechanism by which refresh token exchange preserves
// session data. For any session with authorization_details in Extra, marshaling
// to JSON and unmarshaling back must retain the same authorization_details data.
func TestProperty8_RefreshTokenPreservesAuthorizationDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Step 1: Generate random authorization_details for Session.Extra.
		authDetails := genAuthDetailsSlice().Draw(t, "authDetails")

		// Step 2: Create a Session with authorization_details in Extra.
		original := &Session{
			DefaultSession: &openid.DefaultSession{
				Claims:  new(jwt.IDTokenClaims),
				Headers: new(jwt.Headers),
				Subject: "test-subject",
			},
			Extra: map[string]interface{}{
				"authorization_details": authDetails,
			},
		}

		// Step 3: Marshal the session to JSON (simulating storage on token creation).
		data, err := json.Marshal(original)
		require.NoError(t, err, "session must marshal to JSON")

		// Step 4: Unmarshal back into a new Session (simulating retrieval on refresh).
		var restored Session
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err, "session must unmarshal from JSON")

		// Step 5: Verify authorization_details is preserved in Extra.
		rawAD, ok := restored.Extra["authorization_details"]
		require.True(t, ok, "restored session.Extra must contain authorization_details key")

		adSlice, ok := rawAD.([]interface{})
		require.True(t, ok, "authorization_details must be a slice after deserialization")
		require.Equal(t, len(authDetails), len(adSlice),
			"authorization_details array length must be preserved")

		// Step 6: Verify each entry is preserved with all fields.
		for i, expectedRaw := range authDetails {
			expected, ok := expectedRaw.(map[string]interface{})
			require.True(t, ok, "original entry must be a map at index %d", i)
			actual, ok := adSlice[i].(map[string]interface{})
			require.True(t, ok, "restored entry must be a map at index %d", i)

			assert.Equal(t, expected["type"], actual["type"],
				"type must be preserved at index %d", i)
			assert.Equal(t, expected["credential_configuration_id"], actual["credential_configuration_id"],
				"credential_configuration_id must be preserved at index %d", i)

			// Verify credential_identifiers if present.
			if expectedCredIDs, hasCredIDs := expected["credential_identifiers"]; hasCredIDs {
				actualCredIDs, ok := actual["credential_identifiers"]
				require.True(t, ok,
					"credential_identifiers must be present in restored entry at index %d", i)

				expectedSlice, ok := expectedCredIDs.([]interface{})
				require.True(t, ok)
				actualSlice, ok := actualCredIDs.([]interface{})
				require.True(t, ok)
				require.Equal(t, len(expectedSlice), len(actualSlice),
					"credential_identifiers length must match at index %d", i)
				for j, expID := range expectedSlice {
					assert.Equal(t, expID, actualSlice[j],
						"credential_identifiers[%d] must match at index %d", j, i)
				}
			}

			// Verify locations if present.
			if expectedLocs, hasLocs := expected["locations"]; hasLocs {
				actualLocs, ok := actual["locations"]
				require.True(t, ok,
					"locations must be present in restored entry at index %d", i)

				expectedLocSlice, ok := expectedLocs.([]interface{})
				require.True(t, ok)
				actualLocSlice, ok := actualLocs.([]interface{})
				require.True(t, ok)
				assert.Equal(t, expectedLocSlice, actualLocSlice,
					"locations must be preserved at index %d", i)
			}
		}
	})
}
