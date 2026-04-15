// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-rar-consent, Introspection authorization_details verification

package oauth2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// **Validates: Requirements 8.4**

// TestIntrospection_AuthorizationDetailsInExt verifies that when
// authorization_details is present in Session.Extra, the Introspection struct
// serializes it under the "ext" JSON key as ext.authorization_details.
// This confirms the existing Hydra introspection data path works correctly
// with the new RAR session data — no production code changes are needed.
func TestIntrospection_AuthorizationDetailsInExt(t *testing.T) {
	t.Parallel()

	authDetails := []interface{}{
		map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": "UniversityDegree_jwt_vc_json",
			"credential_identifiers":      []interface{}{"cred-id-1", "cred-id-2"},
		},
		map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": "DriverLicense_mdoc",
		},
	}

	intro := &Introspection{
		Active:   true,
		ClientID: "test-client",
		Subject:  "test-subject",
		Extra: map[string]interface{}{
			"authorization_details": authDetails,
		},
	}

	data, err := json.Marshal(intro)
	require.NoError(t, err, "Introspection must marshal to JSON")

	// Parse into generic map to inspect structure.
	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// ext must be present.
	extRaw, exists := raw["ext"]
	require.True(t, exists, "ext key must be present in introspection JSON")

	// ext.authorization_details must be present.
	var ext map[string]json.RawMessage
	err = json.Unmarshal(extRaw, &ext)
	require.NoError(t, err)

	adRaw, exists := ext["authorization_details"]
	require.True(t, exists,
		"authorization_details must be present inside ext")

	// Decode and verify the authorization_details array.
	var decoded []map[string]interface{}
	err = json.Unmarshal(adRaw, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded, 2, "authorization_details must have 2 entries")

	// First entry: with credential_identifiers.
	assert.Equal(t, "openid_credential", decoded[0]["type"])
	assert.Equal(t, "UniversityDegree_jwt_vc_json", decoded[0]["credential_configuration_id"])
	credIDs, ok := decoded[0]["credential_identifiers"].([]interface{})
	require.True(t, ok, "credential_identifiers must be a slice")
	assert.Equal(t, []interface{}{"cred-id-1", "cred-id-2"}, credIDs)

	// Second entry: without credential_identifiers.
	assert.Equal(t, "openid_credential", decoded[1]["type"])
	assert.Equal(t, "DriverLicense_mdoc", decoded[1]["credential_configuration_id"])
	_, hasCredIDs := decoded[1]["credential_identifiers"]
	assert.False(t, hasCredIDs,
		"second entry should not have credential_identifiers")
}

// TestIntrospection_NoAuthorizationDetails verifies that when Session.Extra
// does not contain authorization_details, the ext key either omits it or
// does not include authorization_details — ensuring no spurious data leaks.
func TestIntrospection_NoAuthorizationDetails(t *testing.T) {
	t.Parallel()

	intro := &Introspection{
		Active:   true,
		ClientID: "test-client",
		Subject:  "test-subject",
		Extra: map[string]interface{}{
			"some_other_claim": "value",
		},
	}

	data, err := json.Marshal(intro)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	extRaw, exists := raw["ext"]
	require.True(t, exists, "ext must be present when Extra has data")

	var ext map[string]json.RawMessage
	err = json.Unmarshal(extRaw, &ext)
	require.NoError(t, err)

	_, hasAD := ext["authorization_details"]
	assert.False(t, hasAD,
		"authorization_details must not appear in ext when not set in session")
}

// TestIntrospection_EmptyExtra verifies that when Session.Extra is nil,
// the ext key is omitted entirely from the JSON output.
func TestIntrospection_EmptyExtra(t *testing.T) {
	t.Parallel()

	intro := &Introspection{
		Active:   true,
		ClientID: "test-client",
		Subject:  "test-subject",
		Extra:    nil,
	}

	data, err := json.Marshal(intro)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, exists := raw["ext"]
	assert.False(t, exists,
		"ext must be omitted when Extra is nil (omitempty)")
}
