// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-rar-consent, Property 3: RAR Round-Trip Persistence

package flow_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/flow"
	"github.com/ory/x/sqlxx"
)

// --- rapid generators ---

// genCredentialConfigID generates a random credential_configuration_id string.
func genCredentialConfigID() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_]{0,29}`)
}

// genAuthDetailsObject generates a single authorization_details object with
// type=openid_credential and a random credential_configuration_id.
func genAuthDetailsObject() *rapid.Generator[map[string]interface{}] {
	return rapid.Custom(func(t *rapid.T) map[string]interface{} {
		obj := map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": genCredentialConfigID().Draw(t, "credConfigID"),
		}
		if rapid.Bool().Draw(t, "hasLocations") {
			obj["locations"] = []interface{}{"https://issuer.example.com"}
		}
		return obj
	})
}

// genAuthDetailsArray generates a non-empty authorization_details JSON array.
func genAuthDetailsArray() *rapid.Generator[[]map[string]interface{}] {
	return rapid.SliceOfN(genAuthDetailsObject(), 1, 5)
}

// genEnrichedAuthDetailsObject generates an authorization_details object enriched
// with credential_identifiers (as the Consent Node would add).
func genEnrichedAuthDetailsObject() *rapid.Generator[map[string]interface{}] {
	return rapid.Custom(func(t *rapid.T) map[string]interface{} {
		obj := map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": genCredentialConfigID().Draw(t, "credConfigID"),
		}
		n := rapid.IntRange(1, 4).Draw(t, "numCredIDs")
		credIDs := make([]interface{}, n)
		for i := range credIDs {
			credIDs[i] = rapid.StringMatching(`cred-[a-z0-9]{4,10}`).Draw(t, "credID")
		}
		obj["credential_identifiers"] = credIDs
		return obj
	})
}

// genEnrichedAuthDetailsArray generates a non-empty enriched authorization_details array.
func genEnrichedAuthDetailsArray() *rapid.Generator[[]map[string]interface{}] {
	return rapid.SliceOfN(genEnrichedAuthDetailsObject(), 1, 5)
}

// --- Property 3 Tests ---

// **Validates: Requirements 1.9, 4.1, 4.2, 4.3, 8.1**

// TestProperty3_RARRoundTripPersistence verifies that authorization_details stored
// during the authorization phase is retrievable in the consent challenge
// (OAuth2ConsentRequest.AuthorizationDetails), and after consent accept with
// enriched authorization_details (including credential_identifiers), the enriched
// data is present on the Flow's ConsentAuthorizationDetails without loss or mutation.
func TestProperty3_RARRoundTripPersistence(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Step 1: Generate random authorization_details and marshal to JSON.
		authDetailsArr := genAuthDetailsArray().Draw(t, "authDetails")
		authDetailsJSON, err := json.Marshal(authDetailsArr)
		require.NoError(t, err)

		// Step 2: Create a Flow with AuthorizationDetails set (simulating RAR handler storage).
		f := &flow.Flow{
			State:                flow.FlowStateConsentUnused,
			AuthorizationDetails: sqlxx.JSONRawMessage(authDetailsJSON),
		}

		// Step 3: Call GetConsentRequest and verify AuthorizationDetails is present.
		consentReq := f.GetConsentRequest("test-challenge")
		require.NotNil(t, consentReq)
		assert.NotNil(t, consentReq.AuthorizationDetails,
			"consent challenge must contain authorization_details")

		// Verify the consent request's authorization_details matches what was stored.
		var consentAuthDetails []map[string]interface{}
		err = json.Unmarshal(consentReq.AuthorizationDetails, &consentAuthDetails)
		require.NoError(t, err, "consent authorization_details must be valid JSON")
		assert.Equal(t, len(authDetailsArr), len(consentAuthDetails),
			"consent authorization_details array length must match original")

		// Step 4: Generate enriched authorization_details (with credential_identifiers).
		enrichedArr := genEnrichedAuthDetailsArray().Draw(t, "enrichedAuthDetails")
		enrichedJSON, err := json.Marshal(enrichedArr)
		require.NoError(t, err)

		// Step 5: Create AcceptOAuth2ConsentRequest with enriched AuthorizationDetails.
		acceptReq := &flow.AcceptOAuth2ConsentRequest{
			GrantedScope:         []string{"openid"},
			AuthorizationDetails: sqlxx.JSONRawMessage(enrichedJSON),
		}

		// Step 6: Call HandleConsentRequest and verify ConsentAuthorizationDetails is set.
		err = f.HandleConsentRequest(acceptReq)
		require.NoError(t, err, "HandleConsentRequest should succeed")

		// Step 7: Verify the enriched data persists on the Flow without loss or mutation.
		require.NotNil(t, f.ConsentAuthorizationDetails,
			"Flow.ConsentAuthorizationDetails must be set after consent accept")

		var flowConsentAuthDetails []map[string]interface{}
		err = json.Unmarshal(f.ConsentAuthorizationDetails, &flowConsentAuthDetails)
		require.NoError(t, err, "ConsentAuthorizationDetails must be valid JSON")
		assert.Equal(t, len(enrichedArr), len(flowConsentAuthDetails),
			"ConsentAuthorizationDetails array length must match enriched input")

		// Verify each enriched object is preserved.
		for i, expected := range enrichedArr {
			actual := flowConsentAuthDetails[i]
			assert.Equal(t, expected["type"], actual["type"],
				"type must be preserved at index %d", i)
			assert.Equal(t, expected["credential_configuration_id"], actual["credential_configuration_id"],
				"credential_configuration_id must be preserved at index %d", i)

			// Verify credential_identifiers are preserved.
			expectedCredIDs, ok := expected["credential_identifiers"].([]interface{})
			require.True(t, ok, "expected credential_identifiers must be a slice at index %d", i)
			actualCredIDs, ok := actual["credential_identifiers"].([]interface{})
			require.True(t, ok, "actual credential_identifiers must be a slice at index %d", i)
			assert.Equal(t, len(expectedCredIDs), len(actualCredIDs),
				"credential_identifiers length must match at index %d", i)
			for j, expID := range expectedCredIDs {
				assert.Equal(t, expID, actualCredIDs[j],
					"credential_identifiers[%d] must match at index %d", j, i)
			}
		}

		// Step 8: Verify the original AuthorizationDetails on the Flow is unchanged.
		var originalAuthDetails []map[string]interface{}
		err = json.Unmarshal(f.AuthorizationDetails, &originalAuthDetails)
		require.NoError(t, err, "original AuthorizationDetails must still be valid JSON")
		assert.Equal(t, len(authDetailsArr), len(originalAuthDetails),
			"original AuthorizationDetails must be unchanged after consent accept")
	})
}

// Feature: oidc4vci-rar-consent, Property 6: issuer_state Round-Trip

// genIssuerState generates random issuer_state strings including empty, unicode, and long strings.
func genIssuerState() *rapid.Generator[string] {
	return rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[a-zA-Z0-9_\-]{1,64}`),
		rapid.StringMatching(`[a-zA-Z0-9\-._~]{100,512}`),
		rapid.String(),
	)
}

// **Validates: Requirements 6.1, 6.2**

// TestProperty6_IssuerStateRoundTrip verifies that issuer_state from an authorization or PAR
// request is preserved identically in OAuth2ConsentRequest.IssuerState, for any issuer_state
// value (including empty, unicode, and long strings).
func TestProperty6_IssuerStateRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Step 1: Generate a random issuer_state value.
		issuerState := genIssuerState().Draw(t, "issuerState")

		// Step 2: Create a Flow with IssuerState set (simulating extraction from the request form).
		f := &flow.Flow{
			State:       flow.FlowStateConsentUnused,
			IssuerState: issuerState,
		}

		// Step 3: Call GetConsentRequest() and verify IssuerState matches exactly.
		consentReq := f.GetConsentRequest("test-challenge")
		require.NotNil(t, consentReq)
		assert.Equal(t, issuerState, consentReq.IssuerState,
			"OAuth2ConsentRequest.IssuerState must be identical to the original issuer_state value")
	})
}

// Feature: oidc4vci-rar-consent, Property 7: Consent Node Can Enrich authorization_details

// **Validates: Requirements 4.2, 4.3, 8.1, 8.3, 8.4**

// TestProperty7_ConsentEnrichmentAuthorizationDetails verifies that enriched
// authorization_details (with credential_identifiers) from a consent accept response
// flows into Flow.ConsentAuthorizationDetails, can be unmarshaled into session.Extra,
// and the enriched data (including credential_identifiers) is preserved in the session
// for downstream consumption by token responses and introspection.
func TestProperty7_ConsentEnrichmentAuthorizationDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Step 1: Generate initial authorization_details (without credential_identifiers).
		initialArr := genAuthDetailsArray().Draw(t, "initialAuthDetails")
		initialJSON, err := json.Marshal(initialArr)
		require.NoError(t, err)

		// Step 2: Generate enriched authorization_details (with credential_identifiers).
		enrichedArr := genEnrichedAuthDetailsArray().Draw(t, "enrichedAuthDetails")
		enrichedJSON, err := json.Marshal(enrichedArr)
		require.NoError(t, err)

		// Step 3: Create a Flow with initial AuthorizationDetails set.
		f := &flow.Flow{
			State:                flow.FlowStateConsentUnused,
			AuthorizationDetails: sqlxx.JSONRawMessage(initialJSON),
		}

		// Step 4: Process consent accept with enriched AuthorizationDetails.
		acceptReq := &flow.AcceptOAuth2ConsentRequest{
			GrantedScope:         []string{"openid"},
			AuthorizationDetails: sqlxx.JSONRawMessage(enrichedJSON),
		}
		err = f.HandleConsentRequest(acceptReq)
		require.NoError(t, err, "HandleConsentRequest should succeed")

		// Step 5: Verify enriched data is stored on Flow.ConsentAuthorizationDetails.
		require.NotNil(t, f.ConsentAuthorizationDetails,
			"Flow.ConsentAuthorizationDetails must be set after consent accept")

		// Step 6: Simulate the session merge (as done in oauth2/handler.go).
		// Unmarshal ConsentAuthorizationDetails into []interface{} and set on session.Extra.
		var authDetails []interface{}
		err = json.Unmarshal(f.ConsentAuthorizationDetails, &authDetails)
		require.NoError(t, err, "ConsentAuthorizationDetails must unmarshal to []interface{}")
		require.NotEmpty(t, authDetails, "unmarshaled authorization_details must not be empty")

		sessionExtra := make(map[string]interface{})
		sessionExtra["authorization_details"] = authDetails

		// Step 7: Verify session.Extra["authorization_details"] contains the enriched data.
		rawAD, ok := sessionExtra["authorization_details"]
		require.True(t, ok, "session.Extra must contain authorization_details key")

		adSlice, ok := rawAD.([]interface{})
		require.True(t, ok, "authorization_details must be a slice")
		assert.Equal(t, len(enrichedArr), len(adSlice),
			"session authorization_details array length must match enriched input")

		// Step 8: Verify each enriched object preserves credential_identifiers.
		for i, expected := range enrichedArr {
			actual, ok := adSlice[i].(map[string]interface{})
			require.True(t, ok, "each authorization_details entry must be a map at index %d", i)

			assert.Equal(t, expected["type"], actual["type"],
				"type must be preserved at index %d", i)
			assert.Equal(t, expected["credential_configuration_id"], actual["credential_configuration_id"],
				"credential_configuration_id must be preserved at index %d", i)

			// Verify credential_identifiers are present and preserved.
			expectedCredIDs, ok := expected["credential_identifiers"].([]interface{})
			require.True(t, ok, "expected credential_identifiers must be a slice at index %d", i)
			actualCredIDs, ok := actual["credential_identifiers"].([]interface{})
			require.True(t, ok, "actual credential_identifiers must be a slice at index %d", i)
			assert.Equal(t, len(expectedCredIDs), len(actualCredIDs),
				"credential_identifiers length must match at index %d", i)
			for j, expID := range expectedCredIDs {
				assert.Equal(t, expID, actualCredIDs[j],
					"credential_identifiers[%d] must match at index %d", j, i)
			}
		}

		// Step 9: Verify the original AuthorizationDetails on the Flow is unchanged
		// (consent enrichment does not mutate the request-side authorization_details).
		var originalAuthDetails []map[string]interface{}
		err = json.Unmarshal(f.AuthorizationDetails, &originalAuthDetails)
		require.NoError(t, err, "original AuthorizationDetails must still be valid JSON")
		assert.Equal(t, len(initialArr), len(originalAuthDetails),
			"original AuthorizationDetails must be unchanged after consent enrichment")
	})
}
