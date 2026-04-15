// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-rar-consent, Property 1: RAR Parsing and Validation

package rar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/rar"
)

// mockRARConfig is a simple test implementation of fosite.RARConfigProvider.
type mockRARConfig struct {
	enabled        bool
	typesSupported []string
}

func (m *mockRARConfig) GetRAREnabled(_ context.Context) bool      { return m.enabled }
func (m *mockRARConfig) GetRARTypesSupported(_ context.Context) []string { return m.typesSupported }

// newHandler creates a RARHandler with the given supported types.
func newHandler(supportedTypes []string) *rar.RARHandler {
	return &rar.RARHandler{
		Config: &mockRARConfig{enabled: true, typesSupported: supportedTypes},
	}
}

// newAuthorizeRequest creates a fosite.AuthorizeRequest with authorization_details set in the form.
func newAuthorizeRequest(authDetails string) *fosite.AuthorizeRequest {
	ar := fosite.NewAuthorizeRequest()
	if authDetails != "" {
		ar.Form = url.Values{"authorization_details": {authDetails}}
	}
	return ar
}

// --- rapid generators ---

// genNonEmptyAlphaString generates a non-empty alphanumeric string.
func genNonEmptyAlphaString() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z0-9_]{1,30}`)
}

// genSupportedTypes generates a non-empty slice of supported type strings.
func genSupportedTypes() *rapid.Generator[[]string] {
	return rapid.SliceOfN(genNonEmptyAlphaString(), 1, 5)
}


// genValidObject generates a valid authorization_details object with a type from supportedTypes.
// If the type is "openid_credential", it includes a non-empty credential_configuration_id.
func genValidObject(supportedTypes []string) *rapid.Generator[map[string]interface{}] {
	return rapid.Custom(func(t *rapid.T) map[string]interface{} {
		typeVal := rapid.SampledFrom(supportedTypes).Draw(t, "type")
		obj := map[string]interface{}{
			"type": typeVal,
		}
		if typeVal == "openid_credential" {
			obj["credential_configuration_id"] = rapid.StringMatching(`[a-zA-Z0-9_]{1,40}`).Draw(t, "credential_configuration_id")
		}
		// Optionally add extra fields to ensure they are preserved/ignored.
		if rapid.Bool().Draw(t, "hasExtra") {
			obj["locations"] = []interface{}{"https://example.com"}
		}
		return obj
	})
}

// genValidPayload generates a valid authorization_details JSON array string.
func genValidPayload(supportedTypes []string) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		objects := rapid.SliceOfN(genValidObject(supportedTypes), 1, 5).Draw(t, "objects")
		data, err := json.Marshal(objects)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	})
}

// genMalformedJSON generates a string that is not valid JSON or not a valid JSON array of objects.
func genMalformedJSON() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		// Pick from known malformed patterns that cannot parse as []map[string]interface{}.
		patterns := []string{
			`{not json}`,
			`[{"type":}]`,
			`[{"type": "openid_credential"`,
			`just a string`,
			`{"type": "openid_credential"}`, // JSON object, not array
			`"a string"`,                    // JSON string, not array
			`[1, 2, 3]`,                     // JSON array of numbers, not objects
			`[true]`,                        // JSON array of booleans, not objects
		}
		return rapid.SampledFrom(patterns).Draw(t, "malformed")
	})
}

// genMissingTypeObject generates an object missing the "type" field.
func genMissingTypeObject() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		obj := map[string]interface{}{
			"credential_configuration_id": "SomeCredential",
		}
		if rapid.Bool().Draw(t, "hasExtra") {
			obj["locations"] = []interface{}{"https://example.com"}
		}
		arr := []map[string]interface{}{obj}
		data, _ := json.Marshal(arr)
		return string(data)
	})
}

// genUnsupportedTypePayload generates a payload where at least one object has an unsupported type.
func genUnsupportedTypePayload(supportedTypes []string) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		// Generate a type that is NOT in supportedTypes.
		unsupported := rapid.StringMatching(`unsupported_[a-z]{1,10}`).Draw(t, "unsupportedType")
		obj := map[string]interface{}{
			"type": unsupported,
		}
		arr := []map[string]interface{}{obj}
		data, _ := json.Marshal(arr)
		return string(data)
	})
}

// genMissingCredConfigIDPayload generates a payload with type=openid_credential but missing credential_configuration_id.
func genMissingCredConfigIDPayload() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		obj := map[string]interface{}{
			"type": "openid_credential",
		}
		// Optionally add an empty credential_configuration_id.
		variant := rapid.IntRange(0, 2).Draw(t, "variant")
		switch variant {
		case 1:
			obj["credential_configuration_id"] = ""
		case 2:
			obj["credential_configuration_id"] = 12345 // non-string
		}
		arr := []map[string]interface{}{obj}
		data, _ := json.Marshal(arr)
		return string(data)
	})
}


// --- Property Tests ---

// **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 12.2**

// TestProperty1_ValidPayloadsAccepted verifies that valid authorization_details payloads
// are accepted by both authorize and PAR endpoints identically.
func TestProperty1_ValidPayloadsAccepted(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := genSupportedTypes().Draw(t, "supportedTypes")
		// Ensure openid_credential is in supported types for richer testing.
		supportedTypes = append(supportedTypes, "openid_credential")
		handler := newHandler(supportedTypes)

		payload := genValidPayload(supportedTypes).Draw(t, "payload")
		ctx := context.Background()

		arAuth := newAuthorizeRequest(payload)
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest(payload)
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		// Both must succeed.
		assert.NoError(t, errAuth, "authorize endpoint should accept valid payload")
		assert.NoError(t, errPAR, "PAR endpoint should accept valid payload")
	})
}

// TestProperty1_AbsentPayloadReturnsNil verifies that when authorization_details is absent,
// both handlers return nil without error.
func TestProperty1_AbsentPayloadReturnsNil(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := genSupportedTypes().Draw(t, "supportedTypes")
		handler := newHandler(supportedTypes)
		ctx := context.Background()

		arAuth := newAuthorizeRequest("")
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest("")
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		assert.NoError(t, errAuth, "authorize should return nil when authorization_details absent")
		assert.NoError(t, errPAR, "PAR should return nil when authorization_details absent")
	})
}

// TestProperty1_MalformedJSONRejected verifies that malformed JSON produces
// an invalid_authorization_details error on both endpoints.
func TestProperty1_MalformedJSONRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := []string{"openid_credential"}
		handler := newHandler(supportedTypes)
		ctx := context.Background()

		payload := genMalformedJSON().Draw(t, "malformed")

		arAuth := newAuthorizeRequest(payload)
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest(payload)
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		// Both must return an error.
		require.Error(t, errAuth, "authorize should reject malformed JSON")
		require.Error(t, errPAR, "PAR should reject malformed JSON")

		// Error must be invalid_authorization_details.
		assertInvalidAuthorizationDetailsError(t, errAuth)
		assertInvalidAuthorizationDetailsError(t, errPAR)
	})
}

// TestProperty1_MissingTypeRejected verifies that objects missing the type field
// produce an invalid_authorization_details error.
func TestProperty1_MissingTypeRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := []string{"openid_credential"}
		handler := newHandler(supportedTypes)
		ctx := context.Background()

		payload := genMissingTypeObject().Draw(t, "missingType")

		arAuth := newAuthorizeRequest(payload)
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest(payload)
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		require.Error(t, errAuth, "authorize should reject missing type")
		require.Error(t, errPAR, "PAR should reject missing type")

		assertInvalidAuthorizationDetailsError(t, errAuth)
		assertInvalidAuthorizationDetailsError(t, errPAR)
	})
}

// TestProperty1_UnsupportedTypeRejected verifies that unsupported type values
// produce an invalid_authorization_details error.
func TestProperty1_UnsupportedTypeRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := []string{"openid_credential"}
		handler := newHandler(supportedTypes)
		ctx := context.Background()

		payload := genUnsupportedTypePayload(supportedTypes).Draw(t, "unsupportedType")

		arAuth := newAuthorizeRequest(payload)
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest(payload)
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		require.Error(t, errAuth, "authorize should reject unsupported type")
		require.Error(t, errPAR, "PAR should reject unsupported type")

		assertInvalidAuthorizationDetailsError(t, errAuth)
		assertInvalidAuthorizationDetailsError(t, errPAR)
	})
}

// TestProperty1_MissingCredConfigIDRejected verifies that openid_credential objects
// missing or empty credential_configuration_id produce an invalid_authorization_details error.
func TestProperty1_MissingCredConfigIDRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := []string{"openid_credential"}
		handler := newHandler(supportedTypes)
		ctx := context.Background()

		payload := genMissingCredConfigIDPayload().Draw(t, "missingCredConfigID")

		arAuth := newAuthorizeRequest(payload)
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest(payload)
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		require.Error(t, errAuth, "authorize should reject missing credential_configuration_id")
		require.Error(t, errPAR, "PAR should reject missing credential_configuration_id")

		assertInvalidAuthorizationDetailsError(t, errAuth)
		assertInvalidAuthorizationDetailsError(t, errPAR)
	})
}

// TestProperty1_AuthorizeAndPARIdenticalBehavior verifies that for any arbitrary
// authorization_details string, both endpoints produce identical error/success outcomes.
func TestProperty1_AuthorizeAndPARIdenticalBehavior(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		supportedTypes := []string{"openid_credential"}
		handler := newHandler(supportedTypes)
		ctx := context.Background()

		// Generate an arbitrary JSON-ish string (mix of valid and invalid).
		payload := rapid.OneOf(
			genValidPayload(supportedTypes),
			genMalformedJSON(),
			genMissingTypeObject(),
			genUnsupportedTypePayload(supportedTypes),
			genMissingCredConfigIDPayload(),
		).Draw(t, "anyPayload")

		arAuth := newAuthorizeRequest(payload)
		authResp := fosite.NewAuthorizeResponse()
		errAuth := handler.HandleAuthorizeEndpointRequest(ctx, arAuth, authResp)

		arPAR := newAuthorizeRequest(payload)
		parResp := &fosite.PushedAuthorizeResponse{
			Header: make(map[string][]string),
			Extra:  make(map[string]interface{}),
		}
		errPAR := handler.HandlePushedAuthorizeEndpointRequest(ctx, arPAR, parResp)

		// Both must agree on success/failure.
		authOK := errAuth == nil
		parOK := errPAR == nil
		assert.Equal(t, authOK, parOK,
			"authorize and PAR must agree: auth=%v par=%v payload=%s", errAuth, errPAR, payload)

		// If both failed, they must produce the same error code.
		if !authOK && !parOK {
			authRFC := fosite.ErrorToRFC6749Error(errAuth)
			parRFC := fosite.ErrorToRFC6749Error(errPAR)
			assert.Equal(t, authRFC.ErrorField, parRFC.ErrorField,
				"error codes must match for payload: %s", payload)
		}
	})
}

// --- helpers ---

// assertInvalidAuthorizationDetailsError asserts that the error is an RFC6749Error
// with ErrorField "invalid_authorization_details".
func assertInvalidAuthorizationDetailsError(t require.TestingT, err error) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}
	rfcErr := fosite.ErrorToRFC6749Error(err)
	require.NotNil(t, rfcErr, "expected RFC6749Error")
	assert.Equal(t, "invalid_authorization_details", rfcErr.ErrorField,
		"expected invalid_authorization_details error, got: %s", rfcErr.ErrorField)
}

// Feature: oidc4vci-rar-consent, Property 2: RAR Token Request Subset Validation

// --- token endpoint helpers ---

// newAccessRequestWithAuthDetails creates a fosite.AccessRequest for token endpoint testing.
// authDetailsJSON is set in the request form; sessionAuthDetails is set in session.Extra["authorization_details"].
func newAccessRequestWithAuthDetails(authDetailsJSON string, sessionAuthDetails []interface{}) *fosite.AccessRequest {
	session := &fosite.DefaultSession{
		Extra: make(map[string]interface{}),
	}
	if sessionAuthDetails != nil {
		session.Extra["authorization_details"] = sessionAuthDetails
	}

	ar := fosite.NewAccessRequest(session)
	if authDetailsJSON != "" {
		ar.Form.Set("authorization_details", authDetailsJSON)
	}
	return ar
}

// buildAuthDetailsArray builds an authorization_details []interface{} from a set of credential_configuration_id values.
func buildAuthDetailsArray(ids []string) []interface{} {
	var arr []interface{}
	for _, id := range ids {
		arr = append(arr, map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": id,
		})
	}
	return arr
}

// buildAuthDetailsJSON builds an authorization_details JSON string from a set of credential_configuration_id values.
func buildAuthDetailsJSON(ids []string) string {
	var objects []map[string]interface{}
	for _, id := range ids {
		objects = append(objects, map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": id,
		})
	}
	data, _ := json.Marshal(objects)
	return string(data)
}

// --- rapid generators for Property 2 ---

// genCredentialConfigID generates a single credential_configuration_id string.
func genCredentialConfigID() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_]{0,29}`)
}

// genCredentialConfigIDSet generates a non-empty set of unique credential_configuration_id values.
func genCredentialConfigIDSet() *rapid.Generator[[]string] {
	return rapid.Custom(func(t *rapid.T) []string {
		n := rapid.IntRange(1, 8).Draw(t, "setSize")
		seen := make(map[string]bool)
		var ids []string
		for len(ids) < n {
			id := genCredentialConfigID().Draw(t, "id")
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		return ids
	})
}

// genSubset generates a non-empty subset of the given set.
func genSubset(superset []string) *rapid.Generator[[]string] {
	return rapid.Custom(func(t *rapid.T) []string {
		// Pick a random non-empty subset by including each element with some probability.
		var subset []string
		for _, id := range superset {
			if rapid.Bool().Draw(t, "include_"+id) {
				subset = append(subset, id)
			}
		}
		// Ensure at least one element.
		if len(subset) == 0 {
			idx := rapid.IntRange(0, len(superset)-1).Draw(t, "fallbackIdx")
			subset = append(subset, superset[idx])
		}
		return subset
	})
}

// genNonSubsetIDs generates a set of credential_configuration_id values where at least one is NOT in the authorized set.
func genNonSubsetIDs(authorizedSet []string) *rapid.Generator[[]string] {
	return rapid.Custom(func(t *rapid.T) []string {
		authorized := make(map[string]bool)
		for _, id := range authorizedSet {
			authorized[id] = true
		}

		// Generate an ID guaranteed not to be in the authorized set.
		var extraID string
		for {
			extraID = rapid.StringMatching(`extra_[a-z0-9]{1,15}`).Draw(t, "extraID")
			if !authorized[extraID] {
				break
			}
		}

		// Optionally include some authorized IDs too.
		var ids []string
		for _, id := range authorizedSet {
			if rapid.Bool().Draw(t, "includeAuthorized_"+id) {
				ids = append(ids, id)
			}
		}
		ids = append(ids, extraID)
		return ids
	})
}

// --- Property 2 Tests ---

// **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**

// TestProperty2_CanHandleReturnsFalseWithoutAuthDetails verifies that
// CanHandleTokenEndpointRequest returns false when no authorization_details is in the request.
func TestProperty2_CanHandleReturnsFalseWithoutAuthDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		// Create an access request with NO authorization_details in the form.
		ar := newAccessRequestWithAuthDetails("", nil)

		result := handler.CanHandleTokenEndpointRequest(ctx, ar)
		assert.False(t, result, "CanHandleTokenEndpointRequest should return false when no authorization_details")
	})
}

// TestProperty2_CanHandleReturnsTrueWithAuthDetails verifies that
// CanHandleTokenEndpointRequest returns true when authorization_details is present in the request.
func TestProperty2_CanHandleReturnsTrueWithAuthDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		authorizedIDs := genCredentialConfigIDSet().Draw(t, "authorizedIDs")
		requestJSON := buildAuthDetailsJSON(authorizedIDs)

		ar := newAccessRequestWithAuthDetails(requestJSON, buildAuthDetailsArray(authorizedIDs))

		result := handler.CanHandleTokenEndpointRequest(ctx, ar)
		assert.True(t, result, "CanHandleTokenEndpointRequest should return true when authorization_details present")
	})
}

// TestProperty2_CanSkipClientAuthAlwaysFalse verifies that CanSkipClientAuth always returns false.
func TestProperty2_CanSkipClientAuthAlwaysFalse(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		ar := newAccessRequestWithAuthDetails("", nil)

		result := handler.CanSkipClientAuth(ctx, ar)
		assert.False(t, result, "CanSkipClientAuth should always return false")
	})
}

// TestProperty2_SubsetRequestAccepted verifies that when the token request's
// credential_configuration_id values are a subset of the authorized set, HandleTokenEndpointRequest succeeds.
func TestProperty2_SubsetRequestAccepted(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		authorizedIDs := genCredentialConfigIDSet().Draw(t, "authorizedIDs")
		subsetIDs := genSubset(authorizedIDs).Draw(t, "subsetIDs")

		sessionAuthDetails := buildAuthDetailsArray(authorizedIDs)
		requestJSON := buildAuthDetailsJSON(subsetIDs)

		ar := newAccessRequestWithAuthDetails(requestJSON, sessionAuthDetails)

		err := handler.HandleTokenEndpointRequest(ctx, ar)
		assert.NoError(t, err, "HandleTokenEndpointRequest should accept subset request")
	})
}

// TestProperty2_NonSubsetRequestRejected verifies that when the token request contains
// a credential_configuration_id NOT in the authorized set, HandleTokenEndpointRequest
// returns an invalid_authorization_details error.
func TestProperty2_NonSubsetRequestRejected(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		authorizedIDs := genCredentialConfigIDSet().Draw(t, "authorizedIDs")
		nonSubsetIDs := genNonSubsetIDs(authorizedIDs).Draw(t, "nonSubsetIDs")

		sessionAuthDetails := buildAuthDetailsArray(authorizedIDs)
		requestJSON := buildAuthDetailsJSON(nonSubsetIDs)

		ar := newAccessRequestWithAuthDetails(requestJSON, sessionAuthDetails)

		err := handler.HandleTokenEndpointRequest(ctx, ar)
		require.Error(t, err, "HandleTokenEndpointRequest should reject non-subset request")
		assertInvalidAuthorizationDetailsError(t, err)
	})
}

// TestProperty2_NoSubsetValidationWithoutAuthDetails verifies that when the token request
// does not contain authorization_details, CanHandleTokenEndpointRequest returns false
// and HandleTokenEndpointRequest returns nil (no-op) if called directly.
func TestProperty2_NoSubsetValidationWithoutAuthDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		authorizedIDs := genCredentialConfigIDSet().Draw(t, "authorizedIDs")
		sessionAuthDetails := buildAuthDetailsArray(authorizedIDs)

		// No authorization_details in the request form.
		ar := newAccessRequestWithAuthDetails("", sessionAuthDetails)

		canHandle := handler.CanHandleTokenEndpointRequest(ctx, ar)
		assert.False(t, canHandle, "CanHandleTokenEndpointRequest should return false without authorization_details")

		// Even if called directly, HandleTokenEndpointRequest should be a no-op.
		err := handler.HandleTokenEndpointRequest(ctx, ar)
		assert.NoError(t, err, "HandleTokenEndpointRequest should return nil when no authorization_details in request")
	})
}

// TestProperty2_ExactSetAccepted verifies that requesting exactly the authorized set succeeds.
func TestProperty2_ExactSetAccepted(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		authorizedIDs := genCredentialConfigIDSet().Draw(t, "authorizedIDs")
		sessionAuthDetails := buildAuthDetailsArray(authorizedIDs)
		requestJSON := buildAuthDetailsJSON(authorizedIDs)

		ar := newAccessRequestWithAuthDetails(requestJSON, sessionAuthDetails)

		err := handler.HandleTokenEndpointRequest(ctx, ar)
		assert.NoError(t, err, "HandleTokenEndpointRequest should accept exact authorized set")
	})
}

// Feature: oidc4vci-rar-consent, Property 4: Token Response Contains authorization_details

// --- rapid generators for Property 4 ---

// genAuthDetailsArrayWithCredIDs generates a random authorization_details []interface{} array
// where each entry has type=openid_credential, a random credential_configuration_id,
// and optionally credential_identifiers.
func genAuthDetailsArrayWithCredIDs() *rapid.Generator[[]interface{}] {
	return rapid.Custom(func(t *rapid.T) []interface{} {
		ids := genCredentialConfigIDSet().Draw(t, "ids")
		var arr []interface{}
		for _, id := range ids {
			obj := map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": id,
			}
			// Optionally add credential_identifiers to simulate Consent Node enrichment.
			if rapid.Bool().Draw(t, "hasCredIDs_"+id) {
				n := rapid.IntRange(1, 4).Draw(t, "numCredIDs_"+id)
				var credIDs []interface{}
				for i := 0; i < n; i++ {
					credIDs = append(credIDs, rapid.StringMatching(`cred-[a-z0-9]{4,10}`).Draw(t, "credID"))
				}
				obj["credential_identifiers"] = credIDs
			}
			arr = append(arr, obj)
		}
		return arr
	})
}

// --- Property 4 Tests ---

// **Validates: Requirements 3.1, 3.2, 3.3**

// TestProperty4_PopulateResponseCopiesSessionAuthDetails verifies that when
// Session.Extra["authorization_details"] is present, PopulateTokenEndpointResponse
// copies the value into the access response extras — regardless of whether the
// token request form contains authorization_details.
func TestProperty4_PopulateResponseCopiesSessionAuthDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		sessionAuthDetails := genAuthDetailsArrayWithCredIDs().Draw(t, "sessionAuthDetails")

		// Randomly decide whether the token request form also has authorization_details.
		includeInForm := rapid.Bool().Draw(t, "includeInForm")
		var formJSON string
		if includeInForm {
			// Use a subset of the session IDs in the form (or all of them).
			var ids []string
			for _, item := range sessionAuthDetails {
				obj := item.(map[string]interface{})
				ids = append(ids, obj["credential_configuration_id"].(string))
			}
			formJSON = buildAuthDetailsJSON(ids)
		}

		ar := newAccessRequestWithAuthDetails(formJSON, sessionAuthDetails)
		resp := fosite.NewAccessResponse()

		err := handler.PopulateTokenEndpointResponse(ctx, ar, resp)
		require.NoError(t, err, "PopulateTokenEndpointResponse should succeed when session has authorization_details")

		// Verify the response extras contain authorization_details matching the session.
		got := resp.GetExtra("authorization_details")
		require.NotNil(t, got, "response extras must contain authorization_details")
		assert.Equal(t, sessionAuthDetails, got,
			"response authorization_details must equal session authorization_details")
	})
}

// TestProperty4_PopulateResponseReturnsErrUnknownRequestWithoutSessionAuthDetails verifies
// that when Session.Extra has no authorization_details key, PopulateTokenEndpointResponse
// returns fosite.ErrUnknownRequest.
func TestProperty4_PopulateResponseReturnsErrUnknownRequestWithoutSessionAuthDetails(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		// Session with no authorization_details.
		ar := newAccessRequestWithAuthDetails("", nil)
		resp := fosite.NewAccessResponse()

		err := handler.PopulateTokenEndpointResponse(ctx, ar, resp)
		require.Error(t, err, "PopulateTokenEndpointResponse should return error when no authorization_details in session")
		assert.ErrorIs(t, err, fosite.ErrUnknownRequest,
			"error should be fosite.ErrUnknownRequest")

		// Verify response extras do NOT contain authorization_details.
		got := resp.GetExtra("authorization_details")
		assert.Nil(t, got, "response extras must not contain authorization_details when session has none")
	})
}

// Feature: oidc4vci-rar-consent, Property 9: credential_identifiers Warning Log

// --- rapid generators for Property 9 ---

// genAuthDetailsArrayMissingCredentialIdentifiers generates a random authorization_details
// []interface{} where every openid_credential entry is missing credential_identifiers or
// has an empty array. At least one entry is always of type openid_credential.
func genAuthDetailsArrayMissingCredentialIdentifiers() *rapid.Generator[[]interface{}] {
	return rapid.Custom(func(t *rapid.T) []interface{} {
		ids := genCredentialConfigIDSet().Draw(t, "ids")
		var arr []interface{}
		for _, id := range ids {
			obj := map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": id,
			}
			// Randomly choose: missing credential_identifiers entirely, or empty array.
			if rapid.Bool().Draw(t, "emptyArray_"+id) {
				obj["credential_identifiers"] = []interface{}{}
			}
			// Otherwise the key is simply absent.
			arr = append(arr, obj)
		}
		return arr
	})
}

// genAuthDetailsArrayAllWithCredIDs generates a random authorization_details []interface{}
// where every openid_credential entry has a non-empty credential_identifiers array.
func genAuthDetailsArrayAllWithCredIDs() *rapid.Generator[[]interface{}] {
	return rapid.Custom(func(t *rapid.T) []interface{} {
		ids := genCredentialConfigIDSet().Draw(t, "ids")
		var arr []interface{}
		for _, id := range ids {
			n := rapid.IntRange(1, 4).Draw(t, "numCredIDs_"+id)
			var credIDs []interface{}
			for i := 0; i < n; i++ {
				credIDs = append(credIDs, rapid.StringMatching(`cred-[a-z0-9]{4,10}`).Draw(t, "credID"))
			}
			obj := map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": id,
				"credential_identifiers":      credIDs,
			}
			arr = append(arr, obj)
		}
		return arr
	})
}

// captureSlogWarnings installs a custom slog handler that writes to the returned buffer,
// and returns a cleanup function that restores the previous default logger.
// Must not be used concurrently — callers should not mark the test as t.Parallel().
func captureSlogWarnings() (buf *bytes.Buffer, restore func()) {
	var logBuf bytes.Buffer
	textHandler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()
	slog.SetDefault(slog.New(textHandler))
	return &logBuf, func() { slog.SetDefault(prev) }
}

// --- Property 9 Tests ---

// **Validates: Requirements 3.4**

// TestProperty9_CredentialIdentifiersWarningLog verifies that when authorization_details
// of type openid_credential is present but entries are missing credential_identifiers
// (or have an empty array), the AS logs a warning and the response is still produced
// successfully.
//
// Not parallel — modifies global slog default.
func TestProperty9_CredentialIdentifiersWarningLog(t *testing.T) {
	logBuf, restore := captureSlogWarnings()
	defer restore()

	rapid.Check(t, func(t *rapid.T) {
		logBuf.Reset()

		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		sessionAuthDetails := genAuthDetailsArrayMissingCredentialIdentifiers().Draw(t, "sessionAuthDetails")

		ar := newAccessRequestWithAuthDetails("", sessionAuthDetails)
		resp := fosite.NewAccessResponse()

		err := handler.PopulateTokenEndpointResponse(ctx, ar, resp)

		// Response must succeed — the warning is informational only.
		require.NoError(t, err, "PopulateTokenEndpointResponse should succeed even when credential_identifiers missing")

		// Verify the response extras contain authorization_details.
		got := resp.GetExtra("authorization_details")
		require.NotNil(t, got, "response extras must contain authorization_details")
		assert.Equal(t, sessionAuthDetails, got,
			"response authorization_details must equal session authorization_details")

		// Verify that a warning was logged.
		logOutput := logBuf.String()
		assert.Contains(t, logOutput, "credential_identifiers",
			"expected warning log mentioning credential_identifiers")
	})
}

// TestProperty9_NoWarningWhenCredentialIdentifiersPresent verifies that when all
// openid_credential entries have non-empty credential_identifiers, no warning is logged
// and the response is produced successfully.
//
// Not parallel — modifies global slog default.
func TestProperty9_NoWarningWhenCredentialIdentifiersPresent(t *testing.T) {
	logBuf, restore := captureSlogWarnings()
	defer restore()

	rapid.Check(t, func(t *rapid.T) {
		logBuf.Reset()

		handler := newHandler([]string{"openid_credential"})
		ctx := context.Background()

		sessionAuthDetails := genAuthDetailsArrayAllWithCredIDs().Draw(t, "sessionAuthDetails")

		ar := newAccessRequestWithAuthDetails("", sessionAuthDetails)
		resp := fosite.NewAccessResponse()

		err := handler.PopulateTokenEndpointResponse(ctx, ar, resp)

		require.NoError(t, err, "PopulateTokenEndpointResponse should succeed")

		got := resp.GetExtra("authorization_details")
		require.NotNil(t, got, "response extras must contain authorization_details")

		// No warning should be logged when all entries have credential_identifiers.
		logOutput := logBuf.String()
		assert.Empty(t, logOutput,
			"no warning should be logged when all entries have credential_identifiers")
	})
}
