// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-rar-consent, Property 5: RAR and Scope Independence

package oauth2_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/rar"
)

// mockRARScopeConfig is a test implementation of fosite.RARConfigProvider for scope independence tests.
type mockRARScopeConfig struct {
	typesSupported []string
}

func (m *mockRARScopeConfig) GetRAREnabled(_ context.Context) bool        { return true }
func (m *mockRARScopeConfig) GetRARTypesSupported(_ context.Context) []string { return m.typesSupported }

// --- rapid generators ---

// genScopeValue generates a random scope string (e.g. "openid", "profile", "credential_xyz").
func genScopeValue() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z][a-z0-9_.]{0,20}`)
}

// genScopeSet generates a non-empty set of scope values as a space-separated string.
func genScopeSet() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		n := rapid.IntRange(1, 5).Draw(t, "numScopes")
		scopes := make([]string, n)
		for i := range scopes {
			scopes[i] = genScopeValue().Draw(t, "scope")
		}
		return strings.Join(scopes, " ")
	})
}

// genCredConfigID generates a credential_configuration_id string.
func genCredConfigID() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9_]{0,29}`)
}

// genValidAuthDetailsJSON generates a valid authorization_details JSON array with openid_credential entries.
func genValidAuthDetailsJSON() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		n := rapid.IntRange(1, 3).Draw(t, "numObjects")
		var objects []map[string]interface{}
		for i := 0; i < n; i++ {
			objects = append(objects, map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": genCredConfigID().Draw(t, "credConfigID"),
			})
		}
		data, err := json.Marshal(objects)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	})
}

// --- Property 5 Tests ---

// **Validates: Requirements 7.1, 7.2, 7.3**

// TestProperty5_ScopeAndAuthDetailsPreservedIndependently verifies that when both
// authorization_details and scope are present in an authorize request, the RAR handler
// processes authorization_details without modifying or rejecting the request based on
// scope values. Both parameters are preserved independently in the request form.
func TestProperty5_ScopeAndAuthDetailsPreservedIndependently(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := &rar.RARHandler{
			Config: &mockRARScopeConfig{typesSupported: []string{"openid_credential"}},
		}
		ctx := context.Background()

		scopeStr := genScopeSet().Draw(t, "scope")
		authDetailsJSON := genValidAuthDetailsJSON().Draw(t, "authDetails")

		ar := fosite.NewAuthorizeRequest()
		ar.Form = url.Values{
			"authorization_details": {authDetailsJSON},
			"scope":                 {scopeStr},
		}

		resp := fosite.NewAuthorizeResponse()
		err := handler.HandleAuthorizeEndpointRequest(ctx, ar, resp)

		// RAR handler must succeed — scope values must not cause interference.
		require.NoError(t, err, "RAR handler should not reject request due to scope values")

		// Verify authorization_details is preserved in the form.
		gotAuthDetails := ar.GetRequestForm().Get("authorization_details")
		assert.Equal(t, authDetailsJSON, gotAuthDetails,
			"authorization_details must be preserved unchanged in the request form")

		// Verify scope is preserved in the form — RAR handler must not modify it.
		gotScope := ar.GetRequestForm().Get("scope")
		assert.Equal(t, scopeStr, gotScope,
			"scope must be preserved unchanged in the request form")
	})
}

// TestProperty5_UnknownScopeDoesNotCauseRARError verifies that unknown or
// credential-related scope values do not cause the RAR handler to return an error.
// The RAR handler is scope-agnostic.
func TestProperty5_UnknownScopeDoesNotCauseRARError(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := &rar.RARHandler{
			Config: &mockRARScopeConfig{typesSupported: []string{"openid_credential"}},
		}
		ctx := context.Background()

		// Generate scope values that include unknown/credential-related scopes.
		unknownScopes := rapid.Custom(func(t *rapid.T) string {
			scopes := []string{
				"openid",
				rapid.StringMatching(`credential_[a-z]{1,10}`).Draw(t, "credScope"),
				rapid.StringMatching(`unknown_[a-z]{1,10}`).Draw(t, "unknownScope"),
			}
			return strings.Join(scopes, " ")
		}).Draw(t, "unknownScopes")

		authDetailsJSON := genValidAuthDetailsJSON().Draw(t, "authDetails")

		ar := fosite.NewAuthorizeRequest()
		ar.Form = url.Values{
			"authorization_details": {authDetailsJSON},
			"scope":                 {unknownScopes},
		}

		resp := fosite.NewAuthorizeResponse()
		err := handler.HandleAuthorizeEndpointRequest(ctx, ar, resp)

		// RAR handler must succeed regardless of scope values.
		require.NoError(t, err,
			"RAR handler must not reject request based on unknown scope values")
	})
}

// TestProperty5_ScopeOnlyRequestNotAffectedByRAR verifies that when only scope
// is present (no authorization_details), the RAR handler returns nil without
// interfering with the request.
func TestProperty5_ScopeOnlyRequestNotAffectedByRAR(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := &rar.RARHandler{
			Config: &mockRARScopeConfig{typesSupported: []string{"openid_credential"}},
		}
		ctx := context.Background()

		scopeStr := genScopeSet().Draw(t, "scope")

		ar := fosite.NewAuthorizeRequest()
		ar.Form = url.Values{
			"scope": {scopeStr},
		}

		resp := fosite.NewAuthorizeResponse()
		err := handler.HandleAuthorizeEndpointRequest(ctx, ar, resp)

		// RAR handler returns nil when authorization_details is absent.
		require.NoError(t, err,
			"RAR handler must return nil when only scope is present")

		// Scope must be preserved.
		gotScope := ar.GetRequestForm().Get("scope")
		assert.Equal(t, scopeStr, gotScope,
			"scope must be preserved unchanged when no authorization_details present")
	})
}

// TestProperty5_AuthDetailsOnlyRequestPreservesNoScope verifies that when only
// authorization_details is present (no scope), the RAR handler processes it
// without adding or requiring scope.
func TestProperty5_AuthDetailsOnlyRequestPreservesNoScope(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		handler := &rar.RARHandler{
			Config: &mockRARScopeConfig{typesSupported: []string{"openid_credential"}},
		}
		ctx := context.Background()

		authDetailsJSON := genValidAuthDetailsJSON().Draw(t, "authDetails")

		ar := fosite.NewAuthorizeRequest()
		ar.Form = url.Values{
			"authorization_details": {authDetailsJSON},
		}

		resp := fosite.NewAuthorizeResponse()
		err := handler.HandleAuthorizeEndpointRequest(ctx, ar, resp)

		require.NoError(t, err,
			"RAR handler must succeed with authorization_details only (no scope)")

		// authorization_details preserved.
		gotAuthDetails := ar.GetRequestForm().Get("authorization_details")
		assert.Equal(t, authDetailsJSON, gotAuthDetails,
			"authorization_details must be preserved")

		// scope must remain empty — RAR handler must not inject scope.
		gotScope := ar.GetRequestForm().Get("scope")
		assert.Empty(t, gotScope,
			"scope must remain empty when not provided in the request")
	})
}
