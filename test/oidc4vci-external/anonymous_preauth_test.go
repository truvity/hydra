// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc4vci_external_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Anonymous Pre-Authorized Code Tests (SEC-346) ─────────────────────────────

// TestExternal_PreAuthCode_AnonymousAccess verifies that when
// pre-authorized_grant_anonymous_access_supported is true, a Wallet can redeem
// a pre-authorized code without any client authentication (no client_id, no
// Basic Auth, no Wallet Attestation). This is the fix for SEC-346 where the
// token endpoint returned server_error due to a FK violation.
func TestExternal_PreAuthCode_AnonymousAccess(t *testing.T) {
	skipIfHydraDown(t)
	requireAnonymousAccessEnabled(t)

	// Create an unbound pre-authorized code (no client_id binding).
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"credential_configuration_ids": []string{"AnonymousTestCredential"},
	})
	code, ok := codeResp["pre_authorized_code"].(string)
	require.True(t, ok, "pre_authorized_code missing: %v", codeResp)
	require.NotEmpty(t, code)
	t.Logf("Pre-authorized code (anonymous, unbound): %s...", code[:20])

	// Exchange the code at the token endpoint WITHOUT any client authentication.
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
	}
	req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No client_id, no Basic Auth, no OAuth-Client-Attestation header.

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &tokenResp))

	// The fix for SEC-346: this must NOT return server_error (500).
	require.NotContains(t, tokenResp, "error",
		"anonymous token exchange should succeed (SEC-346 fix): %s", string(raw))
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"expected 200 OK, got %d: %s", resp.StatusCode, string(raw))

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok, "access_token missing from response")
	require.NotEmpty(t, accessToken)
	t.Logf("Access token (anonymous): %s...", accessToken[:20])

	// token_type should be "bearer" (no DPoP proof was sent).
	tokenType, _ := tokenResp["token_type"].(string)
	assert.Equal(t, "bearer", strings.ToLower(tokenType), "token_type should be bearer for anonymous access")

	// No refresh_token should be issued for anonymous clients.
	assert.Nil(t, tokenResp["refresh_token"],
		"refresh_token must NOT be issued for anonymous clients")

	// authorization_details should be present in the response.
	authDetails, ok := tokenResp["authorization_details"]
	require.True(t, ok, "authorization_details must be in token response")
	adList, ok := authDetails.([]interface{})
	require.True(t, ok, "authorization_details must be an array")
	require.Len(t, adList, 1)
	adEntry := adList[0].(map[string]interface{})
	assert.Equal(t, "openid_credential", adEntry["type"])
	assert.Equal(t, "AnonymousTestCredential", adEntry["credential_configuration_id"])

	// Introspect the token — it should be active.
	intro := introspect(t, accessToken)
	assert.Equal(t, true, intro["active"],
		"anonymous access token should be active on introspection")
	t.Logf("Introspection: active=%v", intro["active"])
}

// TestExternal_PreAuthCode_AnonymousAccess_WithTxCode verifies that anonymous
// access works correctly with transaction code validation.
func TestExternal_PreAuthCode_AnonymousAccess_WithTxCode(t *testing.T) {
	skipIfHydraDown(t)
	requireAnonymousAccessEnabled(t)

	txCode := "987654"

	// Create an unbound code with tx_code.
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"credential_configuration_ids": []string{"AnonymousTestCredential"},
		"tx_code":                      txCode,
		"tx_code_input_mode":           "numeric",
		"tx_code_length":               6,
	})
	code, ok := codeResp["pre_authorized_code"].(string)
	require.True(t, ok, "pre_authorized_code missing: %v", codeResp)

	t.Run("case=correct tx_code succeeds anonymously", func(t *testing.T) {
		// Need a fresh code for this sub-test.
		freshResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
			"credential_configuration_ids": []string{"AnonymousTestCredential"},
			"tx_code":                      txCode,
			"tx_code_input_mode":           "numeric",
			"tx_code_length":               6,
		})
		freshCode := freshResp["pre_authorized_code"].(string)

		form := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {freshCode},
			"tx_code":             {txCode},
		}
		req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)

		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &result))
		require.NotContains(t, result, "error",
			"anonymous + correct tx_code should succeed: %s", string(raw))
		assert.NotEmpty(t, result["access_token"])
	})

	t.Run("case=wrong tx_code fails", func(t *testing.T) {
		// Use the code from the outer scope (not yet redeemed).
		form := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {code},
			"tx_code":             {"000000"},
		}
		req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Contains(t, result, "error", "wrong tx_code should fail")
	})
}

// TestExternal_PreAuthCode_AnonymousAccess_SingleUse verifies that anonymous
// pre-authorized codes are single-use.
func TestExternal_PreAuthCode_AnonymousAccess_SingleUse(t *testing.T) {
	skipIfHydraDown(t)
	requireAnonymousAccessEnabled(t)

	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"credential_configuration_ids": []string{"AnonymousTestCredential"},
	})
	code := codeResp["pre_authorized_code"].(string)

	exchange := func() map[string]interface{} {
		form := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {code},
		}
		req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		return result
	}

	// First exchange succeeds.
	r1 := exchange()
	require.NotContains(t, r1, "error", "first anonymous exchange should succeed")
	assert.NotEmpty(t, r1["access_token"])

	// Second exchange fails (single-use).
	r2 := exchange()
	assert.Contains(t, r2, "error", "second anonymous exchange should fail (single-use)")
}

// TestExternal_PreAuthCode_AnonymousAccess_AuthorizationDetailsSubset verifies
// that the Wallet can request a subset of credential_configuration_ids via
// authorization_details in the anonymous flow.
func TestExternal_PreAuthCode_AnonymousAccess_AuthorizationDetailsSubset(t *testing.T) {
	skipIfHydraDown(t)
	requireAnonymousAccessEnabled(t)

	// Create a code with multiple credential configurations.
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"credential_configuration_ids": []string{"CredA", "CredB", "CredC"},
	})
	code := codeResp["pre_authorized_code"].(string)

	// Request only CredB via authorization_details.
	authDetails, _ := json.Marshal([]map[string]interface{}{
		{
			"type":                        "openid_credential",
			"credential_configuration_id": "CredB",
		},
	})

	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code":   {code},
		"authorization_details": {string(authDetails)},
	}
	req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &tokenResp))
	require.NotContains(t, tokenResp, "error",
		"anonymous + authorization_details subset should succeed: %s", string(raw))

	// Verify only CredB is in the response.
	adResp, ok := tokenResp["authorization_details"].([]interface{})
	require.True(t, ok, "authorization_details must be in response")
	require.Len(t, adResp, 1)
	assert.Equal(t, "CredB", adResp[0].(map[string]interface{})["credential_configuration_id"])
}

// ── Helper ────────────────────────────────────────────────────────────────────

// requireAnonymousAccessEnabled checks the discovery endpoint for
// pre-authorized_grant_anonymous_access_supported and skips the test if it's
// not enabled on the running Hydra instance.
func requireAnonymousAccessEnabled(t *testing.T) {
	t.Helper()

	resp, err := http.Get(publicURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var disco map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&disco))

	anonSupported, ok := disco["pre-authorized_grant_anonymous_access_supported"]
	if !ok {
		t.Skip("pre-authorized_grant_anonymous_access_supported not present in discovery — anonymous access not enabled")
	}
	if supported, isBool := anonSupported.(bool); !isBool || !supported {
		t.Skip("pre-authorized_grant_anonymous_access_supported is false — anonymous access not enabled")
	}
}
