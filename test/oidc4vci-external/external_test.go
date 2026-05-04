// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Package oidc4vci_external_test runs OIDC4VCI e2e tests against a running
// Hydra instance (not in-process). Start Hydra with:
//
//	docker compose -f quickstart-oidc4vci.yml up --build
//
// Then run:
//
//	go test -v -count=1 -timeout=60s -run TestExternal ./test/oidc4vci-external/...
//
// Environment variables:
//
//	HYDRA_PUBLIC_URL  — default http://127.0.0.1:4444
//	HYDRA_ADMIN_URL   — default http://127.0.0.1:4445
//
// Tests are skipped if Hydra is not reachable.
package oidc4vci_external_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func publicURL() string {
	if u := os.Getenv("HYDRA_PUBLIC_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:4444"
}

func adminURL() string {
	if u := os.Getenv("HYDRA_ADMIN_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:4445"
}

func skipIfHydraDown(t *testing.T) {
	t.Helper()
	cl := &http.Client{Timeout: 2 * time.Second}
	resp, err := cl.Get(publicURL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("Hydra not reachable at %s: %v", publicURL(), err)
	}
	defer resp.Body.Close()

	// Guard against a common footgun: tests hit localhost but Hydra was
	// started with a different public URL (e.g. ngrok). Cookies and client
	// assertion audiences then silently mismatch. Fail loudly.
	var disco struct {
		Issuer string `json:"issuer"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&disco)
	if disco.Issuer != "" && !strings.HasPrefix(publicURL(), disco.Issuer) &&
		!strings.HasPrefix(disco.Issuer, publicURL()) {
		t.Fatalf("HYDRA_PUBLIC_URL (%s) does not match Hydra's advertised issuer (%s). "+
			"Export HYDRA_PUBLIC_URL to the URL Hydra was started with.",
			publicURL(), disco.Issuer)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func adminPost(t *testing.T, path string, body interface{}) map[string]interface{} {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(adminURL()+path, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &result), "body: %s", string(raw))
	return result
}

func adminPut(t *testing.T, path string, body interface{}) map[string]interface{} {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, adminURL()+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &result), "body: %s", string(raw))
	return result
}

func adminGet(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(adminURL() + path)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &result), "body: %s", string(raw))
	return result
}

func createClient(t *testing.T, redirectURI string, grantTypes []string) (clientID, clientSecret string) {
	t.Helper()
	secret := "test-secret-" + uuid.New()
	result := adminPost(t, "/admin/clients", map[string]interface{}{
		"client_secret":  secret,
		"redirect_uris":  []string{redirectURI},
		"grant_types":    grantTypes,
		"response_types": []string{"code"},
		"scope":          "openid offline",
		"token_endpoint_auth_method": "client_secret_basic",
	})
	id, ok := result["client_id"].(string)
	require.True(t, ok, "client_id missing: %v", result)
	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, adminURL()+"/admin/clients/"+id, nil)
		http.DefaultClient.Do(req) //nolint:errcheck
	})
	return id, secret
}

func buildDPoPProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: key, KeyID: "wallet-key"},
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(jose.HeaderType): "dpop+jwt",
		},
		EmbedJWK: true,
	})
	require.NoError(t, err)
	raw, err := josejwt.Signed(signer).Claims(map[string]interface{}{
		"jti": uuid.New(),
		"htm": htm,
		"htu": htu,
		"iat": josejwt.NewNumericDate(time.Now()),
	}).CompactSerialize()
	require.NoError(t, err)
	return raw
}

func introspect(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	form := url.Values{"token": {token}}
	resp, err := http.Post(adminURL()+"/admin/oauth2/introspect",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

// ── Pre-Authorized Code Tests ─────────────────────────────────────────────────

func TestExternal_PreAuthCode_HappyPath(t *testing.T) {
	skipIfHydraDown(t)

	// Create a client with the pre-authorized code grant type.
	clientID, clientSecret := createClient(t, "http://localhost:9999/callback",
		[]string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"})

	// Create a pre-authorized code via admin API.
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"client_id":                    clientID,
		"credential_configuration_ids": []string{"TestCredential_JWT"},
	})
	code, ok := codeResp["pre_authorized_code"].(string)
	require.True(t, ok, "pre_authorized_code missing: %v", codeResp)
	require.NotEmpty(t, code)
	t.Logf("Pre-authorized code: %s", code[:20]+"...")

	// Exchange the code at the token endpoint.
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
		"client_id":           {clientID},
	}
	req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &tokenResp))
	require.NotContains(t, tokenResp, "error",
		"token exchange should succeed: %s", string(raw))

	accessToken := tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)
	t.Logf("Access token: %s...", accessToken[:20])

	// Verify authorization_details in token response.
	authDetails, ok := tokenResp["authorization_details"]
	require.True(t, ok, "authorization_details must be in token response")
	adList := authDetails.([]interface{})
	require.Len(t, adList, 1)
	assert.Equal(t, "openid_credential", adList[0].(map[string]interface{})["type"])

	// Introspect.
	intro := introspect(t, accessToken)
	assert.Equal(t, true, intro["active"])
}

func TestExternal_PreAuthCode_WithTxCode(t *testing.T) {
	skipIfHydraDown(t)

	clientID, clientSecret := createClient(t, "http://localhost:9999/callback",
		[]string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"})

	txCode := "493536"
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"client_id":                    clientID,
		"credential_configuration_ids": []string{"TestCredential_JWT"},
		"tx_code":                      txCode,
		"tx_code_input_mode":           "numeric",
		"tx_code_length":               6,
	})
	_ = codeResp // Both sub-tests create fresh codes

	t.Run("case=wrong tx_code", func(t *testing.T) {
		// Need a fresh code — the handler invalidates on any redemption attempt.
		codeRespWrong := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
			"client_id":                    clientID,
			"credential_configuration_ids": []string{"TestCredential_JWT"},
			"tx_code":                      txCode,
			"tx_code_input_mode":           "numeric",
			"tx_code_length":               6,
		})
		codeWrong := codeRespWrong["pre_authorized_code"].(string)

		form := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {codeWrong},
			"tx_code":             {"000000"},
			"client_id":           {clientID},
		}
		req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		assert.Contains(t, result, "error")
	})

	t.Run("case=correct tx_code", func(t *testing.T) {
		// Need a fresh code since the previous one may have been invalidated.
		codeResp2 := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
			"client_id":                    clientID,
			"credential_configuration_ids": []string{"TestCredential_JWT"},
			"tx_code":                      txCode,
			"tx_code_input_mode":           "numeric",
			"tx_code_length":               6,
		})
		code2 := codeResp2["pre_authorized_code"].(string)

		form := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {code2},
			"tx_code":             {txCode},
			"client_id":           {clientID},
		}
		req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		require.NotContains(t, result, "error", "got: %v", result)
		assert.NotEmpty(t, result["access_token"])
	})
}

func TestExternal_PreAuthCode_SingleUse(t *testing.T) {
	skipIfHydraDown(t)

	clientID, clientSecret := createClient(t, "http://localhost:9999/callback",
		[]string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"})

	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"client_id":                    clientID,
		"credential_configuration_ids": []string{"TestCredential_JWT"},
	})
	code := codeResp["pre_authorized_code"].(string)

	exchange := func() map[string]interface{} {
		form := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {code},
			"client_id":           {clientID},
		}
		req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		return result
	}

	// First exchange succeeds.
	r1 := exchange()
	require.NotContains(t, r1, "error")

	// Second exchange fails (single-use).
	r2 := exchange()
	assert.Contains(t, r2, "error")
}

// ── Discovery Test ────────────────────────────────────────────────────────────

func TestExternal_Discovery(t *testing.T) {
	skipIfHydraDown(t)

	resp, err := http.Get(publicURL() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	var disco map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&disco))

	// Pre-authorized code grant type.
	grantTypes := disco["grant_types_supported"].([]interface{})
	grantTypeStrs := make([]string, len(grantTypes))
	for i, gt := range grantTypes {
		grantTypeStrs[i] = gt.(string)
	}
	assert.Contains(t, grantTypeStrs, "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	assert.Contains(t, grantTypeStrs, "authorization_code")

	// DPoP.
	dpopAlgs, ok := disco["dpop_signing_alg_values_supported"]
	assert.True(t, ok, "dpop_signing_alg_values_supported must be present")
	if ok {
		assert.Contains(t, dpopAlgs.([]interface{}), "ES256")
	}

	// PAR endpoint.
	parEndpoint, ok := disco["pushed_authorization_request_endpoint"]
	if ok {
		assert.Contains(t, parEndpoint.(string), "/oauth2/par")
	}

	t.Logf("Discovery: grant_types=%v, dpop_algs=%v", grantTypeStrs, dpopAlgs)
}

// ── PAR + DPoP + Consent Emulation Test ───────────────────────────────────────

// extractQueryParam extracts a query parameter from a URL string.
func extractQueryParam(rawURL, param string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(param)
}

// noRedirectClient returns an HTTP client with cookie jar that stops at redirects.
func noRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestExternal_PAR_DPoP_ConsentViaAdminAPI(t *testing.T) {
	skipIfHydraDown(t)

	clientID, clientSecret := createClient(t, "http://127.0.0.1:9999/callback",
		[]string{"authorization_code", "refresh_token"})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	state := "state-" + uuid.New()

	// ── Step 1: PAR ───────────────────────────────────────────────────────────
	t.Log("Step 1: Pushed Authorization Request")

	parForm := url.Values{
		"client_id":             {clientID},
		"response_type":        {"code"},
		"redirect_uri":         {"http://127.0.0.1:9999/callback"},
		"scope":                {"openid offline"},
		"state":                {state},
		"code_challenge":       {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	dpopProofPAR := buildDPoPProof(t, dpopKey, "POST", publicURL()+"/oauth2/par")
	parReq, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/par",
		strings.NewReader(parForm.Encode()))
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.Header.Set("DPoP", dpopProofPAR)
	parReq.SetBasicAuth(clientID, clientSecret)

	parResp, err := http.DefaultClient.Do(parReq)
	require.NoError(t, err)
	defer parResp.Body.Close()
	parBody, _ := io.ReadAll(parResp.Body)
	require.Equal(t, 201, parResp.StatusCode, "PAR failed: %s", string(parBody))

	// Capture DPoP-Nonce from PAR response for use in token request.
	dpopNonce := parResp.Header.Get("DPoP-Nonce")
	if dpopNonce != "" {
		t.Logf("  DPoP-Nonce from PAR: %s", dpopNonce)
	}

	var parResult struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(parBody, &parResult))
	require.NotEmpty(t, parResult.RequestURI)
	t.Logf("  request_uri: %s", parResult.RequestURI)

	// ── Step 2: Initiate authorization → extract login_challenge ──────────────
	t.Log("Step 2: Initiate authorization, extract login_challenge")

	cl := noRedirectClient(t)
	authURL := fmt.Sprintf("%s/oauth2/auth?client_id=%s&request_uri=%s",
		publicURL(), clientID, url.QueryEscape(parResult.RequestURI))

	authResp, err := cl.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Equal(t, http.StatusFound, authResp.StatusCode, "expected redirect to login")

	loginRedirect, err := authResp.Location()
	require.NoError(t, err)
	loginChallenge := loginRedirect.Query().Get("login_challenge")
	require.NotEmpty(t, loginChallenge, "login_challenge missing from redirect: %s", loginRedirect)
	t.Logf("  login_challenge: %s", loginChallenge[:40]+"...")

	// ── Step 3: Accept login via admin API ────────────────────────────────────
	t.Log("Step 3: Accept login via admin API")

	loginAcceptResp := adminPut(t,
		"/admin/oauth2/auth/requests/login/accept?login_challenge="+url.QueryEscape(loginChallenge),
		map[string]interface{}{
			"subject":     "test-user",
			"remember":    false,
		})
	loginRedirectTo, ok := loginAcceptResp["redirect_to"].(string)
	require.True(t, ok, "redirect_to missing from login accept: %v", loginAcceptResp)
	t.Logf("  login redirect_to: %s", loginRedirectTo[:80]+"...")

	// ── Step 4: Follow login redirect → extract consent_challenge ─────────────
	t.Log("Step 4: Follow login redirect, extract consent_challenge")

	consentRedirectResp, err := cl.Get(loginRedirectTo)
	require.NoError(t, err)
	defer consentRedirectResp.Body.Close()
	require.True(t,
		consentRedirectResp.StatusCode == http.StatusFound || consentRedirectResp.StatusCode == http.StatusSeeOther,
		"expected redirect to consent, got %d", consentRedirectResp.StatusCode)

	consentRedirect, err := consentRedirectResp.Location()
	require.NoError(t, err)
	consentChallenge := consentRedirect.Query().Get("consent_challenge")
	require.NotEmpty(t, consentChallenge, "consent_challenge missing from redirect: %s", consentRedirect)
	t.Logf("  consent_challenge: %s", consentChallenge[:40]+"...")

	// ── Step 5: Accept consent via admin API ──────────────────────────────────
	t.Log("Step 5: Accept consent via admin API")

	consentAcceptResp := adminPut(t,
		"/admin/oauth2/auth/requests/consent/accept?consent_challenge="+url.QueryEscape(consentChallenge),
		map[string]interface{}{
			"grant_scope":                []string{"openid", "offline"},
			"grant_access_token_audience": []string{},
			"remember":                   false,
			"session": map[string]interface{}{
				"access_token": map[string]interface{}{},
				"id_token":     map[string]interface{}{},
			},
		})
	consentRedirectTo, ok := consentAcceptResp["redirect_to"].(string)
	require.True(t, ok, "redirect_to missing from consent accept: %v", consentAcceptResp)
	t.Logf("  consent redirect_to: %s", consentRedirectTo[:80]+"...")

	// ── Step 6: Follow consent redirect → extract authorization code ──────────
	t.Log("Step 6: Follow consent redirect, extract authorization code")

	codeRedirectResp, err := cl.Get(consentRedirectTo)
	require.NoError(t, err)
	defer codeRedirectResp.Body.Close()

	// Capture DPoP-Nonce from consent redirect response.
	if n := codeRedirectResp.Header.Get("DPoP-Nonce"); n != "" && dpopNonce == "" {
		dpopNonce = n
		t.Logf("  DPoP-Nonce from consent redirect: %s", dpopNonce)
	}
	require.True(t,
		codeRedirectResp.StatusCode == http.StatusFound || codeRedirectResp.StatusCode == http.StatusSeeOther,
		"expected redirect to callback, got %d", codeRedirectResp.StatusCode)

	callbackLoc, err := codeRedirectResp.Location()
	require.NoError(t, err)
	authCode := callbackLoc.Query().Get("code")
	require.NotEmpty(t, authCode, "code missing from callback: %s", callbackLoc)
	assert.Equal(t, state, callbackLoc.Query().Get("state"))
	t.Logf("  authorization code: %s...", authCode[:20])

	// Capture DPoP-Nonce from any response in the chain.
	if n := codeRedirectResp.Header.Get("DPoP-Nonce"); n != "" && dpopNonce == "" {
		dpopNonce = n
		t.Logf("  DPoP-Nonce from auth redirect: %s", dpopNonce)
	}

	// ── Step 7: Token exchange with DPoP ──────────────────────────────────────
	t.Log("Step 7: Token exchange with DPoP proof")

	// When DPoP nonces are enabled, the server returns use_dpop_nonce with a
	// DPoP-Nonce header BEFORE consuming the auth code (early validation).
	// The client retries with the nonce included in the DPoP proof.
	var dpopProofToken string
	if dpopNonce != "" {
		t.Logf("  Using DPoP nonce from prior response: %s", dpopNonce)
		dpopProofToken = buildDPoPProofWithNonce(t, dpopKey, "POST", publicURL()+"/oauth2/token", dpopNonce)
	} else {
		dpopProofToken = buildDPoPProof(t, dpopKey, "POST", publicURL()+"/oauth2/token")
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"code_verifier": {codeVerifier},
		"client_id":     {clientID},
	}

	tokenReq, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
		strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("DPoP", dpopProofToken)
	tokenReq.SetBasicAuth(clientID, clientSecret)

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	tokenBody, _ := io.ReadAll(tokenResp.Body)

	var tokenResult map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))

	// Handle use_dpop_nonce: the early validation returns this error with a
	// DPoP-Nonce header WITHOUT consuming the auth code, so retry is safe.
	if tokenResp.StatusCode != http.StatusOK {
		if errCode, _ := tokenResult["error"].(string); errCode == "use_dpop_nonce" {
			retryNonce := tokenResp.Header.Get("DPoP-Nonce")
			require.NotEmpty(t, retryNonce, "DPoP-Nonce header missing on use_dpop_nonce error")
			t.Logf("  Got use_dpop_nonce, retrying with nonce: %s", retryNonce)

			dpopProofRetry := buildDPoPProofWithNonce(t, dpopKey, "POST", publicURL()+"/oauth2/token", retryNonce)
			retryReq, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
				strings.NewReader(tokenForm.Encode()))
			retryReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			retryReq.Header.Set("DPoP", dpopProofRetry)
			retryReq.SetBasicAuth(clientID, clientSecret)

			retryResp, err := http.DefaultClient.Do(retryReq)
			require.NoError(t, err)
			defer retryResp.Body.Close()
			tokenBody, _ = io.ReadAll(retryResp.Body)
			require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))
			require.Equal(t, http.StatusOK, retryResp.StatusCode,
				"retry should succeed: %s", string(tokenBody))
		} else {
			require.Failf(t, "token exchange failed", "status=%d body=%s", tokenResp.StatusCode, string(tokenBody))
		}
	}

	// The response may contain a residual "error" field from DPoP nonce
	// handling alongside the access_token. Check for access_token presence
	// as the success indicator.
	accessToken := tokenResult["access_token"].(string)
	require.NotEmpty(t, accessToken)
	tokenType := tokenResult["token_type"].(string)
	assert.Equal(t, "DPoP", tokenType, "token_type must be DPoP")
	t.Logf("  access_token: %s...", accessToken[:20])
	t.Logf("  token_type: %s", tokenType)

	// ── Step 8: Introspect — verify cnf.jkt ───────────────────────────────────
	t.Log("Step 8: Introspect token, verify cnf.jkt")

	intro := introspect(t, accessToken)
	assert.Equal(t, true, intro["active"])
	assert.Equal(t, "test-user", intro["sub"])

	ext, ok := intro["ext"].(map[string]interface{})
	require.True(t, ok, "ext missing from introspection")
	cnf, ok := ext["cnf"].(map[string]interface{})
	require.True(t, ok, "cnf missing from ext — DPoP binding not stored")
	jkt, ok := cnf["jkt"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, jkt, "cnf.jkt must be non-empty")
	t.Logf("  cnf.jkt: %s", jkt)

	t.Log("All steps passed.")
}

// buildDPoPProofWithNonce builds a DPoP proof JWT that includes a nonce claim.
func buildDPoPProofWithNonce(t *testing.T, key *ecdsa.PrivateKey, htm, htu, nonce string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: key, KeyID: "wallet-key"},
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(jose.HeaderType): "dpop+jwt",
		},
		EmbedJWK: true,
	})
	require.NoError(t, err)
	raw, err := josejwt.Signed(signer).Claims(map[string]interface{}{
		"jti":   uuid.New(),
		"htm":   htm,
		"htu":   htu,
		"iat":   josejwt.NewNumericDate(time.Now()),
		"nonce": nonce,
	}).CompactSerialize()
	require.NoError(t, err)
	return raw
}

// ── Pre-Authorized Code with session_extra Test ───────────────────────────────

// TestExternal_PreAuthCode_SessionExtra verifies that extra claims passed via
// session_extra in the admin API request are embedded in the pre-authorized
// code session and propagated to the access token. After token exchange, the
// claims must appear in the introspection response under the `ext` field.
//
// This validates the feature added in BAC-343: Credential Issuers can pass
// correlation identifiers (e.g., offer_id) through the token lifecycle.
func TestExternal_PreAuthCode_SessionExtra(t *testing.T) {
	skipIfHydraDown(t)

	clientID, clientSecret := createClient(t, "http://localhost:9999/callback",
		[]string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"})

	offerID := uuid.New()
	correlationTag := "session-extra-test-" + uuid.New()

	// Create a pre-authorized code with session_extra containing offer_id
	// and an arbitrary correlation tag.
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"client_id":                    clientID,
		"credential_configuration_ids": []string{"TestCredential_JWT"},
		"session_extra": map[string]interface{}{
			"offer_id":        offerID,
			"correlation_tag": correlationTag,
		},
	})
	code, ok := codeResp["pre_authorized_code"].(string)
	require.True(t, ok, "pre_authorized_code missing: %v", codeResp)
	require.NotEmpty(t, code)
	t.Logf("Pre-authorized code (with session_extra): %s...", code[:20])

	// Exchange the code at the token endpoint.
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
		"client_id":           {clientID},
	}
	req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &tokenResp))
	require.NotContains(t, tokenResp, "error",
		"token exchange should succeed: %s", string(raw))

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok, "access_token missing from response")
	require.NotEmpty(t, accessToken)
	t.Logf("Access token: %s...", accessToken[:20])

	// Introspect the token and verify session_extra claims appear in ext.
	intro := introspect(t, accessToken)
	assert.Equal(t, true, intro["active"])

	ext, ok := intro["ext"].(map[string]interface{})
	require.True(t, ok, "ext missing from introspection response: %v", intro)

	// Verify offer_id is present and matches.
	gotOfferID, ok := ext["offer_id"]
	require.True(t, ok, "offer_id missing from ext: %v", ext)
	assert.Equal(t, offerID, gotOfferID, "offer_id should match the value set in session_extra")
	t.Logf("  ext.offer_id: %v", gotOfferID)

	// Verify correlation_tag is present and matches.
	gotTag, ok := ext["correlation_tag"]
	require.True(t, ok, "correlation_tag missing from ext: %v", ext)
	assert.Equal(t, correlationTag, gotTag, "correlation_tag should match the value set in session_extra")
	t.Logf("  ext.correlation_tag: %v", gotTag)

	// authorization_details should also be present (set by the preauth handler).
	_, adExists := ext["authorization_details"]
	assert.True(t, adExists, "authorization_details should be present in ext")

	t.Log("session_extra claims propagated successfully through token exchange.")
}

// TestExternal_PreAuthCode_SessionExtraEmpty verifies that omitting session_extra
// (or passing an empty map) does not break the existing flow — the token exchange
// still succeeds and introspection returns a valid ext without the extra fields.
func TestExternal_PreAuthCode_SessionExtraEmpty(t *testing.T) {
	skipIfHydraDown(t)

	clientID, clientSecret := createClient(t, "http://localhost:9999/callback",
		[]string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"})

	// Create a pre-authorized code WITHOUT session_extra.
	codeResp := adminPost(t, "/admin/oauth2/preauth", map[string]interface{}{
		"client_id":                    clientID,
		"credential_configuration_ids": []string{"TestCredential_JWT"},
	})
	code, ok := codeResp["pre_authorized_code"].(string)
	require.True(t, ok, "pre_authorized_code missing: %v", codeResp)

	// Exchange the code.
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
		"client_id":           {clientID},
	}
	req, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var tokenResp map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &tokenResp))
	require.NotContains(t, tokenResp, "error",
		"token exchange should succeed without session_extra: %s", string(raw))

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)

	// Introspect — ext should exist (authorization_details) but no offer_id.
	intro := introspect(t, accessToken)
	assert.Equal(t, true, intro["active"])

	ext, ok := intro["ext"].(map[string]interface{})
	if ok {
		_, hasOfferID := ext["offer_id"]
		assert.False(t, hasOfferID, "offer_id should NOT be present when session_extra is omitted")
	}

	t.Log("Empty session_extra: token exchange succeeded without extra claims in ext.")
}
