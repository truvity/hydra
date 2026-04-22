// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc4vci_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/x/configx"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func walletKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func walletJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padLeft(pub.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padLeft(pub.Y.Bytes(), 32)),
	}
}

func signES256JWT(t *testing.T, header, payload map[string]interface{}, key *ecdsa.PrivateKey) string {
	t.Helper()
	hBytes, err := json.Marshal(header)
	require.NoError(t, err)
	pBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." +
		base64.RawURLEncoding.EncodeToString(pBytes)

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)

	rb := padLeft(r.Bytes(), 32)
	sb := padLeft(s.Bytes(), 32)
	sigBytes := append(rb, sb...) //nolint:gocritic
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
}

func buildProofJWT(t *testing.T, key *ecdsa.PrivateKey, audience, nonce string) string {
	t.Helper()
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"jwk": walletJWK(&key.PublicKey),
	}
	payload := map[string]interface{}{
		"aud":   audience,
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	}
	return signES256JWT(t, header, payload, key)
}

// ── Hydra setup ───────────────────────────────────────────────────────────────

func setupHydra(t *testing.T) (publicURL, adminURL string) {
	t.Helper()
	ctx := t.Context()

	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(
		configx.WithValue(config.KeyPreAuthorizedCodeEnabled, true),
		configx.WithValue(config.KeyPreAuthorizedCodeAnonymousAccess, true),
		configx.WithValue(config.KeyAccessTokenLifespan, time.Hour),
	))

	publicTS, adminTS := testhelpers.NewConfigurableOAuth2Server(ctx, t, reg)

	// Register a test client for pre-authorized code binding.
	// Even with anonymous access enabled, binding to a client avoids FK issues
	// in the access token table.
	err := reg.ClientManager().CreateClient(ctx, &client.Client{
		ID:            "test-wallet",
		Secret:        "test-secret",
		GrantTypes:    []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		ResponseTypes: []string{"token"},
		Scope:         "openid offline",
	})
	require.NoError(t, err)

	return publicTS.URL, adminTS.URL
}

// ── Admin API helpers ─────────────────────────────────────────────────────────

func createPreAuthCode(t *testing.T, adminURL string, configIDs []string, scope, txCode string) (code, expiresAt string) {
	t.Helper()

	payload := map[string]interface{}{
		"credential_configuration_ids": configIDs,
		"client_id":                    "test-wallet",
	}
	if scope != "" {
		payload["scope"] = scope
	}
	if txCode != "" {
		payload["tx_code"] = txCode
		payload["tx_code_input_mode"] = "numeric"
		payload["tx_code_length"] = len(txCode)
	}

	body, err := json.Marshal(payload)
	require.NoError(t, err)

	resp, err := http.Post(adminURL+"/admin/oauth2/preauth", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create preauth failed: %s", string(respBody))

	var result struct {
		PreAuthorizedCode string `json:"pre_authorized_code"`
		ExpiresAt         string `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(respBody, &result))
	require.NotEmpty(t, result.PreAuthorizedCode)
	require.NotEmpty(t, result.ExpiresAt)
	return result.PreAuthorizedCode, result.ExpiresAt
}

func exchangePreAuthCode(t *testing.T, publicURL, code, txCode string) map[string]interface{} {
	t.Helper()

	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
		"client_id":           {"test-wallet"},
	}
	if txCode != "" {
		form.Set("tx_code", txCode)
	}

	req, err := http.NewRequest(http.MethodPost, publicURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-wallet", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

func exchangePreAuthCodeWithAuthDetails(t *testing.T, publicURL, code, authDetailsJSON string) map[string]interface{} {
	t.Helper()

	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code":   {code},
		"client_id":             {"test-wallet"},
		"authorization_details": {authDetailsJSON},
	}

	req, err := http.NewRequest(http.MethodPost, publicURL+"/oauth2/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("test-wallet", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

func introspectToken(t *testing.T, adminURL, token string) map[string]interface{} {
	t.Helper()

	form := url.Values{"token": {token}}
	resp, err := http.Post(adminURL+"/admin/oauth2/introspect", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

// ── Mock Issuer (in-process) ──────────────────────────────────────────────────

func mockIssuerServer(t *testing.T, hydraPublicURL, hydraAdminURL string) *httptest.Server {
	t.Helper()

	type storedNonce struct {
		value     string
		expiresAt time.Time
	}
	nonces := make(map[string]*storedNonce)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var issuerURL string

	mux.HandleFunc("GET /.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"credential_issuer":   issuerURL,
			"credential_endpoint": issuerURL + "/credential",
			"nonce_endpoint":      issuerURL + "/nonce",
			"authorization_servers": []string{hydraPublicURL},
			"credential_configurations_supported": map[string]interface{}{
				"TestCredential_JWT": map[string]interface{}{
					"format": "vc+sd-jwt",
					"vct":    "TestCredential",
					"cryptographic_binding_methods_supported": []string{"jwk"},
					"credential_signing_alg_values_supported": []string{"ES256"},
					"proof_types_supported": map[string]interface{}{
						"jwt": map[string]interface{}{
							"proof_signing_alg_values_supported": []string{"ES256"},
						},
					},
				},
			},
		})
	})

	mux.HandleFunc("POST /nonce", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		n := &storedNonce{
			value:     base64.RawURLEncoding.EncodeToString(b),
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		nonces[n.value] = n
		writeJSON(w, 200, map[string]interface{}{
			"c_nonce":            n.value,
			"c_nonce_expires_in": 300,
		})
	})

	mux.HandleFunc("POST /credential", func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract bearer token
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") && !strings.HasPrefix(auth, "bearer ") {
			writeJSONErr(w, 401, "invalid_token", "missing bearer token")
			return
		}
		token := auth[7:]

		// 2. Introspect via Hydra
		introResp := doIntrospect(r.Context(), hydraAdminURL, token)
		if introResp == nil || introResp["active"] != true {
			writeJSONErr(w, 401, "invalid_token", "token not active")
			return
		}

		// 3. Parse request
		var req struct {
			CredentialConfigurationID string                 `json:"credential_configuration_id"`
			Proofs                    map[string]interface{} `json:"proofs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONErr(w, 400, "invalid_request", "invalid JSON")
			return
		}

		// 4. Validate proof JWT (minimal: extract and consume nonce)
		proofJWT := extractProofJWT(req.Proofs)
		if proofJWT == "" {
			writeJSONErr(w, 400, "invalid_or_missing_proof", "jwt proof required")
			return
		}
		parts := strings.Split(proofJWT, ".")
		if len(parts) != 3 {
			writeJSONErr(w, 400, "invalid_or_missing_proof", "invalid JWT")
			return
		}
		payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]interface{}
		_ = json.Unmarshal(payloadBytes, &claims)
		nonceVal, _ := claims["nonce"].(string)
		if nonceVal == "" {
			writeJSONErr(w, 400, "invalid_or_missing_proof", "nonce required")
			return
		}
		n, exists := nonces[nonceVal]
		if !exists || time.Now().After(n.expiresAt) {
			writeJSONErr(w, 400, "invalid_or_missing_proof", "nonce invalid or expired")
			return
		}
		delete(nonces, nonceVal)

		// 5. Sign stub SD-JWT VC
		sub, _ := introResp["sub"].(string)
		credential := signStubSDJWTVC(issuerKey, issuerURL, sub, "TestCredential")

		// 6. Fresh nonce
		freshB := make([]byte, 32)
		_, _ = rand.Read(freshB)
		fn := &storedNonce{
			value:     base64.RawURLEncoding.EncodeToString(freshB),
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		nonces[fn.value] = fn

		writeJSON(w, 200, map[string]interface{}{
			"credentials": []map[string]interface{}{
				{"credential": credential},
			},
			"c_nonce":            fn.value,
			"c_nonce_expires_in": 300,
		})
	})

	ts := httptest.NewServer(mux)
	issuerURL = ts.URL
	t.Cleanup(ts.Close)
	return ts
}

func extractProofJWT(proofs map[string]interface{}) string {
	jwtProofs, ok := proofs["jwt"]
	if !ok {
		return ""
	}
	switch v := jwtProofs.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			s, _ := v[0].(string)
			return s
		}
	}
	return ""
}

func doIntrospect(ctx context.Context, adminURL, token string) map[string]interface{} {
	form := url.Values{"token": {token}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, adminURL+"/admin/oauth2/introspect",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func signStubSDJWTVC(key *ecdsa.PrivateKey, issuer, subject, vct string) string {
	header := map[string]interface{}{"alg": "ES256", "typ": "vc+sd-jwt"}
	payload := map[string]interface{}{
		"iss": issuer, "sub": subject, "iat": time.Now().Unix(), "vct": vct,
	}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." +
		base64.RawURLEncoding.EncodeToString(pBytes)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
	rb := padLeft(r.Bytes(), 32)
	sb := padLeft(s.Bytes(), 32)
	sigBytes := append(rb, sb...) //nolint:gocritic
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes) + "~"
}

// ── E2E Tests ─────────────────────────────────────────────────────────────────

func TestPreAuthorizedCodeFlow_HappyPath(t *testing.T) {
	t.Parallel()

	publicURL, adminURL := setupHydra(t)
	issuerTS := mockIssuerServer(t, publicURL, adminURL)

	// Step 1: Credential Issuer creates a pre-authorized code via Hydra admin API.
	code, expiresAt := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", "")
	require.NotEmpty(t, code)
	require.NotEmpty(t, expiresAt)

	// Step 2: Wallet exchanges the pre-authorized code at the token endpoint.
	tokenResp := exchangePreAuthCode(t, publicURL, code, "")
	require.NotContains(t, tokenResp, "error", "token exchange failed: %v", tokenResp)

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)

	// Verify authorization_details in token response.
	authDetails, ok := tokenResp["authorization_details"]
	require.True(t, ok, "token response must contain authorization_details")
	adList, ok := authDetails.([]interface{})
	require.True(t, ok)
	require.Len(t, adList, 1)
	ad0 := adList[0].(map[string]interface{})
	assert.Equal(t, "openid_credential", ad0["type"])
	assert.Equal(t, "TestCredential_JWT", ad0["credential_configuration_id"])

	// Step 3: Introspect the token.
	introResp := introspectToken(t, adminURL, accessToken)
	assert.Equal(t, true, introResp["active"])

	// Step 4: Wallet fetches issuer metadata.
	metaResp, err := http.Get(issuerTS.URL + "/.well-known/openid-credential-issuer")
	require.NoError(t, err)
	defer metaResp.Body.Close()
	require.Equal(t, http.StatusOK, metaResp.StatusCode)

	var metadata map[string]interface{}
	require.NoError(t, json.NewDecoder(metaResp.Body).Decode(&metadata))
	assert.Equal(t, issuerTS.URL, metadata["credential_issuer"])

	// Step 5: Wallet requests a nonce.
	nonceResp, err := http.Post(issuerTS.URL+"/nonce", "application/json", nil)
	require.NoError(t, err)
	defer nonceResp.Body.Close()
	require.Equal(t, http.StatusOK, nonceResp.StatusCode)

	var nonceData map[string]interface{}
	require.NoError(t, json.NewDecoder(nonceResp.Body).Decode(&nonceData))
	cNonce, ok := nonceData["c_nonce"].(string)
	require.True(t, ok)
	require.NotEmpty(t, cNonce)

	// Step 6: Wallet builds proof JWT and requests credential.
	wKey := walletKey(t)
	proofJWT := buildProofJWT(t, wKey, issuerTS.URL, cNonce)

	credReqBody, _ := json.Marshal(map[string]interface{}{
		"credential_configuration_id": "TestCredential_JWT",
		"proofs":                      map[string]interface{}{"jwt": []string{proofJWT}},
	})
	credReq, _ := http.NewRequest(http.MethodPost, issuerTS.URL+"/credential", bytes.NewReader(credReqBody))
	credReq.Header.Set("Content-Type", "application/json")
	credReq.Header.Set("Authorization", "Bearer "+accessToken)

	credResp, err := http.DefaultClient.Do(credReq)
	require.NoError(t, err)
	defer credResp.Body.Close()
	require.Equal(t, http.StatusOK, credResp.StatusCode)

	var credData map[string]interface{}
	require.NoError(t, json.NewDecoder(credResp.Body).Decode(&credData))
	credentials := credData["credentials"].([]interface{})
	require.Len(t, credentials, 1)
	credStr := credentials[0].(map[string]interface{})["credential"].(string)
	require.NotEmpty(t, credStr)

	// SD-JWT VC ends with ~
	assert.True(t, strings.HasSuffix(credStr, "~"))
	jwtPart := strings.TrimSuffix(credStr, "~")
	assert.Len(t, strings.Split(jwtPart, "."), 3)

	// Fresh nonce returned
	freshNonce := credData["c_nonce"].(string)
	assert.NotEmpty(t, freshNonce)
	assert.NotEqual(t, cNonce, freshNonce)
}

func TestPreAuthorizedCodeFlow_WithTxCode(t *testing.T) {
	t.Parallel()
	publicURL, adminURL := setupHydra(t)
	txCode := "493536"

	t.Run("case=missing tx_code when required", func(t *testing.T) {
		code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", txCode)
		tokenResp := exchangePreAuthCode(t, publicURL, code, "")
		assert.Contains(t, tokenResp, "error")
	})

	t.Run("case=wrong tx_code", func(t *testing.T) {
		code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", txCode)
		tokenResp := exchangePreAuthCode(t, publicURL, code, "999999")
		assert.Contains(t, tokenResp, "error")
	})

	t.Run("case=correct tx_code succeeds", func(t *testing.T) {
		code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", txCode)
		tokenResp := exchangePreAuthCode(t, publicURL, code, txCode)
		require.NotContains(t, tokenResp, "error", "got: %v", tokenResp)
		require.NotEmpty(t, tokenResp["access_token"])
	})
}

func TestPreAuthorizedCodeFlow_SingleUse(t *testing.T) {
	t.Parallel()
	publicURL, adminURL := setupHydra(t)

	code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", "")

	// First exchange succeeds.
	tokenResp := exchangePreAuthCode(t, publicURL, code, "")
	require.NotContains(t, tokenResp, "error")
	require.NotEmpty(t, tokenResp["access_token"])

	// Second exchange fails (single-use).
	tokenResp2 := exchangePreAuthCode(t, publicURL, code, "")
	assert.Contains(t, tokenResp2, "error")
}

func TestPreAuthorizedCodeFlow_InvalidCode(t *testing.T) {
	t.Parallel()
	publicURL, _ := setupHydra(t)

	tokenResp := exchangePreAuthCode(t, publicURL, "totally-invalid-code", "")
	assert.Contains(t, tokenResp, "error")
}

func TestPreAuthorizedCodeFlow_MissingCode(t *testing.T) {
	t.Parallel()
	publicURL, _ := setupHydra(t)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
	}
	resp, err := http.Post(publicURL+"/oauth2/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Contains(t, result, "error")
}

func TestPreAuthorizedCodeFlow_MultipleCredentialConfigs(t *testing.T) {
	t.Parallel()
	publicURL, adminURL := setupHydra(t)

	code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT", "DriverLicense_JWT"}, "", "")
	tokenResp := exchangePreAuthCode(t, publicURL, code, "")
	require.NotContains(t, tokenResp, "error")

	authDetails := tokenResp["authorization_details"].([]interface{})
	require.Len(t, authDetails, 2)

	ids := make([]string, 0, 2)
	for _, ad := range authDetails {
		m := ad.(map[string]interface{})
		assert.Equal(t, "openid_credential", m["type"])
		ids = append(ids, m["credential_configuration_id"].(string))
	}
	assert.Contains(t, ids, "TestCredential_JWT")
	assert.Contains(t, ids, "DriverLicense_JWT")
}

func TestPreAuthorizedCodeFlow_AuthorizationDetailsSubset(t *testing.T) {
	t.Parallel()
	publicURL, adminURL := setupHydra(t)

	code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT", "DriverLicense_JWT"}, "", "")
	tokenResp := exchangePreAuthCodeWithAuthDetails(t, publicURL, code,
		`[{"type":"openid_credential","credential_configuration_id":"TestCredential_JWT"}]`)
	require.NotContains(t, tokenResp, "error", "got: %v", tokenResp)

	authDetails := tokenResp["authorization_details"].([]interface{})
	require.Len(t, authDetails, 1)
	assert.Equal(t, "TestCredential_JWT", authDetails[0].(map[string]interface{})["credential_configuration_id"])
}

func TestPreAuthorizedCodeFlow_UnauthorizedConfigID(t *testing.T) {
	t.Parallel()
	publicURL, adminURL := setupHydra(t)

	code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", "")
	tokenResp := exchangePreAuthCodeWithAuthDetails(t, publicURL, code,
		`[{"type":"openid_credential","credential_configuration_id":"NotAuthorized_JWT"}]`)
	assert.Contains(t, tokenResp, "error")
}

func TestPreAuthorizedCodeFlow_DiscoveryMetadata(t *testing.T) {
	t.Parallel()
	publicURL, _ := setupHydra(t)

	resp, err := http.Get(publicURL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var disco map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&disco))

	// Pre-authorized code grant type advertised.
	grantTypes := disco["grant_types_supported"].([]interface{})
	found := false
	for _, gt := range grantTypes {
		if gt == "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
			found = true
			break
		}
	}
	assert.True(t, found, "discovery must advertise pre-authorized_code grant type")

	// Anonymous access advertised.
	assert.Equal(t, true, disco["pre-authorized_grant_anonymous_access_supported"])
}

func TestPreAuthorizedCodeFlow_ExpiryInFuture(t *testing.T) {
	t.Parallel()
	_, adminURL := setupHydra(t)

	_, expiresAt := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", "")
	expiry, err := time.Parse(time.RFC3339, expiresAt)
	require.NoError(t, err)
	assert.True(t, expiry.After(time.Now()), "expiry must be in the future")
}

func TestPreAuthorizedCodeFlow_TxCodeNotExpectedButProvided(t *testing.T) {
	t.Parallel()
	publicURL, adminURL := setupHydra(t)

	// Create code WITHOUT tx_code.
	code, _ := createPreAuthCode(t, adminURL, []string{"TestCredential_JWT"}, "", "")

	// Exchange WITH tx_code — should fail.
	tokenResp := exchangePreAuthCode(t, publicURL, code, "unexpected-pin")
	assert.Contains(t, tokenResp, "error",
		"providing tx_code when not expected should fail, got: %v", tokenResp)
	assert.Equal(t, "invalid_request", fmt.Sprintf("%v", tokenResp["error"]))
}
