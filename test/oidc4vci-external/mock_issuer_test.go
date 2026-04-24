// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc4vci_external_test

// End-to-end OIDC4VCI tests against the quickstart-oidc4vci.yml stack:
// Hydra (authorization server) + mock-issuer (credential issuer).
//
// Running:
//   ./build-and-run-oidc4vci-local.sh
//   go test -v -count=1 -timeout=60s \
//     -run TestExternal_MockIssuer ./test/oidc4vci-external/...
//
// Test artifacts (clients, credential configurations, authorization requests)
// are cached under ./testdata/ across runs. Set REFRESH_TESTDATA=1 to force
// regeneration. Cached clients that no longer exist in Hydra (e.g. after a
// `docker compose down -v`) are detected and re-created automatically.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCredentialConfigID = "TestCredential_JWT"
	testCallbackURI        = "http://127.0.0.1:9999/callback"
	// conformanceCallbackURI is the OpenID Certification conformance suite
	// redirect target, included so cached clients can also run against the
	// hosted test harness at certification.openid.net.
	conformanceCallbackURI       = "https://www.certification.openid.net/test/a/uniquealias1337/callback"
	testSubject                  = "test-user-e2e"
	clientAName                  = "client_a"
	clientBName                  = "client_b"
	credentialConfigArtifact     = "credential_config"
	authorizationRequestArtifact = "authorization_request"

	// Wallet-attestation clients for HAIP conformance. The client_id MUST
	// equal the `sub` claim of the Client Attestation JWT the attester
	// signs, so we pin it explicitly here.
	clientAttesterAName = "client_attester_a"
	clientAttesterAID   = "haip-wallet-attester-a"
	clientAttesterBName = "client_attester_b"
	clientAttesterBID   = "haip-wallet-attester-b"
)

// TestExternal_MockIssuer_AuthCode_DPoP_PAR exercises the full end-to-end
// OIDC4VCI flow against Hydra + mock-issuer:
//
//  1. Load/create two long-lived clients (private_key_jwt + ES256).
//  2. Load/create a mock-issuer credential configuration.
//  3. PAR with the first client (with authorization_details for RAR).
//  4. Emulated login + consent via Hydra admin API.
//  5. Token exchange with DPoP and a signed client_assertion.
//  6. Request a nonce from the mock-issuer.
//  7. Build a proof JWT bound to the DPoP key, request a credential.
//  8. Assert the credential is a well-formed SD-JWT VC.
func TestExternal_MockIssuer_AuthCode_DPoP_PAR(t *testing.T) {
	skipIfHydraDown(t)
	skipIfMockIssuerDown(t)

	// ── cached artifacts ──────────────────────────────────────────────────────
	grantTypes := []string{"authorization_code", "refresh_token"}
	redirectURIs := []string{testCallbackURI, conformanceCallbackURI}
	clientA := loadOrCreateClient(t, clientAName, redirectURIs, grantTypes)
	// Second client is created on demand so it exists for downstream tests
	// that may want to use it — the main flow uses clientA.
	_ = loadOrCreateClient(t, clientBName, redirectURIs, grantTypes)

	// Two wallet-attestation clients are also provisioned so the HAIP
	// conformance harness can authenticate against them. The main flow in
	// this test doesn't use them.
	_ = loadOrCreateAttesterClient(t, clientAttesterAName, clientAttesterAID, redirectURIs, grantTypes)
	_ = loadOrCreateAttesterClient(t, clientAttesterBName, clientAttesterBID, redirectURIs, grantTypes)

	credConfig := loadOrCreateCredentialConfig(t, credentialConfigArtifact, testCredentialConfigID)
	t.Logf("using client=%s, credential_config=%s", clientA.ClientID, credConfig.ID)

	// ── 1. PAR ────────────────────────────────────────────────────────────────
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	state := "state-" + uuid.New()

	authDetails := fmt.Sprintf(
		`[{"type":"openid_credential","credential_configuration_id":%q}]`,
		credConfig.ID)

	parForm := url.Values{
		"client_id":             {clientA.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {testCallbackURI},
		"scope":                 {clientA.Scope},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"authorization_details": {authDetails},
		// private_key_jwt assertion. Per RFC 7523 §3, the `aud` of a client
		// assertion must identify the authorization server — Hydra pins it to
		// the token endpoint URL for every request that authenticates the
		// client, including PAR.
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signClientAssertion(t, clientA, publicURL()+"/oauth2/token")},
	}

	parReq, _ := http.NewRequest(http.MethodPost, publicURL()+"/oauth2/par",
		strings.NewReader(parForm.Encode()))
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.Header.Set("DPoP", newDPoPProof(t, clientA, "POST", publicURL()+"/oauth2/par", ""))

	parResp, err := http.DefaultClient.Do(parReq)
	require.NoError(t, err)
	defer parResp.Body.Close()
	parBody, _ := io.ReadAll(parResp.Body)
	require.Equal(t, http.StatusCreated, parResp.StatusCode,
		"PAR failed: %s", string(parBody))

	var parResult struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(parBody, &parResult))
	require.NotEmpty(t, parResult.RequestURI)

	dpopNonce := parResp.Header.Get("DPoP-Nonce")

	// Persist the authorization request for inspection / replay.
	saveAuthorizationRequest(t, authorizationRequestArtifact, &CachedAuthorizationRequest{
		ClientID:      clientA.ClientID,
		Form:          parForm,
		RequestURI:    parResult.RequestURI,
		ExpiresIn:     parResult.ExpiresIn,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		State:         state,
	})

	// ── 2. Authorization redirect → extract login_challenge ──────────────────
	authURL := fmt.Sprintf("%s/oauth2/auth?client_id=%s&request_uri=%s",
		publicURL(), clientA.ClientID, url.QueryEscape(parResult.RequestURI))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	walkClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := walkClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	loc, err := resp.Location()
	require.NoError(t, err, "auth must redirect to login")
	loginChallenge := loc.Query().Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	// ── 3. Accept login via admin API ────────────────────────────────────────
	loginAccept := adminPut(t,
		"/admin/oauth2/auth/requests/login/accept?login_challenge="+url.QueryEscape(loginChallenge),
		map[string]interface{}{
			"subject":  testSubject,
			"remember": false,
		})
	loginRedirect, _ := loginAccept["redirect_to"].(string)
	require.NotEmpty(t, loginRedirect)

	// ── 4. Follow login → extract consent_challenge ──────────────────────────
	resp, err = walkClient.Get(loginRedirect)
	require.NoError(t, err)
	resp.Body.Close()
	loc, err = resp.Location()
	require.NoError(t, err)
	consentChallenge := loc.Query().Get("consent_challenge")
	require.NotEmpty(t, consentChallenge)

	// ── 5. Accept consent via admin API ──────────────────────────────────────
	// The external test drives the admin API directly rather than going
	// through the Consent Node. To match what the Consent Node would do,
	// we must echo authorization_details back here and enrich each
	// openid_credential entry with credential_identifiers (OIDC4VCI §6.2).
	enrichedAuthDetails := []map[string]interface{}{
		{
			"type":                        "openid_credential",
			"credential_configuration_id": credConfig.ID,
			"credential_identifiers": []string{
				credConfig.ID + "-" + uuid.New()[:8],
			},
		},
	}

	consentAccept := adminPut(t,
		"/admin/oauth2/auth/requests/consent/accept?consent_challenge="+url.QueryEscape(consentChallenge),
		map[string]interface{}{
			"grant_scope":                 []string{"openid", "offline"},
			"grant_access_token_audience": []string{},
			"remember":                    false,
			"authorization_details":       enrichedAuthDetails,
			"session": map[string]interface{}{
				"access_token": map[string]interface{}{},
				"id_token":     map[string]interface{}{},
			},
		})
	consentRedirect, _ := consentAccept["redirect_to"].(string)
	require.NotEmpty(t, consentRedirect)

	// ── 6. Follow consent → extract authorization code ───────────────────────
	resp, err = walkClient.Get(consentRedirect)
	require.NoError(t, err)
	resp.Body.Close()
	if n := resp.Header.Get("DPoP-Nonce"); n != "" {
		dpopNonce = n
	}
	loc, err = resp.Location()
	require.NoError(t, err)
	authCode := loc.Query().Get("code")
	require.NotEmpty(t, authCode, "authorization code missing: %s", loc)
	assert.Equal(t, state, loc.Query().Get("state"))

	// ── 7. Token exchange (DPoP + private_key_jwt) ───────────────────────────
	tokenResp := exchangeAuthCodeWithDPoP(t, clientA, authCode, codeVerifier, dpopNonce)
	accessToken, _ := tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)
	assert.Equal(t, "DPoP", tokenResp["token_type"])

	// ── 7a. Verify authorization_details in the token response ───────────────
	// Per OIDC4VCI §6.2 the token response MUST contain authorization_details
	// with credential_identifiers on every openid_credential entry.
	authDetailsResp, ok := tokenResp["authorization_details"].([]interface{})
	require.True(t, ok,
		"token response must contain authorization_details array, got: %v",
		tokenResp["authorization_details"])
	require.NotEmpty(t, authDetailsResp,
		"token response authorization_details must be non-empty")
	for i, entry := range authDetailsResp {
		m, ok := entry.(map[string]interface{})
		require.True(t, ok, "entry %d must be an object", i)
		if m["type"] != "openid_credential" {
			continue
		}
		ids, ok := m["credential_identifiers"].([]interface{})
		require.True(t, ok,
			"entry %d missing credential_identifiers: %v", i, m)
		require.NotEmpty(t, ids,
			"entry %d credential_identifiers must be non-empty", i)
	}

	// ── 8. Fetch mock-issuer nonce ───────────────────────────────────────────
	nonceResp, err := http.Post(mockIssuerURL()+"/nonce", "application/json", nil)
	require.NoError(t, err)
	defer nonceResp.Body.Close()
	require.Equal(t, http.StatusOK, nonceResp.StatusCode)
	var nonceBody struct {
		CNonce string `json:"c_nonce"`
	}
	require.NoError(t, json.NewDecoder(nonceResp.Body).Decode(&nonceBody))
	require.NotEmpty(t, nonceBody.CNonce)

	// ── 9. Build proof JWT with DPoP key, request credential ─────────────────
	proofJWT := buildOID4VCIProofJWT(t, clientA, mockIssuerURL(), nonceBody.CNonce)

	credReqBody, _ := json.Marshal(map[string]interface{}{
		"credential_configuration_id": credConfig.ID,
		"proofs":                      map[string]interface{}{"jwt": []string{proofJWT}},
	})
	credEndpoint := mockIssuerURL() + "/credential"
	credReq, _ := http.NewRequest(http.MethodPost, credEndpoint,
		bytes.NewReader(credReqBody))
	credReq.Header.Set("Content-Type", "application/json")
	// Present the access token via DPoP scheme and attach a DPoP proof that
	// includes the ath claim (RFC 9449 §7.1). The issuer verifies the proof
	// against the token's cnf.jkt before issuing the credential.
	credReq.Header.Set("Authorization", "DPoP "+accessToken)
	credReq.Header.Set("DPoP",
		newDPoPProofWithATH(t, clientA, "POST", credEndpoint, "", accessToken))

	credResp, err := http.DefaultClient.Do(credReq)
	require.NoError(t, err)
	defer credResp.Body.Close()
	credBodyRaw, _ := io.ReadAll(credResp.Body)
	require.Equal(t, http.StatusOK, credResp.StatusCode,
		"credential request failed: %s", string(credBodyRaw))

	var credBody struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
		CNonce string `json:"c_nonce"`
	}
	require.NoError(t, json.Unmarshal(credBodyRaw, &credBody))
	require.Len(t, credBody.Credentials, 1)

	credStr := credBody.Credentials[0].Credential
	require.NotEmpty(t, credStr)
	assert.True(t, strings.HasSuffix(credStr, "~"),
		"SD-JWT VC must end with ~, got: %s", credStr)
	jwtPart := strings.TrimSuffix(credStr, "~")
	assert.Len(t, strings.Split(jwtPart, "."), 3,
		"SD-JWT VC header.payload.signature must have 3 parts")
	assert.NotEmpty(t, credBody.CNonce, "fresh c_nonce must be returned")
	assert.NotEqual(t, nonceBody.CNonce, credBody.CNonce,
		"fresh nonce must differ from previous one")
}

// exchangeAuthCodeWithDPoP POSTs to /oauth2/token using private_key_jwt auth and
// a DPoP proof, transparently handling the RFC 9449 use_dpop_nonce retry.
func exchangeAuthCodeWithDPoP(t *testing.T, c *CachedClient, code, codeVerifier, initialNonce string) map[string]interface{} {
	t.Helper()

	tokenEndpoint := publicURL() + "/oauth2/token"

	doRequest := func(nonce string) (*http.Response, []byte, map[string]interface{}) {
		form := url.Values{
			"grant_type":            {"authorization_code"},
			"code":                  {code},
			"redirect_uri":          {testCallbackURI},
			"code_verifier":         {codeVerifier},
			"client_id":             {c.ClientID},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {signClientAssertion(t, c, tokenEndpoint)},
		}
		req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", newDPoPProof(t, c, "POST", tokenEndpoint, nonce))

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &parsed),
			"token response not JSON: %s", string(body))
		return resp, body, parsed
	}

	resp, body, parsed := doRequest(initialNonce)
	if resp.StatusCode == http.StatusOK {
		return parsed
	}

	// Handle use_dpop_nonce per RFC 9449 §8.
	if code, _ := parsed["error"].(string); code == "use_dpop_nonce" {
		retryNonce := resp.Header.Get("DPoP-Nonce")
		require.NotEmpty(t, retryNonce, "use_dpop_nonce without DPoP-Nonce header")
		t.Logf("retrying token request with DPoP nonce: %s", retryNonce)
		resp2, body2, parsed2 := doRequest(retryNonce)
		require.Equal(t, http.StatusOK, resp2.StatusCode,
			"token retry failed: %s", string(body2))
		return parsed2
	}

	require.Failf(t, "token exchange failed",
		"status=%d body=%s", resp.StatusCode, string(body))
	return nil
}

// buildOID4VCIProofJWT signs an OpenID4VCI proof JWT using the client's DPoP
// key. The public JWK is embedded in the header so the issuer can bind the
// credential to the holder.
func buildOID4VCIProofJWT(t *testing.T, c *CachedClient, audience, nonce string) string {
	t.Helper()
	jwk := parsePrivateJWK(t, c.DPoPPrivateKeyJWK)

	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"jwk": jwk.Public(),
	}
	payload := map[string]interface{}{
		"aud":   audience,
		"iat":   nowUnix(),
		"nonce": nonce,
	}
	return signManualES256JWT(t, header, payload, jwk.Key.(*ecdsa.PrivateKey))
}

// signManualES256JWT serializes a JWT by hand so the header can carry an
// explicit `jwk` claim without the go-jose `EmbedJWK` machinery also emitting
// `kid`. This matches what the mock-issuer expects in validateProof().
func signManualES256JWT(t *testing.T, header, payload map[string]interface{}, key *ecdsa.PrivateKey) string {
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

	rb := leftPad(r.Bytes(), 32)
	sb := leftPad(s.Bytes(), 32)
	sig := append(rb, sb...) //nolint:gocritic

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func nowUnix() int64 {
	return time.Now().Unix()
}
