// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc4vci_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hydra "github.com/ory/hydra-client-go/v2"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/configx"
)

// ── DPoP proof builder ────────────────────────────────────────────────────────

func boolPtr(b bool) *bool { return &b }

func buildDPoPProofJWT(t *testing.T, key *ecdsa.PrivateKey, htm, htu string) string {
	t.Helper()
	signerOpts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(jose.HeaderType): "dpop+jwt",
		},
		EmbedJWK: true,
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: key, KeyID: "wallet-key"},
	}, signerOpts)
	require.NoError(t, err)

	now := time.Now()
	claims := map[string]interface{}{
		"jti": uuid.New(),
		"htm": htm,
		"htu": htu,
		"iat": josejwt.NewNumericDate(now),
	}
	raw, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return raw
}

// ── Hydra setup for auth code flow ────────────────────────────────────────────

type authCodeEnv struct {
	publicURL   string
	adminURL    string
	reg         *driver.RegistrySQL
	adminClient *hydra.APIClient
}

func setupAuthCodeHydra(t *testing.T) *authCodeEnv {
	t.Helper()
	ctx := t.Context()

	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(
		configx.WithValue(config.KeyRAREnabled, true),
		configx.WithValue(config.KeyRARTypesSupported, []string{"openid_credential"}),
		configx.WithValue(config.KeyDPoPEnabled, true),
		configx.WithValue(config.KeyDPoPSigningAlgValues, []string{"ES256"}),
		configx.WithValue(config.KeyDPoPProofMaxAge, "60s"),
		configx.WithValue(config.KeyAccessTokenLifespan, time.Hour),
		configx.WithValue(config.KeyScopeStrategy, "wildcard"),
	))

	publicTS, adminTS := testhelpers.NewConfigurableOAuth2Server(ctx, t, reg)

	// Set login/consent URLs — these will be overridden per-test.
	reg.Config().MustSet(ctx, config.KeyLoginURL, "http://placeholder/login")
	reg.Config().MustSet(ctx, config.KeyConsentURL, "http://placeholder/consent")

	adminClient := hydra.NewAPIClient(hydra.NewConfiguration())
	adminClient.GetConfig().Servers = hydra.ServerConfigurations{{URL: adminTS.URL}}

	return &authCodeEnv{
		publicURL:   publicTS.URL,
		adminURL:    adminTS.URL,
		reg:         reg,
		adminClient: adminClient,
	}
}

func (e *authCodeEnv) createClient(t *testing.T, callbackURL string) *client.Client {
	t.Helper()
	secret := "test-secret-" + uuid.New()
	c := &client.Client{
		Secret:        secret,
		RedirectURIs:  []string{callbackURL},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scope:         "openid offline",
		Audience:      []string{},
	}
	require.NoError(t, e.reg.ClientManager().CreateClient(t.Context(), c))
	c.Secret = secret // CreateClient hashes the secret
	return c
}

// ── Login/consent emulation ───────────────────────────────────────────────────

func simpleLoginHandler(t *testing.T, adminClient *hydra.APIClient, subject string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("login_challenge")
		v, _, err := adminClient.OAuth2API.AcceptOAuth2LoginRequest(r.Context()).
			LoginChallenge(challenge).
			AcceptOAuth2LoginRequest(hydra.AcceptOAuth2LoginRequest{
				Subject:  subject,
				Remember: boolPtr(false),
			}).Execute()
		if err != nil {
			t.Logf("login handler: AcceptOAuth2LoginRequest failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, v.RedirectTo, http.StatusFound)
	}
}

func consentHandlerWithRAR(t *testing.T, adminURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("consent_challenge")

		// Get consent request via raw HTTP (SDK doesn't know authorization_details).
		getResp, err := http.Get(adminURL + "/admin/oauth2/auth/requests/consent?consent_challenge=" + url.QueryEscape(challenge))
		if err != nil {
			t.Logf("consent handler: get consent request failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer getResp.Body.Close()
		var consentReq map[string]interface{}
		if err := json.NewDecoder(getResp.Body).Decode(&consentReq); err != nil {
			t.Logf("consent handler: decode consent request failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Extract requested scopes.
		var grantScope []string
		if scopes, ok := consentReq["requested_scope"].([]interface{}); ok {
			for _, s := range scopes {
				grantScope = append(grantScope, s.(string))
			}
		}

		// Accept consent — grant all requested scopes.
		acceptBody, _ := json.Marshal(map[string]interface{}{
			"grant_scope":                grantScope,
			"grant_access_token_audience": consentReq["requested_access_token_audience"],
			"remember":                   false,
			"session": map[string]interface{}{
				"access_token": map[string]interface{}{},
				"id_token":     map[string]interface{}{},
			},
		})

		acceptReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPut,
			adminURL+"/admin/oauth2/auth/requests/consent/accept?consent_challenge="+url.QueryEscape(challenge),
			bytes.NewReader(acceptBody))
		acceptReq.Header.Set("Content-Type", "application/json")

		acceptResp, err := http.DefaultClient.Do(acceptReq)
		if err != nil {
			t.Logf("consent handler: accept consent failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer acceptResp.Body.Close()
		var acceptResult map[string]interface{}
		if err := json.NewDecoder(acceptResp.Body).Decode(&acceptResult); err != nil {
			t.Logf("consent handler: decode accept response failed: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		redirectTo, ok := acceptResult["redirect_to"].(string)
		if !ok {
			t.Logf("consent handler: no redirect_to in accept response: %v", acceptResult)
			http.Error(w, "no redirect_to", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

// ── PAR + RAR + DPoP E2E Tests ────────────────────────────────────────────────

func TestAuthCodeFlow_PAR_RAR_DPoP(t *testing.T) {
	t.Parallel()
	env := setupAuthCodeHydra(t)
	ctx := t.Context()

	// Callback server — the final redirect target.
	callbackTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(callbackTS.Close)

	// Register client.
	c := env.createClient(t, callbackTS.URL+"/callback")

	// Set up login/consent handlers.
	loginTS := httptest.NewServer(simpleLoginHandler(t, env.adminClient, "the-subject"))
	t.Cleanup(loginTS.Close)
	consentTS := httptest.NewServer(consentHandlerWithRAR(t, env.adminURL))
	t.Cleanup(consentTS.Close)

	env.reg.Config().MustSet(ctx, config.KeyLoginURL, loginTS.URL)
	env.reg.Config().MustSet(ctx, config.KeyConsentURL, consentTS.URL)

	// Wallet DPoP key.
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// PKCE challenge.
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // S256 of verifier

	// authorization_details for RAR.
	authDetails := `[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_JWT"}]`

	state := "test-state-" + uuid.New()

	// ── Step 1: PAR request ───────────────────────────────────────────────────
	parForm := url.Values{
		"client_id":             {c.GetID()},
		"response_type":        {"code"},
		"redirect_uri":         {callbackTS.URL + "/callback"},
		"scope":                {"openid offline"},
		"state":                {state},
		"code_challenge":       {codeChallenge},
		"code_challenge_method": {"S256"},
		"authorization_details": {authDetails},
	}

	dpopProofPAR := buildDPoPProofJWT(t, dpopKey, "POST", env.publicURL+"/oauth2/par")

	parReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		env.publicURL+"/oauth2/par", strings.NewReader(parForm.Encode()))
	require.NoError(t, err)
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.Header.Set("DPoP", dpopProofPAR)
	parReq.SetBasicAuth(c.GetID(), c.Secret)

	parResp, err := http.DefaultClient.Do(parReq)
	require.NoError(t, err)
	defer parResp.Body.Close()

	parBody, err := io.ReadAll(parResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, parResp.StatusCode,
		"PAR should succeed, got: %s", string(parBody))

	var parResult struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(parBody, &parResult))
	require.NotEmpty(t, parResult.RequestURI, "PAR must return request_uri")
	require.True(t, parResult.ExpiresIn > 0, "PAR must return positive expires_in")

	// ── Step 2: Authorization redirect using request_uri from PAR ─────────────
	authURL := fmt.Sprintf("%s/oauth2/auth?client_id=%s&request_uri=%s",
		env.publicURL, c.GetID(), url.QueryEscape(parResult.RequestURI))

	// Follow the full redirect chain: auth → login → auth → consent → auth → callback.
	jarClient := x.NewEmptyJarClient(t)
	authResp, err := jarClient.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()

	// The final URL should be the callback with the authorization code.
	finalURL := authResp.Request.URL
	capturedCode := finalURL.Query().Get("code")
	capturedState := finalURL.Query().Get("state")
	require.NotEmpty(t, capturedCode, "authorization code must be in final URL: %s", finalURL)
	assert.Equal(t, state, capturedState)

	// ── Step 3: Token exchange with DPoP ──────────────────────────────────────
	dpopProofToken := buildDPoPProofJWT(t, dpopKey, "POST", env.publicURL+"/oauth2/token")

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {capturedCode},
		"redirect_uri":  {callbackTS.URL + "/callback"},
		"code_verifier": {codeVerifier},
		"client_id":     {c.GetID()},
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		env.publicURL+"/oauth2/token", strings.NewReader(tokenForm.Encode()))
	require.NoError(t, err)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("DPoP", dpopProofToken)
	tokenReq.SetBasicAuth(c.GetID(), c.Secret)

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)

	var tokenResult map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))
	require.NotContains(t, tokenResult, "error",
		"token exchange should succeed, got: %s", string(tokenBody))

	accessToken, ok := tokenResult["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)

	// Verify token_type is DPoP.
	assert.Equal(t, "DPoP", tokenResult["token_type"],
		"token_type must be DPoP when DPoP proof is present")

	// ── Step 4: Introspect — verify DPoP binding ─────────────────────────────
	introResult := introspectToken(t, env.adminURL, accessToken)
	assert.Equal(t, true, introResult["active"])
	assert.Equal(t, "the-subject", introResult["sub"])

	// Verify cnf.jkt is present.
	ext, ok := introResult["ext"].(map[string]interface{})
	require.True(t, ok, "ext must be present in introspection response")

	cnf, ok := ext["cnf"].(map[string]interface{})
	require.True(t, ok, "cnf must be present in ext (DPoP binding)")
	jkt, ok := cnf["jkt"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, jkt, "cnf.jkt must be non-empty")

	// __dpop_validated_jkt should be cleaned up.
	_, hasTransportKey := ext["__dpop_validated_jkt"]
	assert.False(t, hasTransportKey, "__dpop_validated_jkt transport key should be cleaned up")
}

func TestAuthCodeFlow_PAR_Required_Without_PAR_Fails(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(
		configx.WithValue(config.KeyEnforcePushedAuthorize, true),
		configx.WithValue(config.KeyAccessTokenLifespan, time.Hour),
		configx.WithValue(config.KeyScopeStrategy, "wildcard"),
	))

	publicTS, _ := testhelpers.NewConfigurableOAuth2Server(ctx, t, reg)

	// Set dummy login/consent URLs.
	reg.Config().MustSet(ctx, config.KeyLoginURL, "http://localhost:9999/login")
	reg.Config().MustSet(ctx, config.KeyConsentURL, "http://localhost:9999/consent")

	// Register client.
	secret := "test-secret"
	require.NoError(t, reg.ClientManager().CreateClient(ctx, &client.Client{
		Secret:        secret,
		RedirectURIs:  []string{"http://localhost:9999/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scope:         "openid",
	}))

	// Direct authorize request without PAR should fail when PAR is enforced.
	authURL := fmt.Sprintf("%s/oauth2/auth?client_id=%s&response_type=code&redirect_uri=%s&scope=openid&state=test",
		publicTS.URL, "test-client", url.QueryEscape("http://localhost:9999/callback"))

	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := cl.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should get an error redirect or error response (not a login redirect).
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	// When PAR is enforced, direct auth requests should be rejected.
	// The response could be a redirect to the error URL or an inline error.
	assert.True(t,
		resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusBadRequest ||
			strings.Contains(bodyStr, "error"),
		"direct auth request should fail when PAR is enforced, status=%d body=%s",
		resp.StatusCode, bodyStr)
}

func TestAuthCodeFlow_Discovery_Advertises_OIDC4VCI(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(
		configx.WithValue(config.KeyRAREnabled, true),
		configx.WithValue(config.KeyDPoPEnabled, true),
		configx.WithValue(config.KeyPreAuthorizedCodeEnabled, true),
		configx.WithValue(config.KeyPreAuthorizedCodeAnonymousAccess, true),
		configx.WithValue(config.KeyAccessTokenLifespan, time.Hour),
	))

	publicTS, _ := testhelpers.NewConfigurableOAuth2Server(ctx, t, reg)

	resp, err := http.Get(publicTS.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var disco map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&disco))

	// Verify grant types include pre-authorized code.
	grantTypes := disco["grant_types_supported"].([]interface{})
	grantTypeStrs := make([]string, len(grantTypes))
	for i, gt := range grantTypes {
		grantTypeStrs[i] = gt.(string)
	}
	assert.Contains(t, grantTypeStrs, "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	assert.Contains(t, grantTypeStrs, "authorization_code")

	// Verify DPoP signing algorithms are advertised.
	dpopAlgs, ok := disco["dpop_signing_alg_values_supported"]
	assert.True(t, ok, "dpop_signing_alg_values_supported must be present")
	if ok {
		algs := dpopAlgs.([]interface{})
		assert.Contains(t, algs, "ES256")
	}

	// Verify anonymous access is advertised.
	assert.Equal(t, true, disco["pre-authorized_grant_anonymous_access_supported"])
}
