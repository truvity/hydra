// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc4vci_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/configx"
)

// walletProvider is a test Wallet Provider: a trust anchor and the leaf that
// signs Wallet Attestations, issued directly by the anchor.
type walletProvider struct {
	anchorPEM string
	leafKey   *ecdsa.PrivateKey
	leafDER   []byte
}

func newWalletProvider(t *testing.T) *walletProvider {
	t.Helper()

	now := time.Now()

	anchorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	anchorTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Wallet Provider Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	anchorDER, err := x509.CreateCertificate(rand.Reader, anchorTmpl, anchorTmpl, &anchorKey.PublicKey, anchorKey)
	require.NoError(t, err)

	anchor, err := x509.ParseCertificate(anchorDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Wallet Provider WIA signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, anchor, &leafKey.PublicKey, anchorKey)
	require.NoError(t, err)

	return &walletProvider{
		anchorPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchorDER})),
		leafKey:   leafKey,
		leafDER:   leafDER,
	}
}

// wia signs a Wallet Attestation for clientID binding instanceKey (cnf.jwk).
func (p *walletProvider) wia(t *testing.T, clientID string, instanceKey *ecdsa.PrivateKey) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: p.leafKey},
		(&jose.SignerOptions{}).
			WithType("oauth-client-attestation+jwt").
			WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(p.leafDER)}),
	)
	require.NoError(t, err)

	now := time.Now()
	raw, err := josejwt.Signed(signer).Claims(map[string]interface{}{
		"iss": "https://wallet-provider.example.test",
		"sub": clientID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]interface{}{"jwk": jose.JSONWebKey{Key: &instanceKey.PublicKey}},
	}).CompactSerialize()
	require.NoError(t, err)

	return raw
}

// attestationPoP signs a fresh PoP of the instance key for the AS issuer.
func attestationPoP(t *testing.T, clientID, issuer string, instanceKey *ecdsa.PrivateKey) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: instanceKey},
		(&jose.SignerOptions{}).WithType("oauth-client-attestation-pop+jwt"),
	)
	require.NoError(t, err)

	raw, err := josejwt.Signed(signer).Claims(map[string]interface{}{
		"iss": clientID,
		"aud": issuer,
		"jti": uuid.New(),
		"iat": time.Now().Unix(),
	}).CompactSerialize()
	require.NoError(t, err)

	return raw
}

// TestAuthCodeFlow_WalletAttestation_WIACnf: the RFC 7638 thumbprint of the
// WIA's cnf.jwk reaches the token hook request and the introspection ext as
// wia_cnf, and equals cnf.jkt when the wallet uses its instance key for DPoP.
func TestAuthCodeFlow_WalletAttestation_WIACnf(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	provider := newWalletProvider(t)

	var (
		hookMu    sync.Mutex
		hookExtra map[string]interface{}
	)

	hookTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Session struct {
				Extra map[string]interface{} `json:"extra"`
			} `json:"session"`
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))

		hookMu.Lock()
		hookExtra = body.Session.Extra
		hookMu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(hookTS.Close)

	reg := testhelpers.NewRegistryMemory(t, driver.WithConfigOptions(
		configx.WithValue(config.KeyRAREnabled, true),
		configx.WithValue(config.KeyRARTypesSupported, []string{"openid_credential"}),
		configx.WithValue(config.KeyDPoPEnabled, true),
		configx.WithValue(config.KeyDPoPSigningAlgValues, []string{"ES256"}),
		configx.WithValue(config.KeyDPoPProofMaxAge, "60s"),
		configx.WithValue(config.KeyWalletAttestationEnabled, true),
		configx.WithValue(config.KeyWalletAttestationTrustAnchors, []string{provider.anchorPEM}),
		configx.WithValue(config.KeyTokenHook, hookTS.URL),
		configx.WithValue(config.KeyAccessTokenLifespan, time.Hour),
		configx.WithValue(config.KeyScopeStrategy, "wildcard"),
	))

	publicTS, adminTS := testhelpers.NewConfigurableOAuth2Server(ctx, t, reg)
	env := &authCodeEnv{publicURL: publicTS.URL, adminURL: adminTS.URL, reg: reg}
	env.adminClient = setupAuthCodeHydraAdminClient(adminTS.URL)

	callbackTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(callbackTS.Close)

	loginTS := httptest.NewServer(simpleLoginHandler(t, env.adminClient, "the-subject"))
	t.Cleanup(loginTS.Close)
	consentTS := httptest.NewServer(consentHandlerWithRAR(t, env.adminURL))
	t.Cleanup(consentTS.Close)

	reg.Config().MustSet(ctx, config.KeyLoginURL, loginTS.URL)
	reg.Config().MustSet(ctx, config.KeyConsentURL, consentTS.URL)

	// The wallet's pre-registered client: attestation-based authentication.
	clientID := "wallet-client-" + uuid.New()
	redirectURI := callbackTS.URL + "/callback"
	require.NoError(t, reg.ClientManager().CreateClient(ctx, &client.Client{
		ID:                      clientID,
		RedirectURIs:            []string{redirectURI},
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
		Scope:                   "openid",
		Audience:                []string{},
		TokenEndpointAuthMethod: "attest_jwt_client_auth",
	}))

	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia := provider.wia(t, clientID, instanceKey)
	issuer := reg.Config().IssuerURL(ctx).String()

	attested := func(req *http.Request) {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("OAuth-Client-Attestation", wia)
		req.Header.Set("OAuth-Client-Attestation-PoP", attestationPoP(t, clientID, issuer, instanceKey))
	}

	// PAR, authenticated with the WIA.
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	parForm := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {"state-" + uuid.New()},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_JWT"}]`},
	}

	parReq, err := http.NewRequestWithContext(ctx, http.MethodPost, env.publicURL+"/oauth2/par", strings.NewReader(parForm.Encode()))
	require.NoError(t, err)
	attested(parReq)

	parResp, err := http.DefaultClient.Do(parReq)
	require.NoError(t, err)
	defer func() { _ = parResp.Body.Close() }()

	parBody, err := io.ReadAll(parResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, parResp.StatusCode, "PAR: %s", parBody)

	var par struct {
		RequestURI string `json:"request_uri"`
	}
	require.NoError(t, json.Unmarshal(parBody, &par))

	// Authorization: login and consent, to the callback with a code.
	authResp, err := x.NewEmptyJarClient(t).Get(env.publicURL + "/oauth2/auth?client_id=" + url.QueryEscape(clientID) +
		"&request_uri=" + url.QueryEscape(par.RequestURI))
	require.NoError(t, err)
	defer func() { _ = authResp.Body.Close() }()

	code := authResp.Request.URL.Query().Get("code")
	require.NotEmpty(t, code, "no code in %s", authResp.Request.URL)

	// Token request: WIA authentication and DPoP with the instance key.
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, env.publicURL+"/oauth2/token", strings.NewReader(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
		"client_id":     {clientID},
	}.Encode()))
	require.NoError(t, err)
	attested(tokenReq)
	tokenReq.Header.Set("DPoP", buildDPoPProofJWT(t, instanceKey, "POST", env.publicURL+"/oauth2/token"))

	tokenResp, err := http.DefaultClient.Do(tokenReq)
	require.NoError(t, err)
	defer func() { _ = tokenResp.Body.Close() }()

	tokenBody, err := io.ReadAll(tokenResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, tokenResp.StatusCode, "token: %s", tokenBody)

	var token struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(tokenBody, &token))

	thumbprint, err := (&jose.JSONWebKey{Key: &instanceKey.PublicKey}).Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	want := base64.RawURLEncoding.EncodeToString(thumbprint)

	hookMu.Lock()
	assert.Equal(t, want, hookExtra["wia_cnf"], "the token hook request carries wia_cnf")
	hookMu.Unlock()

	intro := introspectToken(t, env.adminURL, token.AccessToken)
	require.Equal(t, true, intro["active"])

	ext, ok := intro["ext"].(map[string]interface{})
	require.True(t, ok, "ext in introspection")
	assert.Equal(t, want, ext["wia_cnf"], "introspection ext carries wia_cnf")

	cnf, ok := ext["cnf"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, want, cnf["jkt"], "DPoP with the instance key: cnf.jkt equals wia_cnf")
}
