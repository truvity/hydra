// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc4vci_external_test

// Test-artifact caching: clients, mock-issuer credential configurations, and
// authorization request JSON are persisted under ./testdata/ so a subsequent
// test run can skip re-creation. Set REFRESH_TESTDATA=1 to force regeneration.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/require"
)

// ── paths ─────────────────────────────────────────────────────────────────────

func testdataDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	dir := filepath.Join(filepath.Dir(thisFile), "testdata")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	return dir
}

func testdataPath(t *testing.T, name string) string {
	return filepath.Join(testdataDir(t), name)
}

func refreshTestdata() bool {
	return os.Getenv("REFRESH_TESTDATA") == "1"
}

// readCached reads a JSON artifact; returns false if absent or refresh requested.
func readCached(t *testing.T, name string, out interface{}) bool {
	t.Helper()
	if refreshTestdata() {
		return false
	}
	b, err := os.ReadFile(testdataPath(t, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		t.Fatalf("read %s: %v", name, err)
	}
	require.NoError(t, json.Unmarshal(b, out), "decode %s", name)
	return true
}

func writeCached(t *testing.T, name string, v interface{}) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(testdataPath(t, name), b, 0o644))
}

// ── test artifact types ───────────────────────────────────────────────────────

// CachedClient is the persistent record for a Hydra OAuth2 client authenticated
// via private_key_jwt. Both the private and public signing JWK are stored so
// the test can rebuild a signer without re-contacting Hydra.
type CachedClient struct {
	ClientID                    string          `json:"client_id"`
	TokenEndpointAuthMethod     string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg string          `json:"token_endpoint_auth_signing_alg"`
	RedirectURIs                []string        `json:"redirect_uris"`
	GrantTypes                  []string        `json:"grant_types"`
	ResponseTypes               []string        `json:"response_types"`
	Scope                       string          `json:"scope"`
	PrivateKeyJWK               json.RawMessage `json:"private_key_jwk"`
	PublicKeyJWK                json.RawMessage `json:"public_key_jwk"`
	DPoPSigningAlg              string          `json:"dpop_signing_alg"`
	DPoPPrivateKeyJWK           json.RawMessage `json:"dpop_private_key_jwk"`
}

// CachedCredentialConfig is the persistent record for a mock-issuer credential
// configuration. The full original request body is preserved for traceability.
type CachedCredentialConfig struct {
	ID      string          `json:"id"`
	Request json.RawMessage `json:"request"`
}

// CachedAuthorizationRequest is the form payload of the PAR request together
// with the request_uri Hydra returned. Re-used across runs when still valid.
type CachedAuthorizationRequest struct {
	ClientID       string    `json:"client_id"`
	Form           map[string][]string `json:"form"`
	RequestURI     string    `json:"request_uri"`
	ExpiresIn      int       `json:"expires_in"`
	CreatedAt      time.Time `json:"created_at"`
	CodeVerifier   string    `json:"code_verifier"`
	CodeChallenge  string    `json:"code_challenge"`
	State          string    `json:"state"`
}

// ── key & JWK helpers ─────────────────────────────────────────────────────────

// generateES256Key creates an ECDSA P-256 key and its JOSE-serializable JWK
// representations (private and public).
func generateES256Key(t *testing.T, kid string) (priv, pub json.RawMessage) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privJWK := jose.JSONWebKey{Key: key, KeyID: kid, Algorithm: "ES256", Use: "sig"}
	pubJWK := privJWK.Public()

	pb, err := privJWK.MarshalJSON()
	require.NoError(t, err)
	ub, err := pubJWK.MarshalJSON()
	require.NoError(t, err)
	return pb, ub
}

// parsePrivateJWK unmarshals a raw JWK and asserts it carries a private key.
func parsePrivateJWK(t *testing.T, raw json.RawMessage) *jose.JSONWebKey {
	t.Helper()
	var jwk jose.JSONWebKey
	require.NoError(t, jwk.UnmarshalJSON(raw))
	require.True(t, jwk.IsPublic() == false, "expected private JWK")
	return &jwk
}

// ── cached-client acquisition ─────────────────────────────────────────────────

// loadOrCreateClient returns a cached client under name, creating and
// registering a new one with Hydra on first call (or when REFRESH_TESTDATA=1).
//
// The client is registered with token_endpoint_auth_method=private_key_jwt and
// a fresh ES256/P-256 key pair; a separate ES256/P-256 key is generated and
// cached for DPoP proofs so tests don't need to regenerate them on each run.
func loadOrCreateClient(t *testing.T, name string, redirectURIs []string, grantTypes []string) *CachedClient {
	t.Helper()

	var c CachedClient
	if readCached(t, name+".json", &c) && clientStillExists(t, c.ClientID) {
		return &c
	}

	// Fresh signing + DPoP key pairs.
	signKid := "sign-" + uuid.New()
	signPriv, signPub := generateES256Key(t, signKid)

	dpopKid := "dpop-" + uuid.New()
	dpopPriv, _ := generateES256Key(t, dpopKid)

	// Build JWKS for Hydra registration. Hydra expects {"keys":[...]} with
	// public-only keys (no "d"). The public JWK we just marshalled is already
	// public.
	var pubJWK map[string]interface{}
	require.NoError(t, json.Unmarshal(signPub, &pubJWK))

	body := map[string]interface{}{
		"client_name":                     name,
		"redirect_uris":                   redirectURIs,
		"grant_types":                     grantTypes,
		"response_types":                  []string{"code"},
		"scope":                           "openid offline openid_credential",
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"jwks": map[string]interface{}{
			"keys": []map[string]interface{}{pubJWK},
		},
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(adminURL()+"/admin/clients", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.True(t,
		resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK,
		"create client %s: %d %s", name, resp.StatusCode, string(raw))

	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &created))
	clientID, ok := created["client_id"].(string)
	require.True(t, ok, "client_id missing: %s", string(raw))

	c = CachedClient{
		ClientID:                    clientID,
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "ES256",
		RedirectURIs:                redirectURIs,
		GrantTypes:                  grantTypes,
		ResponseTypes:               []string{"code"},
		Scope:                       "openid offline openid_credential",
		PrivateKeyJWK:               signPriv,
		PublicKeyJWK:                signPub,
		DPoPSigningAlg:              "ES256",
		DPoPPrivateKeyJWK:           dpopPriv,
	}
	writeCached(t, name+".json", &c)
	return &c
}

// clientStillExists returns true if a client with the given ID is known to
// Hydra. Used to detect a wiped database between test runs — in that case we
// re-create the client instead of reusing the stale cached record.
func clientStillExists(t *testing.T, clientID string) bool {
	t.Helper()
	resp, err := http.Get(adminURL() + "/admin/clients/" + clientID)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// loadOrCreateAttesterClient returns a cached client registered with
// token_endpoint_auth_method=attest_jwt_client_auth (HAIP / Wallet
// Attestation).
//
// Unlike private_key_jwt clients, the wallet attestation flow:
//   - Uses a fixed, caller-supplied client_id that MUST match the `sub` claim
//     of the Client Attestation JWT. Hydra looks up the client by that id.
//   - Does not register a jwks: trust is anchored in the attester's x5c chain
//     and hydra's wallet_attestation.trust_anchors config.
//   - Still uses a DPoP key at the token endpoint, so we generate & cache one.
//
// The caller (e.g. an HAIP e2e test or the conformance harness) signs the
// Client Attestation JWT separately using the attester key bundle produced by
// gen-attester-jwks.sh.
func loadOrCreateAttesterClient(t *testing.T, name, clientID string, redirectURIs, grantTypes []string) *CachedClient {
	t.Helper()

	var c CachedClient
	if readCached(t, name+".json", &c) && clientStillExists(t, c.ClientID) {
		return &c
	}

	dpopKid := "dpop-" + uuid.New()
	dpopPriv, _ := generateES256Key(t, dpopKid)

	body := map[string]interface{}{
		"client_id":                  clientID,
		"client_name":                name,
		"redirect_uris":              redirectURIs,
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"scope":                      "openid offline openid_credential",
		"token_endpoint_auth_method": "attest_jwt_client_auth",
	}
	b, _ := json.Marshal(body)
	resp, err := http.Post(adminURL()+"/admin/clients", "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.True(t,
		resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK,
		"create attester client %s: %d %s", name, resp.StatusCode, string(raw))

	var created map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &created))
	id, _ := created["client_id"].(string)
	require.NotEmpty(t, id, "client_id missing in create response")
	require.Equal(t, clientID, id,
		"hydra did not honor the requested client_id (needed for attester sub match)")

	c = CachedClient{
		ClientID:                id,
		TokenEndpointAuthMethod: "attest_jwt_client_auth",
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           []string{"code"},
		Scope:                   "openid offline openid_credential",
		DPoPSigningAlg:          "ES256",
		DPoPPrivateKeyJWK:       dpopPriv,
	}
	writeCached(t, name+".json", &c)
	return &c
}

// ── cached credential configuration ───────────────────────────────────────────

// loadOrCreateCredentialConfig provisions a credential configuration on the
// mock-issuer and caches the result. The cached file retains the exact request
// body to make debugging easier.
func loadOrCreateCredentialConfig(t *testing.T, name, configID string) *CachedCredentialConfig {
	t.Helper()

	var c CachedCredentialConfig
	if readCached(t, name+".json", &c) && credentialConfigExists(t, c.ID) {
		return &c
	}

	reqBody := map[string]interface{}{
		"id":     configID,
		"format": "dc+sd-jwt",
		"vct":    "TestCredential",
		"scope":  "openid_credential",
		"cryptographic_binding_methods_supported": []string{"jwk"},
		"credential_signing_alg_values_supported": []string{"ES256"},
		"proof_types_supported": map[string]interface{}{
			"jwt": map[string]interface{}{
				"proof_signing_alg_values_supported": []string{"ES256"},
			},
		},
		"display": []map[string]interface{}{
			{"name": "Test Credential", "locale": "en-US"},
		},
	}

	raw, _ := json.Marshal(reqBody)

	resp, err := http.Post(mockIssuerURL()+"/admin/oidc4vci/credential-configurations",
		"application/json", bytes.NewReader(raw))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// 409 (already_exists) is fine — happens when the mock-issuer was not
	// restarted between runs but the local cache was wiped.
	require.True(t,
		resp.StatusCode == http.StatusCreated ||
			resp.StatusCode == http.StatusOK ||
			resp.StatusCode == http.StatusConflict,
		"create credential config: %d %s", resp.StatusCode, string(body))

	c = CachedCredentialConfig{ID: configID, Request: raw}
	writeCached(t, name+".json", &c)
	return &c
}

func credentialConfigExists(t *testing.T, id string) bool {
	t.Helper()
	resp, err := http.Get(mockIssuerURL() + "/admin/oidc4vci/credential-configurations/" + id)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ── cached authorization request ──────────────────────────────────────────────

// saveAuthorizationRequest persists the PAR form payload and the returned
// request_uri for later inspection.
func saveAuthorizationRequest(t *testing.T, name string, req *CachedAuthorizationRequest) {
	t.Helper()
	req.CreatedAt = time.Now()
	writeCached(t, name+".json", req)
}

// ── private_key_jwt client assertion ──────────────────────────────────────────

// signClientAssertion builds and signs an RFC 7521/7523 client assertion JWT
// for use with token_endpoint_auth_method=private_key_jwt.
//
// claims: iss = sub = clientID, aud = full token endpoint URL, jti = random,
//         iat = now, exp = now + 60s.
func signClientAssertion(t *testing.T, c *CachedClient, tokenEndpointURL string) string {
	t.Helper()
	jwk := parsePrivateJWK(t, c.PrivateKeyJWK)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: jwk.Key, KeyID: jwk.KeyID},
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(jose.HeaderType): "JWT",
		},
	})
	require.NoError(t, err)

	now := time.Now()
	claims := map[string]interface{}{
		"iss": c.ClientID,
		"sub": c.ClientID,
		"aud": tokenEndpointURL,
		"jti": uuid.New(),
		"iat": josejwt.NewNumericDate(now),
		"exp": josejwt.NewNumericDate(now.Add(60 * time.Second)),
	}
	assertion, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return assertion
}

// ── DPoP proof built from a cached client's DPoP key ──────────────────────────

// newDPoPProof builds a DPoP proof JWT for the given HTTP method + URL using
// the client's persisted DPoP key. When nonce is non-empty, it is included.
func newDPoPProof(t *testing.T, c *CachedClient, htm, htu, nonce string) string {
	t.Helper()
	return newDPoPProofWithATH(t, c, htm, htu, nonce, "")
}

// newDPoPProofWithATH builds a DPoP proof JWT that additionally carries an
// `ath` claim — the base64url-encoded SHA-256 of the access token. Required
// on resource server requests that present a DPoP-bound access token
// (RFC 9449 §4.2 / §7.1). Pass "" for accessToken to omit the claim.
func newDPoPProofWithATH(t *testing.T, c *CachedClient, htm, htu, nonce, accessToken string) string {
	t.Helper()
	jwk := parsePrivateJWK(t, c.DPoPPrivateKeyJWK)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: jwk.Key, KeyID: jwk.KeyID},
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(jose.HeaderType): "dpop+jwt",
		},
		EmbedJWK: true,
	})
	require.NoError(t, err)

	claims := map[string]interface{}{
		"jti": uuid.New(),
		"htm": htm,
		"htu": htu,
		"iat": josejwt.NewNumericDate(time.Now()),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	proof, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return proof
}

// ── shared environment helpers ────────────────────────────────────────────────

// mockIssuerURL returns the mock-issuer endpoint. Override with
// MOCK_ISSUER_URL (default http://127.0.0.1:4448).
func mockIssuerURL() string {
	if u := os.Getenv("MOCK_ISSUER_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:4448"
}

// skipIfMockIssuerDown skips the test if the mock-issuer is not reachable.
func skipIfMockIssuerDown(t *testing.T) {
	t.Helper()
	cl := &http.Client{Timeout: 2 * time.Second}
	resp, err := cl.Get(mockIssuerURL() + "/.well-known/openid-credential-issuer")
	if err != nil {
		t.Skipf("mock-issuer not reachable at %s: %v", mockIssuerURL(), err)
	}
	resp.Body.Close()
}
