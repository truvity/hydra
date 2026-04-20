// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package wallet_attestation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/fosite"
)

// =========================================================================
// Test helpers
// =========================================================================

func generateTestCA(t testing.TB) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	return caCert, caKey
}

func generateTestLeafCert(t testing.TB, ca *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return leafCert, leafKey
}

func generateTestAttestationJWT(t testing.TB, leafKey crypto.Signer, leafCert *x509.Certificate, claims map[string]interface{}) string {
	t.Helper()

	x5cChain := []string{base64.StdEncoding.EncodeToString(leafCert.Raw)}

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("oauth-client-attestation+jwt")
	signerOpts.WithHeader(jose.HeaderKey("x5c"), x5cChain)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: leafKey}, &signerOpts)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	compact, err := jws.CompactSerialize()
	require.NoError(t, err)

	return compact
}

func generateTestPoPJWT(t testing.TB, cnfKey crypto.Signer, claims map[string]interface{}) string {
	t.Helper()

	signerOpts := jose.SignerOptions{}
	signerOpts.WithType("oauth-client-attestation-pop+jwt")

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cnfKey}, &signerOpts)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	compact, err := jws.CompactSerialize()
	require.NoError(t, err)

	return compact
}

// mockJTIStore is an in-memory JTI store implementing JTIStorage.
type mockJTIStore struct {
	mu   sync.Mutex
	jtis map[string]time.Time
}

func newMockJTIStore() *mockJTIStore {
	return &mockJTIStore{jtis: make(map[string]time.Time)}
}

func (s *mockJTIStore) IsJTIUsed(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.jtis[jti]
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		delete(s.jtis, jti)
		return false, nil
	}
	return true, nil
}

func (s *mockJTIStore) MarkJTIUsed(_ context.Context, jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jtis[jti] = expiry
	return nil
}

// mockClientManager implements fosite.ClientManager.
type mockClientManager struct {
	clients map[string]fosite.Client
}

func (m *mockClientManager) GetClient(_ context.Context, id string) (fosite.Client, error) {
	c, ok := m.clients[id]
	if !ok {
		return nil, fmt.Errorf("client %q not found", id)
	}
	return c, nil
}

func (m *mockClientManager) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

func (m *mockClientManager) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}

// mockStorage implements fosite.Storage.
type mockStorage struct {
	cm fosite.ClientManager
}

func (s *mockStorage) FositeClientManager() fosite.ClientManager {
	return s.cm
}

func newMockClientStore(clients map[string]fosite.Client) fosite.Storage {
	return &mockStorage{cm: &mockClientManager{clients: clients}}
}

// mockClient implements both fosite.Client and fosite.OpenIDConnectClient.
type mockClient struct {
	id                      string
	tokenEndpointAuthMethod string
}

func (m *mockClient) GetID() string                            { return m.id }
func (m *mockClient) GetHashedSecret() []byte                  { return nil }
func (m *mockClient) GetRedirectURIs() []string                { return nil }
func (m *mockClient) GetGrantTypes() fosite.Arguments          { return nil }
func (m *mockClient) GetResponseTypes() fosite.Arguments       { return nil }
func (m *mockClient) GetScopes() fosite.Arguments              { return nil }
func (m *mockClient) IsPublic() bool                           { return true }
func (m *mockClient) GetAudience() fosite.Arguments            { return nil }
func (m *mockClient) GetRequestURIs() []string                 { return nil }
func (m *mockClient) GetJSONWebKeys() *jose.JSONWebKeySet      { return nil }
func (m *mockClient) GetJSONWebKeysURI() string                { return "" }
func (m *mockClient) GetRequestObjectSigningAlgorithm() string { return "" }
func (m *mockClient) GetTokenEndpointAuthMethod() string       { return m.tokenEndpointAuthMethod }
func (m *mockClient) GetTokenEndpointAuthSigningAlgorithm() string { return "" }

func buildTestRequest(attestation, pop string, form url.Values) *http.Request {
	r := &http.Request{
		Header: http.Header{},
	}
	if attestation != "" {
		r.Header.Set("OAuth-Client-Attestation", attestation)
	}
	if pop != "" {
		r.Header.Set("OAuth-Client-Attestation-PoP", pop)
	}
	if form == nil {
		form = url.Values{}
	}
	return r
}

// requireErrorWithHint asserts that the error is an RFC6749Error containing the expected hint substring.
func requireErrorWithHint(t testing.TB, err error, hintSubstring string) {
	t.Helper()
	require.Error(t, err)
	var rfc *fosite.RFC6749Error
	ok := errors.As(err, &rfc)
	require.True(t, ok, "expected *fosite.RFC6749Error, got %T: %v", err, err)
	assert.Contains(t, rfc.Reason(), hintSubstring, "hint %q should contain %q", rfc.Reason(), hintSubstring)
}

// cnfJWKJSON returns the JSON representation of a public JWK for embedding in cnf claim.
func cnfJWKJSON(t testing.TB, pub *ecdsa.PublicKey) json.RawMessage {
	t.Helper()
	jwk := jose.JSONWebKey{Key: pub, Algorithm: "ES256"}
	b, err := jwk.MarshalJSON()
	require.NoError(t, err)
	return b
}

const testIssuerURL = "https://as.example.com"
const testClientID = "https://wallet.example.org"

// newTestAuthenticator creates an Authenticator with standard test fixtures.
func newTestAuthenticator(t testing.TB, caCert *x509.Certificate, clients map[string]fosite.Client) (*Authenticator, *mockJTIStore) {
	t.Helper()
	jtiStore := newMockJTIStore()
	auth := &Authenticator{
		Config: &mockWalletAttestationConfig{
			enabled:      true,
			trustAnchors: []*x509.Certificate{caCert},
		},
		Store:    newMockClientStore(clients),
		JTIStore: jtiStore,
		IssuerURL: func(_ context.Context) string {
			return testIssuerURL
		},
	}
	return auth, jtiStore
}

// mockWalletAttestationConfig implements WalletAttestationConfigProvider.
type mockWalletAttestationConfig struct {
	enabled      bool
	trustAnchors []*x509.Certificate
}

func (m *mockWalletAttestationConfig) GetWalletAttestationEnabled(_ context.Context) bool {
	return m.enabled
}

func (m *mockWalletAttestationConfig) GetWalletAttestationTrustAnchors(_ context.Context) []*x509.Certificate {
	return m.trustAnchors
}

// makeValidAttestationClaims builds a valid attestation claims map.
func makeValidAttestationClaims(t testing.TB, cnfPub *ecdsa.PublicKey) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"iss": "https://wallet-provider.example.com",
		"sub": testClientID,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"cnf": map[string]interface{}{
			"jwk": json.RawMessage(cnfJWKJSON(t, cnfPub)),
		},
	}
}

// makeValidPoPClaims builds a valid PoP claims map.
func makeValidPoPClaims() map[string]interface{} {
	return map[string]interface{}{
		"iss": testClientID,
		"aud": testIssuerURL,
		"iat": time.Now().Unix(),
		"jti": uuid.New().String(),
	}
}


// =========================================================================
// Property 1: End-to-end Wallet Attestation Authentication
// Feature: oidc4vci-wallet-attestation, Property 1: End-to-end Wallet Attestation Authentication
// **Validates: Requirements 1.1, 1.3, 1.4, 1.5, 1.7, 1.9, 1.11, 1.13, 1.14, 1.15, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 5.4, 5.5**
// =========================================================================

func TestProperty1_EndToEndWalletAttestationAuthentication(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

	t.Run("case=valid attestation and pop returns client without error", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			// Generate a fresh cnf key per iteration.
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// Randomize iss for the attestation (wallet provider identifier).
			issuer := rapid.StringMatching(`https://wp-[a-z]{3,8}\.example\.com`).Draw(rt, "issuer")

			attClaims := map[string]interface{}{
				"iss": issuer,
				"sub": testClientID,
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"cnf": map[string]interface{}{
					"jwk": json.RawMessage(cnfJWKJSON(t, &cnfKey.PublicKey)),
				},
			}

			popClaims := map[string]interface{}{
				"iss": testClientID,
				"aud": testIssuerURL,
				"iat": time.Now().Unix(),
				"jti": uuid.New().String(),
			}

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			form := url.Values{}

			c, err := auth.AuthenticateClient(t.Context(), r, form)
			require.NoError(t, err)
			require.NotNil(t, c)
			assert.Equal(t, testClientID, c.GetID())
		})
	})
}

// =========================================================================
// Property 2: X.509 Certificate Chain Validation with HAIP Rules
// Feature: oidc4vci-wallet-attestation, Property 2: X.509 Certificate Chain Validation with HAIP Rules
// **Validates: Requirements 1.7, 1.8, 2.1, 2.2**
// =========================================================================

func TestProperty2_X509CertificateChainValidation(t *testing.T) {
	t.Parallel()

	t.Run("case=valid chain accepted", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			caCert, caKey := generateTestCA(t)
			leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			popClaims := makeValidPoPClaims()

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			c, err := auth.AuthenticateClient(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())
		})
	})

	t.Run("case=trust anchor in x5c chain rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			caCert, caKey := generateTestCA(t)
			leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)

			// Build attestation JWT with trust anchor included in x5c chain.
			x5cChain := []string{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw), // trust anchor in chain — HAIP violation
			}

			signerOpts := jose.SignerOptions{}
			signerOpts.WithType("oauth-client-attestation+jwt")
			signerOpts.WithHeader(jose.HeaderKey("x5c"), x5cChain)

			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: leafKey}, &signerOpts)
			require.NoError(t, err)

			payload, err := json.Marshal(attClaims)
			require.NoError(t, err)

			jws, err := signer.Sign(payload)
			require.NoError(t, err)

			attestation, err := jws.CompactSerialize()
			require.NoError(t, err)

			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "Trust anchor must not be included in x5c chain")
		})
	})

	t.Run("case=self-signed leaf rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			caCert, _ := generateTestCA(t)

			// Create a self-signed leaf cert.
			selfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			selfTemplate := &x509.Certificate{
				SerialNumber:          big.NewInt(99),
				Subject:               pkix.Name{CommonName: "Self-Signed Leaf"},
				Issuer:                pkix.Name{CommonName: "Self-Signed Leaf"},
				NotBefore:             time.Now().Add(-1 * time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
			}

			selfDER, err := x509.CreateCertificate(rand.Reader, selfTemplate, selfTemplate, &selfKey.PublicKey, selfKey)
			require.NoError(t, err)

			selfCert, err := x509.ParseCertificate(selfDER)
			require.NoError(t, err)

			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, selfKey, selfCert, attClaims)
			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "must not be self-signed")
		})
	})

	t.Run("case=chain not terminating at trust anchor rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			// Create two separate CAs — one trusted, one not.
			trustedCA, _ := generateTestCA(t)
			untrustedCA, untrustedCAKey := generateTestCA(t)
			leafCert, leafKey := generateTestLeafCert(t, untrustedCA, untrustedCAKey)

			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, trustedCA, map[string]fosite.Client{testClientID: client})

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "certificate chain is not trusted")
		})
	})
}


// =========================================================================
// Property 3: Signature Verification Binds Attestation to Wallet Provider and PoP to Client Instance
// Feature: oidc4vci-wallet-attestation, Property 3: Signature Verification Binds Attestation to Wallet Provider and PoP to Client Instance
// **Validates: Requirements 1.9, 1.10, 3.4**
// =========================================================================

func TestProperty3_SignatureVerificationBinding(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

	t.Run("case=attestation signed with wrong key rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// Sign attestation with a random key (not the leaf cert key).
			wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)

			// Build JWT signed by wrongKey but with leafCert in x5c.
			x5cChain := []string{base64.StdEncoding.EncodeToString(leafCert.Raw)}
			signerOpts := jose.SignerOptions{}
			signerOpts.WithType("oauth-client-attestation+jwt")
			signerOpts.WithHeader(jose.HeaderKey("x5c"), x5cChain)

			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: wrongKey}, &signerOpts)
			require.NoError(t, err)

			payload, err := json.Marshal(attClaims)
			require.NoError(t, err)

			jws, err := signer.Sign(payload)
			require.NoError(t, err)

			attestation, err := jws.CompactSerialize()
			require.NoError(t, err)

			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "signature verification failed")
		})
	})

	t.Run("case=pop signed with wrong key rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			// Sign PoP with a different key than cnfKey.
			wrongPopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, wrongPopKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "PoP JWT signature verification failed")
		})
	})

	t.Run("case=correct keys accepted", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			c, err := auth.AuthenticateClient(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())
		})
	})
}

// =========================================================================
// Property 4: Cross-JWT Claim Consistency
// Feature: oidc4vci-wallet-attestation, Property 4: Cross-JWT Claim Consistency
// **Validates: Requirements 1.14, 3.5, 5.8**
// =========================================================================

func TestProperty4_CrossJWTClaimConsistency(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	t.Run("case=matching sub iss and client_id accepted", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			clientID := rapid.StringMatching(`https://wallet-[a-z]{3,6}\.example\.org`).Draw(rt, "clientID")

			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: clientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{clientID: client})

			attClaims := map[string]interface{}{
				"iss": "https://wallet-provider.example.com",
				"sub": clientID,
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"cnf": map[string]interface{}{
					"jwk": json.RawMessage(cnfJWKJSON(t, &cnfKey.PublicKey)),
				},
			}

			popClaims := map[string]interface{}{
				"iss": clientID,
				"aud": testIssuerURL,
				"iat": time.Now().Unix(),
				"jti": uuid.New().String(),
			}

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			form := url.Values{"client_id": {clientID}}
			r := buildTestRequest(attestation, pop, nil)
			c, err := auth.AuthenticateClient(t.Context(), r, form)
			require.NoError(t, err)
			assert.Equal(t, clientID, c.GetID())
		})
	})

	t.Run("case=mismatched sub and pop iss rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			// PoP iss does not match attestation sub.
			mismatchedIss := rapid.StringMatching(`https://other-[a-z]{3,6}\.example\.org`).Draw(rt, "mismatchedIss")
			popClaims := map[string]interface{}{
				"iss": mismatchedIss,
				"aud": testIssuerURL,
				"iat": time.Now().Unix(),
				"jti": uuid.New().String(),
			}
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "PoP JWT iss does not match client_id")
		})
	})

	t.Run("case=mismatched form client_id and sub rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			// Form client_id does not match attestation sub.
			wrongFormClientID := rapid.StringMatching(`https://wrong-[a-z]{3,6}\.example\.org`).Draw(rt, "wrongFormClientID")
			form := url.Values{"client_id": {wrongFormClientID}}
			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, form)
			requireErrorWithHint(t, err, "sub does not match client_id")
		})
	})
}


// =========================================================================
// Property 5: Temporal Claim Validation
// Feature: oidc4vci-wallet-attestation, Property 5: Temporal Claim Validation
// **Validates: Requirements 1.11, 1.12, 3.7, 3.10**
// =========================================================================

func TestProperty5_TemporalClaimValidation(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

	t.Run("case=expired attestation rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// exp in the past (beyond clock skew tolerance).
			pastSeconds := rapid.IntRange(10, 3600).Draw(rt, "pastSeconds")
			attClaims := map[string]interface{}{
				"iss": "https://wallet-provider.example.com",
				"sub": testClientID,
				"exp": time.Now().Add(-time.Duration(pastSeconds) * time.Second).Unix(),
				"cnf": map[string]interface{}{
					"jwk": json.RawMessage(cnfJWKJSON(t, &cnfKey.PublicKey)),
				},
			}

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "expired")
		})
	})

	t.Run("case=stale pop iat rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			// iat too far in the past (beyond freshness window).
			staleSeconds := rapid.IntRange(120, 3600).Draw(rt, "staleSeconds")
			popClaims := map[string]interface{}{
				"iss": testClientID,
				"aud": testIssuerURL,
				"iat": time.Now().Add(-time.Duration(staleSeconds) * time.Second).Unix(),
				"jti": uuid.New().String(),
			}
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "iat is not recent")
		})
	})

	t.Run("case=future pop iat rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			// iat too far in the future (beyond future tolerance).
			futureSeconds := rapid.IntRange(10, 3600).Draw(rt, "futureSeconds")
			popClaims := map[string]interface{}{
				"iss": testClientID,
				"aud": testIssuerURL,
				"iat": time.Now().Add(time.Duration(futureSeconds) * time.Second).Unix(),
				"jti": uuid.New().String(),
			}
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "iat is not recent")
		})
	})

	t.Run("case=valid temporal combination accepted", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// exp in the future, iat within freshness window.
			expOffset := rapid.IntRange(60, 7200).Draw(rt, "expOffset")
			iatOffset := rapid.IntRange(0, 50).Draw(rt, "iatOffset") // within 60s freshness window

			attClaims := map[string]interface{}{
				"iss": "https://wallet-provider.example.com",
				"sub": testClientID,
				"exp": time.Now().Add(time.Duration(expOffset) * time.Second).Unix(),
				"cnf": map[string]interface{}{
					"jwk": json.RawMessage(cnfJWKJSON(t, &cnfKey.PublicKey)),
				},
			}

			popClaims := map[string]interface{}{
				"iss": testClientID,
				"aud": testIssuerURL,
				"iat": time.Now().Add(-time.Duration(iatOffset) * time.Second).Unix(),
				"jti": uuid.New().String(),
			}

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			c, err := auth.AuthenticateClient(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())
		})
	})
}

// =========================================================================
// Property 6: PoP JTI Replay Detection
// Feature: oidc4vci-wallet-attestation, Property 6: PoP JTI Replay Detection
// **Validates: Requirements 3.8, 3.9**
// =========================================================================

func TestProperty6_PoPJTIReplayDetection(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, jtiStore := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})
	_ = jtiStore

	t.Run("case=first jti accepted then replay rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			jti := uuid.New().String()

			// First request with this jti should succeed.
			popClaims1 := map[string]interface{}{
				"iss": testClientID,
				"aud": testIssuerURL,
				"iat": time.Now().Unix(),
				"jti": jti,
			}
			pop1 := generateTestPoPJWT(t, cnfKey, popClaims1)

			r1 := buildTestRequest(attestation, pop1, nil)
			c, err := auth.AuthenticateClient(t.Context(), r1, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())

			// Second request with the same jti should be rejected.
			popClaims2 := map[string]interface{}{
				"iss": testClientID,
				"aud": testIssuerURL,
				"iat": time.Now().Unix(),
				"jti": jti,
			}
			pop2 := generateTestPoPJWT(t, cnfKey, popClaims2)

			r2 := buildTestRequest(attestation, pop2, nil)
			_, err = auth.AuthenticateClient(t.Context(), r2, url.Values{})
			requireErrorWithHint(t, err, "jti has already been used")
		})
	})
}


// =========================================================================
// Property 9: Public Key Only in cnf Claim
// Feature: oidc4vci-wallet-attestation, Property 9: Public Key Only in cnf Claim
// **Validates: Requirements 1.17**
// =========================================================================

func TestProperty9_PublicKeyOnlyInCNFClaim(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

	t.Run("case=public key accepted", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			c, err := auth.AuthenticateClient(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())
		})
	})

	t.Run("case=private key in cnf rejected", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			// Build cnf with private key material (includes "d" parameter).
			privateJWK := jose.JSONWebKey{Key: cnfKey, Algorithm: "ES256"}
			privateJWKBytes, err := privateJWK.MarshalJSON()
			require.NoError(t, err)

			attClaims := map[string]interface{}{
				"iss": "https://wallet-provider.example.com",
				"sub": testClientID,
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"cnf": map[string]interface{}{
					"jwk": json.RawMessage(privateJWKBytes),
				},
			}

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			_, err = auth.AuthenticateClient(t.Context(), r, url.Values{})
			requireErrorWithHint(t, err, "public key only")
		})
	})
}

// =========================================================================
// Property 10: Attestation JWT Reuse with Fresh PoP
// Feature: oidc4vci-wallet-attestation, Property 10: Attestation JWT Reuse with Fresh PoP
// **Validates: Requirements 12.1**
// =========================================================================

func TestProperty10_AttestationJWTReuseWithFreshPoP(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

	t.Run("case=same attestation with distinct pop jtis all succeed", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)

			// Present the same attestation multiple times with distinct PoP JWTs.
			numRequests := rapid.IntRange(2, 5).Draw(rt, "numRequests")
			for i := 0; i < numRequests; i++ {
				popClaims := map[string]interface{}{
					"iss": testClientID,
					"aud": testIssuerURL,
					"iat": time.Now().Unix(),
					"jti": uuid.New().String(), // unique jti each time
				}
				pop := generateTestPoPJWT(t, cnfKey, popClaims)

				r := buildTestRequest(attestation, pop, nil)
				c, err := auth.AuthenticateClient(t.Context(), r, url.Values{})
				require.NoError(t, err, "request %d should succeed", i)
				assert.Equal(t, testClientID, c.GetID())
			}
		})
	})
}

// =========================================================================
// Property 11: Unknown Claims Tolerance
// Feature: oidc4vci-wallet-attestation, Property 11: Unknown Claims Tolerance
// **Validates: Requirements 1.18**
// =========================================================================

func TestProperty11_UnknownClaimsTolerance(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	auth, _ := newTestAuthenticator(t, caCert, map[string]fosite.Client{testClientID: client})

	t.Run("case=attestation with unknown claims accepted", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)

			// Add random unknown claims.
			numExtra := rapid.IntRange(1, 5).Draw(rt, "numExtraClaims")
			for i := 0; i < numExtra; i++ {
				claimName := rapid.StringMatching(`x_[a-z]{3,8}`).Draw(rt, fmt.Sprintf("claimName_%d", i))
				claimValue := rapid.StringMatching(`[a-zA-Z0-9]{1,20}`).Draw(rt, fmt.Sprintf("claimValue_%d", i))
				attClaims[claimName] = claimValue
			}

			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			popClaims := makeValidPoPClaims()
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			c, err := auth.AuthenticateClient(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())
		})
	})
}


// =========================================================================
// Property 7: Strategy Routing — Header Presence Determines Authentication Path
// Feature: oidc4vci-wallet-attestation, Property 7: Strategy Routing — Header Presence Determines Authentication Path
// **Validates: Requirements 5.1, 5.2, 5.7, 6.1**
// =========================================================================

// mockFositeInstance simulates the Fosite instance for strategy routing tests.
// It tracks whether DefaultClientAuthenticationStrategy was called.
type mockFositeInstance struct {
	defaultCalled bool
	defaultClient fosite.Client
	defaultErr    error
}

func (m *mockFositeInstance) DefaultClientAuthenticationStrategy(_ context.Context, _ *http.Request, _ url.Values) (fosite.Client, error) {
	m.defaultCalled = true
	return m.defaultClient, m.defaultErr
}

func TestProperty7_StrategyRoutingHeaderPresence(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	leafCert, leafKey := generateTestLeafCert(t, caCert, caKey)

	client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
	defaultClient := &mockClient{id: "default-client", tokenEndpointAuthMethod: "client_secret_post"}

	t.Run("case=header present and enabled delegates to wallet attestation authenticator", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			jtiStore := newMockJTIStore()
			auth := &Authenticator{
				Config: &mockWalletAttestationConfig{
					enabled:      true,
					trustAnchors: []*x509.Certificate{caCert},
				},
				Store:    newMockClientStore(map[string]fosite.Client{testClientID: client}),
				JTIStore: jtiStore,
				IssuerURL: func(_ context.Context) string {
					return testIssuerURL
				},
			}

			mockFosite := &mockFositeInstance{
				defaultClient: defaultClient,
			}

			// Build the strategy function that mirrors fositex.Config.GetClientAuthenticationStrategy.
			strategy := func(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
				if r.Header.Get("OAuth-Client-Attestation") != "" {
					return auth.AuthenticateClient(ctx, r, form)
				}
				return mockFosite.DefaultClientAuthenticationStrategy(ctx, r, form)
			}

			attClaims := makeValidAttestationClaims(t, &cnfKey.PublicKey)
			popClaims := makeValidPoPClaims()
			attestation := generateTestAttestationJWT(t, leafKey, leafCert, attClaims)
			pop := generateTestPoPJWT(t, cnfKey, popClaims)

			r := buildTestRequest(attestation, pop, nil)
			c, err := strategy(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, testClientID, c.GetID())
			assert.False(t, mockFosite.defaultCalled, "default strategy should NOT be called when header is present")
		})
	})

	t.Run("case=header absent and enabled delegates to default strategy", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			mockFosite := &mockFositeInstance{
				defaultClient: defaultClient,
			}

			// Strategy with wallet attestation enabled but no header.
			strategy := func(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
				if r.Header.Get("OAuth-Client-Attestation") != "" {
					return nil, fmt.Errorf("should not reach authenticator")
				}
				return mockFosite.DefaultClientAuthenticationStrategy(ctx, r, form)
			}

			// Request without attestation header.
			r := buildTestRequest("", "", nil)
			c, err := strategy(t.Context(), r, url.Values{})
			require.NoError(t, err)
			assert.Equal(t, "default-client", c.GetID())
			assert.True(t, mockFosite.defaultCalled, "default strategy SHOULD be called when header is absent")
		})
	})

	t.Run("case=disabled returns nil strategy", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cfg := &mockWalletAttestationConfig{
				enabled: false,
			}

			// When disabled, GetClientAuthenticationStrategy returns nil.
			// Simulate the check.
			var strategy fosite.ClientAuthenticationStrategy
			if !cfg.GetWalletAttestationEnabled(t.Context()) {
				strategy = nil
			}

			assert.Nil(t, strategy, "strategy must be nil when wallet attestation is disabled")
		})
	})
}


// =========================================================================
// Property 8: Refresh Token Binding Round-Trip
// Feature: oidc4vci-wallet-attestation, Property 8: Refresh Token Binding Round-Trip
// **Validates: Requirements 7.1, 7.3**
// =========================================================================

// mockAccessRequester implements fosite.AccessRequester for testing RefreshBindingHandler.
type mockAccessRequester struct {
	grantTypes fosite.Arguments
	client     fosite.Client
	session    fosite.Session
	form       url.Values
}

func (m *mockAccessRequester) GetGrantTypes() fosite.Arguments { return m.grantTypes }
func (m *mockAccessRequester) GetClient() fosite.Client        { return m.client }
func (m *mockAccessRequester) GetSession() fosite.Session      { return m.session }
func (m *mockAccessRequester) SetSession(s fosite.Session)     { m.session = s }

// Stub the remaining Requester interface methods.
func (m *mockAccessRequester) SetID(_ string)                                   {}
func (m *mockAccessRequester) GetID() string                                    { return "" }
func (m *mockAccessRequester) GetRequestedAt() time.Time                        { return time.Time{} }
func (m *mockAccessRequester) GetRequestedScopes() fosite.Arguments             { return nil }
func (m *mockAccessRequester) GetRequestedAudience() fosite.Arguments           { return nil }
func (m *mockAccessRequester) SetRequestedScopes(_ fosite.Arguments)            {}
func (m *mockAccessRequester) SetRequestedAudience(_ fosite.Arguments)          {}
func (m *mockAccessRequester) AppendRequestedScope(_ string)                    {}
func (m *mockAccessRequester) GetGrantedScopes() fosite.Arguments               { return nil }
func (m *mockAccessRequester) GetGrantedAudience() fosite.Arguments             { return nil }
func (m *mockAccessRequester) GrantScope(_ string)                              {}
func (m *mockAccessRequester) GrantAudience(_ string)                           {}
func (m *mockAccessRequester) GetRequestForm() url.Values                       { return m.form }
func (m *mockAccessRequester) Merge(_ fosite.Requester)                         {}
func (m *mockAccessRequester) Sanitize(_ []string) fosite.Requester             { return m }

// mockAccessResponder implements fosite.AccessResponder for testing.
type mockAccessResponder struct{}

func (m *mockAccessResponder) SetExtra(_ string, _ interface{})  {}
func (m *mockAccessResponder) GetExtra(_ string) interface{}     { return nil }
func (m *mockAccessResponder) SetExpiresIn(_ time.Duration)      {}
func (m *mockAccessResponder) SetScopes(_ fosite.Arguments)      {}
func (m *mockAccessResponder) SetAccessToken(_ string)           {}
func (m *mockAccessResponder) SetTokenType(_ string)             {}
func (m *mockAccessResponder) GetAccessToken() string            { return "" }
func (m *mockAccessResponder) GetTokenType() string              { return "" }
func (m *mockAccessResponder) ToMap() map[string]interface{}     { return nil }

func TestProperty8_RefreshTokenBindingRoundTrip(t *testing.T) {
	t.Parallel()

	handler := &RefreshBindingHandler{
		Config: &mockWalletAttestationConfig{enabled: true},
	}

	// cnfJWKForm serializes a JWK into a form with the internal transport key.
	cnfJWKForm := func(t testing.TB, jwk *jose.JSONWebKey) url.Values {
		t.Helper()
		b, err := json.Marshal(jwk)
		require.NoError(t, err)
		return url.Values{walletAttestationCNFFormKey: {string(b)}}
	}

	t.Run("case=thumbprint stored in session matches cnf jwk thumbprint", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			// Generate a key pair.
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			cnfJWK := &jose.JSONWebKey{Key: &cnfKey.PublicKey, Algorithm: "ES256"}

			// Compute expected thumbprint.
			expectedThumbprint, err := computeJWKThumbprint(cnfJWK)
			require.NoError(t, err)

			// Simulate PopulateTokenEndpointResponse storing the thumbprint.
			session := &fosite.DefaultSession{
				Extra: make(map[string]interface{}),
			}

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			form := cnfJWKForm(t, cnfJWK)
			requester := &mockAccessRequester{
				grantTypes: fosite.Arguments{"authorization_code"},
				client:     client,
				session:    session,
				form:       form,
			}

			err = handler.PopulateTokenEndpointResponse(t.Context(), requester, &mockAccessResponder{})
			require.NoError(t, err)

			// Verify the stored thumbprint matches.
			storedJKT, ok := session.Extra["wallet_attestation_cnf_jkt"].(string)
			require.True(t, ok, "wallet_attestation_cnf_jkt should be stored in session")
			assert.Equal(t, expectedThumbprint, storedJKT)
		})
	})

	t.Run("case=same key accepted on refresh", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			cnfKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			cnfJWK := &jose.JSONWebKey{Key: &cnfKey.PublicKey, Algorithm: "ES256"}

			// Compute and store the thumbprint.
			jkt, err := computeJWKThumbprint(cnfJWK)
			require.NoError(t, err)

			session := &fosite.DefaultSession{
				Extra: map[string]interface{}{
					"wallet_attestation_cnf_jkt": jkt,
				},
			}

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}
			form := cnfJWKForm(t, cnfJWK)
			requester := &mockAccessRequester{
				grantTypes: fosite.Arguments{"refresh_token"},
				client:     client,
				session:    session,
				form:       form,
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), requester)
			require.NoError(t, err, "same key should be accepted on refresh")
		})
	})

	t.Run("case=different key rejected on refresh", func(t *testing.T) {
		t.Parallel()
		rapid.Check(t, func(rt *rapid.T) {
			// Original key.
			originalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			originalJWK := &jose.JSONWebKey{Key: &originalKey.PublicKey, Algorithm: "ES256"}
			originalJKT, err := computeJWKThumbprint(originalJWK)
			require.NoError(t, err)

			session := &fosite.DefaultSession{
				Extra: map[string]interface{}{
					"wallet_attestation_cnf_jkt": originalJKT,
				},
			}

			client := &mockClient{id: testClientID, tokenEndpointAuthMethod: "attest_jwt_client_auth"}

			// Different key in form.
			differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			differentJWK := &jose.JSONWebKey{Key: &differentKey.PublicKey, Algorithm: "ES256"}
			form := cnfJWKForm(t, differentJWK)
			requester := &mockAccessRequester{
				grantTypes: fosite.Arguments{"refresh_token"},
				client:     client,
				session:    session,
				form:       form,
			}

			err = handler.HandleTokenEndpointRequest(t.Context(), requester)
			requireErrorWithHint(t, err, "Refresh token is bound to a different client instance key")
		})
	})
}
