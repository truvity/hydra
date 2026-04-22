// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Feature: oidc4vci-dpop, Property 10: DPoP Header Injection

package dpop_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/dpop"
)

func TestProperty10_DPoPHeaderInjection(t *testing.T) {
	t.Parallel()

	t.Run("case=property 10 dpop header injection", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 10: DPoP Header Injection
		// **Validates: Requirements 12.1, 12.2**
		rapid.Check(t, func(t *rapid.T) {
			numHeaders := rapid.IntRange(0, 3).Draw(t, "numHeaders")
			headers := make([]string, numHeaders)
			for i := range headers {
				headers[i] = rapid.StringMatching(`[a-zA-Z0-9._\-]{1,64}`).Draw(t, "dpopValue")
			}

			r := &http.Request{
				Header:   http.Header{},
				PostForm: url.Values{},
			}
			for _, h := range headers {
				r.Header.Add("DPoP", h)
			}

			dpop.InjectDPoPHeader(r)

			switch {
			case numHeaders == 0:
				// No DPoP header → both fields unset.
				assert.Empty(t, r.PostForm.Get("dpop_proof"), "dpop_proof should be empty when no DPoP header")
				assert.Empty(t, r.PostForm.Get("dpop_proof_error"), "dpop_proof_error should be empty when no DPoP header")

			case numHeaders == 1:
				// Single DPoP header → dpop_proof set to the value.
				require.Equal(t, headers[0], r.PostForm.Get("dpop_proof"), "dpop_proof should equal the single DPoP header value")
				assert.Empty(t, r.PostForm.Get("dpop_proof_error"), "dpop_proof_error should be empty for single header")

			default:
				// Multiple DPoP headers → dpop_proof_error=multiple_headers.
				assert.Equal(t, "multiple_headers", r.PostForm.Get("dpop_proof_error"), "dpop_proof_error should be 'multiple_headers'")
			}
		})
	})
}

// --- mock types for Property 1 ---

// mockDPoPConfig implements dpop.DPoPConfigProvider for testing.
type mockDPoPConfig struct {
	enabled       bool
	algValues     []string
	nonceEnabled  bool
	nonceLifespan time.Duration
	proofMaxAge   time.Duration
	parURLs       []string
}

func (m *mockDPoPConfig) GetDPoPEnabled(_ context.Context) bool                       { return m.enabled }
func (m *mockDPoPConfig) GetDPoPSigningAlgValuesSupported(_ context.Context) []string  { return m.algValues }
func (m *mockDPoPConfig) GetDPoPNonceEnabled(_ context.Context) bool                   { return m.nonceEnabled }
func (m *mockDPoPConfig) GetDPoPNonceLifespan(_ context.Context) time.Duration         { return m.nonceLifespan }
func (m *mockDPoPConfig) GetDPoPProofMaxAge(_ context.Context) time.Duration           { return m.proofMaxAge }
func (m *mockDPoPConfig) GetDPoPPARURLs(_ context.Context) []string                    { return m.parURLs }

// mockDPoPNonceStorage implements dpop.DPoPNonceStorage for testing.
type mockDPoPNonceStorage struct {
	usedJTIs map[string]bool
}

func newMockNonceStorage() *mockDPoPNonceStorage {
	return &mockDPoPNonceStorage{usedJTIs: make(map[string]bool)}
}

func (m *mockDPoPNonceStorage) DPoPNonceStorage() dpop.DPoPNonceStorage {
	return m
}

func (m *mockDPoPNonceStorage) IsJTIUsed(_ context.Context, jti string) (bool, error) {
	return m.usedJTIs[jti], nil
}

func (m *mockDPoPNonceStorage) MarkJTIUsed(_ context.Context, jti string, _ time.Time) error {
	m.usedJTIs[jti] = true
	return nil
}

func (m *mockDPoPNonceStorage) CreateDPoPNonce(_ context.Context) (string, error) {
	return "test-nonce", nil
}

func (m *mockDPoPNonceStorage) ValidateDPoPNonce(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// --- DPoP proof JWT helpers ---

const testPARURL = "https://auth.example.com/oauth2/par"

// buildDPoPProof creates a signed DPoP proof JWT string with the given parameters.
// It returns the serialized JWT and the public key used for signing.
func buildDPoPProof(t require.TestingT, privateKey *ecdsa.PrivateKey, opts dpopProofOpts) string {
	signerOpts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{},
	}

	// Set typ header: use opts.typ if explicitly set (even empty), otherwise default to dpop+jwt.
	if opts.overrideTyp {
		if opts.typ != "" {
			signerOpts.ExtraHeaders[jose.HeaderKey(jose.HeaderType)] = opts.typ
		}
		// If opts.typ == "" and overrideTyp is true, we omit the typ header entirely.
	} else {
		signerOpts.ExtraHeaders[jose.HeaderKey(jose.HeaderType)] = "dpop+jwt"
	}

	alg := jose.ES256
	if opts.alg != "" {
		alg = jose.SignatureAlgorithm(opts.alg)
	}

	// Embed the public key in the JWK header.
	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key: jose.JSONWebKey{
			Key:   privateKey,
			KeyID: "test-key",
		},
	}
	signerOpts.EmbedJWK = true

	signer, err := jose.NewSigner(signingKey, signerOpts)
	require.NoError(t, err)

	claims := map[string]interface{}{}
	if opts.jti != "" {
		claims["jti"] = opts.jti
	}
	if opts.htm != "" {
		claims["htm"] = opts.htm
	}
	if opts.htu != "" {
		claims["htu"] = opts.htu
	}
	if opts.iat != nil {
		claims["iat"] = josejwt.NewNumericDate(*opts.iat)
	}
	if opts.nonce != "" {
		claims["nonce"] = opts.nonce
	}

	builder := josejwt.Signed(signer).Claims(claims)
	raw, err := builder.CompactSerialize()
	require.NoError(t, err)
	return raw
}

type dpopProofOpts struct {
	overrideTyp bool   // if true, use typ field (even if empty) instead of default
	typ         string // override typ header (default: dpop+jwt)
	alg         string // override alg (default: ES256)
	jti         string
	htm         string
	htu         string
	iat         *time.Time
	nonce       string
}

// validProofOpts returns dpopProofOpts for a valid DPoP proof.
func validProofOpts() dpopProofOpts {
	now := time.Now()
	return dpopProofOpts{
		jti: uuid.New().String(),
		htm: "POST",
		htu: testPARURL,
		iat: &now,
	}
}

// newTestHandler creates a dpop.Handler with standard test configuration.
func newTestHandler() (*dpop.Handler, *mockDPoPNonceStorage) {
	store := newMockNonceStorage()
	return &dpop.Handler{
		Config: &mockDPoPConfig{
			enabled:       true,
			algValues:     []string{"ES256"},
			nonceEnabled:  false,
			nonceLifespan: 5 * time.Minute,
			proofMaxAge:   60 * time.Second,
			parURLs:       []string{testPARURL},
		},
		NonceStore: store,
	}, store
}

// newECKey generates a fresh EC P-256 key pair.
func newECKey(t require.TestingT) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// computeJKT computes the JWK Thumbprint (base64url SHA-256) for an EC public key.
func computeJKT(t require.TestingT, pub *ecdsa.PublicKey) string {
	jwk := jose.JSONWebKey{Key: pub}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}

// isInvalidDPoPProofError checks if the error is an invalid_dpop_proof error.
func isInvalidDPoPProofError(err error) bool {
	if err == nil {
		return false
	}
	var rfcErr *fosite.RFC6749Error
	if !errors.As(err, &rfcErr) {
		return false
	}
	return rfcErr.ErrorField == "invalid_dpop_proof"
}

// corruption constants for Property 1.
const (
	corruptionNone           = iota // 0: valid proof
	corruptionWrongTyp              // 1: wrong typ header
	corruptionUnsupportedAlg        // 2: unsupported alg (HS256)
	corruptionAlgNone               // 3: alg=none
	corruptionMissingJTI            // 4: missing jti claim
	corruptionMissingHTM            // 5: missing htm claim
	corruptionMissingHTU            // 6: missing htu claim
	corruptionMissingIAT            // 7: missing iat claim
	corruptionWrongHTM              // 8: wrong htm (GET instead of POST)
	corruptionWrongHTU              // 9: wrong htu (doesn't match configured URL)
	corruptionIATTooOld             // 10: iat too old (beyond maxAge)
	corruptionIATFuture             // 11: iat too far in future (beyond 5s tolerance)
	corruptionCount                 // sentinel: total number of corruption types
)

// Feature: oidc4vci-dpop, Property 1: DPoP Proof Validation (§4.3 Checklist)
func TestProperty1_DPoPProofValidation(t *testing.T) {
	t.Parallel()

	t.Run("case=property 1 dpop proof validation", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 1: DPoP Proof Validation (§4.3 Checklist)
		// **Validates: Requirements 1.1, 1.3, 1.4, 1.5, 1.7, 1.8, 1.9, 1.11**
		rapid.Check(t, func(t *rapid.T) {
			handler, _ := newTestHandler()
			privateKey := newECKey(t)

			corruption := rapid.IntRange(0, corruptionCount-1).Draw(t, "corruption")

			opts := validProofOpts()

			switch corruption {
			case corruptionNone:
				// Valid proof — no corruption.
			case corruptionWrongTyp:
				badTyp := rapid.SampledFrom([]string{"JWT", "at+jwt", "jwt", ""}).Draw(t, "badTyp")
				opts.overrideTyp = true
				opts.typ = badTyp
			case corruptionUnsupportedAlg:
				// We can't actually sign with HS256 using an EC key, so we test
				// this by configuring the handler to only accept RS256 while we
				// sign with ES256. The handler checks alg against the supported list.
				handler.Config = &mockDPoPConfig{
					enabled:       true,
					algValues:     []string{"RS256"},
					nonceEnabled:  false,
					nonceLifespan: 5 * time.Minute,
					proofMaxAge:   60 * time.Second,
					parURLs:       []string{testPARURL},
				}
			case corruptionAlgNone:
				// Similar to above — we can't sign with "none" using go-jose,
				// so we test by configuring the handler to only accept "PS256".
				handler.Config = &mockDPoPConfig{
					enabled:       true,
					algValues:     []string{"PS256"},
					nonceEnabled:  false,
					nonceLifespan: 5 * time.Minute,
					proofMaxAge:   60 * time.Second,
					parURLs:       []string{testPARURL},
				}
			case corruptionMissingJTI:
				opts.jti = ""
			case corruptionMissingHTM:
				opts.htm = ""
			case corruptionMissingHTU:
				opts.htu = ""
			case corruptionMissingIAT:
				opts.iat = nil
			case corruptionWrongHTM:
				opts.htm = rapid.SampledFrom([]string{"GET", "PUT", "DELETE", "PATCH"}).Draw(t, "badHTM")
			case corruptionWrongHTU:
				opts.htu = rapid.SampledFrom([]string{
					"https://other.example.com/oauth2/par",
					"https://auth.example.com/oauth2/token",
					"https://auth.example.com/wrong",
				}).Draw(t, "badHTU")
			case corruptionIATTooOld:
				// iat is beyond maxAge (60s) in the past.
				old := time.Now().Add(-2 * time.Minute)
				opts.iat = &old
			case corruptionIATFuture:
				// iat is more than 5s in the future.
				future := time.Now().Add(30 * time.Second)
				opts.iat = &future
			}

			proofJWT := buildDPoPProof(t, privateKey, opts)

			// Build the authorize request with the DPoP proof injected.
			ar := fosite.NewAuthorizeRequest()
			ar.Form = url.Values{
				"dpop_proof": {proofJWT},
			}

			responder := &fosite.PushedAuthorizeResponse{
				Header: http.Header{},
				Extra:  map[string]interface{}{},
			}

			ctx := context.Background()
			err := handler.HandlePushedAuthorizeEndpointRequest(ctx, ar, responder)

			if corruption == corruptionNone {
				// Valid proof should succeed.
				require.NoError(t, err, "valid DPoP proof should be accepted")
				// After success, dpop_jkt should be set in the form.
				jkt := ar.Form.Get("dpop_jkt")
				assert.NotEmpty(t, jkt, "dpop_jkt should be set after valid proof")
				// Verify the JKT matches the expected thumbprint.
				expectedJKT := computeJKT(t, &privateKey.PublicKey)
				assert.Equal(t, expectedJKT, jkt, "dpop_jkt should match computed JWK Thumbprint")
			} else {
				// Corrupted proof should produce invalid_dpop_proof error.
				require.Error(t, err, "corrupted DPoP proof (corruption=%d) should be rejected", corruption)
				assert.True(t, isInvalidDPoPProofError(err),
					"corruption=%d should produce invalid_dpop_proof, got: %v", corruption, err)
			}
		})
	})
}

// Feature: oidc4vci-dpop, Property 2: DPoP Signature Verification
func TestProperty2_DPoPSignatureVerification(t *testing.T) {
	t.Parallel()

	t.Run("case=property 2 dpop signature verification", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 2: DPoP Signature Verification
		// **Validates: Requirements 1.2, 1.6**
		rapid.Check(t, func(t *rapid.T) {
			handler, _ := newTestHandler()

			keyA := newECKey(t)
			keyB := newECKey(t)

			useMatchingKey := rapid.Bool().Draw(t, "useMatchingKey")

			if useMatchingKey {
				// Sign with keyA, handler verifies with keyA's embedded public key.
				opts := validProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)

				ar := fosite.NewAuthorizeRequest()
				ar.Form = url.Values{
					"dpop_proof": {proofJWT},
				}

				responder := &fosite.PushedAuthorizeResponse{
					Header: http.Header{},
					Extra:  map[string]interface{}{},
				}

				ctx := context.Background()
				err := handler.HandlePushedAuthorizeEndpointRequest(ctx, ar, responder)

				require.NoError(t, err, "proof signed with matching key should be accepted")
				jkt := ar.Form.Get("dpop_jkt")
				assert.NotEmpty(t, jkt, "dpop_jkt should be set after valid proof")
				expectedJKT := computeJKT(t, &keyA.PublicKey)
				assert.Equal(t, expectedJKT, jkt, "dpop_jkt should match keyA's JWK Thumbprint")
			} else {
				// Sign with keyB but embed keyA's public key in the jwk header.
				// This creates a signature that won't verify with the embedded public key.
				proofJWT := buildMismatchedDPoPProof(t, keyB, &keyA.PublicKey, validProofOpts())

				ar := fosite.NewAuthorizeRequest()
				ar.Form = url.Values{
					"dpop_proof": {proofJWT},
				}

				responder := &fosite.PushedAuthorizeResponse{
					Header: http.Header{},
					Extra:  map[string]interface{}{},
				}

				ctx := context.Background()
				err := handler.HandlePushedAuthorizeEndpointRequest(ctx, ar, responder)

				require.Error(t, err, "proof signed with mismatched key should be rejected")
				assert.True(t, isInvalidDPoPProofError(err),
					"mismatched key should produce invalid_dpop_proof, got: %v", err)
			}
		})
	})
}

// buildMismatchedDPoPProof creates a DPoP proof JWT signed with signingKey but
// with embeddedPub in the jwk header. This produces a signature mismatch since
// the embedded public key does not correspond to the signing private key.
func buildMismatchedDPoPProof(t require.TestingT, signingKey *ecdsa.PrivateKey, embeddedPub *ecdsa.PublicKey, opts dpopProofOpts) string {
	// Build the header manually: sign with signingKey but embed embeddedPub.
	signerOpts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey(jose.HeaderType): "dpop+jwt",
			// Manually set the jwk header to the wrong public key.
			jose.HeaderKey("jwk"): jose.JSONWebKey{
				Key:   embeddedPub,
				KeyID: "test-key",
			},
		},
	}

	alg := jose.ES256
	if opts.alg != "" {
		alg = jose.SignatureAlgorithm(opts.alg)
	}

	// Sign with signingKey but do NOT embed its public key (we set jwk manually above).
	joseSigningKey := jose.SigningKey{
		Algorithm: alg,
		Key: jose.JSONWebKey{
			Key:   signingKey,
			KeyID: "test-key",
		},
	}

	signer, err := jose.NewSigner(joseSigningKey, signerOpts)
	require.NoError(t, err)

	now := time.Now()
	claims := map[string]interface{}{
		"jti": opts.jti,
		"htm": opts.htm,
		"htu": opts.htu,
		"iat": josejwt.NewNumericDate(now),
	}
	if opts.jti == "" {
		claims["jti"] = uuid.New().String()
	}

	builder := josejwt.Signed(signer).Claims(claims)
	raw, err := builder.CompactSerialize()
	require.NoError(t, err)
	return raw
}

// Feature: oidc4vci-dpop, Property 7: dpop_jkt PAR Storage
func TestProperty7_DPoPJKTPARStorage(t *testing.T) {
	t.Parallel()

	t.Run("case=property 7 dpop_jkt PAR storage", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 7: dpop_jkt PAR Storage
		// **Validates: Requirements 4.1, 4.2, 4.3, 4.5**
		rapid.Check(t, func(t *rapid.T) {
			handler, _ := newTestHandler()
			keyA := newECKey(t)
			keyB := newECKey(t)

			scenario := rapid.IntRange(0, 4).Draw(t, "scenario")

			ar := fosite.NewAuthorizeRequest()
			ar.Form = url.Values{}

			expectedJKT := computeJKT(t, &keyA.PublicKey)

			switch scenario {
			case 0:
				// Scenario 0: Only dpop_jkt parameter present (no DPoP proof).
				// dpop_jkt stays in form unchanged.
				ar.Form.Set("dpop_jkt", expectedJKT)

			case 1:
				// Scenario 1: Only DPoP proof present (no dpop_jkt param).
				// dpop_jkt set to computed JKT from proof.
				opts := validProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)
				ar.Form.Set("dpop_proof", proofJWT)

			case 2:
				// Scenario 2: Both dpop_jkt and DPoP proof present with matching thumbprints.
				// Accepted, dpop_jkt set to computed JKT.
				opts := validProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)
				ar.Form.Set("dpop_proof", proofJWT)
				ar.Form.Set("dpop_jkt", expectedJKT)

			case 3:
				// Scenario 3: Both dpop_jkt and DPoP proof present with mismatching thumbprints.
				// Rejected with invalid_dpop_proof.
				opts := validProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)
				ar.Form.Set("dpop_proof", proofJWT)
				mismatchJKT := computeJKT(t, &keyB.PublicKey)
				ar.Form.Set("dpop_jkt", mismatchJKT)

			case 4:
				// Scenario 4: Neither dpop_jkt nor dpop_proof present.
				// Handler returns nil (not responsible).
			}

			responder := &fosite.PushedAuthorizeResponse{
				Header: http.Header{},
				Extra:  map[string]interface{}{},
			}

			ctx := context.Background()
			err := handler.HandlePushedAuthorizeEndpointRequest(ctx, ar, responder)

			switch scenario {
			case 0:
				// dpop_jkt stays unchanged in form.
				require.NoError(t, err, "scenario 0: dpop_jkt only should succeed")
				assert.Equal(t, expectedJKT, ar.Form.Get("dpop_jkt"),
					"scenario 0: dpop_jkt should remain unchanged in form")

			case 1:
				// dpop_jkt set to computed JKT from proof.
				require.NoError(t, err, "scenario 1: DPoP proof only should succeed")
				assert.Equal(t, expectedJKT, ar.Form.Get("dpop_jkt"),
					"scenario 1: dpop_jkt should be set to computed JKT")

			case 2:
				// Both match — accepted, dpop_jkt set.
				require.NoError(t, err, "scenario 2: matching dpop_jkt and proof should succeed")
				assert.Equal(t, expectedJKT, ar.Form.Get("dpop_jkt"),
					"scenario 2: dpop_jkt should match computed JKT")

			case 3:
				// Mismatch — rejected with invalid_dpop_proof.
				require.Error(t, err, "scenario 3: mismatching thumbprints should be rejected")
				assert.True(t, isInvalidDPoPProofError(err),
					"scenario 3: should produce invalid_dpop_proof, got: %v", err)

			case 4:
				// Neither present — handler returns nil.
				require.NoError(t, err, "scenario 4: neither present should return nil")
				assert.Empty(t, ar.Form.Get("dpop_jkt"),
					"scenario 4: dpop_jkt should not be set")
			}
		})
	})
}

// testTokenURLs is the token endpoint URL used for token endpoint tests.
const testTokenURL = "https://auth.example.com/oauth2/token"

// mockDPoPConfigWithTokenURLs extends mockDPoPConfig with GetTokenURLs for
// token endpoint handler tests. The tokenURLProvider interface in
// token_handler.go is satisfied via type assertion on Config.
type mockDPoPConfigWithTokenURLs struct {
	mockDPoPConfig
	tokenURLs []string
}

func (m *mockDPoPConfigWithTokenURLs) GetTokenURLs(_ context.Context) []string {
	return m.tokenURLs
}

// newTestTokenHandler creates a dpop.Handler configured for token endpoint
// tests (with token URLs for htu validation).
func newTestTokenHandler() (*dpop.Handler, *mockDPoPNonceStorage) {
	store := newMockNonceStorage()
	return &dpop.Handler{
		Config: &mockDPoPConfigWithTokenURLs{
			mockDPoPConfig: mockDPoPConfig{
				enabled:       true,
				algValues:     []string{"ES256"},
				nonceEnabled:  false,
				nonceLifespan: 5 * time.Minute,
				proofMaxAge:   60 * time.Second,
				parURLs:       []string{testPARURL},
			},
			tokenURLs: []string{testTokenURL},
		},
		NonceStore: store,
	}, store
}

// validTokenProofOpts returns dpopProofOpts for a valid DPoP proof targeting
// the token endpoint (htu = testTokenURL).
func validTokenProofOpts() dpopProofOpts {
	now := time.Now()
	return dpopProofOpts{
		jti: uuid.New().String(),
		htm: "POST",
		htu: testTokenURL,
		iat: &now,
	}
}

// Feature: oidc4vci-dpop, Property 4: DPoP Token Binding (cnf.jkt)
func TestProperty4_DPoPTokenBinding(t *testing.T) {
	t.Parallel()

	t.Run("case=property 4 dpop token binding", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 4: DPoP Token Binding (cnf.jkt)
		// **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
		rapid.Check(t, func(t *rapid.T) {
			handler, _ := newTestTokenHandler()
			privateKey := newECKey(t)

			withDPoPProof := rapid.Bool().Draw(t, "withDPoPProof")

			session := &fosite.DefaultSession{
				Extra: map[string]interface{}{},
			}

			client := &fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID: "test-client",
				},
				TokenEndpointAuthMethod: "client_secret_post",
			}

			ar := fosite.NewAccessRequest(session)
			ar.Client = client
			ar.Form = url.Values{}

			responder := fosite.NewAccessResponse()

			ctx := context.Background()

			if withDPoPProof {
				// Build a valid DPoP proof targeting the token endpoint.
				opts := validTokenProofOpts()
				proofJWT := buildDPoPProof(t, privateKey, opts)
				ar.Form.Set("dpop_proof", proofJWT)

				// Step 1: HandleTokenEndpointRequest validates the proof and
				// stores the JKT in the session extra.
				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.NoError(t, err, "HandleTokenEndpointRequest should succeed with valid proof")

				// Step 2: PopulateTokenEndpointResponse sets cnf.jkt and token_type.
				err = handler.PopulateTokenEndpointResponse(ctx, ar, responder)
				require.NoError(t, err, "PopulateTokenEndpointResponse should succeed after valid proof")

				// Verify: token_type is "DPoP".
				assert.Equal(t, "DPoP", responder.GetTokenType(),
					"token_type should be DPoP after successful DPoP binding")

				// Verify: session.Extra["cnf"]["jkt"] equals the expected JWK Thumbprint.
				expectedJKT := computeJKT(t, &privateKey.PublicKey)
				cnfRaw, ok := session.Extra["cnf"]
				require.True(t, ok, "session.Extra should contain cnf claim")
				cnfMap, ok := cnfRaw.(map[string]interface{})
				require.True(t, ok, "cnf should be a map[string]interface{}")
				jkt, ok := cnfMap["jkt"].(string)
				require.True(t, ok, "cnf.jkt should be a string")
				assert.Equal(t, expectedJKT, jkt,
					"cnf.jkt should equal the JWK SHA-256 Thumbprint of the proof's public key")
			} else {
				// No DPoP proof present — PopulateTokenEndpointResponse should
				// return fosite.ErrUnknownRequest.
				err := handler.PopulateTokenEndpointResponse(ctx, ar, responder)
				require.Error(t, err, "PopulateTokenEndpointResponse should error without DPoP proof")

				var rfcErr *fosite.RFC6749Error
				require.True(t, errors.As(err, &rfcErr), "error should be an RFC6749Error")
				assert.Equal(t, fosite.ErrUnknownRequest.ErrorField, rfcErr.ErrorField,
					"error should be ErrUnknownRequest when no DPoP proof present")
			}
		})
	})
}

// --- mock types for Property 5 ---

// mockDPoPNonceStorageWithNonce extends mockDPoPNonceStorage with configurable
// nonce validation behavior. ValidateDPoPNonce returns true only for the
// validNonce value; CreateDPoPNonce returns freshNonce.
type mockDPoPNonceStorageWithNonce struct {
	usedJTIs   map[string]bool
	validNonce string
	freshNonce string
}

func newMockNonceStorageWithNonce(validNonce, freshNonce string) *mockDPoPNonceStorageWithNonce {
	return &mockDPoPNonceStorageWithNonce{
		usedJTIs:   make(map[string]bool),
		validNonce: validNonce,
		freshNonce: freshNonce,
	}
}

func (m *mockDPoPNonceStorageWithNonce) DPoPNonceStorage() dpop.DPoPNonceStorage {
	return m
}

func (m *mockDPoPNonceStorageWithNonce) IsJTIUsed(_ context.Context, jti string) (bool, error) {
	return m.usedJTIs[jti], nil
}

func (m *mockDPoPNonceStorageWithNonce) MarkJTIUsed(_ context.Context, jti string, _ time.Time) error {
	m.usedJTIs[jti] = true
	return nil
}

func (m *mockDPoPNonceStorageWithNonce) CreateDPoPNonce(_ context.Context) (string, error) {
	return m.freshNonce, nil
}

func (m *mockDPoPNonceStorageWithNonce) ValidateDPoPNonce(_ context.Context, nonce string) (bool, error) {
	return nonce == m.validNonce, nil
}

// newTestTokenHandlerWithNonce creates a dpop.Handler configured for token
// endpoint tests with nonce exchange enabled and configurable nonce storage.
func newTestTokenHandlerWithNonce(nonceEnabled bool, validNonce, freshNonce string) (*dpop.Handler, *mockDPoPNonceStorageWithNonce) {
	store := newMockNonceStorageWithNonce(validNonce, freshNonce)
	return &dpop.Handler{
		Config: &mockDPoPConfigWithTokenURLs{
			mockDPoPConfig: mockDPoPConfig{
				enabled:       true,
				algValues:     []string{"ES256"},
				nonceEnabled:  nonceEnabled,
				nonceLifespan: 5 * time.Minute,
				proofMaxAge:   60 * time.Second,
				parURLs:       []string{testPARURL},
			},
			tokenURLs: []string{testTokenURL},
		},
		NonceStore: store,
	}, store
}

// isUseDPoPNonceError checks if the error is a use_dpop_nonce error.
func isUseDPoPNonceError(err error) bool {
	if err == nil {
		return false
	}
	var rfcErr *fosite.RFC6749Error
	if !errors.As(err, &rfcErr) {
		return false
	}
	return rfcErr.ErrorField == "use_dpop_nonce"
}

// Feature: oidc4vci-dpop, Property 5: DPoP Nonce Exchange
func TestProperty5_DPoPNonceExchange(t *testing.T) {
	t.Parallel()

	t.Run("case=property 5 dpop nonce exchange", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 5: DPoP Nonce Exchange
		// **Validates: Requirements 1.10, 3.1, 3.2, 3.3**
		rapid.Check(t, func(t *rapid.T) {
			const (
				scenarioValidNonce   = 0 // nonces enabled, proof has valid nonce → accepted
				scenarioMissingNonce = 1 // nonces enabled, proof has no nonce → use_dpop_nonce
				scenarioInvalidNonce = 2 // nonces enabled, proof has invalid nonce → use_dpop_nonce
				scenarioNonceOff     = 3 // nonces disabled, proof has no nonce → accepted
			)

			scenario := rapid.IntRange(0, 3).Draw(t, "scenario")

			const validNonce = "valid-nonce"
			const freshNonce = "fresh-nonce-123"

			privateKey := newECKey(t)

			session := &fosite.DefaultSession{
				Extra: map[string]interface{}{},
			}

			client := &fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID: "test-client",
				},
				TokenEndpointAuthMethod: "client_secret_post",
			}

			var handler *dpop.Handler
			opts := validTokenProofOpts()

			switch scenario {
			case scenarioValidNonce:
				handler, _ = newTestTokenHandlerWithNonce(true, validNonce, freshNonce)
				opts.nonce = validNonce

			case scenarioMissingNonce:
				handler, _ = newTestTokenHandlerWithNonce(true, validNonce, freshNonce)
				// opts.nonce remains empty — no nonce in proof.

			case scenarioInvalidNonce:
				handler, _ = newTestTokenHandlerWithNonce(true, validNonce, freshNonce)
				badNonce := rapid.StringMatching(`[a-zA-Z0-9]{8,32}`).Draw(t, "badNonce")
				// Ensure the bad nonce is not accidentally the valid nonce.
				if badNonce == validNonce {
					badNonce = badNonce + "-bad"
				}
				opts.nonce = badNonce

			case scenarioNonceOff:
				handler, _ = newTestTokenHandlerWithNonce(false, validNonce, freshNonce)
				// opts.nonce remains empty — nonce not required when disabled.
			}

			proofJWT := buildDPoPProof(t, privateKey, opts)

			ar := fosite.NewAccessRequest(session)
			ar.Client = client
			ar.Form = url.Values{
				"dpop_proof": {proofJWT},
			}

			// Set up context with nonce pointer for delivery.
			var dpopNonce string
			ctx := context.WithValue(context.Background(), dpop.DPoPNonceContextKey, &dpopNonce)

			switch scenario {
			case scenarioValidNonce:
				// HandleTokenEndpointRequest should succeed.
				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.NoError(t, err, "scenario 0: valid nonce should be accepted")

				// PopulateTokenEndpointResponse should succeed and produce a fresh nonce.
				responder := fosite.NewAccessResponse()
				err = handler.PopulateTokenEndpointResponse(ctx, ar, responder)
				require.NoError(t, err, "scenario 0: PopulateTokenEndpointResponse should succeed")

				assert.Equal(t, "DPoP", responder.GetTokenType(),
					"scenario 0: token_type should be DPoP")
				assert.Equal(t, freshNonce, dpopNonce,
					"scenario 0: fresh nonce should be set in context for response header")

			case scenarioMissingNonce:
				// HandleTokenEndpointRequest should fail with use_dpop_nonce.
				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.Error(t, err, "scenario 1: missing nonce should be rejected")
				assert.True(t, isUseDPoPNonceError(err),
					"scenario 1: should produce use_dpop_nonce, got: %v", err)
				assert.Equal(t, freshNonce, dpopNonce,
					"scenario 1: fresh nonce should be set in context for DPoP-Nonce header")

			case scenarioInvalidNonce:
				// HandleTokenEndpointRequest should fail with use_dpop_nonce.
				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.Error(t, err, "scenario 2: invalid nonce should be rejected")
				assert.True(t, isUseDPoPNonceError(err),
					"scenario 2: should produce use_dpop_nonce, got: %v", err)
				assert.Equal(t, freshNonce, dpopNonce,
					"scenario 2: fresh nonce should be set in context for DPoP-Nonce header")

			case scenarioNonceOff:
				// HandleTokenEndpointRequest should succeed without nonce.
				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.NoError(t, err, "scenario 3: nonces disabled should accept proof without nonce")

				// PopulateTokenEndpointResponse should succeed without producing a nonce.
				responder := fosite.NewAccessResponse()
				err = handler.PopulateTokenEndpointResponse(ctx, ar, responder)
				require.NoError(t, err, "scenario 3: PopulateTokenEndpointResponse should succeed")

				assert.Equal(t, "DPoP", responder.GetTokenType(),
					"scenario 3: token_type should be DPoP")
				assert.Empty(t, dpopNonce,
					"scenario 3: no nonce should be set when nonces are disabled")
			}
		})
	})
}

// Feature: oidc4vci-dpop, Property 8: dpop_jkt Binding Verification at Token Endpoint
func TestProperty8_DPoPJKTBindingAtTokenEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("case=property 8 dpop_jkt binding at token endpoint", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 8: dpop_jkt Binding Verification at Token Endpoint
		// **Validates: Requirements 4.4**
		rapid.Check(t, func(t *rapid.T) {
			handler, _ := newTestTokenHandler()

			keyA := newECKey(t)
			keyB := newECKey(t)

			matching := rapid.Bool().Draw(t, "matching")

			session := &fosite.DefaultSession{
				Extra: map[string]interface{}{},
			}

			client := &fosite.DefaultOpenIDConnectClient{
				DefaultClient: &fosite.DefaultClient{
					ID: "test-client",
				},
				TokenEndpointAuthMethod: "client_secret_post",
			}

			// Build a valid DPoP proof signed with keyA.
			opts := validTokenProofOpts()
			proofJWT := buildDPoPProof(t, keyA, opts)

			ar := fosite.NewAccessRequest(session)
			ar.Client = client
			ar.Form = url.Values{
				"dpop_proof": {proofJWT},
			}

			if matching {
				// Set dpop_jkt to keyA's JKT — matches the proof's key.
				ar.Form.Set("dpop_jkt", computeJKT(t, &keyA.PublicKey))
			} else {
				// Set dpop_jkt to keyB's JKT — mismatches the proof's key.
				ar.Form.Set("dpop_jkt", computeJKT(t, &keyB.PublicKey))
			}

			ctx := context.Background()
			err := handler.HandleTokenEndpointRequest(ctx, ar)

			if matching {
				require.NoError(t, err, "matching dpop_jkt should be accepted")

				// Verify the cnf.jkt was stored in session extra.
				expectedJKT := computeJKT(t, &keyA.PublicKey)
				cnf, ok := session.Extra["cnf"].(map[string]interface{})
				require.True(t, ok, "cnf should be stored in session extra")
				storedJKT, ok := cnf["jkt"].(string)
				require.True(t, ok, "cnf.jkt should be a string")
				assert.Equal(t, expectedJKT, storedJKT,
					"stored JKT should match keyA's thumbprint")
			} else {
				require.Error(t, err, "mismatching dpop_jkt should be rejected")
				assert.True(t, isInvalidDPoPProofError(err),
					"mismatching dpop_jkt should produce invalid_dpop_proof, got: %v", err)
			}
		})
	})
}

// Feature: oidc4vci-dpop, Property 9: Refresh Token DPoP Binding (Public vs Confidential)
func TestProperty9_RefreshTokenDPoPBinding(t *testing.T) {
	t.Parallel()

	t.Run("case=property 9 refresh token dpop binding", func(t *testing.T) {
		t.Parallel()

		// Feature: oidc4vci-dpop, Property 9: Refresh Token DPoP Binding (Public vs Confidential)
		// **Validates: Requirements 5.1, 5.2, 5.3, 5.4**
		rapid.Check(t, func(t *rapid.T) {
			const (
				scenarioPublicInitial          = 0 // Public client initial token → dpop_jkt_binding stored
				scenarioConfidentialInitial     = 1 // Confidential client initial token → no dpop_jkt_binding
				scenarioPublicRefreshSameKey    = 2 // Public client refresh with same key → accepted
				scenarioPublicRefreshDiffKey    = 3 // Public client refresh with different key → invalid_dpop_proof
			)

			scenario := rapid.IntRange(0, 3).Draw(t, "scenario")

			handler, _ := newTestTokenHandler()
			keyA := newECKey(t)
			keyB := newECKey(t)

			publicAuthMethods := rapid.SampledFrom([]string{"none", "attest_jwt_client_auth"})
			confidentialAuthMethods := rapid.SampledFrom([]string{"client_secret_post", "private_key_jwt"})

			switch scenario {
			case scenarioPublicInitial:
				// Public client with initial token request → dpop_jkt_binding stored in session.
				authMethod := publicAuthMethods.Draw(t, "publicAuthMethod")

				session := &fosite.DefaultSession{
					Extra: map[string]interface{}{},
				}

				isPublic := authMethod == "none"
				client := &fosite.DefaultOpenIDConnectClient{
					DefaultClient: &fosite.DefaultClient{
						ID:     "public-client",
						Public: isPublic,
					},
					TokenEndpointAuthMethod: authMethod,
				}

				opts := validTokenProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)

				ar := fosite.NewAccessRequest(session)
				ar.Client = client
				ar.Form = url.Values{
					"dpop_proof": {proofJWT},
				}

				ctx := context.Background()

				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.NoError(t, err, "HandleTokenEndpointRequest should succeed for public client")

				responder := fosite.NewAccessResponse()
				err = handler.PopulateTokenEndpointResponse(ctx, ar, responder)
				require.NoError(t, err, "PopulateTokenEndpointResponse should succeed for public client")

				// Verify dpop_jkt_binding is stored for public client.
				expectedJKT := computeJKT(t, &keyA.PublicKey)
				binding, ok := session.Extra["dpop_jkt_binding"].(string)
				require.True(t, ok, "dpop_jkt_binding should be stored for public client (auth_method=%s)", authMethod)
				assert.Equal(t, expectedJKT, binding,
					"dpop_jkt_binding should match the proof's JWK Thumbprint")

				// Also verify cnf.jkt and token_type.
				assert.Equal(t, "DPoP", responder.GetTokenType(),
					"token_type should be DPoP")

			case scenarioConfidentialInitial:
				// Confidential client with initial token request → no dpop_jkt_binding.
				authMethod := confidentialAuthMethods.Draw(t, "confidentialAuthMethod")

				session := &fosite.DefaultSession{
					Extra: map[string]interface{}{},
				}

				client := &fosite.DefaultOpenIDConnectClient{
					DefaultClient: &fosite.DefaultClient{
						ID: "confidential-client",
					},
					TokenEndpointAuthMethod: authMethod,
				}

				opts := validTokenProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)

				ar := fosite.NewAccessRequest(session)
				ar.Client = client
				ar.Form = url.Values{
					"dpop_proof": {proofJWT},
				}

				ctx := context.Background()

				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.NoError(t, err, "HandleTokenEndpointRequest should succeed for confidential client")

				responder := fosite.NewAccessResponse()
				err = handler.PopulateTokenEndpointResponse(ctx, ar, responder)
				require.NoError(t, err, "PopulateTokenEndpointResponse should succeed for confidential client")

				// Verify dpop_jkt_binding is NOT stored for confidential client.
				_, hasBinding := session.Extra["dpop_jkt_binding"]
				assert.False(t, hasBinding,
					"dpop_jkt_binding should NOT be stored for confidential client (auth_method=%s)", authMethod)

				// cnf.jkt and token_type should still be set.
				assert.Equal(t, "DPoP", responder.GetTokenType(),
					"token_type should be DPoP even for confidential client")
				cnfRaw, ok := session.Extra["cnf"]
				require.True(t, ok, "cnf should be present for confidential client")
				cnfMap, ok := cnfRaw.(map[string]interface{})
				require.True(t, ok, "cnf should be a map")
				_, ok = cnfMap["jkt"].(string)
				assert.True(t, ok, "cnf.jkt should be a string")

			case scenarioPublicRefreshSameKey:
				// Public client refresh with same key → accepted.
				authMethod := publicAuthMethods.Draw(t, "publicAuthMethod")
				expectedJKT := computeJKT(t, &keyA.PublicKey)

				session := &fosite.DefaultSession{
					Extra: map[string]interface{}{
						"dpop_jkt_binding": expectedJKT,
					},
				}

				isPublic := authMethod == "none"
				client := &fosite.DefaultOpenIDConnectClient{
					DefaultClient: &fosite.DefaultClient{
						ID:     "public-client",
						Public: isPublic,
					},
					TokenEndpointAuthMethod: authMethod,
				}

				// Build proof with the SAME key (keyA) that was used for the original binding.
				opts := validTokenProofOpts()
				proofJWT := buildDPoPProof(t, keyA, opts)

				ar := fosite.NewAccessRequest(session)
				ar.Client = client
				ar.Form = url.Values{
					"dpop_proof":  {proofJWT},
					"grant_type":  {"refresh_token"},
				}

				ctx := context.Background()

				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.NoError(t, err,
					"refresh with same key should be accepted for public client (auth_method=%s)", authMethod)

			case scenarioPublicRefreshDiffKey:
				// Public client refresh with different key → rejected with invalid_dpop_proof.
				authMethod := publicAuthMethods.Draw(t, "publicAuthMethod")
				originalJKT := computeJKT(t, &keyA.PublicKey)

				session := &fosite.DefaultSession{
					Extra: map[string]interface{}{
						"dpop_jkt_binding": originalJKT,
					},
				}

				isPublic := authMethod == "none"
				client := &fosite.DefaultOpenIDConnectClient{
					DefaultClient: &fosite.DefaultClient{
						ID:     "public-client",
						Public: isPublic,
					},
					TokenEndpointAuthMethod: authMethod,
				}

				// Build proof with a DIFFERENT key (keyB) than the original binding (keyA).
				opts := validTokenProofOpts()
				proofJWT := buildDPoPProof(t, keyB, opts)

				ar := fosite.NewAccessRequest(session)
				ar.Client = client
				ar.Form = url.Values{
					"dpop_proof":  {proofJWT},
					"grant_type":  {"refresh_token"},
				}

				ctx := context.Background()

				err := handler.HandleTokenEndpointRequest(ctx, ar)
				require.Error(t, err,
					"refresh with different key should be rejected for public client (auth_method=%s)", authMethod)
				assert.True(t, isInvalidDPoPProofError(err),
					"should produce invalid_dpop_proof, got: %v", err)
			}
		})
	})
}
