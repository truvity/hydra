// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package wallet_attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// contextKey is an unexported type for context keys in this package,
// preventing collisions with keys defined in other packages.
type contextKey string

// WalletAttestationCNFContextKey is the context key used to propagate the
// validated cnf.jwk (*jose.JSONWebKey) from the Wallet Attestation
// authenticator to the RefreshBindingHandler. The authenticator stores the
// Client Instance Key in the request context after successful authentication;
// the RefreshBindingHandler reads it to compute the JWK thumbprint for
// session storage and binding checks.
const WalletAttestationCNFContextKey contextKey = "wallet_attestation_cnf_jwk"

// walletAttestationCNFFormKey is the internal form parameter used to transport
// the serialized cnf.jwk JSON from the authenticator to the RefreshBindingHandler.
// This follows the same pattern as DPoP's form injection (dpop_proof) — the form
// is shared between AuthenticateClient and token endpoint handlers via
// requester.GetRequestForm(). The double-underscore prefix signals this is an
// internal transport key, not a client-supplied parameter.
const walletAttestationCNFFormKey = "__wallet_attestation_cnf_jwk"

// clockSkewTolerance is the tolerance for exp/nbf claim validation.
const clockSkewTolerance = 5 * time.Second

// popFreshnessWindow is the maximum age of a PoP JWT iat claim.
const popFreshnessWindow = 60 * time.Second

// popFutureTolerance is the tolerance for PoP JWT iat claims in the future.
const popFutureTolerance = 5 * time.Second

// supportedAsymmetricAlgorithms is the set of supported asymmetric signing algorithms.
var supportedAsymmetricAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"EdDSA": true,
}

// WalletAttestationConfigProvider is a type alias for the fosite interface,
// allowing external packages to reference it without importing fosite directly.
type WalletAttestationConfigProvider = fosite.WalletAttestationConfigProvider

// Authenticator validates Wallet Attestation headers (OAuth-Client-Attestation
// and OAuth-Client-Attestation-PoP) per draft-ietf-oauth-attestation-based-client-auth-07
// and returns an authenticated client.
type Authenticator struct {
	Config    WalletAttestationConfigProvider
	Store     fosite.Storage
	JTIStore  JTIStorage
	IssuerURL func(ctx context.Context) string
}

// attestationClaims holds the claims from the Client Attestation JWT (draft-07 §5.1).
type attestationClaims struct {
	Issuer    string           `json:"iss"`
	Subject   string           `json:"sub"`
	ExpiresAt *josejwt.NumericDate `json:"exp"`
	IssuedAt  *josejwt.NumericDate `json:"iat,omitempty"`
	NotBefore *josejwt.NumericDate `json:"nbf,omitempty"`
	CNF       *cnfClaim        `json:"cnf"`
}

// cnfClaim represents the confirmation claim per RFC 7800.
type cnfClaim struct {
	JWK json.RawMessage `json:"jwk"`
}

// popClaims holds the claims from the Client Attestation PoP JWT (draft-07 §5.2).
type popClaims struct {
	Issuer    string               `json:"iss"`
	Audience  josejwt.Audience     `json:"aud"`
	JTI       string               `json:"jti"`
	IssuedAt  *josejwt.NumericDate `json:"iat"`
	NotBefore *josejwt.NumericDate `json:"nbf,omitempty"`
}

// AuthenticateClient validates the Wallet Attestation headers and returns the
// authenticated client. It implements the full validation pipeline per
// draft-ietf-oauth-attestation-based-client-auth-07 §5.1, §5.2, and §9.
func (a *Authenticator) AuthenticateClient(ctx context.Context, r *http.Request, form url.Values) (fosite.Client, error) {
	// =========================================================================
	// Phase 1 — Client Attestation JWT Validation (draft-07 §5.1, §9)
	// =========================================================================

	// Step 1: Extract OAuth-Client-Attestation header.
	attestationString := r.Header.Get("OAuth-Client-Attestation")
	if attestationString == "" {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("OAuth-Client-Attestation header is missing."),
		)
	}

	// Step 2: Parse JWT.
	parsedAttestation, err := jose.ParseSigned(attestationString)
	if err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is not a well-formed JWT.").
				WithDebugf("jwt parse error: %s", err.Error()),
		)
	}

	if len(parsedAttestation.Signatures) != 1 {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation must have exactly one signature.").
				WithDebugf("got %d signatures", len(parsedAttestation.Signatures)),
		)
	}

	attHeader := parsedAttestation.Signatures[0].Protected

	// Step 3: Validate typ JOSE header == oauth-client-attestation+jwt.
	typRaw, ok := attHeader.ExtraHeaders[jose.HeaderKey("typ")]
	if !ok {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation typ must be oauth-client-attestation+jwt."),
		)
	}
	typStr, _ := typRaw.(string)
	if !strings.EqualFold(typStr, "oauth-client-attestation+jwt") {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation typ must be oauth-client-attestation+jwt.").
				WithDebugf("got typ=%q", typStr),
		)
	}

	// Step 4: Validate alg JOSE header.
	attAlg := attHeader.Algorithm
	if err := validateAsymmetricAlgorithm(attAlg); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation uses unsupported signing algorithm.").
				WithDebugf("alg=%q: %s", attAlg, err.Error()),
		)
	}

	// Step 5: Extract x5c JOSE header — required per HAIP §4.4.1.
	// go-jose v3 parses x5c into a private certificates field accessible via
	// Header.Certificates(). If that is empty, fall back to ExtraHeaders for
	// raw (unparsed) x5c values.
	certs, err := extractX5CCerts(parsedAttestation)
	if err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is missing the x5c JOSE header.").
				WithDebugf("x5c extraction error: %s", err.Error()),
		)
	}
	if len(certs) == 0 {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation x5c chain is empty."),
		)
	}

	leafCert := certs[0]

	// Step 7: HAIP check — verify leaf cert is not self-signed.
	if isSelfSigned(leafCert) {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation signing certificate must not be self-signed."),
		)
	}

	// Step 8: HAIP check — verify trust anchor is not in the x5c chain.
	trustAnchors := a.Config.GetWalletAttestationTrustAnchors(ctx)
	if containsTrustAnchor(certs, trustAnchors) {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Trust anchor must not be included in x5c chain."),
		)
	}

	// Step 9: Build CertPool and verify chain.
	rootPool := x509.NewCertPool()
	for _, ta := range trustAnchors {
		rootPool.AddCert(ta)
	}

	intermediatePool := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediatePool.AddCert(c)
	}

	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	}); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation certificate chain is not trusted.").
				WithDebugf("x509 verify error: %s", err.Error()),
		)
	}

	// Step 10: Verify JWT signature using leaf cert's public key.
	var attClaims attestationClaims
	if err := parseSignedClaims(parsedAttestation, leafCert.PublicKey, &attClaims); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation signature verification failed.").
				WithDebugf("signature error: %s", err.Error()),
		)
	}

	now := time.Now()

	// Step 11: Validate exp claim.
	if attClaims.ExpiresAt == nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is missing exp claim."),
		)
	}
	if now.After(attClaims.ExpiresAt.Time().Add(clockSkewTolerance)) {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is expired.").
				WithDebugf("exp=%v, now=%v", attClaims.ExpiresAt.Time(), now),
		)
	}

	// Step 12: Validate nbf claim if present.
	if attClaims.NotBefore != nil {
		if now.Before(attClaims.NotBefore.Time().Add(-clockSkewTolerance)) {
			return nil, errors.WithStack(
				ErrInvalidWalletAttestation.
					WithHint("Wallet Attestation is not yet valid.").
					WithDebugf("nbf=%v, now=%v", attClaims.NotBefore.Time(), now),
			)
		}
	}

	// Step 13: Validate iss claim is present.
	if attClaims.Issuer == "" {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is missing iss claim."),
		)
	}

	// Step 14: Extract sub claim — this is the client_id.
	sub := attClaims.Subject
	if sub == "" {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is missing sub claim."),
		)
	}

	// Step 15: Extract cnf claim with jwk representation.
	if attClaims.CNF == nil || attClaims.CNF.JWK == nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation is missing the cnf claim."),
		)
	}

	var cnfKey jose.JSONWebKey
	if err := json.Unmarshal(attClaims.CNF.JWK, &cnfKey); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation cnf.jwk is malformed.").
				WithDebugf("jwk unmarshal error: %s", err.Error()),
		)
	}

	// Step 16: Validate cnf.jwk is a public key (no private key material).
	if err := validatePublicKeyOnly(&cnfKey); err != nil {
		return nil, err
	}

	// Step 17: If form client_id is non-empty, verify it matches sub.
	if formClientID := form.Get("client_id"); formClientID != "" && formClientID != sub {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation sub does not match client_id.").
				WithDebugf("sub=%q, form client_id=%q", sub, formClientID),
		)
	}

	// =========================================================================
	// Phase 2 — Client Attestation PoP JWT Validation (draft-07 §5.2, §9)
	// =========================================================================

	// Step 18: Extract OAuth-Client-Attestation-PoP header.
	popString := r.Header.Get("OAuth-Client-Attestation-PoP")
	if popString == "" {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("OAuth-Client-Attestation-PoP header is required."),
		)
	}

	// Step 19: Parse the PoP JWT.
	parsedPoP, err := jose.ParseSigned(popString)
	if err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT is not a well-formed JWT.").
				WithDebugf("jwt parse error: %s", err.Error()),
		)
	}

	if len(parsedPoP.Signatures) != 1 {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT must have exactly one signature.").
				WithDebugf("got %d signatures", len(parsedPoP.Signatures)),
		)
	}

	popHeader := parsedPoP.Signatures[0].Protected

	// Step 20: Validate typ JOSE header == oauth-client-attestation-pop+jwt.
	popTypRaw, ok := popHeader.ExtraHeaders[jose.HeaderKey("typ")]
	if !ok {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT typ must be oauth-client-attestation-pop+jwt."),
		)
	}
	popTypStr, _ := popTypRaw.(string)
	if !strings.EqualFold(popTypStr, "oauth-client-attestation-pop+jwt") {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT typ must be oauth-client-attestation-pop+jwt.").
				WithDebugf("got typ=%q", popTypStr),
		)
	}

	// Step 21: Validate alg JOSE header.
	popAlg := popHeader.Algorithm
	if err := validateAsymmetricAlgorithm(popAlg); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT uses unsupported signing algorithm.").
				WithDebugf("alg=%q: %s", popAlg, err.Error()),
		)
	}

	// Step 22: Verify PoP JWT signature using the public key from cnf.jwk.
	var popClaimsVal popClaims
	if err := parseSignedClaims(parsedPoP, cnfKey.Key, &popClaimsVal); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT signature verification failed.").
				WithDebugf("signature error: %s", err.Error()),
		)
	}

	// Step 23: Validate iss claim matches sub from attestation JWT.
	if popClaimsVal.Issuer != sub {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT iss does not match client_id.").
				WithDebugf("pop iss=%q, attestation sub=%q", popClaimsVal.Issuer, sub),
		)
	}

	// Step 24: Validate aud claim matches AS Issuer Identifier.
	issuerURL := a.IssuerURL(ctx)
	if !popClaimsVal.Audience.Contains(issuerURL) {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT aud does not match AS issuer.").
				WithDebugf("pop aud=%v, expected=%q", popClaimsVal.Audience, issuerURL),
		)
	}

	// Step 25: Validate iat claim.
	if popClaimsVal.IssuedAt == nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT is missing iat claim."),
		)
	}
	popIAT := popClaimsVal.IssuedAt.Time()
	if popIAT.Before(now.Add(-popFreshnessWindow)) {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT iat is not recent.").
				WithDebugf("iat=%v is before now-60s=%v", popIAT, now.Add(-popFreshnessWindow)),
		)
	}
	if popIAT.After(now.Add(popFutureTolerance)) {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT iat is not recent.").
				WithDebugf("iat=%v is after now+5s=%v", popIAT, now.Add(popFutureTolerance)),
		)
	}

	// Step 26: Validate jti claim.
	if popClaimsVal.JTI == "" {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT is missing jti claim."),
		)
	}

	used, err := a.JTIStore.IsJTIUsed(ctx, popClaimsVal.JTI)
	if err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Failed to check PoP JWT jti uniqueness.").
				WithDebugf("jti check error: %s", err.Error()),
		)
	}
	if used {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("PoP JWT jti has already been used.").
				WithDebugf("jti=%q is a replay", popClaimsVal.JTI),
		)
	}
	if err := a.JTIStore.MarkJTIUsed(ctx, popClaimsVal.JTI, now.Add(popFreshnessWindow)); err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Failed to record PoP JWT jti.").
				WithDebugf("jti mark error: %s", err.Error()),
		)
	}

	// Step 27: Validate nbf claim if present.
	if popClaimsVal.NotBefore != nil {
		if now.Before(popClaimsVal.NotBefore.Time().Add(-clockSkewTolerance)) {
			return nil, errors.WithStack(
				ErrInvalidWalletAttestation.
					WithHint("PoP JWT is not yet valid.").
					WithDebugf("nbf=%v, now=%v", popClaimsVal.NotBefore.Time(), now),
			)
		}
	}

	// =========================================================================
	// Phase 3 — Client Lookup and Auth Method Check
	// =========================================================================

	// Step 28: Look up client via Store.
	client, err := a.Store.FositeClientManager().GetClient(ctx, sub)
	if err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("No client record found for wallet type. The AS operator must pre-register a client with client_id matching the attestation sub claim.").
				WithDebugf("GetClient error for sub=%q: %s", sub, err.Error()),
		)
	}

	// Step 29: Check token_endpoint_auth_method == "attest_jwt_client_auth".
	oidcClient, ok := client.(fosite.OpenIDConnectClient)
	if !ok {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Client is not configured for attestation-based authentication.").
				WithDebugf("client does not implement OpenIDConnectClient"),
		)
	}
	if oidcClient.GetTokenEndpointAuthMethod() != "attest_jwt_client_auth" {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Client is not configured for attestation-based authentication.").
				WithDebugf("token_endpoint_auth_method=%q, expected attest_jwt_client_auth", oidcClient.GetTokenEndpointAuthMethod()),
		)
	}

	// =========================================================================
	// Phase 4 — Store cnf.jwk in form for RefreshBindingHandler
	// =========================================================================

	// Step 30: Store validated cnf.jwk in the request form for RefreshBindingHandler.
	// The ClientAuthenticationStrategy returns (Client, error) — not a context —
	// and the ctx passed to token endpoint handlers is the original context from
	// NewAccessRequest, NOT r.Context(). Therefore we use the request form as the
	// transport mechanism (same pattern as DPoP's InjectDPoPHeader). The form is
	// shared between AuthenticateClient and the token endpoint handlers via
	// requester.GetRequestForm().
	cnfJWKBytes, err := json.Marshal(&cnfKey)
	if err != nil {
		return nil, errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Failed to serialize cnf.jwk for session propagation.").
				WithDebugf("json marshal error: %s", err.Error()),
		)
	}
	form.Set(walletAttestationCNFFormKey, string(cnfJWKBytes))

	// Step 31: Return the client.
	return client, nil
}

// validateAsymmetricAlgorithm checks that the alg is a supported asymmetric
// algorithm: not "none", not symmetric (HS*), and in the supported set.
func validateAsymmetricAlgorithm(alg string) error {
	if alg == "" || strings.EqualFold(alg, "none") {
		return errors.New("algorithm is none or empty")
	}
	if strings.HasPrefix(alg, "HS") {
		return errors.New("symmetric algorithms are not allowed")
	}
	if !supportedAsymmetricAlgorithms[alg] {
		return errors.Errorf("algorithm %q is not supported", alg)
	}
	return nil
}

// decodeX5CChain decodes the x5c JOSE header value into a slice of
// *x509.Certificate. The x5c value is expected to be a []interface{} of
// base64-encoded DER certificates per RFC 7515 §4.1.6.
func decodeX5CChain(x5cRaw interface{}) ([]*x509.Certificate, error) {
	x5cSlice, ok := x5cRaw.([]interface{})
	if !ok {
		return nil, errors.New("x5c is not an array")
	}

	certs := make([]*x509.Certificate, 0, len(x5cSlice))
	for i, entry := range x5cSlice {
		certStr, ok := entry.(string)
		if !ok {
			return nil, errors.Errorf("x5c[%d] is not a string", i)
		}

		certDER, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, errors.Wrapf(err, "x5c[%d] base64 decode failed", i)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, errors.Wrapf(err, "x5c[%d] certificate parse failed", i)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// extractX5CCerts extracts x5c certificates from a JOSE header.
// go-jose v3 parses x5c into a private certificates field and does NOT
// expose it via ExtraHeaders. We re-parse the raw protected header JSON
// to extract the x5c array.
func extractX5CCerts(jws *jose.JSONWebSignature) ([]*x509.Certificate, error) {
	if len(jws.Signatures) == 0 {
		return nil, errors.New("no signatures in JWS")
	}

	rawHeader := jws.Signatures[0].Protected

	// First check ExtraHeaders (works when x5c was set but not parsed by go-jose).
	if x5cRaw, ok := rawHeader.ExtraHeaders[jose.HeaderKey("x5c")]; ok {
		return decodeX5CChain(x5cRaw)
	}

	// go-jose v3 parses x5c into a private field. Extract by re-parsing
	// the compact serialization header.
	return extractX5CFromCompact(jws)
}

// extractX5CFromCompact extracts x5c certificates by re-serializing
// the JWS and parsing the base64url-encoded protected header JSON.
func extractX5CFromCompact(jws *jose.JSONWebSignature) ([]*x509.Certificate, error) {
	compact, err := jws.CompactSerialize()
	if err != nil {
		return nil, errors.Wrap(err, "failed to re-serialize JWS")
	}

	parts := strings.SplitN(compact, ".", 3)
	if len(parts) < 1 {
		return nil, errors.New("invalid compact serialization")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode header")
	}

	var headerMap map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &headerMap); err != nil {
		return nil, errors.Wrap(err, "failed to parse header JSON")
	}

	x5cRaw, ok := headerMap["x5c"]
	if !ok {
		return nil, errors.New("x5c JOSE header is missing")
	}

	var x5cStrings []string
	if err := json.Unmarshal(x5cRaw, &x5cStrings); err != nil {
		return nil, errors.Wrap(err, "failed to parse x5c array")
	}

	certs := make([]*x509.Certificate, 0, len(x5cStrings))
	for i, certStr := range x5cStrings {
		certDER, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, errors.Wrapf(err, "x5c[%d] base64 decode failed", i)
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, errors.Wrapf(err, "x5c[%d] certificate parse failed", i)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// isSelfSigned checks whether a certificate is self-signed by comparing
// the issuer and subject AND verifying the certificate's signature with
// its own public key. Uses Verify with the cert as its own root to handle
// certs without the CA flag.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	// CheckSignatureFrom requires IsCA on the parent. For leaf certs that
	// are self-signed but not CAs, verify by checking if the cert can
	// validate itself as a root.
	if cert.CheckSignatureFrom(cert) == nil {
		return true
	}
	// Fallback: try to verify the raw signature using the cert's public key.
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// containsTrustAnchor checks whether any certificate in the chain matches
// a configured trust anchor by comparing raw certificate bytes.
func containsTrustAnchor(chain []*x509.Certificate, trustAnchors []*x509.Certificate) bool {
	for _, chainCert := range chain {
		for _, ta := range trustAnchors {
			if string(chainCert.Raw) == string(ta.Raw) {
				return true
			}
		}
	}
	return false
}

// parseSignedClaims verifies the JWS signature with the given key and
// unmarshals the payload into the claims struct. This uses go-jose/v3's
// JSONWebSignature.Verify() to verify and extract the payload.
func parseSignedClaims(jws *jose.JSONWebSignature, key interface{}, claims interface{}) error {
	payload, err := jws.Verify(key)
	if err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(json.Unmarshal(payload, claims))
}

// validatePublicKeyOnly checks that the JWK does not contain private key
// material. For RSA keys, a private key is *rsa.PrivateKey; for EC keys,
// *ecdsa.PrivateKey. Additionally checks the raw JSON for a "d" parameter.
func validatePublicKeyOnly(jwk *jose.JSONWebKey) error {
	switch jwk.Key.(type) {
	case *rsa.PrivateKey:
		return errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation cnf must contain a public key only.").
				WithDebugf("jwk key type is *rsa.PrivateKey"),
		)
	case *ecdsa.PrivateKey:
		return errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Wallet Attestation cnf must contain a public key only.").
				WithDebugf("jwk key type is *ecdsa.PrivateKey"),
		)
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return nil
	default:
		if jwk.Key == nil {
			return errors.WithStack(
				ErrInvalidWalletAttestation.
					WithHint("Wallet Attestation cnf.jwk does not contain a valid key.").
					WithDebugf("jwk key is nil"),
			)
		}
		return nil
	}
}
