// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// extractCnfJKT pulls the confirmation JWK Thumbprint from the `ext.cnf.jkt`
// claim that Hydra returns for DPoP-bound access tokens. Returns (jkt, true)
// when present and non-empty.
func extractCnfJKT(ext map[string]interface{}) (string, bool) {
	cnfAny, ok := ext["cnf"]
	if !ok {
		return "", false
	}
	cnf, ok := cnfAny.(map[string]interface{})
	if !ok {
		return "", false
	}
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" {
		return "", false
	}
	return jkt, true
}

// validateDPoPProof enforces the resource-server checks required by
// RFC 9449 §7.1:
//
//   - A `DPoP` header is present on the request and parses as a JWS with
//     `typ=dpop+jwt` and an `alg` other than `none`.
//   - The signature verifies against the JWK embedded in the header.
//   - The embedded JWK's thumbprint matches the access token's `cnf.jkt`.
//   - `htm` matches the request method, `htu` matches the request URL
//     (normalised — scheme + host + path, no query or fragment).
//   - `ath` matches base64url(SHA-256(access_token)).
//   - `iat` is within ±5 minutes of now.
//
// Nonce handling is intentionally omitted: the mock issuer does not challenge
// with DPoP-Nonce, so wallets can issue proofs without one.
func validateDPoPProof(r *http.Request, accessToken, expectedJKT string) error {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP header is required")
	}

	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP proof must have three parts")
	}

	// Header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return newOIDCError(errCodeInvalidToken, 401, "failed to decode DPoP header")
	}
	var header struct {
		Alg string                 `json:"alg"`
		Typ string                 `json:"typ"`
		JWK map[string]interface{} `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return newOIDCError(errCodeInvalidToken, 401, "failed to parse DPoP header")
	}
	if header.Typ != "dpop+jwt" {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("DPoP header typ must be 'dpop+jwt', got %q", header.Typ))
	}
	if header.Alg == "" || strings.EqualFold(header.Alg, "none") {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("DPoP header alg %q is not acceptable", header.Alg))
	}
	if len(header.JWK) == 0 {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP header is missing jwk")
	}

	// Signature verification (only ES256/P-256 is supported — matches what
	// the rest of this mock issuer can sign/verify).
	pubKey, err := parseECPublicKeyFromJWK(header.JWK)
	if err != nil {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("DPoP jwk is not an EC P-256 key: %v", err))
	}
	ecKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP jwk is not an EC public key")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return newOIDCError(errCodeInvalidToken, 401, "failed to decode DPoP signature")
	}
	if len(sigBytes) != 64 {
		return newOIDCError(errCodeInvalidToken, 401, "invalid DPoP ES256 signature length")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r1 := new(big.Int).SetBytes(sigBytes[:32])
	s1 := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(ecKey, digest[:], r1, s1) {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP signature verification failed")
	}

	// Thumbprint binding to the access token's cnf.jkt.
	actualJKT, err := rfc7638Thumbprint(header.JWK)
	if err != nil {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("failed to compute DPoP jkt: %v", err))
	}
	if actualJKT != expectedJKT {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("DPoP proof key thumbprint %q does not match token cnf.jkt %q",
				actualJKT, expectedJKT))
	}

	// Claims.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return newOIDCError(errCodeInvalidToken, 401, "failed to decode DPoP payload")
	}
	var claims struct {
		HTM string  `json:"htm"`
		HTU string  `json:"htu"`
		IAT float64 `json:"iat"`
		ATH string  `json:"ath"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return newOIDCError(errCodeInvalidToken, 401, "failed to parse DPoP claims")
	}

	if !strings.EqualFold(claims.HTM, r.Method) {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("DPoP htm %q does not match request method %q", claims.HTM, r.Method))
	}
	if !sameResourceURL(claims.HTU, requestURL(r)) {
		return newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("DPoP htu %q does not match request URL %q", claims.HTU, requestURL(r)))
	}

	const maxSkew = 5 * time.Minute
	if claims.IAT == 0 {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP iat claim is required")
	}
	iat := time.Unix(int64(claims.IAT), 0)
	now := time.Now()
	if now.Sub(iat) > maxSkew || iat.After(now.Add(maxSkew)) {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP iat is out of range")
	}

	expectedATH := base64.RawURLEncoding.EncodeToString(sha256Sum(accessToken))
	if claims.ATH == "" {
		return newOIDCError(errCodeInvalidToken, 401, "DPoP ath claim is required")
	}
	if claims.ATH != expectedATH {
		return newOIDCError(errCodeInvalidToken, 401,
			"DPoP ath does not match SHA-256 of access token")
	}

	return nil
}

// rfc7638Thumbprint computes the JWK Thumbprint (RFC 7638) for an EC P-256
// public key. It canonicalises the JWK to the required `{crv,kty,x,y}` shape
// and SHA-256-hashes the UTF-8 bytes of the resulting JSON.
func rfc7638Thumbprint(jwk map[string]interface{}) (string, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return "", fmt.Errorf("unsupported kty %q", kty)
	}
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	if crv == "" || x == "" || y == "" {
		return "", fmt.Errorf("JWK missing crv/x/y")
	}
	// Per RFC 7638 §3.2 the canonical form for an EC key is:
	// {"crv":...,"kty":"EC","x":...,"y":...}  (members in lexicographic order).
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, crv, kty, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// requestURL reconstructs the absolute URL the client targeted. r.URL is
// relative for server-side requests, and we need scheme + host from the
// Host header (respecting X-Forwarded-* headers set by ngrok / reverse
// proxies).
func requestURL(r *http.Request) string {
	scheme := r.URL.Scheme
	if scheme == "" {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			scheme = v
		} else if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = v
	}
	u := &url.URL{Scheme: scheme, Host: host, Path: r.URL.Path}
	return u.String()
}

// sameResourceURL compares two htu-shaped URLs ignoring query and fragment
// (RFC 9449 §4.3: htu is constructed without them).
func sameResourceURL(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	ua.RawQuery, ua.Fragment = "", ""
	ub.RawQuery, ub.Fragment = "", ""
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host) &&
		ua.Path == ub.Path
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
