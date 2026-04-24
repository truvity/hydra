// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Signer holds an ECDSA P-256 key pair generated at startup and signs SD-JWT VC credentials.
type Signer struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	keyID      string
}

// NewSigner generates a fresh ECDSA P-256 key pair and returns a Signer.
func NewSigner() (*Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA P-256 key: %w", err)
	}
	kid, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}
	return &Signer{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
		keyID:      kid,
	}, nil
}

// KeyID returns the key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKeyJWK returns the issuer's public key as a JWK map.
func (s *Signer) PublicKeyJWK() map[string]interface{} {
	return ecPublicKeyToJWK(s.publicKey, s.keyID)
}

// IssueSDJWTVC signs a minimal SD-JWT VC and returns the compact serialisation.
// format is the SD-JWT VC format identifier used as the JWS `typ` header —
// either "vc+sd-jwt" (legacy) or "dc+sd-jwt" (SD-JWT VC draft 06+). An empty
// string defaults to "dc+sd-jwt".
func (s *Signer) IssueSDJWTVC(
	issuerURL, subject, vct, format string,
	holderKey crypto.PublicKey,
	claims map[string]interface{},
) (string, error) {
	if format == "" {
		format = "dc+sd-jwt"
	}
	now := time.Now()
	payload := map[string]interface{}{
		"iss": issuerURL,
		"sub": subject,
		"iat": now.Unix(),
		"vct": vct,
	}

	if holderKey != nil {
		cnfJWK, err := publicKeyToJWK(holderKey)
		if err != nil {
			return "", fmt.Errorf("failed to convert holder key to JWK: %w", err)
		}
		payload["cnf"] = map[string]interface{}{"jwk": cnfJWK}
	}

	reserved := map[string]bool{"iss": true, "sub": true, "iat": true, "vct": true, "cnf": true}
	for k, v := range claims {
		if !reserved[k] {
			payload[k] = v
		}
	}

	header := map[string]interface{}{
		"alg": "ES256",
		"typ": format,
		"kid": s.keyID,
	}

	jwtStr, err := s.signJWT(header, payload)
	if err != nil {
		return "", err
	}
	return jwtStr + "~", nil
}

// signJWT produces a compact JWS using ES256.
func (s *Signer) signJWT(header, payload map[string]interface{}) (string, error) {
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hBytes) + "." +
		base64.RawURLEncoding.EncodeToString(pBytes)

	digest := sha256.Sum256([]byte(signingInput))
	r, sig, err := ecdsa.Sign(rand.Reader, s.privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	rb := padLeft(r.Bytes(), 32)
	sb := padLeft(sig.Bytes(), 32)
	sigBytes := append(rb, sb...) //nolint:gocritic

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func ecPublicKeyToJWK(key *ecdsa.PublicKey, kid string) map[string]interface{} {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padLeft(key.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padLeft(key.Y.Bytes(), 32)),
	}
	if kid != "" {
		jwk["kid"] = kid
	}
	return jwk
}

func publicKeyToJWK(key crypto.PublicKey) (map[string]interface{}, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return ecPublicKeyToJWK(k, ""), nil
	default:
		return nil, fmt.Errorf("unsupported holder key type: %T", key)
	}
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// randomHex generates n random bytes and returns them as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
