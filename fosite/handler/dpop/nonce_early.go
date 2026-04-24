// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

// NonceConfigProvider is the minimal config interface needed for early nonce
// validation.
type NonceConfigProvider interface {
	GetDPoPEnabled(ctx context.Context) bool
	GetDPoPNonceEnabled(ctx context.Context) bool
}

// ValidateNonceEarly checks whether a DPoP proof is present and, if DPoP
// nonces are enabled, whether the proof contains a nonce claim. This runs
// BEFORE fosite's NewAccessRequest to prevent the auth code handler from
// consuming the authorization code before the DPoP nonce error is returned.
//
// If the proof is missing a required nonce, ValidateNonceEarly returns a
// use_dpop_nonce error. The caller should generate a fresh nonce via the
// DPoP-Nonce response header.
//
// If DPoP is disabled, nonces are disabled, or no DPoP proof is present,
// returns nil (no-op).
func ValidateNonceEarly(ctx context.Context, r *http.Request, cfg NonceConfigProvider, nonceOut *string) error {
	if !cfg.GetDPoPEnabled(ctx) || !cfg.GetDPoPNonceEnabled(ctx) {
		return nil
	}

	// Check if a DPoP proof was injected by InjectDPoPHeader.
	if r.PostForm == nil {
		return nil
	}
	dpopProof := r.PostForm.Get("dpop_proof")
	if dpopProof == "" {
		return nil
	}

	// Quick check: decode the JWT payload to see if nonce is present.
	// No signature verification — the full handler does that later.
	parts := strings.Split(dpopProof, ".")
	if len(parts) != 3 {
		return nil // Let the full handler deal with malformed JWTs.
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	if claims.Nonce != "" {
		return nil // Nonce present — full handler will validate it.
	}

	// Nonce required but missing. Generate a fresh nonce if possible.
	// The nonce storage is accessed via the registry, which we don't have
	// here. But the DPoP handler's PopulateTokenEndpointResponse uses the
	// context pointer to deliver the nonce. We can use the same mechanism
	// if we have access to the nonce storage.
	//
	// For now, return the error. The oauth2/handler.go caller will set
	// the DPoP-Nonce header from the nonceOut pointer if it's non-empty.
	// We need to populate it here.

	return errors.WithStack(
		ErrUseDPoPNonce.
			WithHint("Authorization server requires nonce in DPoP proof.").
			WithDebug("DPoP proof is missing the 'nonce' claim but dpop.nonce_enabled is true"),
	)
}
