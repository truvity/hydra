// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package wallet_attestation

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"net/url"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// RefreshBindingHandler is a lightweight TokenEndpointHandler that stores the
// Client Instance Key thumbprint in the session when a refresh token is issued
// via Wallet Attestation, and verifies it on refresh. This is needed because
// the ClientAuthenticationStrategy function does not have access to the session.
type RefreshBindingHandler struct {
	Config WalletAttestationConfigProvider
}

var _ fosite.TokenEndpointHandler = (*RefreshBindingHandler)(nil)

// CanHandleTokenEndpointRequest returns true when the client's
// token_endpoint_auth_method is attest_jwt_client_auth.
func (h *RefreshBindingHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	oidcClient, ok := requester.GetClient().(fosite.OpenIDConnectClient)
	if !ok {
		return false
	}
	return oidcClient.GetTokenEndpointAuthMethod() == "attest_jwt_client_auth"
}

// CanSkipClientAuth returns false — client authentication is always required.
func (h *RefreshBindingHandler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

// HandleTokenEndpointRequest verifies refresh token key binding on
// grant_type=refresh_token requests. It reads the stored
// wallet_attestation_cnf_jkt from the session and compares it against the
// current request's cnf.jwk thumbprint (transported via the request form by
// the authenticator).
func (h *RefreshBindingHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetGrantTypes().ExactOne("refresh_token") {
		return nil
	}

	// Read the cnf.jwk from the request form (set by the authenticator).
	cnfKey, err := getCNFKeyFromForm(requester.GetRequestForm())
	if err != nil || cnfKey == nil {
		// No cnf.jwk in form — the request was not authenticated via Wallet Attestation.
		return nil
	}

	// Read the stored thumbprint from the session.
	session, ok := requester.GetSession().(fosite.ExtraClaimsSession)
	if !ok {
		return nil
	}

	extra := session.GetExtraClaims()
	if extra == nil {
		return nil
	}

	storedJKT, ok := extra["wallet_attestation_cnf_jkt"].(string)
	if !ok || storedJKT == "" {
		// No stored binding — this is the first issuance or binding was not set.
		return nil
	}

	// Compute the current key's thumbprint and compare.
	currentJKT, err := computeJWKThumbprint(cnfKey)
	if err != nil {
		return errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Failed to compute JWK thumbprint for refresh token binding check.").
				WithDebugf("thumbprint error: %s", err.Error()),
		)
	}

	if currentJKT != storedJKT {
		return errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Refresh token is bound to a different client instance key.").
				WithDebugf("stored jkt=%q, current jkt=%q", storedJKT, currentJKT),
		)
	}

	return nil
}

// PopulateTokenEndpointResponse computes the JWK thumbprint of the current
// cnf.jwk and stores it in session.Extra["wallet_attestation_cnf_jkt"] for
// future refresh token binding checks.
func (h *RefreshBindingHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, _ fosite.AccessResponder) error {
	// Read the cnf.jwk from the request form (set by the authenticator).
	cnfKey, err := getCNFKeyFromForm(requester.GetRequestForm())
	if err != nil || cnfKey == nil {
		return nil
	}

	session, ok := requester.GetSession().(fosite.ExtraClaimsSession)
	if !ok {
		return nil
	}

	jkt, err := computeJWKThumbprint(cnfKey)
	if err != nil {
		return errors.WithStack(
			ErrInvalidWalletAttestation.
				WithHint("Failed to compute JWK thumbprint for session storage.").
				WithDebugf("thumbprint error: %s", err.Error()),
		)
	}

	extra := session.GetExtraClaims()
	extra["wallet_attestation_cnf_jkt"] = jkt

	return nil
}

// computeJWKThumbprint computes the RFC 7638 JWK Thumbprint using SHA-256
// and returns the base64url-encoded result.
func computeJWKThumbprint(jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errors.Wrap(err, "jwk thumbprint computation failed")
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

// getCNFKeyFromForm reads the serialized cnf.jwk from the request form
// (set by the authenticator via walletAttestationCNFFormKey). Returns nil
// if the form key is absent or empty.
func getCNFKeyFromForm(form url.Values) (*jose.JSONWebKey, error) {
	raw := form.Get(walletAttestationCNFFormKey)
	if raw == "" {
		return nil, nil
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(raw), &jwk); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal cnf.jwk from form")
	}
	return &jwk, nil
}
