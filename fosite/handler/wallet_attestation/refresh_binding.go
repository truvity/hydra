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

// WIACnfExtraKey is the session extra member holding the RFC 7638 thumbprint
// of the Wallet Attestation's cnf.jwk (the Client Instance Key). It travels
// with the access token session, so the token hook request and the
// introspection ext carry it, and it is the refresh token binding.
const WIACnfExtraKey = "wia_cnf"

// RefreshBindingHandler is a lightweight TokenEndpointHandler that stores the
// Client Instance Key thumbprint in the session when a token is issued via
// Wallet Attestation, and verifies it on refresh. This is needed because the
// ClientAuthenticationStrategy function does not have access to the session.
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

// HandleTokenEndpointRequest stores the Client Instance Key thumbprint as
// wia_cnf on every grant except refresh_token, and on refresh_token compares
// the stored wia_cnf against the current request's cnf.jwk thumbprint
// (transported via the request form by the authenticator).
//
// The thumbprint is stored here, at token validation, and not in
// PopulateTokenEndpointResponse: the access request hooks (the token hook)
// run between the two phases and the grant-type handler persists the session
// in PopulateTokenEndpointResponse, so only a value set now reaches the token
// hook, the introspection ext and the stored refresh token session. The DPoP
// handler stores cnf.jkt at the same point for the same reason.
func (h *RefreshBindingHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !requester.GetGrantTypes().ExactOne("refresh_token") {
		return h.storeThumbprint(requester)
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

	storedJKT, ok := extra[WIACnfExtraKey].(string)
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

// PopulateTokenEndpointResponse does nothing: the thumbprint is stored by
// HandleTokenEndpointRequest, before the session is persisted.
func (h *RefreshBindingHandler) PopulateTokenEndpointResponse(context.Context, fosite.AccessRequester, fosite.AccessResponder) error {
	return nil
}

// storeThumbprint sets wia_cnf in the session extra when the request was
// authenticated with a Wallet Attestation.
func (h *RefreshBindingHandler) storeThumbprint(requester fosite.AccessRequester) error {
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
	if extra == nil {
		return nil
	}

	extra[WIACnfExtraKey] = jkt

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
