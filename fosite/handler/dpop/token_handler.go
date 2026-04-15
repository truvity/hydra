// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package dpop

import (
	"context"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// Compile-time check that Handler satisfies TokenEndpointHandler.
var _ fosite.TokenEndpointHandler = (*Handler)(nil)

// tokenURLProvider is a local interface for accessing GetTokenURLs via type
// assertion. The handler's Config field is DPoPConfigProvider, but at runtime
// the concrete value is the full Configurator which also implements
// TokenURLProvider. This avoids adding GetTokenURLs to DPoPConfigProvider.
type tokenURLProvider interface {
	GetTokenURLs(ctx context.Context) []string
}

// CanHandleTokenEndpointRequest returns true when the request form contains
// dpop_proof or dpop_proof_error, indicating a DPoP header was present on the
// HTTP request (injected by the endpoint handler via InjectDPoPHeader).
func (h *Handler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	form := requester.GetRequestForm()
	return form.Get("dpop_proof") != "" || form.Get("dpop_proof_error") != ""
}

// CanSkipClientAuth always returns false — DPoP is a token binding mechanism,
// not a client authentication method.
func (h *Handler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

// HandleTokenEndpointRequest validates the DPoP proof JWT per RFC 9449 §4.3,
// checks dpop_jkt binding from the authorization session, and checks refresh
// token DPoP binding for public clients. The validated JKT is stored in the
// session extra claims for PopulateTokenEndpointResponse to read.
func (h *Handler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	form := requester.GetRequestForm()

	// Resolve token endpoint URLs for htu validation via type assertion.
	var allowedURLs []string
	if p, ok := h.Config.(tokenURLProvider); ok {
		allowedURLs = p.GetTokenURLs(ctx)
	}

	// Validate the DPoP proof (full §4.3 checklist).
	jkt, _, err := h.validateDPoPProof(ctx, form, allowedURLs)
	if err != nil {
		return err
	}

	// Get session for binding checks.
	session, ok := requester.GetSession().(fosite.ExtraClaimsSession)
	if !ok {
		// Session doesn't support extra claims — store JKT in form for
		// PopulateTokenEndpointResponse and return.
		form.Set("__dpop_validated_jkt", jkt)
		return nil
	}

	extra := session.GetExtraClaims()

	// dpop_jkt binding check: if the authorization session contains a dpop_jkt
	// (set during PAR and carried through the authorize flow), verify the
	// proof's public key matches.
	dpopJKT := form.Get("dpop_jkt")
	if dpopJKT != "" && dpopJKT != jkt {
		return errors.WithStack(
			ErrInvalidDPoPProof.
				WithHint("The DPoP proof public key does not match the dpop_jkt from the authorization request.").
				WithDebugf("dpop_jkt=%q != proof jkt=%q", dpopJKT, jkt),
		)
	}

	// Refresh token DPoP binding check: for grant_type=refresh_token, verify
	// the proof's key matches the stored binding (public clients only).
	if form.Get("grant_type") == "refresh_token" {
		if binding, ok := extra["dpop_jkt_binding"].(string); ok && binding != "" {
			if jkt != binding {
				return errors.WithStack(
					ErrInvalidDPoPProof.
						WithHint("The DPoP proof public key does not match the refresh token's DPoP binding.").
						WithDebugf("dpop_jkt_binding=%q != proof jkt=%q", binding, jkt),
				)
			}
		}
	}

	// Store the validated JKT in the session extra for PopulateTokenEndpointResponse.
	// Using session extra as a transport mechanism since context is immutable.
	extra["__dpop_validated_jkt"] = jkt

	return nil
}

// PopulateTokenEndpointResponse sets cnf.jkt in the session, sets token_type
// to DPoP, binds refresh tokens for public clients, and generates a fresh
// nonce when nonces are enabled.
func (h *Handler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	form := requester.GetRequestForm()

	// If no DPoP proof was present, this handler is not responsible.
	if form.Get("dpop_proof") == "" {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	// Read the validated JKT from session extra (stored by HandleTokenEndpointRequest).
	session, ok := requester.GetSession().(fosite.ExtraClaimsSession)
	if !ok {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	extra := session.GetExtraClaims()

	jkt, _ := extra["__dpop_validated_jkt"].(string)
	if jkt == "" {
		// Fallback: check request form (for sessions that don't support extra claims
		// in HandleTokenEndpointRequest).
		jkt = form.Get("__dpop_validated_jkt")
	}
	if jkt == "" {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	// Clean up the transport key from session extra.
	delete(extra, "__dpop_validated_jkt")

	// Store confirmation claim: cnf.jkt for introspection propagation.
	extra["cnf"] = map[string]interface{}{"jkt": jkt}

	// Set token type to DPoP.
	responder.SetTokenType("DPoP")

	// For public clients, bind the refresh token to the DPoP key.
	if isPublicClient(requester.GetClient()) {
		extra["dpop_jkt_binding"] = jkt
	}

	// If nonces are enabled, generate a fresh nonce for the response header.
	if h.Config.GetDPoPNonceEnabled(ctx) {
		freshNonce, err := h.NonceStore.CreateDPoPNonce(ctx)
		if err != nil {
			return errors.WithStack(
				ErrInvalidDPoPProof.
					WithHint("Failed to generate DPoP nonce for response.").
					WithDebugf("nonce creation error: %s", err.Error()),
			)
		}
		if noncePtr, ok := ctx.Value(DPoPNonceContextKey).(*string); ok && noncePtr != nil {
			*noncePtr = freshNonce
		}
	}

	return nil
}
