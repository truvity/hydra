// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package preauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/x/errorsx"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/oauth2"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/fosite/token/jwt"
	oauth2session "github.com/ory/hydra/v2/oauth2"
)

// CoreStrategy is a type alias for oauth2.CoreStrategy which composes
// AuthorizeCodeStrategy, AccessTokenStrategy, and RefreshTokenStrategy.
// The pre-auth handler uses AuthorizeCodeSignature for HMAC signature extraction,
// GenerateAuthorizeCode for code generation (admin API), and GenerateAccessToken /
// GenerateRefreshToken for token issuance at the token endpoint.
type CoreStrategy = oauth2.CoreStrategy

// PreAuthorizedCodeConfigProvider is a type alias for the fosite.PreAuthorizedCodeConfigProvider
// interface, allowing external packages to reference it without importing fosite directly.
type PreAuthorizedCodeConfigProvider = fosite.PreAuthorizedCodeConfigProvider

// Handler implements fosite.TokenEndpointHandler for the Pre-Authorized Code
// grant type (urn:ietf:params:oauth:grant-type:pre-authorized_code).
type Handler struct {
	Config  PreAuthorizedCodeConfigProvider
	Storage interface {
		PreAuthorizedCodeStorageProvider
		oauth2.AccessTokenStorageProvider
	}
	Strategy CoreStrategy
}

// Compile-time check that Handler satisfies fosite.TokenEndpointHandler.
var _ fosite.TokenEndpointHandler = (*Handler)(nil)

// CanHandleTokenEndpointRequest returns true when the grant type is
// urn:ietf:params:oauth:grant-type:pre-authorized_code.
func (h *Handler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code")
}

// CanSkipClientAuth returns the configured anonymous access setting.
func (h *Handler) CanSkipClientAuth(ctx context.Context, _ fosite.AccessRequester) bool {
	return h.Config.GetPreAuthorizedCodeAnonymousAccess(ctx)
}

// HandleTokenEndpointRequest validates the pre-authorized code grant: extracts
// the code, verifies it against storage, validates tx_code and client_id,
// atomically invalidates the code, validates authorization_details, and
// populates the requester session.
func (h *Handler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	// 1. Extract pre-authorized_code from request form.
	code := requester.GetRequestForm().Get("pre-authorized_code")
	if code == "" {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("pre-authorized_code parameter is required"))
	}

	// 2. Compute HMAC signature for DB lookup.
	signature := h.Strategy.AuthorizeCodeSignature(ctx, code)

	// 3. Load stored grant data.
	data, err := h.Storage.PreAuthorizedCodeStorage().GetPreAuthorizedCodeSession(ctx, signature)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("pre-authorized code not found"))
		}
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// 4. Check redeemed flag.
	if data.Redeemed {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("pre-authorized code already redeemed"))
	}

	// 5. Check expiry.
	if data.ExpiresAt.Before(time.Now()) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("pre-authorized code expired"))
	}

	// 6. Client ID validation: if stored ClientID is non-empty AND client auth
	// was performed (requester has a non-empty client ID), verify match.
	if data.ClientID != "" && requester.GetClient() != nil && requester.GetClient().GetID() != "" {
		if requester.GetClient().GetID() != data.ClientID {
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("client_id mismatch"))
		}
	}

	// 7. Transaction code validation.
	if err := h.validateTxCode(data, requester); err != nil {
		return err
	}

	// 8. Atomic invalidation.
	if err := h.Storage.PreAuthorizedCodeStorage().InvalidatePreAuthorizedCode(ctx, signature); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// 9. authorization_details validation.
	authDetails, err := h.resolveAuthorizationDetails(data, requester)
	if err != nil {
		return err
	}

	// 10. Deserialize SessionData into *oauth2.Session, set granted scopes,
	// set Session.Extra["authorization_details"], and set session on requester.
	session := &oauth2session.Session{}
	if err := json.Unmarshal(data.SessionData, session); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("failed to deserialize session data: %s", err.Error()))
	}

	// Ensure DefaultSession and Extra map are initialized.
	if session.DefaultSession == nil {
		session.DefaultSession = &openid.DefaultSession{
			Claims:    new(jwt.IDTokenClaims),
			Headers:   new(jwt.Headers),
			ExpiresAt: make(map[fosite.TokenType]time.Time),
		}
	}
	if session.Extra == nil {
		session.Extra = make(map[string]interface{})
	}
	session.Extra["authorization_details"] = authDetails

	// Preserve DPoP confirmation claim (cnf.jkt) set by the DPoP handler
	// in its HandleTokenEndpointRequest. The DPoP handler runs before preauth
	// and writes cnf into the requester's session extra. We must carry it over
	// into the deserialized session to avoid losing the DPoP binding.
	if existingSession, ok := requester.GetSession().(fosite.ExtraClaimsSession); ok {
		if cnf, exists := existingSession.GetExtraClaims()["cnf"]; exists {
			session.Extra["cnf"] = cnf
		}
	}

	for _, scope := range data.GrantedScope {
		requester.GrantScope(scope)
	}

	requester.SetSession(session)

	return nil
}

// validateTxCode implements the 5-case transaction code validation matrix from
// the design document using SHA-256 hashing and constant-time comparison.
func (h *Handler) validateTxCode(data *PreAuthorizedCodeData, requester fosite.AccessRequester) error {
	txCode := requester.GetRequestForm().Get("tx_code")
	storedHash := data.TxCodeHash

	switch {
	case storedHash != "" && txCode != "":
		// Required and provided — hash and compare.
		hash := sha256.Sum256([]byte(txCode))
		computedHash := hex.EncodeToString(hash[:])
		if subtle.ConstantTimeCompare([]byte(computedHash), []byte(storedHash)) != 1 {
			return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("tx_code does not match"))
		}
		return nil

	case storedHash != "" && txCode == "":
		// Required but not provided.
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("tx_code required but not provided"))

	case storedHash == "" && txCode != "":
		// Not required but provided.
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("tx_code provided but not expected"))

	default:
		// Neither required nor provided — proceed.
		return nil
	}
}

// resolveAuthorizationDetails validates authorization_details from the token
// request (subset check) or constructs a default set from stored
// CredentialConfigurationIDs.
func (h *Handler) resolveAuthorizationDetails(data *PreAuthorizedCodeData, requester fosite.AccessRequester) ([]map[string]interface{}, error) {
	rawJSON := requester.GetRequestForm().Get("authorization_details")

	if rawJSON != "" {
		// Parse the token request's authorization_details.
		var requestDetails []map[string]interface{}
		if err := json.Unmarshal([]byte(rawJSON), &requestDetails); err != nil {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.
				WithHint("malformed authorization_details JSON").
				WithDebugf("json parse error: %s", err.Error()))
		}

		// Reject empty array per RFC 9396 §2.
		if len(requestDetails) == 0 {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.
				WithHint("authorization_details must be a non-empty array"))
		}

		// Build allowed set from stored CredentialConfigurationIDs.
		allowed := make(map[string]bool, len(data.CredentialConfigurationIDs))
		for _, id := range data.CredentialConfigurationIDs {
			allowed[id] = true
		}

		// Validate every requested credential_configuration_id is in the allowed set.
		for _, obj := range requestDetails {
			if id, ok := obj["credential_configuration_id"].(string); ok && id != "" {
				if !allowed[id] {
					return nil, errorsx.WithStack(fosite.ErrInvalidRequest.
						WithHint("requested credential_configuration_id not authorized").
						WithDebugf("credential_configuration_id %q not in allowed set", id))
				}

				// Ensure credential_identifiers is present per OID4VCI 1.0 Section 6.2.
				if _, hasIDs := obj["credential_identifiers"]; !hasIDs {
					obj["credential_identifiers"] = []interface{}{id}
				}
			}
		}

		return requestDetails, nil
	}

	// No authorization_details in request — construct default set from all
	// stored CredentialConfigurationIDs.
	defaultDetails := make([]map[string]interface{}, 0, len(data.CredentialConfigurationIDs))
	for _, id := range data.CredentialConfigurationIDs {
		defaultDetails = append(defaultDetails, map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": id,
			"credential_identifiers":      []interface{}{id},
		})
	}

	return defaultDetails, nil
}

// getExpiresIn computes the remaining lifetime for a token type. If the session
// has an explicit expiry set, it returns the duration until that time; otherwise
// it falls back to the default lifespan. Same logic as fosite/handler/oauth2.getExpiresIn.
func getExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}

// PopulateTokenEndpointResponse issues an access token (and optionally a refresh
// token) for the Pre-Authorized Code grant type. Returns fosite.ErrUnknownRequest
// for non-matching grant types so the response writer skips this handler.
func (h *Handler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	// SEC-346: When anonymous access is enabled and no client was authenticated,
	// assign the synthetic anonymous client so that CreateAccessTokenSession can
	// persist the token (hydra_oauth2_access.client_id has a NOT NULL FK to
	// hydra_client). The anonymous client row is provisioned via DB migration.
	if requester.GetClient() == nil || requester.GetClient().GetID() == "" {
		requester.(*fosite.AccessRequest).Client = &fosite.DefaultClient{
			ID:     AnonymousClientID,
			Public: true,
		}
	}

	// Determine access token lifespan. Type-assert Config to AccessTokenLifespanProvider
	// since PreAuthorizedCodeConfigProvider does not include GetAccessTokenLifespan.
	var atLifespan time.Duration
	if p, ok := h.Config.(fosite.AccessTokenLifespanProvider); ok {
		defaultLifespan := p.GetAccessTokenLifespan(ctx)
		if requester.GetClient() != nil {
			atLifespan = fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, defaultLifespan)
		} else {
			atLifespan = defaultLifespan
		}
	} else {
		atLifespan = time.Hour
	}

	// Set access token expiry on session so getExpiresIn can use it.
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	// Issue access token.
	access, accessSignature, err := h.Strategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Store the access token session for introspection.
	if err := h.Storage.AccessTokenStorage().CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())

	// Copy authorization_details from session extras to response extras.
	if session, ok := requester.GetSession().(fosite.ExtraClaimsSession); ok {
		if authDetails, exists := session.GetExtraClaims()["authorization_details"]; exists {
			responder.SetExtra("authorization_details", authDetails)
		}
	}

	// Refresh token eligibility check (Req 4.6, 4.7).
	// Anonymous (no bound client) → never issue refresh token.
	if requester.GetClient() == nil || requester.GetClient().GetID() == "" || requester.GetClient().GetID() == AnonymousClientID {
		return nil
	}

	// Client must have refresh_token grant type.
	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return nil
	}

	// Check refresh token scopes: if configured scopes are non-empty, the granted
	// scopes must include at least one. If configured scopes are empty, all
	// exchanges get refresh tokens.
	if p, ok := h.Config.(fosite.RefreshTokenScopesProvider); ok {
		rtScopes := p.GetRefreshTokenScopes(ctx)
		if len(rtScopes) > 0 && !requester.GetGrantedScopes().HasOneOf(rtScopes...) {
			return nil
		}
	}

	refresh, _, err := h.Strategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	responder.SetExtra("refresh_token", refresh)

	return nil
}
