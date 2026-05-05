// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rar

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// Compile-time check that RARHandler satisfies TokenEndpointHandler.
var _ fosite.TokenEndpointHandler = (*RARHandler)(nil)

// CanHandleTokenEndpointRequest returns true when the token request form
// contains an authorization_details parameter, enabling subset validation
// via HandleTokenEndpointRequest.
func (h *RARHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetRequestForm().Get("authorization_details") != ""
}

// CanSkipClientAuth returns true when the grant type is the pre-authorized
// code flow. RAR runs at the token endpoint as a cross-cutting handler that
// validates authorization_details against the session — it should not enforce
// client authentication on its own. The grant-specific handler (preauth) is
// responsible for the client auth decision based on its own configuration
// (e.g., preauth.anonymous_access). For all other grant types, RAR returns
// false because they always require client authentication anyway.
//
// SEC-346: Without this, an anonymous pre-auth request that includes
// authorization_details would be rejected by RAR before the preauth handler
// could run, even though the preauth handler is configured to allow anonymous
// access.
func (h *RARHandler) CanSkipClientAuth(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code")
}

// HandleTokenEndpointRequest validates that the credential_configuration_id values
// in the token request's authorization_details are a subset of the previously
// authorized set stored in session.Extra["authorization_details"].
//
// SEC-346: For the pre-authorized code grant, this validation is delegated to
// the preauth handler (which checks against the stored CredentialConfigurationIDs
// — the equivalent of the authorized set, established at code creation time).
// At this point in the pipeline the preauth handler has not yet run, so the
// session is still empty; validating here would always reject. Skip cleanly
// and let the preauth handler perform the subset check.
func (h *RARHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if requester.GetGrantTypes().ExactOne("urn:ietf:params:oauth:grant-type:pre-authorized_code") {
		return nil
	}

	rawJSON := requester.GetRequestForm().Get("authorization_details")
	if rawJSON == "" {
		return nil
	}

	// Parse the token request's authorization_details.
	var requestDetails []map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &requestDetails); err != nil {
		return errors.WithStack(
			ErrInvalidAuthorizationDetails.
				WithHint("malformed authorization_details JSON").
				WithDebugf("json parse error: %s", err.Error()),
		)
	}

	// Extract credential_configuration_id values from the token request.
	requestedIDs := extractCredentialConfigIDs(requestDetails)

	// Read the authorized set from session.Extra["authorization_details"].
	authorizedIDs, err := extractAuthorizedCredentialConfigIDs(requester)
	if err != nil {
		return err
	}

	// Validate that every requested credential_configuration_id is in the authorized set.
	for _, id := range requestedIDs {
		if !authorizedIDs[id] {
			return errors.WithStack(
				ErrInvalidAuthorizationDetails.
					WithHint(fmt.Sprintf("credential_configuration_id not previously authorized: %s", id)),
			)
		}
	}

	return nil
}

// PopulateTokenEndpointResponse copies session.Extra["authorization_details"] into
// the token response extras. Returns fosite.ErrUnknownRequest when no
// authorization_details is present in the session (handler not responsible).
// Logs a warning when openid_credential entries are missing credential_identifiers.
func (h *RARHandler) PopulateTokenEndpointResponse(_ context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	session, ok := requester.GetSession().(fosite.ExtraClaimsSession)
	if !ok {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	extra := session.GetExtraClaims()
	authDetails, exists := extra["authorization_details"]
	if !exists {
		return errors.WithStack(fosite.ErrUnknownRequest)
	}

	responder.SetExtra("authorization_details", authDetails)

	// Log a warning if any openid_credential entry is missing credential_identifiers.
	checkCredentialIdentifiers(authDetails)

	return nil
}

// extractCredentialConfigIDs collects all credential_configuration_id values
// from a parsed authorization_details array.
func extractCredentialConfigIDs(details []map[string]interface{}) []string {
	var ids []string
	for _, obj := range details {
		if id, ok := obj["credential_configuration_id"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// extractAuthorizedCredentialConfigIDs reads the authorized set of
// credential_configuration_id values from session.Extra["authorization_details"].
func extractAuthorizedCredentialConfigIDs(requester fosite.AccessRequester) (map[string]bool, error) {
	session, ok := requester.GetSession().(fosite.ExtraClaimsSession)
	if !ok {
		return nil, nil
	}

	extra := session.GetExtraClaims()
	authDetailsRaw, exists := extra["authorization_details"]
	if !exists {
		return nil, nil
	}

	authDetails, ok := authDetailsRaw.([]interface{})
	if !ok {
		return nil, nil
	}

	authorized := make(map[string]bool)
	for _, item := range authDetails {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := obj["credential_configuration_id"].(string); ok && id != "" {
			authorized[id] = true
		}
	}

	return authorized, nil
}

// checkCredentialIdentifiers logs a warning for any openid_credential entry
// that is missing credential_identifiers or has an empty array.
func checkCredentialIdentifiers(authDetailsRaw interface{}) {
	authDetails, ok := authDetailsRaw.([]interface{})
	if !ok {
		return
	}

	for _, item := range authDetails {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		typeVal, ok := obj["type"].(string)
		if !ok || typeVal != "openid_credential" {
			continue
		}

		credIDs, hasCredIDs := obj["credential_identifiers"]
		if !hasCredIDs {
			slog.Warn("openid_credential entry missing credential_identifiers — Consent Node or Token Hook should set them",
				"credential_configuration_id", obj["credential_configuration_id"],
			)
			continue
		}

		if arr, ok := credIDs.([]interface{}); ok && len(arr) == 0 {
			slog.Warn("openid_credential entry has empty credential_identifiers — Consent Node or Token Hook should populate them",
				"credential_configuration_id", obj["credential_configuration_id"],
			)
		}
	}
}
