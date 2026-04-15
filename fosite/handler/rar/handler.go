// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// RARConfigProvider is a type alias for the fosite.RARConfigProvider interface,
// allowing external packages to reference it without importing fosite directly.
type RARConfigProvider = fosite.RARConfigProvider

// RARHandler validates authorization_details on authorize, PAR, and token endpoints
// per RFC 9396.
type RARHandler struct {
	Config RARConfigProvider
}

// HandleAuthorizeEndpointRequest validates authorization_details on the authorize endpoint.
// Returns nil when authorization_details is absent (not responsible).
func (h *RARHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	rawJSON := ar.GetRequestForm().Get("authorization_details")
	parsed, err := validateAuthorizationDetails(ctx, rawJSON, h.Config)
	if err != nil {
		return err
	}

	if parsed == nil {
		return nil
	}

	// Store the original raw JSON (not re-serialized) for downstream consumption.
	ar.GetRequestForm().Set("authorization_details", rawJSON)

	return nil
}

// HandlePushedAuthorizeEndpointRequest validates authorization_details on the PAR endpoint.
// Uses the same validation logic as HandleAuthorizeEndpointRequest.
func (h *RARHandler) HandlePushedAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.PushedAuthorizeResponder) error {
	rawJSON := ar.GetRequestForm().Get("authorization_details")
	parsed, err := validateAuthorizationDetails(ctx, rawJSON, h.Config)
	if err != nil {
		return err
	}

	if parsed == nil {
		return nil
	}

	// Store the original raw JSON (not re-serialized) for downstream consumption.
	ar.GetRequestForm().Set("authorization_details", rawJSON)

	return nil
}

// validateAuthorizationDetails parses and validates an authorization_details JSON string.
// Returns nil, nil when the input is empty (handler not responsible).
// Returns the parsed array on success, or an error with ErrInvalidAuthorizationDetails on failure.
func validateAuthorizationDetails(ctx context.Context, rawJSON string, config RARConfigProvider) ([]map[string]interface{}, error) {
	if rawJSON == "" {
		return nil, nil
	}

	var details []map[string]interface{}
	if err := json.Unmarshal([]byte(rawJSON), &details); err != nil {
		return nil, errors.WithStack(
			ErrInvalidAuthorizationDetails.
				WithHint("malformed authorization_details JSON").
				WithDebugf("json parse error: %s", err.Error()),
		)
	}

	supportedTypes := config.GetRARTypesSupported(ctx)

	for i, obj := range details {
		typeVal, ok := obj["type"]
		if !ok {
			return nil, errors.WithStack(
				ErrInvalidAuthorizationDetails.
					WithHint("missing type field in authorization_details object").
					WithDebugf("object at index %d missing type field", i),
			)
		}

		typeStr, ok := typeVal.(string)
		if !ok {
			return nil, errors.WithStack(
				ErrInvalidAuthorizationDetails.
					WithHint("missing type field in authorization_details object").
					WithDebugf("object at index %d has non-string type field", i),
			)
		}

		if !typeSupported(typeStr, supportedTypes) {
			return nil, errors.WithStack(
				ErrInvalidAuthorizationDetails.
					WithHint(fmt.Sprintf("unsupported authorization_details type: %s", typeStr)).
					WithDebugf("object at index %d has unsupported type %q", i, typeStr),
			)
		}

		if typeStr == "openid_credential" {
			credCfgID, hasCredCfgID := obj["credential_configuration_id"]
			if !hasCredCfgID {
				return nil, errors.WithStack(
					ErrInvalidAuthorizationDetails.
						WithHint("credential_configuration_id required for openid_credential type").
						WithDebugf("object at index %d missing credential_configuration_id", i),
				)
			}

			credCfgIDStr, ok := credCfgID.(string)
			if !ok || credCfgIDStr == "" {
				return nil, errors.WithStack(
					ErrInvalidAuthorizationDetails.
						WithHint("credential_configuration_id required for openid_credential type").
						WithDebugf("object at index %d has empty or non-string credential_configuration_id", i),
				)
			}
		}
	}

	return details, nil
}

// typeSupported checks if a type value is in the supported types list.
func typeSupported(typeVal string, supported []string) bool {
	for _, s := range supported {
		if s == typeVal {
			return true
		}
	}
	return false
}
