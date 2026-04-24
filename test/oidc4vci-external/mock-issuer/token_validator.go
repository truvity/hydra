// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenInfo holds the information extracted from a validated access token.
type TokenInfo struct {
	Subject string
	Scopes  []string
	Extra   map[string]interface{}
}

// TokenValidator validates access tokens via Hydra's admin introspection endpoint.
type TokenValidator struct {
	introspectionURL string
	httpClient       *http.Client
}

// NewTokenValidator creates a TokenValidator that calls the given Hydra admin URL.
func NewTokenValidator(authServerAdminURL string) *TokenValidator {
	return &TokenValidator{
		introspectionURL: strings.TrimRight(authServerAdminURL, "/") + "/admin/oauth2/introspect",
		httpClient:       &http.Client{Timeout: 10 * time.Second},
	}
}

// introspectionResponse is the JSON shape returned by Hydra's introspection endpoint.
type introspectionResponse struct {
	Active bool                   `json:"active"`
	Sub    string                 `json:"sub"`
	Scope  string                 `json:"scope"`
	Ext    map[string]interface{} `json:"ext"`
}

// Validate calls Hydra's introspection endpoint and returns TokenInfo on success.
func (v *TokenValidator) Validate(ctx context.Context, token string) (*TokenInfo, error) {
	if token == "" {
		return nil, newOIDCError(errCodeInvalidToken, 401, "access token is required")
	}

	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectionURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, newOIDCError(errCodeInvalidToken, 401, "failed to build introspection request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("introspection request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newOIDCError(errCodeInvalidToken, 401,
			fmt.Sprintf("introspection returned HTTP %d", resp.StatusCode))
	}

	var ir introspectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, newOIDCError(errCodeInvalidToken, 401, "failed to decode introspection response")
	}

	if !ir.Active {
		return nil, newOIDCError(errCodeInvalidToken, 401, "token is not active")
	}

	return &TokenInfo{
		Subject: ir.Sub,
		Scopes:  strings.Fields(ir.Scope),
		Extra:   ir.Ext,
	}, nil
}
