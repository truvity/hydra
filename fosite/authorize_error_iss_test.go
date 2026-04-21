// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	. "github.com/ory/hydra/v2/fosite"
)

// Feature: oidc4vci-haip-metadata, Property 5: RFC 9207 iss in Error Redirect Responses
//
// For any redirect error with random issuer URL, when
// GetAuthResponseIssParameterEnabled is true, verify error redirect URL
// contains iss parameter matching issuer; when false or non-redirect error,
// verify iss is absent.
//
// **Validates: Requirements 7.1, 7.2, 7.3, 7.4**
func TestProperty5_RFC9207IssInErrorRedirectResponses(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		issEnabled := rapid.Bool().Draw(t, "issEnabled")
		isRedirect := rapid.Bool().Draw(t, "isRedirect")
		issuer := rapid.StringMatching(`https://[a-z]{3,10}\.[a-z]{2,5}`).Draw(t, "issuer")

		cfg := &issConfig{
			AuthResponseIssEnabled: issEnabled,
			Issuer:                 issuer,
		}
		f := &Fosite{Config: cfg}

		ctx := context.Background()

		if isRedirect {
			// Redirect error: valid redirect URI with a registered client.
			redir, err := url.Parse("https://client.example.com/callback")
			require.NoError(t, err)

			client := &DefaultClient{
				ID:            "test-client",
				RedirectURIs:  []string{"https://client.example.com/callback"},
				ResponseTypes: []string{"code"},
			}

			ar := &AuthorizeRequest{
				RedirectURI:  redir,
				ResponseMode: ResponseModeQuery,
				Request:      *NewRequest(),
			}
			ar.Request.Client = client

			rw := httptest.NewRecorder()
			f.WriteAuthorizeError(ctx, rw, ar, ErrInvalidRequest)

			assert.Equal(t, http.StatusSeeOther, rw.Code,
				"redirect error should produce 303 See Other")

			loc := rw.Header().Get("Location")
			require.NotEmpty(t, loc, "expected a redirect Location header")
			parsed, err := url.Parse(loc)
			require.NoError(t, err)

			if issEnabled {
				assert.Equal(t, issuer, parsed.Query().Get("iss"),
					"iss parameter should equal the configured issuer for redirect errors when enabled")
			} else {
				assert.Empty(t, parsed.Query().Get("iss"),
					"iss parameter should be absent for redirect errors when disabled")
			}
		} else {
			// Non-redirect error: no valid redirect URI → JSON response.
			ar := &AuthorizeRequest{
				RedirectURI:  nil,
				ResponseMode: ResponseModeDefault,
				Request:      *NewRequest(),
			}

			rw := httptest.NewRecorder()
			f.WriteAuthorizeError(ctx, rw, ar, ErrInvalidRequest)

			// Non-redirect errors are rendered as JSON, never contain iss.
			assert.NotEqual(t, http.StatusSeeOther, rw.Code,
				"non-redirect error should not produce 303")

			body := rw.Body.String()
			var jsonResp map[string]interface{}
			err := json.Unmarshal([]byte(body), &jsonResp)
			require.NoError(t, err, "non-redirect error should be valid JSON")
			assert.NotContains(t, jsonResp, "iss",
				"iss parameter should never appear in non-redirect JSON error responses")
		}
	})
}
