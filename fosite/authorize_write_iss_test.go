// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	. "github.com/ory/hydra/v2/fosite"
)

// issConfig embeds Config and overrides the iss-related methods so that
// property tests can control them via generated values.
type issConfig struct {
	Config
	AuthResponseIssEnabled bool
	Issuer                 string
}

func (c *issConfig) GetAuthResponseIssParameterEnabled(_ context.Context) bool {
	return c.AuthResponseIssEnabled
}

func (c *issConfig) GetIDTokenIssuer(_ context.Context) string {
	return c.Issuer
}

// Feature: oidc4vci-haip-metadata, Property 4: RFC 9207 iss in Success Responses
//
// For any random issuer URL and response parameters, when
// GetAuthResponseIssParameterEnabled is true, verify iss parameter equals
// GetIDTokenIssuer(ctx); when false, verify iss is absent.
//
// **Validates: Requirements 6.1, 6.2, 6.4**
func TestProperty4_RFC9207IssInSuccessResponses(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		issEnabled := rapid.Bool().Draw(t, "issEnabled")
		issuer := rapid.StringMatching(`https://[a-z]{3,10}\.[a-z]{2,5}`).Draw(t, "issuer")

		cfg := &issConfig{
			AuthResponseIssEnabled: issEnabled,
			Issuer:                 issuer,
		}
		f := &Fosite{Config: cfg}

		// Build a real AuthorizeRequest with a valid redirect URI and query response mode.
		redir, err := url.Parse("https://client.example.com/callback")
		require.NoError(t, err)
		ar := &AuthorizeRequest{
			RedirectURI:  redir,
			ResponseMode: ResponseModeQuery,
			Request:      *NewRequest(),
		}

		resp := NewAuthorizeResponse()
		resp.AddParameter("code", "test-code")
		resp.AddParameter("state", "test-state")

		rw := httptest.NewRecorder()
		f.WriteAuthorizeResponse(context.Background(), rw, ar, resp)

		// Parse the redirect Location header to inspect query parameters.
		loc := rw.Header().Get("Location")
		require.NotEmpty(t, loc, "expected a redirect Location header")
		parsed, err := url.Parse(loc)
		require.NoError(t, err)

		if issEnabled {
			assert.Equal(t, issuer, parsed.Query().Get("iss"),
				"iss parameter should equal the configured issuer when enabled")
		} else {
			assert.Empty(t, parsed.Query().Get("iss"),
				"iss parameter should be absent when disabled")
		}
	})
}
