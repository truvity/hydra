// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/driver"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/configx"
	"github.com/ory/x/httprouterx"
)

// Feature: oidc4vci-haip-metadata, Property 6: Discovery Metadata Reflects Config State
//
// For any combination of feature flags (haipEnforced, preAuthEnabled, preAuthAnonymous,
// dpopEnabled, issParamEnabled, walletAttestationEnabled, rarEnabled), the discovery
// metadata output SHALL satisfy all conditional population rules from the design.
// Disabled features produce absent fields via omitempty.
//
// **Validates: Requirements 8.1, 8.2, 8.3, 9.1, 9.2, 9.3, 10.1, 10.2, 11.1, 11.2, 12.1, 12.2, 13.1, 13.2, 14.1, 14.3**
func TestProperty6_DiscoveryMetadataReflectsConfigState(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		haipEnforced := rapid.Bool().Draw(rt, "haipEnforced")
		preAuthEnabled := rapid.Bool().Draw(rt, "preAuthEnabled")
		preAuthAnonymous := rapid.Bool().Draw(rt, "preAuthAnonymous")
		dpopEnabled := rapid.Bool().Draw(rt, "dpopEnabled")
		issParamEnabled := rapid.Bool().Draw(rt, "issParamEnabled")
		walletAttestationEnabled := rapid.Bool().Draw(rt, "walletAttestationEnabled")
		rarEnabled := rapid.Bool().Draw(rt, "rarEnabled")
		parEnforced := rapid.Bool().Draw(rt, "parEnforced")

		issuerURL := "http://hydra.localhost"

		vals := map[string]any{
			config.KeyIssuerURL:                        issuerURL,
			config.KeySubjectTypesSupported:            []string{"public"},
			config.KeyOIDCDiscoverySupportedClaims:     []string{"sub"},
			config.KeyOAuth2ClientRegistrationURL:      "http://client-register/registration",
			config.KeyOIDCDiscoveryUserinfoEndpoint:    "/userinfo",
			config.KeyHAIPEnforced:                     haipEnforced,
			config.KeyPreAuthorizedCodeEnabled:         preAuthEnabled,
			config.KeyPreAuthorizedCodeAnonymousAccess: preAuthAnonymous,
			config.KeyDPoPEnabled:                      dpopEnabled,
			config.KeyAuthResponseIssParameterEnabled:  issParamEnabled,
			config.KeyWalletAttestationEnabled:         walletAttestationEnabled,
			config.KeyRAREnabled:                       rarEnabled,
			config.KeyEnforcePushedAuthorize:           parEnforced,
		}

		// Use DisablePreloading to avoid eagerly initializing the OAuth2 provider,
		// which would trigger handler factories (e.g. DPoP) that require storage
		// interfaces not needed by the discovery endpoint.
		reg := testhelpers.NewRegistryMemory(t,
			driver.DisablePreloading(),
			driver.WithConfigOptions(configx.WithValues(vals)),
		)
		testhelpers.MustEnsureRegistryKeys(t, reg, x.OpenIDConnectKeyName)

		h := oauth2.NewHandler(reg)
		r := httprouterx.NewTestRouterAdminWithPrefix(t)
		h.SetPublicRoutes(r.ToPublic(), func(h http.Handler) http.Handler { return h })
		h.SetAdminRoutes(r)
		ts := httptest.NewServer(r)
		defer ts.Close()

		res, err := http.Get(ts.URL + "/.well-known/openid-configuration")
		if err != nil {
			rt.Fatal(err)
		}
		defer res.Body.Close() //nolint:errcheck

		if res.StatusCode != http.StatusOK {
			rt.Fatalf("expected 200, got %d", res.StatusCode)
		}

		// Parse into raw map for precise field presence checks (omitempty).
		var raw map[string]json.RawMessage
		if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
			rt.Fatal(err)
		}

		// Helpers to unmarshal fields from the raw map.
		getString := func(key string) (string, bool) {
			v, ok := raw[key]
			if !ok {
				return "", false
			}
			var s string
			require.NoError(t, json.Unmarshal(v, &s))
			return s, true
		}
		getBool := func(key string) (bool, bool) {
			v, ok := raw[key]
			if !ok {
				return false, false
			}
			var b bool
			require.NoError(t, json.Unmarshal(v, &b))
			return b, true
		}
		getStrings := func(key string) ([]string, bool) {
			v, ok := raw[key]
			if !ok {
				return nil, false
			}
			var ss []string
			require.NoError(t, json.Unmarshal(v, &ss))
			return ss, true
		}

		// --- PAR endpoint (always present) ---
		parEndpoint, parPresent := getString("pushed_authorization_request_endpoint")
		assert.True(rt, parPresent, "pushed_authorization_request_endpoint must always be present")
		assert.Equal(rt, issuerURL+"/oauth2/par", parEndpoint)

		// --- require_pushed_authorization_requests ---
		effectivePAREnforced := parEnforced || haipEnforced
		requirePAR, requirePARPresent := getBool("require_pushed_authorization_requests")
		if effectivePAREnforced {
			assert.True(rt, requirePARPresent, "require_pushed_authorization_requests must be present when PAR enforced")
			assert.True(rt, requirePAR)
		} else {
			assert.False(rt, requirePARPresent, "require_pushed_authorization_requests must be absent when PAR not enforced")
		}

		// --- grant_types_supported ---
		grantTypes, gtPresent := getStrings("grant_types_supported")
		assert.True(rt, gtPresent, "grant_types_supported must always be present")
		preAuthGrant := "urn:ietf:params:oauth:grant-type:pre-authorized_code"
		if preAuthEnabled {
			assert.Contains(rt, grantTypes, preAuthGrant)
		} else {
			assert.NotContains(rt, grantTypes, preAuthGrant)
		}

		// --- pre-authorized_grant_anonymous_access_supported ---
		preAuthAnon, preAuthAnonPresent := getBool("pre-authorized_grant_anonymous_access_supported")
		if preAuthEnabled && preAuthAnonymous {
			assert.True(rt, preAuthAnonPresent,
				"pre-authorized_grant_anonymous_access_supported must be present when preAuth+anonymous")
			assert.True(rt, preAuthAnon)
		} else {
			// omitempty: false bool is omitted; also absent when preAuth disabled
			assert.False(rt, preAuthAnonPresent,
				"pre-authorized_grant_anonymous_access_supported must be absent")
		}

		// --- dpop_signing_alg_values_supported ---
		effectiveDPoP := dpopEnabled || haipEnforced
		dpopAlgs, dpopAlgsPresent := getStrings("dpop_signing_alg_values_supported")
		if effectiveDPoP {
			assert.True(rt, dpopAlgsPresent,
				"dpop_signing_alg_values_supported must be present when DPoP enabled")
			assert.NotEmpty(rt, dpopAlgs)
			if haipEnforced {
				assert.Contains(rt, dpopAlgs, "ES256")
			}
		} else {
			assert.False(rt, dpopAlgsPresent,
				"dpop_signing_alg_values_supported must be absent when DPoP disabled")
		}

		// --- authorization_response_iss_parameter_supported ---
		effectiveIss := issParamEnabled || haipEnforced
		issParam, issParamFieldPresent := getBool("authorization_response_iss_parameter_supported")
		if effectiveIss {
			assert.True(rt, issParamFieldPresent,
				"authorization_response_iss_parameter_supported must be present when enabled")
			assert.True(rt, issParam)
		} else {
			assert.False(rt, issParamFieldPresent,
				"authorization_response_iss_parameter_supported must be absent when disabled")
		}

		// --- token_endpoint_auth_methods_supported ---
		authMethods, authMethodsPresent := getStrings("token_endpoint_auth_methods_supported")
		assert.True(rt, authMethodsPresent, "token_endpoint_auth_methods_supported must always be present")
		if walletAttestationEnabled {
			assert.Contains(rt, authMethods, "attest_jwt_client_auth")
		} else {
			assert.NotContains(rt, authMethods, "attest_jwt_client_auth")
		}

		// --- code_challenge_methods_supported ---
		codeMethods, codeMethodsPresent := getStrings("code_challenge_methods_supported")
		assert.True(rt, codeMethodsPresent, "code_challenge_methods_supported must always be present")
		if haipEnforced {
			assert.Equal(rt, []string{"S256"}, codeMethods)
		} else {
			assert.Equal(rt, []string{"plain", "S256"}, codeMethods)
		}

		// --- authorization_details_types_supported ---
		rarTypes, rarTypesPresent := getStrings("authorization_details_types_supported")
		if rarEnabled {
			assert.True(rt, rarTypesPresent,
				"authorization_details_types_supported must be present when RAR enabled")
			assert.NotEmpty(rt, rarTypes)
		} else {
			assert.False(rt, rarTypesPresent,
				"authorization_details_types_supported must be absent when RAR disabled")
		}
	})
}
