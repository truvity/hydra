// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"pgregory.net/rapid"

	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/spec"
	"github.com/ory/x/configx"
	"github.com/ory/x/contextx"
	"github.com/ory/x/logrusx"
)

func newHAIPProvider(vals map[string]any) *config.DefaultProvider {
	l := logrusx.New("", "")
	ctx := context.Background()
	ctxt := contextx.NewTestConfigProvider(spec.ConfigValidationSchema,
		configx.WithValues(vals),
		configx.SkipValidation(),
	)
	p, err := config.New(ctx, l, ctxt,
		configx.WithValues(vals),
		configx.SkipValidation(),
	)
	if err != nil {
		panic("failed to create config provider: " + err.Error())
	}
	return p
}

// Feature: oidc4vci-haip-metadata, Property 1: HAIP OR-Override for Config Methods
//
// For any pair (haipEnforced, standaloneValue), verify EnforcePushedAuthorize,
// GetEnforcePKCE, GetDPoPEnabled, GetAuthResponseIssParameterEnabled all return
// haipEnforced || standaloneValue.
//
// **Validates: Requirements 1.1, 1.2, 2.1, 2.3, 3.1, 3.3, 4.1, 4.2**
func TestProperty1_HAIPOROverrideConfigMethods(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		haipEnforced := rapid.Bool().Draw(t, "haipEnforced")
		standaloneValue := rapid.Bool().Draw(t, "standaloneValue")
		expected := haipEnforced || standaloneValue
		ctx := context.Background()

		p := newHAIPProvider(map[string]any{
			config.KeyHAIPEnforced:                    haipEnforced,
			config.KeyEnforcePushedAuthorize:          standaloneValue,
			config.KeyPKCEEnforced:                    standaloneValue,
			config.KeyDPoPEnabled:                     standaloneValue,
			config.KeyAuthResponseIssParameterEnabled: standaloneValue,
		})

		assert.Equal(t, expected, p.EnforcePushedAuthorize(ctx),
			"EnforcePushedAuthorize(haip=%v, standalone=%v)", haipEnforced, standaloneValue)
		assert.Equal(t, expected, p.GetEnforcePKCE(ctx),
			"GetEnforcePKCE(haip=%v, standalone=%v)", haipEnforced, standaloneValue)
		assert.Equal(t, expected, p.GetDPoPEnabled(ctx),
			"GetDPoPEnabled(haip=%v, standalone=%v)", haipEnforced, standaloneValue)
		assert.Equal(t, expected, p.GetAuthResponseIssParameterEnabled(ctx),
			"GetAuthResponseIssParameterEnabled(haip=%v, standalone=%v)", haipEnforced, standaloneValue)
	})
}

// Feature: oidc4vci-haip-metadata, Property 2: HAIP PKCE Plain Method Suppression
//
// For any pair (haipEnforced, standalonePlainEnabled), verify
// GetEnablePKCEPlainChallengeMethod returns !haipEnforced && standalonePlainEnabled.
//
// **Validates: Requirements 2.2, 2.4**
func TestProperty2_HAIPPKCEPlainMethodSuppression(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		haipEnforced := rapid.Bool().Draw(t, "haipEnforced")
		standalonePlainEnabled := rapid.Bool().Draw(t, "standalonePlainEnabled")
		expected := !haipEnforced && standalonePlainEnabled
		ctx := context.Background()

		p := newHAIPProvider(map[string]any{
			config.KeyHAIPEnforced:             haipEnforced,
			config.KeyPKCEPlainChallengeMethod: standalonePlainEnabled,
		})

		assert.Equal(t, expected, p.GetEnablePKCEPlainChallengeMethod(ctx),
			"GetEnablePKCEPlainChallengeMethod(haip=%v, standalone=%v)", haipEnforced, standalonePlainEnabled)
	})
}

// Feature: oidc4vci-haip-metadata, Property 3: HAIP Independence of Pre-Auth and Wallet Attestation
//
// For any pair (haipEnforced, featureEnabled), verify GetPreAuthorizedCodeEnabled
// and GetWalletAttestationEnabled return featureEnabled regardless of haipEnforced.
//
// **Validates: Requirements 15.1, 16.1**
func TestProperty3_HAIPIndependencePreAuthAndWalletAttestation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		haipEnforced := rapid.Bool().Draw(t, "haipEnforced")
		featureEnabled := rapid.Bool().Draw(t, "featureEnabled")
		ctx := context.Background()

		p := newHAIPProvider(map[string]any{
			config.KeyHAIPEnforced:             haipEnforced,
			config.KeyPreAuthorizedCodeEnabled: featureEnabled,
			config.KeyWalletAttestationEnabled: featureEnabled,
		})

		assert.Equal(t, featureEnabled, p.GetPreAuthorizedCodeEnabled(ctx),
			"GetPreAuthorizedCodeEnabled(haip=%v, feature=%v)", haipEnforced, featureEnabled)
		assert.Equal(t, featureEnabled, p.GetWalletAttestationEnabled(ctx),
			"GetWalletAttestationEnabled(haip=%v, feature=%v)", haipEnforced, featureEnabled)
	})
}
