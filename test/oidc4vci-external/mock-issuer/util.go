// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import "time"

// isExpired returns true when t is before the current time.
func isExpired(t time.Time) bool {
	return time.Now().After(t)
}

// isSDJWTFormat reports whether the given credential format string is one of
// the SD-JWT VC format identifiers supported by this mock issuer.
//
//   - "vc+sd-jwt" — legacy format name used by early OIDC4VCI drafts.
//   - "dc+sd-jwt" — current format name per SD-JWT VC draft 06+.
func isSDJWTFormat(format string) bool {
	return format == "vc+sd-jwt" || format == "dc+sd-jwt"
}

// resolveCredentialIdentifier looks up a credential_identifier in the token's
// ext.authorization_details array and returns (true, credential_configuration_id)
// when found, (false, "") otherwise. Per OIDC4VCI §8.2 the identifier MUST
// have appeared in the token response's authorization_details entries, so
// anything else is an authorization error.
//
// The ext map is the raw introspection `ext` object returned by Hydra —
// Hydra places authorization_details there, mirroring the token response.
func resolveCredentialIdentifier(ext map[string]interface{}, credentialIdentifier string) (bool, string, error) {
	raw, ok := ext["authorization_details"]
	if !ok {
		return false, "", nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return false, "", nil
	}
	for _, entry := range list {
		m, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		ids, ok := m["credential_identifiers"].([]interface{})
		if !ok {
			continue
		}
		for _, id := range ids {
			if s, _ := id.(string); s == credentialIdentifier {
				cfg, _ := m["credential_configuration_id"].(string)
				if cfg == "" {
					// Malformed — identifier matched but no config id on the entry.
					return false, "", nil
				}
				return true, cfg, nil
			}
		}
	}
	return false, "", nil
}
