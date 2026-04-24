// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"
)

// Config holds the MockIssuer configuration parsed from environment variables.
type Config struct {
	// ListenAddr is the HTTP listen address (default: :4448)
	ListenAddr string

	// IssuerURL is the public URL of this issuer (default: http://localhost:4448)
	IssuerURL string

	// AuthServerURL is the Hydra public URL (default: http://localhost:4444)
	AuthServerURL string

	// AuthServerAdminURL is the Hydra admin URL used for introspection and pre-auth code creation
	// (default: http://localhost:4445)
	AuthServerAdminURL string

	// NonceTTL is the nonce time-to-live in seconds (default: 300)
	NonceTTL int
}

// LoadConfig reads configuration from environment variables and applies defaults.
func LoadConfig() *Config {
	cfg := &Config{
		ListenAddr:         getEnv("MOCK_ISSUER_LISTEN_ADDR", ":4448"),
		IssuerURL:          getEnv("MOCK_ISSUER_URL", "http://localhost:4448"),
		AuthServerURL:      getEnv("MOCK_ISSUER_AUTH_SERVER_URL", "http://localhost:4444"),
		AuthServerAdminURL: getEnv("MOCK_ISSUER_AUTH_SERVER_ADMIN_URL", "http://localhost:4445"),
		NonceTTL:           getEnvInt("MOCK_ISSUER_NONCE_TTL", 300),
	}
	return cfg
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
