// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
)

// IssuerMetadata is the JSON shape returned by GET /.well-known/openid-credential-issuer.
type IssuerMetadata struct {
	CredentialIssuer                  string                              `json:"credential_issuer"`
	CredentialEndpoint                string                              `json:"credential_endpoint"`
	NonceEndpoint                     string                              `json:"nonce_endpoint"`
	AuthorizationServers              []string                            `json:"authorization_servers"`
	CredentialConfigurationsSupported map[string]*CredentialConfiguration `json:"credential_configurations_supported"`
}

// MetadataProvider builds the credential issuer metadata from the in-memory store.
type MetadataProvider struct {
	cfg   *Config
	store *MemoryStore
}

// NewMetadataProvider creates a MetadataProvider.
func NewMetadataProvider(cfg *Config, store *MemoryStore) *MetadataProvider {
	return &MetadataProvider{cfg: cfg, store: store}
}

// Build returns the current IssuerMetadata.
func (p *MetadataProvider) Build(ctx context.Context) (*IssuerMetadata, error) {
	configs, err := p.store.ListCredentialConfigurations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list credential configurations: %w", err)
	}
	if configs == nil {
		configs = make(map[string]*CredentialConfiguration)
	}

	base := p.cfg.IssuerURL
	return &IssuerMetadata{
		CredentialIssuer:                  base,
		CredentialEndpoint:                base + "/credential",
		NonceEndpoint:                     base + "/nonce",
		AuthorizationServers:              []string{p.cfg.AuthServerURL},
		CredentialConfigurationsSupported: configs,
	}, nil
}
