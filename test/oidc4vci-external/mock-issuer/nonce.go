// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// NonceManager handles nonce generation, validation, and single-use enforcement.
type NonceManager struct {
	store *MemoryStore
	ttl   time.Duration
}

// NewNonceManager creates a NonceManager with the given TTL in seconds.
func NewNonceManager(store *MemoryStore, ttlSeconds int) *NonceManager {
	if ttlSeconds <= 0 {
		ttlSeconds = defaultNonceTTL
	}
	return &NonceManager{
		store: store,
		ttl:   time.Duration(ttlSeconds) * time.Second,
	}
}

// GenerateNonce creates a cryptographically random nonce, stores it, and returns it.
func (m *NonceManager) GenerateNonce(ctx context.Context) (*Nonce, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	nonce := &Nonce{
		Value:     base64.RawURLEncoding.EncodeToString(b),
		ExpiresAt: time.Now().Add(m.ttl),
	}
	if err := m.store.CreateNonce(ctx, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// ValidateAndConsume validates the nonce (existence + expiry) and deletes it (single-use).
func (m *NonceManager) ValidateAndConsume(ctx context.Context, value string) error {
	nonce, err := m.store.GetNonce(ctx, value)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return newOIDCError(errCodeInvalidOrMissingProof, 400, "nonce not found or already used")
		}
		return err
	}
	if time.Now().After(nonce.ExpiresAt) {
		_ = m.store.DeleteNonce(ctx, value)
		return newOIDCError(errCodeInvalidOrMissingProof, 400, "nonce has expired")
	}
	return m.store.DeleteNonce(ctx, value)
}

// TTLSeconds returns the configured nonce TTL in seconds.
func (m *NonceManager) TTLSeconds() int {
	return int(m.ttl.Seconds())
}
