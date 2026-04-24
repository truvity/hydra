// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"sync"
)

// MemoryStore is a thread-safe in-memory implementation of the Credential Issuer
// store interfaces. It does NOT implement PreAuthorizedCodeStore — that stays in Hydra.
type MemoryStore struct {
	mu sync.RWMutex

	credentialConfigs   map[string]*CredentialConfiguration
	credentialOffers    map[string]*CredentialOffer
	nonces              map[string]*Nonce
	issuanceRecords     map[string]*IssuanceRecord
	deferredCredentials map[string]*DeferredCredential
}

// NewMemoryStore creates an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		credentialConfigs:   make(map[string]*CredentialConfiguration),
		credentialOffers:    make(map[string]*CredentialOffer),
		nonces:              make(map[string]*Nonce),
		issuanceRecords:     make(map[string]*IssuanceRecord),
		deferredCredentials: make(map[string]*DeferredCredential),
	}
}

// ── CredentialConfigurationStore ────────────────────────────────────────────

func (s *MemoryStore) CreateCredentialConfiguration(_ context.Context, cfg *CredentialConfiguration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentialConfigs[cfg.ID]; exists {
		return errAlreadyExists
	}
	s.credentialConfigs[cfg.ID] = cfg
	return nil
}

func (s *MemoryStore) GetCredentialConfiguration(_ context.Context, id string) (*CredentialConfiguration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.credentialConfigs[id]
	if !ok {
		return nil, errNotFound
	}
	return cfg, nil
}

func (s *MemoryStore) ListCredentialConfigurations(_ context.Context) (map[string]*CredentialConfiguration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*CredentialConfiguration, len(s.credentialConfigs))
	for k, v := range s.credentialConfigs {
		out[k] = v
	}
	return out, nil
}

func (s *MemoryStore) UpdateCredentialConfiguration(_ context.Context, id string, cfg *CredentialConfiguration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentialConfigs[id]; !exists {
		return errNotFound
	}
	s.credentialConfigs[id] = cfg
	return nil
}

func (s *MemoryStore) DeleteCredentialConfiguration(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentialConfigs[id]; !exists {
		return errNotFound
	}
	delete(s.credentialConfigs, id)
	return nil
}

// ── CredentialOfferStore ─────────────────────────────────────────────────────

func (s *MemoryStore) CreateCredentialOffer(_ context.Context, offer *CredentialOffer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentialOffers[offer.ID]; exists {
		return errAlreadyExists
	}
	s.credentialOffers[offer.ID] = offer
	return nil
}

func (s *MemoryStore) GetCredentialOffer(_ context.Context, id string) (*CredentialOffer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	offer, ok := s.credentialOffers[id]
	if !ok {
		return nil, errNotFound
	}
	return offer, nil
}

func (s *MemoryStore) DeleteCredentialOffer(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.credentialOffers[id]; !exists {
		return errNotFound
	}
	delete(s.credentialOffers, id)
	return nil
}

func (s *MemoryStore) ListCredentialOffers(_ context.Context) ([]*CredentialOffer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CredentialOffer, 0, len(s.credentialOffers))
	for _, v := range s.credentialOffers {
		out = append(out, v)
	}
	return out, nil
}

func (s *MemoryStore) DeleteExpiredCredentialOffers(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for id, offer := range s.credentialOffers {
		if isExpired(offer.ExpiresAt) {
			delete(s.credentialOffers, id)
			count++
		}
	}
	return count, nil
}

// ── NonceStore ───────────────────────────────────────────────────────────────

func (s *MemoryStore) CreateNonce(_ context.Context, nonce *Nonce) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nonces[nonce.Value]; exists {
		return errAlreadyExists
	}
	s.nonces[nonce.Value] = nonce
	return nil
}

func (s *MemoryStore) GetNonce(_ context.Context, value string) (*Nonce, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nonce, ok := s.nonces[value]
	if !ok {
		return nil, errNotFound
	}
	return nonce, nil
}

func (s *MemoryStore) DeleteNonce(_ context.Context, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nonces[value]; !exists {
		return errNotFound
	}
	delete(s.nonces, value)
	return nil
}

func (s *MemoryStore) DeleteExpiredNonces(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for v, nonce := range s.nonces {
		if isExpired(nonce.ExpiresAt) {
			delete(s.nonces, v)
			count++
		}
	}
	return count, nil
}

// ── IssuanceRecordStore ──────────────────────────────────────────────────────

func (s *MemoryStore) CreateIssuanceRecord(_ context.Context, record *IssuanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.issuanceRecords[record.ID]; exists {
		return errAlreadyExists
	}
	s.issuanceRecords[record.ID] = record
	return nil
}

func (s *MemoryStore) GetIssuanceRecord(_ context.Context, id string) (*IssuanceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.issuanceRecords[id]
	if !ok {
		return nil, errNotFound
	}
	return r, nil
}

func (s *MemoryStore) GetIssuanceRecordByCredentialIdentifier(_ context.Context, credentialIdentifier string) (*IssuanceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.issuanceRecords {
		if r.CredentialIdentifier == credentialIdentifier {
			return r, nil
		}
	}
	return nil, errNotFound
}

func (s *MemoryStore) ListIssuanceRecords(_ context.Context, filters *IssuanceFilters) ([]*IssuanceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*IssuanceRecord
	for _, r := range s.issuanceRecords {
		if filters != nil {
			if filters.Subject != "" && r.Subject != filters.Subject {
				continue
			}
			if filters.CredentialConfigurationID != "" && r.CredentialConfigurationID != filters.CredentialConfigurationID {
				continue
			}
			if filters.Revoked != nil && r.Revoked != *filters.Revoked {
				continue
			}
		}
		out = append(out, r)
	}
	if filters != nil && filters.Limit > 0 {
		offset := filters.Offset
		if offset > len(out) {
			offset = len(out)
		}
		out = out[offset:]
		if filters.Limit < len(out) {
			out = out[:filters.Limit]
		}
	}
	return out, nil
}

func (s *MemoryStore) UpdateIssuanceRecord(_ context.Context, id string, record *IssuanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.issuanceRecords[id]; !exists {
		return errNotFound
	}
	s.issuanceRecords[id] = record
	return nil
}

func (s *MemoryStore) RevokeCredential(_ context.Context, credentialIdentifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.issuanceRecords {
		if r.CredentialIdentifier == credentialIdentifier {
			r.Revoked = true
			return nil
		}
	}
	return errNotFound
}

// ── DeferredCredentialStore ──────────────────────────────────────────────────

func (s *MemoryStore) CreateDeferredCredential(_ context.Context, deferred *DeferredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deferredCredentials[deferred.TransactionID]; exists {
		return errAlreadyExists
	}
	s.deferredCredentials[deferred.TransactionID] = deferred
	return nil
}

func (s *MemoryStore) GetDeferredCredential(_ context.Context, transactionID string) (*DeferredCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.deferredCredentials[transactionID]
	if !ok {
		return nil, errNotFound
	}
	return d, nil
}

func (s *MemoryStore) UpdateDeferredCredential(_ context.Context, transactionID string, deferred *DeferredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deferredCredentials[transactionID]; !exists {
		return errNotFound
	}
	s.deferredCredentials[transactionID] = deferred
	return nil
}

func (s *MemoryStore) DeleteDeferredCredential(_ context.Context, transactionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deferredCredentials[transactionID]; !exists {
		return errNotFound
	}
	delete(s.deferredCredentials, transactionID)
	return nil
}

func (s *MemoryStore) DeleteExpiredDeferredCredentials(_ context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for id, d := range s.deferredCredentials {
		if isExpired(d.ExpiresAt) {
			delete(s.deferredCredentials, id)
			count++
		}
	}
	return count, nil
}
