// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"
	"net/http"
	"sync"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
)

// inMemoryPARStorage implements fosite.PARStorage using an in-memory map.
// PAR sessions are short-lived (typically 60 seconds) and do not need
// SQL persistence. This matches the upstream fosite MemoryStore pattern.
//
// Hydra's consent flow calls /oauth2/auth multiple times (login redirect,
// consent redirect) and each call re-resolves the request_uri via
// authorizeRequestFromPAR. Therefore:
//   - DeletePARSession is a no-op (the session must survive multiple calls)
//   - GetPARSession enriches the stored AuthorizeRequester with response_type
//     from the current HTTP request context, because the 2nd/3rd calls to
//     /oauth2/auth carry response_type in the URL (from Flow.RequestURL) but
//     the PAR session's Form may not have it if it was only in the PAR body.
type inMemoryPARStorage struct {
	mu       sync.RWMutex
	sessions map[string]fosite.AuthorizeRequester
}

func newInMemoryPARStorage() *inMemoryPARStorage {
	return &inMemoryPARStorage{sessions: make(map[string]fosite.AuthorizeRequester)}
}

func (s *inMemoryPARStorage) CreatePARSession(_ context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[requestURI] = request
	return nil
}

func (s *inMemoryPARStorage) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.sessions[requestURI]
	if !ok {
		return nil, errors.WithStack(fosite.ErrNotFound)
	}

	// Hydra's consent flow redirects back to /oauth2/auth with the original
	// query params (from Flow.RequestURL) plus login_verifier/consent_verifier.
	// On these subsequent calls, NewAuthorizeRequest creates a fresh
	// AuthorizeRequest from r.Form (the URL params), then authorizeRequestFromPAR
	// merges the PAR session into it. The merge copies Form values from the PAR
	// session, but the current request's Form already has response_type (from
	// the URL). We ensure the PAR session's Form also has response_type so the
	// merge doesn't lose it if the PAR session was created without it in the URL.
	if httpReq, ok := ctx.Value(fosite.RequestContextKey).(*http.Request); ok && httpReq != nil {
		if rt := httpReq.Form.Get("response_type"); rt != "" {
			r.GetRequestForm().Set("response_type", rt)
		}
	}

	return r, nil
}

// DeletePARSession is a no-op. Hydra's consent flow calls /oauth2/auth
// multiple times (login → consent → final), and each call re-resolves the
// request_uri. The PAR session must survive across these calls. Sessions
// expire naturally via the PAR context lifespan (default 5 minutes).
func (s *inMemoryPARStorage) DeletePARSession(_ context.Context, _ string) error {
	return nil
}

// PARStorage returns the in-memory PAR session store.
// Implements fosite.PARStorageProvider so that *RegistrySQL can be used
// as fosite.Storage for the PAR handler and authorize request handler.
func (m *RegistrySQL) PARStorage() fosite.PARStorage {
	if m.parStore == nil {
		m.parStore = newInMemoryPARStorage()
	}
	return m.parStore
}
