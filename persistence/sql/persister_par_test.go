// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/token/jwt"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/hydra/v2/persistence/sql"
	"github.com/ory/x/randx"
)

// newPARRequest returns an authorize request whose PAR context expires at expiresAt.
func newPARRequest(t *testing.T, c fosite.Client, expiresAt time.Time) *fosite.AuthorizeRequest {
	t.Helper()

	sess := oauth2.NewTestSession(t, "")
	sess.SetExpiresAt(fosite.PushedAuthorizeRequestContext, expiresAt)
	sess.Claims = new(jwt.IDTokenClaims)

	return &fosite.AuthorizeRequest{
		Request: fosite.Request{
			ID:             randx.MustString(20, randx.AlphaNum),
			RequestedAt:    time.Now().UTC().Round(time.Second),
			Client:         c,
			RequestedScope: fosite.Arguments{"openid", "offline"},
			Form: url.Values{
				"response_type": {"code"},
				"redirect_uri":  {"https://wallet.example.com/cb"},
				"state":         {"some-state"},
			},
			Session: sess,
		},
	}
}

func TestPersister_PARSession(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	reg := testhelpers.NewRegistryMemory(t)
	p := reg.Persister()

	c := &client.Client{ID: "par-client"}
	require.NoError(t, reg.ClientManager().CreateClient(ctx, c))

	countRows := func(t *testing.T, requestURI string) int {
		t.Helper()
		n, err := p.Connection(ctx).Where("signature = ?", requestURI).Count(&sql.OAuth2RequestSQL{Table: "par"})
		require.NoError(t, err)
		return n
	}

	t.Run("case=create and get a live session, repeatedly", func(t *testing.T) {
		uri := "urn:ietf:params:oauth:request_uri:" + randx.MustString(24, randx.AlphaNum)
		req := newPARRequest(t, c, time.Now().Add(5*time.Minute))
		require.NoError(t, p.CreatePARSession(ctx, uri, req))

		// The consent flow resolves the request_uri three times, and DeletePARSession runs after each.
		for range 3 {
			got, err := p.GetPARSession(ctx, uri)
			require.NoError(t, err)
			assert.Equal(t, req.GetID(), got.GetID())
			assert.Equal(t, c.GetID(), got.GetClient().GetID())
			assert.Equal(t, fosite.Arguments{"code"}, got.GetResponseTypes())
			assert.Equal(t, "https://wallet.example.com/cb", got.GetRedirectURI().String())
			assert.Equal(t, "some-state", got.GetState())
			assert.ElementsMatch(t, []string{"openid", "offline"}, got.GetRequestedScopes())

			require.NoError(t, p.DeletePARSession(ctx, uri))
		}
	})

	t.Run("case=unknown request_uri", func(t *testing.T) {
		_, err := p.GetPARSession(ctx, "urn:ietf:params:oauth:request_uri:unknown")
		require.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("case=expired session is rejected", func(t *testing.T) {
		uri := "urn:ietf:params:oauth:request_uri:" + randx.MustString(24, randx.AlphaNum)
		require.NoError(t, p.CreatePARSession(ctx, uri, newPARRequest(t, c, time.Now().Add(-time.Second))))

		_, err := p.GetPARSession(ctx, uri)
		require.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("case=session without an expiry is rejected", func(t *testing.T) {
		uri := "urn:ietf:params:oauth:request_uri:" + randx.MustString(24, randx.AlphaNum)
		require.NoError(t, p.CreatePARSession(ctx, uri, newPARRequest(t, c, time.Time{})))

		_, err := p.GetPARSession(ctx, uri)
		require.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("case=session expires while stored", func(t *testing.T) {
		uri := "urn:ietf:params:oauth:request_uri:" + randx.MustString(24, randx.AlphaNum)
		require.NoError(t, p.CreatePARSession(ctx, uri, newPARRequest(t, c, time.Now().Add(1500*time.Millisecond))))

		_, err := p.GetPARSession(ctx, uri)
		require.NoError(t, err)

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			_, err := p.GetPARSession(ctx, uri)
			assert.ErrorIs(ct, err, fosite.ErrNotFound)
		}, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("case=flush deletes only expired sessions", func(t *testing.T) {
		live := "urn:ietf:params:oauth:request_uri:live-" + randx.MustString(24, randx.AlphaNum)
		require.NoError(t, p.CreatePARSession(ctx, live, newPARRequest(t, c, time.Now().Add(time.Hour))))

		var expired []string
		for range 5 {
			uri := "urn:ietf:params:oauth:request_uri:expired-" + randx.MustString(24, randx.AlphaNum)
			expired = append(expired, uri)
			require.NoError(t, p.CreatePARSession(ctx, uri, newPARRequest(t, c, time.Now().Add(-time.Minute))))
		}

		// notAfter in the far future must not delete a session that has not expired yet.
		// limit 3 with batch size 2: only three of the five expired sessions go.
		require.NoError(t, p.FlushInactivePARSessions(ctx, time.Now().Add(24*time.Hour), 3, 2))
		var remaining int
		for _, uri := range expired {
			remaining += countRows(t, uri)
		}
		assert.Equal(t, 2, remaining, "limit must be honoured")
		assert.Equal(t, 1, countRows(t, live))

		require.NoError(t, p.FlushInactivePARSessions(ctx, time.Now(), 100, 10))
		for _, uri := range expired {
			assert.Zero(t, countRows(t, uri))
		}
		assert.Equal(t, 1, countRows(t, live), "a live session must survive the flush")

		_, err := p.GetPARSession(ctx, live)
		require.NoError(t, err)
	})

	t.Run("case=flush honours notAfter", func(t *testing.T) {
		uri := "urn:ietf:params:oauth:request_uri:recent-" + randx.MustString(24, randx.AlphaNum)
		require.NoError(t, p.CreatePARSession(ctx, uri, newPARRequest(t, c, time.Now().Add(-time.Minute))))

		// Equivalent to --keep-if-younger 1h: a session that expired a minute ago is kept.
		require.NoError(t, p.FlushInactivePARSessions(ctx, time.Now().Add(-time.Hour), 100, 10))
		assert.Equal(t, 1, countRows(t, uri))

		require.NoError(t, p.FlushInactivePARSessions(ctx, time.Now(), 100, 10))
		assert.Zero(t, countRows(t, uri))
	})
}
