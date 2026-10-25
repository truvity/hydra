// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/ory/hydra/v2/cmd"

	"github.com/spf13/cobra"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/cmd/cli"
	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/openid"
	"github.com/ory/hydra/v2/internal/testhelpers"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/hydra/v2/persistence/sql"
	"github.com/ory/x/cmdx"
)

func newJanitorCmd() *cobra.Command {
	return cmd.NewRootCmd()
}

func TestJanitorHandler_PurgeTokenNotAfter(t *testing.T) {
	ctx := t.Context()

	for k, v := range testhelpers.NotAfterTestCycles {
		t.Run(fmt.Sprintf("case=%s", k), func(t *testing.T) {
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg := jt.GetRegistry(t)

			// setup test
			t.Run("step=setup-access", jt.AccessTokenNotAfterSetup(ctx, reg.ClientManager(), reg.OAuth2Storage()))
			t.Run("step=setup-refresh", jt.RefreshTokenNotAfterSetup(ctx, reg.ClientManager(), reg.OAuth2Storage()))

			// run the cleanup routine
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s=%s", cli.KeepIfYounger, v.String()),
					fmt.Sprintf("--%s=%s", cli.AccessLifespan, jt.GetAccessTokenLifespan().String()),
					fmt.Sprintf("--%s=%s", cli.RefreshLifespan, jt.GetRefreshTokenLifespan().String()),
					fmt.Sprintf("--%s", cli.OnlyTokens),
					reg.Config().DSN(),
				)
			})

			// validate test
			notAfter := time.Now().Round(time.Second).Add(-v)
			t.Run("step=validate-access", jt.AccessTokenNotAfterValidate(ctx, notAfter, reg.OAuth2Storage()))
			t.Run("step=validate-refresh", jt.RefreshTokenNotAfterValidate(ctx, notAfter, reg.OAuth2Storage()))
		})
	}
}

func TestJanitorHandler_Arguments(t *testing.T) {
	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		"memory",
	)
	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyTokens),
		"memory",
	)
	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyGrants),
		"memory",
	)

	_, _, err := cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Janitor requires at least one of --tokens, --requests or --grants to be set")

	cmdx.ExecNoErr(t, cmd.NewRootCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		fmt.Sprintf("--%s=%s", cli.Limit, "1000"),
		fmt.Sprintf("--%s=%s", cli.BatchSize, "100"),
		"memory",
	)

	_, _, err = cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		fmt.Sprintf("--%s=%s", cli.Limit, "0"),
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Values for --limit and --batch-size should both be greater than 0")

	_, _, err = cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		fmt.Sprintf("--%s=%s", cli.Limit, "-100"),
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Values for --limit and --batch-size should both be greater than 0")

	_, _, err = cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		fmt.Sprintf("--%s=%s", cli.BatchSize, "0"),
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Values for --limit and --batch-size should both be greater than 0")

	_, _, err = cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		fmt.Sprintf("--%s=%s", cli.BatchSize, "-100"),
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Values for --limit and --batch-size should both be greater than 0")

	_, _, err = cmdx.ExecCtx(context.Background(), cmd.NewRootCmd(), nil,
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyRequests),
		fmt.Sprintf("--%s=%s", cli.Limit, "100"),
		fmt.Sprintf("--%s=%s", cli.BatchSize, "1000"),
		"memory")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Value for --batch-size must not be greater than value for --limit")
}

func TestJanitorHandler_PurgeGrantNotAfter(t *testing.T) {
	ctx := t.Context()

	for k, v := range testhelpers.NotAfterTestCycles {
		t.Run(fmt.Sprintf("case=%s", k), func(t *testing.T) {
			jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
			reg := jt.GetRegistry(t)

			// setup test
			t.Run("step=setup", jt.GrantNotAfterSetup(ctx, reg.GrantManager()))

			// run the cleanup routine
			t.Run("step=cleanup", func(t *testing.T) {
				cmdx.ExecNoErr(t, newJanitorCmd(),
					"janitor",
					fmt.Sprintf("--%s=%s", cli.KeepIfYounger, v.String()),
					fmt.Sprintf("--%s", cli.OnlyGrants),
					reg.Config().DSN(),
				)
			})

			// validate test
			notAfter := time.Now().Round(time.Second).Add(-v)
			t.Run("step=validate-access", jt.GrantNotAfterValidate(ctx, notAfter, reg.GrantManager()))
		})
	}
}

// OIDC4VCI extension: hydra janitor --tokens also deletes expired PAR sessions.
func TestJanitorHandler_PurgeExpiredPARSessions(t *testing.T) {
	ctx := t.Context()

	jt := testhelpers.NewConsentJanitorTestHelper(t.Name())
	reg := jt.GetRegistry(t)
	p := reg.Persister()

	c := &client.Client{ID: "janitor-par-client"}
	require.NoError(t, reg.ClientManager().CreateClient(ctx, c))

	create := func(t *testing.T, id string, expiresAt time.Time) {
		t.Helper()
		sess := &oauth2.Session{DefaultSession: &openid.DefaultSession{Subject: "bar"}}
		sess.SetExpiresAt(fosite.PushedAuthorizeRequestContext, expiresAt)
		require.NoError(t, p.CreatePARSession(ctx, "urn:ietf:params:oauth:request_uri:"+id, &fosite.AuthorizeRequest{
			Request: fosite.Request{
				ID:          id,
				RequestedAt: time.Now().Round(time.Second),
				Client:      c,
				Form:        url.Values{"response_type": {"code"}},
				Session:     sess,
			},
		}))
	}
	exists := func(t *testing.T, id string) bool {
		t.Helper()
		_, err := p.GetPARSession(ctx, "urn:ietf:params:oauth:request_uri:"+id)
		return err == nil
	}

	create(t, "live", time.Now().Add(time.Hour))
	create(t, "expired-1", time.Now().Add(-time.Minute))
	create(t, "expired-2", time.Now().Add(-time.Hour))
	require.True(t, exists(t, "live"))

	cmdx.ExecNoErr(t, newJanitorCmd(),
		"janitor",
		fmt.Sprintf("--%s", cli.OnlyTokens),
		reg.Config().DSN(),
	)

	// Expired sessions are rejected by GetPARSession whether or not the row is still there,
	// so look at the table to see that the janitor deleted them.
	count := func(id string) int {
		n, err := p.Connection(ctx).Where("signature = ?", "urn:ietf:params:oauth:request_uri:"+id).
			Count(&sql.OAuth2RequestSQL{Table: "par"})
		require.NoError(t, err)
		return n
	}
	assert.Equal(t, 1, count("live"))
	assert.True(t, exists(t, "live"))
	assert.Zero(t, count("expired-1"))
	assert.Zero(t, count("expired-2"))
}
