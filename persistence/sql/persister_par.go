// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"net/url"
	"strings"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/oauth2"
	"github.com/ory/x/otelx"
	"github.com/ory/x/sqlcon"
)

func (p *Persister) CreatePARSession(ctx context.Context, requestURI string, requester fosite.AuthorizeRequester) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.CreatePARSession")
	defer otelx.End(span, &err)

	return p.createSession(ctx, requestURI, requester, sqlTablePAR, requester.GetSession().GetExpiresAt(fosite.PushedAuthorizeRequestContext))
}

func (p *Persister) GetPARSession(ctx context.Context, requestURI string) (request fosite.AuthorizeRequester, err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.GetPARSession")
	defer otelx.End(span, &err)

	req, err := p.findSessionBySignature(ctx, requestURI, &oauth2.Session{}, sqlTablePAR)
	if err != nil {
		return nil, err
	}

	r, ok := req.(*fosite.Request)
	if !ok {
		return nil, fosite.ErrServerError.WithDebugf("Expected request to be of type *fosite.Request but got %T", req)
	}

	ar := &fosite.AuthorizeRequest{
		Request: *r,
	}

	// Populate AuthorizeRequest specific fields from Form
	if r.Form != nil {
		ar.ResponseTypes = fosite.RemoveEmpty(strings.Split(r.Form.Get("response_type"), " "))
		if ruri := r.Form.Get("redirect_uri"); ruri != "" {
			if u, err := url.Parse(ruri); err == nil {
				ar.RedirectURI = u
			}
		}
		ar.State = r.Form.Get("state")
		ar.ResponseMode = fosite.ResponseModeType(r.Form.Get("response_mode"))
	}

	return ar, nil
}

// DeletePARSession is a no-op. Hydra's consent flow calls /oauth2/auth
// multiple times (login → consent → final), and each call re-resolves the
// request_uri via authorizeRequestFromPAR. The PAR session must survive
// across these calls. Sessions expire naturally via the expires_at TTL
// (default 5 minutes, configured by KeyPushedAuthorizeContextLifespan).
func (p *Persister) DeletePARSession(ctx context.Context, _ string) (err error) {
	_, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.DeletePARSession")
	defer otelx.End(span, &err)

	return nil
}

// FlushExpiredPARSessions deletes PAR sessions that have expired.
// This should be called periodically as part of the janitor/cleanup process.
func (p *Persister) FlushExpiredPARSessions(ctx context.Context) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.FlushExpiredPARSessions")
	defer otelx.End(span, &err)

	_, err = p.Connection(ctx).RawQuery(
		"DELETE FROM hydra_oauth2_par WHERE expires_at < CURRENT_TIMESTAMP AND nid = ?",
		p.NetworkID(ctx),
	).ExecWithCount()
	return sqlcon.HandleError(err)
}
