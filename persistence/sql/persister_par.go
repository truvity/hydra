// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

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

	// RFC 9126 section 2.2: a request_uri is only valid for the lifetime that was
	// returned as expires_in. The expiry is written by the PAR handler into the
	// session and denormalized into expires_at. A session without an expiry was not
	// written by the PAR handler, so it is treated as expired as well.
	if exp := req.GetSession().GetExpiresAt(fosite.PushedAuthorizeRequestContext); exp.IsZero() || !exp.After(time.Now().UTC()) {
		return nil, errors.WithStack(fosite.ErrNotFound.WithDebug("The PAR session has expired."))
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

// FlushInactivePARSessions deletes PAR sessions that expired before notAfter, in
// batches of batchSize and at most limit rows per run. notAfter is capped at the
// current time: a session that has not expired yet is never deleted.
//
// It is called by the janitor (hydra janitor --tokens), because PAR sessions are
// otherwise never deleted: DeletePARSession is a no-op by design.
func (p *Persister) FlushInactivePARSessions(ctx context.Context, notAfter time.Time, limit int, batchSize int) (err error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.sql.FlushInactivePARSessions")
	defer otelx.End(span, &err)

	if now := time.Now(); now.Before(notAfter) {
		notAfter = now
	}

	table := OAuth2RequestSQL{Table: sqlTablePAR}.TableName()
	totalDeletedCount := 0
	for deletedRecords := batchSize; totalDeletedCount < limit && deletedRecords == batchSize; {
		d := batchSize
		if limit-totalDeletedCount < batchSize {
			d = limit - totalDeletedCount
		}
		// The outer SELECT is necessary because MySQL does not support LIMIT in an IN subquery.
		/* #nosec G201 table is static */
		deletedRecords, err = p.Connection(ctx).RawQuery(
			fmt.Sprintf(`DELETE FROM %s WHERE signature IN (
				SELECT signature FROM (SELECT signature FROM %s WHERE expires_at < ? AND nid = ? ORDER BY expires_at LIMIT %d) AS s
			) AND nid = ?`, table, table, d),
			notAfter.UTC(),
			p.NetworkID(ctx),
			p.NetworkID(ctx),
		).ExecWithCount()
		totalDeletedCount += deletedRecords
		if err != nil {
			break
		}
		p.l.Debugf("Flushing PAR sessions...: %d/%d", totalDeletedCount, limit)
	}
	return sqlcon.HandleError(err)
}
