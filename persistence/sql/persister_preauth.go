// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"database/sql"

	"github.com/pkg/errors"

	"github.com/ory/hydra/v2/fosite"
	"github.com/ory/hydra/v2/fosite/handler/preauth"
)

func (p *Persister) CreatePreAuthorizedCodeSession(ctx context.Context, signature string, data *preauth.PreAuthorizedCodeData) error {
	data.NID = p.NetworkID(ctx)
	data.Signature = signature
	return errors.WithStack(p.Connection(ctx).Create(data))
}

func (p *Persister) GetPreAuthorizedCodeSession(ctx context.Context, signature string) (*preauth.PreAuthorizedCodeData, error) {
	var d preauth.PreAuthorizedCodeData
	if err := p.Connection(ctx).Where("signature = ? AND nid = ?", signature, p.NetworkID(ctx)).First(&d); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.WithStack(fosite.ErrNotFound)
		}
		return nil, errors.WithStack(err)
	}
	return &d, nil
}

func (p *Persister) InvalidatePreAuthorizedCode(ctx context.Context, signature string) error {
	count, err := p.Connection(ctx).RawQuery(
		"UPDATE hydra_oauth2_preauth_code SET redeemed = true WHERE signature = ? AND nid = ? AND redeemed = false",
		signature, p.NetworkID(ctx),
	).ExecWithCount()
	if err != nil {
		return errors.WithStack(err)
	}
	if count == 0 {
		return errors.WithStack(fosite.ErrNotFound)
	}
	return nil
}
