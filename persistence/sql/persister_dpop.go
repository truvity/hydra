// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package sql

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
)

// DPoPJTI represents a row in the hydra_oauth2_dpop_jti table.
type DPoPJTI struct {
	JTI       string    `db:"jti"`
	NID       uuid.UUID `db:"nid"`
	UsedAt    time.Time `db:"used_at"`
	ExpiresAt time.Time `db:"expires_at"`
}

func (DPoPJTI) TableName() string {
	return "hydra_oauth2_dpop_jti"
}

func (p *Persister) IsJTIUsed(ctx context.Context, jti string) (bool, error) {
	nid := p.NetworkID(ctx)
	count, err := p.Connection(ctx).Where("jti = ? AND nid = ?", jti, nid).Count(&DPoPJTI{})
	if err != nil {
		return false, errors.WithStack(err)
	}
	return count > 0, nil
}

func (p *Persister) MarkJTIUsed(ctx context.Context, jti string, expiry time.Time) error {
	nid := p.NetworkID(ctx)
	now := time.Now().UTC()

	dialectName := p.Connection(ctx).Dialect.Name()
	var query string
	if dialectName == "mysql" {
		query = "INSERT IGNORE INTO hydra_oauth2_dpop_jti (jti, nid, used_at, expires_at) VALUES (?, ?, ?, ?)"
	} else {
		query = "INSERT INTO hydra_oauth2_dpop_jti (jti, nid, used_at, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT (jti, nid) DO NOTHING"
	}

	return errors.WithStack(
		p.Connection(ctx).RawQuery(query, jti, nid, now, expiry.UTC()).Exec(),
	)
}

func (p *Persister) CreateDPoPNonce(ctx context.Context) (string, error) {
	secret, err := p.r.Config().GetGlobalSecret(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}

	// 8 bytes timestamp (big-endian Unix seconds)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	// 16 bytes random
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", errors.WithStack(err)
	}

	// HMAC-SHA256 over timestamp || random, truncated to 16 bytes
	mac := hmac.New(sha256.New, secret)
	mac.Write(ts)
	mac.Write(random)
	sig := mac.Sum(nil)[:16]

	// Concatenate: timestamp(8) || random(16) || hmac(16) = 40 bytes
	nonce := make([]byte, 40)
	copy(nonce[0:8], ts)
	copy(nonce[8:24], random)
	copy(nonce[24:40], sig)

	return base64.RawURLEncoding.EncodeToString(nonce), nil
}

func (p *Persister) ValidateDPoPNonce(ctx context.Context, nonce string) (bool, error) {
	secret, err := p.r.Config().GetGlobalSecret(ctx)
	if err != nil {
		return false, errors.WithStack(err)
	}
	lifespan := p.r.Config().GetDPoPNonceLifespan(ctx)

	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 40 {
		return false, nil
	}

	ts := raw[0:8]
	random := raw[8:24]
	providedMAC := raw[24:40]

	// Recompute HMAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(ts)
	mac.Write(random)
	expectedMAC := mac.Sum(nil)[:16]

	// Constant-time comparison
	if subtle.ConstantTimeCompare(providedMAC, expectedMAC) != 1 {
		return false, nil
	}

	// Check timestamp expiry
	timestamp := int64(binary.BigEndian.Uint64(ts))
	if time.Now().Unix()-timestamp > int64(lifespan.Seconds()) {
		return false, nil
	}

	return true, nil
}
