// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

// registerRotatingPgxDriver registers (or returns the cached name of) a
// database/sql driver that re-reads the PostgreSQL DSN from dsnFile on every
// new physical connection.
//
// This is used together with the pg-creds-aurora sidecar (or Lambda extension),
// which periodically writes a fresh PostgreSQL URL containing a rotating IAM
// authentication token to a file. Pop opens database/sql connections by name,
// and database/sql will Open a new physical connection each time
// ConnMaxLifetime forces recycling. Routing through this driver makes every
// such reconnect read the latest DSN from the file via pgx's BeforeConnect
// hook, so the IAM token is always current.
//
// The dsn argument passed to (*connectorDriver).Open is intentionally ignored:
// fresh credentials come from the connector's BeforeConnect callback.
//
// Registration is idempotent per dsnFile path so that repeated registry
// initialisation (e.g., test re-init) does not panic on duplicate sql.Register.
func registerRotatingPgxDriver(dsnFile string) (string, error) {
	rotatingDriverMu.Lock()
	defer rotatingDriverMu.Unlock()

	if name, ok := rotatingDriverByPath[dsnFile]; ok {
		return name, nil
	}

	initialDSN, err := readDSNFile(dsnFile)
	if err != nil {
		return "", errors.Wrapf(err, "read initial dsn from %q", dsnFile)
	}
	cfg, err := pgx.ParseConfig(initialDSN)
	if err != nil {
		return "", errors.Wrapf(err, "parse initial dsn from %q", dsnFile)
	}

	connector := stdlib.GetConnector(*cfg,
		stdlib.OptionBeforeConnect(func(_ context.Context, cc *pgx.ConnConfig) error {
			dsn, err := readDSNFile(dsnFile)
			if err != nil {
				return err
			}
			fresh, err := pgx.ParseConfig(dsn)
			if err != nil {
				return errors.Wrapf(err, "parse dsn from %q", dsnFile)
			}
			*cc = *fresh
			return nil
		}),
	)

	rotatingDriverCounter++
	name := fmt.Sprintf("pgx-rotating-%d", rotatingDriverCounter)
	sql.Register(name, &connectorDriver{connector: connector})
	// Register our custom driver name with sqlx so it knows to use Postgres
	// dollar-style placeholders ($1, $2, …) instead of the default question
	// marks. sqlx looks the driver up by name in a static map (only "pgx",
	// "postgres", etc. are pre-registered); without this call, NamedExec falls
	// back to QUESTION binds and Postgres rejects the resulting SQL with a
	// "syntax error" near each placeholder.
	sqlx.BindDriver(name, sqlx.DOLLAR)
	rotatingDriverByPath[dsnFile] = name
	return name, nil
}

// readDSNFile reads and trims the contents of a DSN file written by
// pg-creds-aurora. An empty file is treated as an error so that callers can
// retry until the sidecar finishes its first refresh.
func readDSNFile(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from trusted config
	if err != nil {
		return "", errors.WithStack(err)
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return "", errors.Errorf("dsn file %q is empty", path)
	}
	return s, nil
}

type (
	// connectorDriver adapts a driver.Connector to the driver.Driver interface
	// because sql.Register requires a Driver, not a Connector. The dsn argument
	// to Open is ignored — fresh credentials come from the connector's
	// BeforeConnect hook.
	connectorDriver struct {
		connector driver.Connector
	}
)

// Open implements driver.Driver. The dsn parameter is ignored; the underlying
// pgx connector resolves connection parameters via its BeforeConnect hook.
func (d *connectorDriver) Open(_ string) (driver.Conn, error) {
	return d.connector.Connect(context.Background())
}

var (
	rotatingDriverMu      sync.Mutex
	rotatingDriverByPath  = map[string]string{}
	rotatingDriverCounter int
)
