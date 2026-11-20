package persist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres stores every record in one JSONB table:
//
//	entities(kind text, id text, doc jsonb, updated_at timestamptz, primary key(kind, id))
//
// One generic table keeps the schema stable while the prototype's records evolve, and JSONB
// keeps it queryable (e.g. SELECT doc->>'verdict', count(*) FROM entities WHERE kind='audit' …).
type Postgres struct {
	pool *pgxpool.Pool
}

const schema = `
CREATE TABLE IF NOT EXISTS entities (
	kind       text        NOT NULL,
	id         text        NOT NULL,
	doc        jsonb       NOT NULL,
	updated_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS entities_kind_updated ON entities (kind, updated_at DESC);
`

// OpenPostgres connects (DATABASE_URL format, e.g. postgres://user:pass@/db?host=/cloudsql/proj:region:inst)
// and creates the schema if needed.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if cfg.MaxConns > 5 {
		cfg.MaxConns = 5
	}
	var pool *pgxpool.Pool
	// Cloud SQL can take a moment to accept connections right after a deploy.
	for attempt := 1; ; attempt++ {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			err = pool.Ping(ctx)
		}
		if err == nil {
			break
		}
		if pool != nil {
			pool.Close()
		}
		if attempt >= 10 {
			return nil, fmt.Errorf("connect to postgres: %w", err)
		}
		time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) LoadAll(ctx context.Context) ([]Row, error) {
	rows, err := p.pool.Query(ctx, `SELECT kind, id, doc FROM entities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Kind, &r.ID, &r.Doc); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) Apply(ctx context.Context, ups []Row, dels []Key) error {
	b := &pgx.Batch{}
	for _, r := range ups {
		b.Queue(`INSERT INTO entities (kind, id, doc, updated_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (kind, id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()`, r.Kind, r.ID, json.RawMessage(r.Doc))
	}
	for _, k := range dels {
		b.Queue(`DELETE FROM entities WHERE kind = $1 AND id = $2`, k.Kind, k.ID)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Get reads one record (used by small standalone processes such as the demo bank).
func (p *Postgres) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	var doc []byte
	err := p.pool.QueryRow(ctx, `SELECT doc FROM entities WHERE kind = $1 AND id = $2`, kind, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return doc, true, nil
}

// Put writes one record.
func (p *Postgres) Put(ctx context.Context, kind, id string, doc []byte) error {
	return p.Apply(ctx, []Row{{Kind: kind, ID: id, Doc: doc}}, nil)
}

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) Close() { p.pool.Close() }
