// Package persist keeps the platform's in-memory state durable.
//
// Every stateful component (auth server, token family DAG, signing keys, tenant store, risk
// engine) implements Source: it can export a snapshot of its records and restore them. The
// Syncer diffs snapshots by content hash and writes only changed rows to a Backend, so the
// hot paths keep their in-memory maps and locks unchanged while Postgres stays the source of
// truth across restarts and deploys.
package persist

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log"
	"sync"
	"time"
)

// Snapshot is kind -> id -> record. Records must be JSON-marshalable.
type Snapshot map[string]map[string]any

// Loaded is kind -> id -> raw JSON, as read back from the backend.
type Loaded map[string]map[string]json.RawMessage

// Source is a component whose state is persisted.
type Source interface {
	// Kinds lists the record kinds this source owns (used to route loaded rows back).
	Kinds() []string
	// Snapshot exports every current record. It must take the component's own locks.
	Snapshot() Snapshot
	// Restore replaces the component's state with the loaded records (only its own kinds).
	Restore(Loaded) error
}

type Key struct{ Kind, ID string }

type Row struct {
	Kind string
	ID   string
	Doc  []byte
}

// Backend stores rows. Apply must be atomic.
type Backend interface {
	LoadAll(ctx context.Context) ([]Row, error)
	Apply(ctx context.Context, upserts []Row, deletes []Key) error
	Close()
}

type Syncer struct {
	backend Backend
	sources []Source

	mu     sync.Mutex // serialises Flush
	hashes map[Key][32]byte
	kick   chan struct{}
}

func NewSyncer(b Backend, sources ...Source) *Syncer {
	return &Syncer{backend: b, sources: sources, hashes: map[Key][32]byte{}, kick: make(chan struct{}, 1)}
}

// Load restores every source from the backend. Call once at startup, before serving.
// It returns false when the backend is empty (first boot), so callers can seed defaults.
func (s *Syncer) Load(ctx context.Context) (bool, error) {
	rows, err := s.backend.LoadAll(ctx)
	if err != nil {
		return false, err
	}
	// Only kinds owned by a source are managed here: other processes (e.g. the demo bank) keep
	// their own rows in the same table, and those must never be treated as deleted.
	owned := map[string]bool{}
	for _, src := range s.sources {
		for _, k := range src.Kinds() {
			owned[k] = true
		}
	}
	all := Loaded{}
	s.mu.Lock()
	for _, r := range rows {
		if !owned[r.Kind] {
			continue
		}
		if all[r.Kind] == nil {
			all[r.Kind] = map[string]json.RawMessage{}
		}
		all[r.Kind][r.ID] = json.RawMessage(r.Doc)
		s.hashes[Key{r.Kind, r.ID}] = sha256.Sum256(r.Doc)
	}
	s.mu.Unlock()
	for _, src := range s.sources {
		mine := Loaded{}
		for _, k := range src.Kinds() {
			if m, ok := all[k]; ok {
				mine[k] = m
			}
		}
		if err := src.Restore(mine); err != nil {
			return false, err
		}
	}
	return len(all) > 0, nil
}

// Flush writes every changed record and deletes removed ones.
func (s *Syncer) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := map[Key][]byte{}
	for _, src := range s.sources {
		for kind, recs := range src.Snapshot() {
			for id, rec := range recs {
				b, err := json.Marshal(rec)
				if err != nil {
					return err
				}
				current[Key{kind, id}] = b
			}
		}
	}
	var ups []Row
	newHashes := make(map[Key][32]byte, len(current))
	for k, b := range current {
		h := sha256.Sum256(b)
		newHashes[k] = h
		if old, ok := s.hashes[k]; !ok || old != h {
			ups = append(ups, Row{Kind: k.Kind, ID: k.ID, Doc: b})
		}
	}
	var dels []Key
	for k := range s.hashes {
		if _, ok := current[k]; !ok {
			dels = append(dels, k)
		}
	}
	if len(ups) == 0 && len(dels) == 0 {
		return nil
	}
	if err := s.backend.Apply(ctx, ups, dels); err != nil {
		return err
	}
	s.hashes = newHashes
	return nil
}

// Kick asks the background loop to flush soon (non-blocking).
func (s *Syncer) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run flushes on every kick and at least every interval, until ctx ends (then flushes once more).
func (s *Syncer) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := s.Flush(fctx); err != nil {
				log.Printf("persist: final flush: %v", err)
			}
			cancel()
			return
		case <-t.C:
		case <-s.kick:
		}
		fctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := s.Flush(fctx); err != nil {
			log.Printf("persist: flush: %v", err)
		}
		cancel()
	}
}

// Decode is a helper for Restore implementations.
func Decode[T any](m map[string]json.RawMessage) (map[string]*T, error) {
	out := make(map[string]*T, len(m))
	for id, raw := range m {
		v := new(T)
		if err := json.Unmarshal(raw, v); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, nil
}
