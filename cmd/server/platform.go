package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
	"github.com/buildathon2026/agent-identity-backend/internal/persist"
	"github.com/buildathon2026/agent-identity-backend/internal/risk"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

// setupPersistence connects to Postgres when DATABASE_URL is set and restores all state.
// Without it the server runs fully in memory (plus the legacy local JSON file for tenant data).
func setupPersistence(ctx context.Context, km *crypto.KeyManager, dag *auth.FamilyDAG, as *auth.Server, eng *risk.Engine, ds *store.DataStore) (*persist.Syncer, *persist.Postgres) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		log.Printf("ℹ️  DATABASE_URL not set: agents, grants and tokens live in memory and are lost on restart")
		return nil, nil
	}
	sealer, err := persist.NewSealer(os.Getenv("APP_SECRET"))
	if err != nil {
		log.Fatalf("APP_SECRET: %v", err)
	}
	if os.Getenv("APP_SECRET") == "" {
		log.Printf("⚠️  APP_SECRET is not set: signing keys are stored unencrypted in the database")
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	pg, err := persist.OpenPostgres(cctx, url)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	ds.DetachFile()
	syncer := persist.NewSyncer(pg, crypto.NewKeyStore(km, sealer), dag, as, eng, ds)
	found, err := syncer.Load(cctx)
	if err != nil {
		log.Fatalf("database: restore state: %v", err)
	}
	if found {
		log.Printf("🗄️  Postgres: state restored")
	} else {
		log.Printf("🗄️  Postgres: empty database, starting fresh")
	}
	if err := syncer.Flush(cctx); err != nil {
		log.Fatalf("database: initial save: %v", err)
	}
	go syncer.Run(ctx, 2*time.Second)
	return syncer, pg
}
