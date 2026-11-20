// Command mcp-gateway is Layer 2 of the Agent Identity platform: an MCP proxy that sits between
// AI clients (Claude, ChatGPT, Gemini, Cursor, MCPJam) and real MCP servers. Every client must
// hold a token from our authorization server; every tool call is decided by the policy + risk
// engine before it reaches the upstream server.
//
//	go run ./cmd/server                                  # authorization server + dashboard API (:8080)
//	go run ./cmd/mcp-gateway                             # this gateway (:8090), reads config/mcp-upstreams.json
//	claude mcp add --transport http agent-gw http://localhost:8090/mcp
//
// The original simulated gateway is still available with -legacy-demo.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	for i, a := range os.Args[1:] {
		if a == "-legacy-demo" || a == "--legacy-demo" {
			os.Args = append(os.Args[:i+1], os.Args[i+2:]...)
			legacyMain()
			return
		}
	}

	configPath := flag.String("config", "config/mcp-upstreams.json", "gateway + upstream MCP servers config")
	listen := flag.String("listen", "", "override listen address (e.g. :8090)")
	publicURL := flag.String("public-url", "", "override the URL clients use to reach this gateway")
	authServer := flag.String("auth-server", "", "override the authorization server URL")
	flag.Parse()

	log.SetFlags(log.Ltime)
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("%v (run from agent-identity-backend/, or pass -config)", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *publicURL != "" {
		cfg.PublicURL = *publicURL
	}
	if *authServer != "" {
		cfg.AuthServer, cfg.AuthServerInternal = *authServer, *authServer
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gw := newGateway(cfg)
	log.Printf("Agent Identity MCP Gateway %s — starting upstream MCP servers…", gatewayVersion)
	gw.startUpstreams(ctx)
	defer gw.close()
	gw.registerEgressAllowlist()

	srv := &http.Server{Addr: cfg.Listen, Handler: gw.handler()}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	log.Printf("MCP endpoint   %s  (%d tools)", gw.resource, len(gw.order))
	log.Printf("Auth server    %s", cfg.AuthServer)
	log.Printf("Connect Claude: claude mcp add --transport http agent-gw %s", gw.resource)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}
