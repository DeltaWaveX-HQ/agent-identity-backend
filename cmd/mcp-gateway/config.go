package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config describes the gateway and the real MCP servers it fronts.
type Config struct {
	Listen             string           `json:"listen"`               // e.g. ":8090"
	PublicURL          string           `json:"public_url"`           // what MCP clients use, e.g. http://localhost:8090
	AuthServer         string           `json:"auth_server"`          // issuer URL advertised to clients
	AuthServerInternal string           `json:"auth_server_internal"` // where the gateway calls /decide (defaults to auth_server)
	EgressAllowlist    []string         `json:"egress_allowlist"`     // hosts agents may reach through URL arguments
	Upstreams          []UpstreamConfig `json:"upstreams"`
}

type UpstreamConfig struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     *bool             `json:"enabled,omitempty"`
	Transport   string            `json:"transport"` // "stdio" | "http"
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Dir         string            `json:"dir,omitempty"`
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	// UntrustedOutput marks servers that return internet content (web fetch, email, tickets…).
	// Their results taint the agent's context, so later risky actions score higher.
	UntrustedOutput bool                  `json:"untrusted_output,omitempty"`
	Tools           map[string]ToolPolicy `json:"tools,omitempty"`
}

// ToolPolicy overrides how the gateway classifies one upstream tool.
type ToolPolicy struct {
	Action    string   `json:"action,omitempty"`     // read | write | delete | payment_transfer | export
	AmountArg string   `json:"amount_arg,omitempty"` // argument holding an INR amount
	URLArgs   []string `json:"url_args,omitempty"`   // arguments holding destination URLs
	Bulk      bool     `json:"bulk,omitempty"`
	Hidden    bool     `json:"hidden,omitempty"` // never expose this tool to agents
}

func (u UpstreamConfig) enabled() bool { return u.Enabled == nil || *u.Enabled }

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = ":8090"
	}
	if c.PublicURL == "" {
		c.PublicURL = "http://localhost" + c.Listen
	}
	if c.AuthServer == "" {
		c.AuthServer = "http://localhost:8080"
	}
	if c.AuthServerInternal == "" {
		c.AuthServerInternal = c.AuthServer
	}
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	c.AuthServer = strings.TrimRight(c.AuthServer, "/")
	c.AuthServerInternal = strings.TrimRight(c.AuthServerInternal, "/")

	seen := map[string]bool{}
	for i := range c.Upstreams {
		u := &c.Upstreams[i]
		if u.Name == "" || strings.Contains(u.Name, "__") {
			return nil, fmt.Errorf("upstream %d: name is required and must not contain \"__\"", i)
		}
		if seen[u.Name] {
			return nil, fmt.Errorf("duplicate upstream name %q", u.Name)
		}
		seen[u.Name] = true
		// ${VAR} expansion so secrets (e.g. GITHUB_TOKEN) stay in the environment, not the file.
		u.Command = os.ExpandEnv(u.Command)
		u.URL = os.ExpandEnv(u.URL)
		for j := range u.Args {
			u.Args[j] = os.ExpandEnv(u.Args[j])
		}
		for k, v := range u.Env {
			u.Env[k] = os.ExpandEnv(v)
		}
		for k, v := range u.Headers {
			u.Headers[k] = os.ExpandEnv(v)
		}
	}
	return &c, nil
}
