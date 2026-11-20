package main

// Sub-agent attribution.
//
// MCP carries no "which sub-agent is calling" field, and clients such as Claude Code run their
// sub-agents over the parent's MCP connection and token. Claude Code does know: its PreToolUse
// hook receives agent_id / agent_type whenever a sub-agent calls a tool. A one-line hook posts
// that hook input here, just before Claude sends the call; the gateway then matches the next
// identical tools/call (same tool, same arguments) to that sub-agent.
//
// Matching is by tool + canonical arguments, oldest first. Notices for the main agent (no agent_id)
// are kept too, so identical calls from parent and sub-agent are not confused.
// Attribution can only narrow access (a sub-agent gets a subset of its parent), never widen it.

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const attributionTTL = 10 * time.Minute // the user may sit on Claude's own permission prompt

type attribution struct {
	key       string
	agentID   string
	agentType string
	at        time.Time
}

type attributionBook struct {
	mu      sync.Mutex
	pending []attribution
}

func canonicalArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	if v == nil {
		return "{}"
	}
	b, _ := json.Marshal(v) // map keys come out sorted
	return string(b)
}

func (b *attributionBook) add(a attribution) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	kept := b.pending[:0]
	for _, p := range b.pending {
		if now.Sub(p.at) < attributionTTL {
			kept = append(kept, p)
		}
	}
	b.pending = append(kept, a)
}

// take removes and returns the oldest notice for this exact call.
func (b *attributionBook) take(key string) (attribution, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for i, p := range b.pending {
		if p.key == key && now.Sub(p.at) < attributionTTL {
			b.pending = append(b.pending[:i], b.pending[i+1:]...)
			return p, true
		}
	}
	return attribution{}, false
}

func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleAttribution receives Claude Code PreToolUse hook input.
func (g *Gateway) handleAttribution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST hook input", http.StatusMethodNotAllowed)
		return
	}
	// Local-only for the prototype: the hook runs on the same machine as the gateway.
	if !isLoopback(r) {
		http.Error(w, "attribution is accepted from this machine only", http.StatusForbidden)
		return
	}
	var in struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
		AgentID   string          `json:"agent_id"`
		AgentType string          `json:"agent_type"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// tool_name is mcp__<server name>__<exposed tool>; the server name is whatever the user chose.
	exposed := ""
	for name := range g.routes {
		if strings.HasSuffix(in.ToolName, "__"+name) && len(name) > len(exposed) {
			exposed = name
		}
	}
	if exposed == "" {
		w.WriteHeader(http.StatusNoContent) // not one of ours
		return
	}
	g.attrib.add(attribution{key: exposed + "|" + canonicalArgs(in.ToolInput), agentID: in.AgentID, agentType: in.AgentType, at: time.Now()})
	if in.AgentID != "" {
		log.Printf("attribute %-28s sub-agent %s (%s)", exposed, in.AgentType, in.AgentID)
	}
	w.WriteHeader(http.StatusNoContent)
}
