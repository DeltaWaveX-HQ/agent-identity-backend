package risk

import (
	"encoding/json"

	"github.com/buildathon2026/agent-identity-backend/internal/persist"
)

// The egress allowlist is tenant configuration (console "Allow host" and the gateway's
// configured list), so it survives restarts.

func (e *Engine) Kinds() []string { return []string{"egress_host"} }

func (e *Engine) Snapshot() persist.Snapshot {
	e.hostsMu.RLock()
	defer e.hostsMu.RUnlock()
	out := persist.Snapshot{"egress_host": {}}
	for h, ok := range e.allowedHosts {
		if ok {
			out["egress_host"][h] = json.RawMessage("true")
		}
	}
	return out
}

func (e *Engine) Restore(l persist.Loaded) error {
	e.hostsMu.Lock()
	defer e.hostsMu.Unlock()
	for h := range l["egress_host"] {
		e.allowedHosts[h] = true
	}
	return nil
}
