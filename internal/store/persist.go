package store

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/persist"
)

func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (ds *DataStore) Kinds() []string {
	return []string{"user", "org", "policy", "route", "audit", "session", "hook_key"}
}

func (ds *DataStore) Snapshot() persist.Snapshot {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	out := persist.Snapshot{"user": {}, "org": {}, "policy": {}, "route": {}, "audit": {}, "session": {}, "hook_key": {}}
	for h, k := range ds.hookKeys {
		out["hook_key"][h] = raw(k) // id is the key's hash; the key itself is never stored
	}
	for _, u := range ds.state.Users {
		out["user"][u.ID] = raw(u) // password field holds a bcrypt hash
	}
	for _, o := range ds.state.Organizations {
		out["org"][o.ID] = raw(o)
	}
	for _, p := range ds.state.Policies {
		out["policy"][p.ID] = raw(p)
	}
	for _, r := range ds.state.GatewayRoutes {
		out["route"][r.ID] = raw(r)
	}
	for _, a := range ds.state.AuditLogs {
		out["audit"][a.ID] = raw(a)
	}
	now := time.Now().Unix()
	for tok, s := range ds.sessions {
		if s.ExpiresAt > now {
			out["session"][tok] = raw(s)
		}
	}
	return out
}

// Restore loads the tenant state. If the database holds none of these kinds yet (first boot),
// the current state (seeded policies, or a migrated local JSON file) is kept and saved on the
// next flush.
func (ds *DataStore) Restore(l persist.Loaded) error {
	if len(l) == 0 {
		return nil
	}
	users, err := persist.Decode[User](l["user"])
	if err != nil {
		return err
	}
	orgs, err := persist.Decode[Organization](l["org"])
	if err != nil {
		return err
	}
	pols, err := persist.Decode[PolicyRule](l["policy"])
	if err != nil {
		return err
	}
	routes, err := persist.Decode[GatewayRoute](l["route"])
	if err != nil {
		return err
	}
	audits, err := persist.Decode[AuditLogEntry](l["audit"])
	if err != nil {
		return err
	}
	sessions, err := persist.Decode[Session](l["session"])
	if err != nil {
		return err
	}
	hookKeys, err := persist.Decode[HookKey](l["hook_key"])
	if err != nil {
		return err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.state.Users = sortedBy(users, func(u *User) int64 { return u.CreatedAt })
	ds.state.Organizations = sortedBy(orgs, func(o *Organization) int64 { return o.CreatedAt })
	if len(pols) > 0 {
		// Keep the seeded order of built-in rules; console toggles (Enabled) come from the database.
		merged := make([]*PolicyRule, 0, len(pols))
		seen := map[string]bool{}
		for _, p := range ds.state.Policies {
			if dbp, ok := pols[p.ID]; ok {
				merged = append(merged, dbp)
				seen[p.ID] = true
			}
		}
		for id, p := range pols {
			if !seen[id] {
				merged = append(merged, p)
			}
		}
		ds.state.Policies = merged
	}
	if len(routes) > 0 {
		ds.state.GatewayRoutes = sortedBy(routes, func(r *GatewayRoute) int64 { return 0 })
	}
	logs := sortedBy(audits, func(a *AuditLogEntry) int64 { return a.Seq })
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 { // newest first
		logs[i], logs[j] = logs[j], logs[i]
	}
	ds.state.AuditLogs = logs
	ds.sessions = sessions
	ds.hookKeys = hookKeys
	return nil
}

func sortedBy[T any](m map[string]*T, key func(*T) int64) []*T {
	out := make([]*T, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}
