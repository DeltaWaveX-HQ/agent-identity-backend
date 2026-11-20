package auth

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/persist"
)

// Records are marshaled while the owner's lock is held, so the syncer never reads live structs
// concurrently with a writer.
func raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---------- auth server: agents, consents, approvals, elevations, delegations ----------

func (s *Server) Kinds() []string {
	return []string{"agent", "consent", "approval", "elevation", "delegation"}
}

func (s *Server) Snapshot() persist.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := persist.Snapshot{"agent": {}, "consent": {}, "approval": {}, "elevation": {}, "delegation": {}}
	for id, a := range s.agents {
		out["agent"][id] = raw(a)
	}
	for id, c := range s.consents {
		out["consent"][id] = raw(c)
	}
	for id, r := range s.cibaRequests {
		out["approval"][id] = raw(r)
	}
	for fam, acts := range s.elevations {
		if len(acts) > 0 {
			out["elevation"][fam] = raw(acts)
		}
	}
	for id, d := range s.delegations {
		out["delegation"][id] = raw(d)
	}
	return out
}

func (s *Server) Restore(l persist.Loaded) error {
	agents, err := persist.Decode[RegisteredAgent](l["agent"])
	if err != nil {
		return err
	}
	consents, err := persist.Decode[ConsentRecord](l["consent"])
	if err != nil {
		return err
	}
	approvals, err := persist.Decode[CIBARequest](l["approval"])
	if err != nil {
		return err
	}
	elev, err := persist.Decode[map[string]int64](l["elevation"])
	if err != nil {
		return err
	}
	dels, err := persist.Decode[Delegation](l["delegation"])
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents = agents
	s.consents = consents
	s.codes = make(map[string]*ConsentRecord)
	for _, c := range consents {
		if c.AuthCode != "" {
			s.codes[c.AuthCode] = c // same pointer, as when issued
		}
	}
	now := time.Now().Unix()
	s.cibaRequests = make(map[string]*CIBARequest, len(approvals))
	for id, r := range approvals {
		r.ResolvedCh = make(chan string, 1)
		// The HTTP request that was waiting on a pending approval did not survive the restart.
		if r.Status == "PENDING" {
			r.Status = "EXPIRED"
		}
		s.cibaRequests[id] = r
	}
	s.elevations = make(map[string]map[string]int64, len(elev))
	for fam, acts := range elev {
		s.elevations[fam] = *acts
	}
	s.delegations = dels
	for _, d := range dels {
		if d.Status == "pending" && d.ExpiresAt > 0 && d.ExpiresAt < now {
			d.Status = "denied"
		}
	}
	return nil
}

// ---------- token family DAG: tokens, used refresh tokens, family links ----------

func (d *FamilyDAG) Kinds() []string { return []string{"token", "used_refresh", "family_link"} }

func (d *FamilyDAG) Snapshot() persist.Snapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := persist.Snapshot{"token": {}, "used_refresh": {}, "family_link": {}}
	for jti, n := range d.tokensByJTI {
		out["token"][jti] = raw(n)
	}
	for jti, fam := range d.usedRefresh {
		out["used_refresh"][jti] = raw(fam)
	}
	for child, parent := range d.parentFam {
		out["family_link"][child] = raw(parent)
	}
	return out
}

func (d *FamilyDAG) Restore(l persist.Loaded) error {
	tokens, err := persist.Decode[TokenNode](l["token"])
	if err != nil {
		return err
	}
	used, err := persist.Decode[string](l["used_refresh"])
	if err != nil {
		return err
	}
	links, err := persist.Decode[string](l["family_link"])
	if err != nil {
		return err
	}
	nodes := make([]*TokenNode, 0, len(tokens))
	for _, n := range tokens {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].IssuedAt < nodes[j].IssuedAt })

	d.mu.Lock()
	defer d.mu.Unlock()
	d.tokensByJTI = tokens
	d.families = make(map[string][]*TokenNode)
	for _, n := range nodes {
		d.families[n.FamilyID] = append(d.families[n.FamilyID], n)
	}
	d.usedRefresh = make(map[string]string, len(used))
	for jti, fam := range used {
		d.usedRefresh[jti] = *fam
	}
	d.parentFam = make(map[string]string, len(links))
	for c, p := range links {
		d.parentFam[c] = *p
	}
	return nil
}
