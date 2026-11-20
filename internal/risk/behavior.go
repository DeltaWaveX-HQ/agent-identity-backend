package risk

import (
	"strings"
	"sync"
	"time"
)

// BehaviorTracker derives runtime risk signals from what the gateway actually observes,
// instead of trusting flags the agent reports about itself. It is the in-memory
// stand-in for the blueprint's online feature store (Redis).
//
// Keys:
//   - token family  → call rate, hosts already contacted, untrusted-content taint
//   - agent client  → recent denials (survive re-authentication, so "kept trying after
//     being told no" is caught even if the agent gets a fresh token)
type BehaviorTracker struct {
	mu       sync.Mutex
	families map[string]*familyBehavior
	denials  map[string][]denial // clientID -> recent denials
}

type familyBehavior struct {
	calls       []time.Time
	hosts       map[string]bool
	taintedAt   time.Time
	taintReason string
}

type denial struct {
	at     time.Time
	tool   string
	action string
}

// Signals is the feature vector handed to the runtime model for one call.
type Signals struct {
	ActionsPerMinute  int
	DeniedThenRetried bool
	NewDestination    bool
	UntrustedContext  bool
	TaintReason       string
}

const (
	denialMemory = 5 * time.Minute
	taintMemory  = 30 * time.Minute
)

func NewBehaviorTracker() *BehaviorTracker {
	return &BehaviorTracker{
		families: make(map[string]*familyBehavior),
		denials:  make(map[string][]denial),
	}
}

func (t *BehaviorTracker) family(id string) *familyBehavior {
	f, ok := t.families[id]
	if !ok {
		f = &familyBehavior{hosts: make(map[string]bool)}
		t.families[id] = f
	}
	return f
}

// Observe records a call attempt and returns the signals computed *before* it,
// so the first call to a host counts as a new destination.
func (t *BehaviorTracker) Observe(familyID, clientID, tool, action, host string) Signals {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	f := t.family(familyID)

	// Sliding one-minute window of calls (including this one).
	kept := f.calls[:0]
	for _, c := range f.calls {
		if now.Sub(c) < time.Minute {
			kept = append(kept, c)
		}
	}
	f.calls = append(kept, now)

	s := Signals{ActionsPerMinute: len(f.calls)}

	if host != "" {
		h := strings.ToLower(host)
		if !f.hosts[h] && len(f.hosts) > 0 {
			s.NewDestination = true
		}
		f.hosts[h] = true
	}

	for _, d := range t.denials[clientID] {
		if now.Sub(d.at) < denialMemory && (d.tool == tool || (d.action != "" && d.action == action)) {
			s.DeniedThenRetried = true
			break
		}
	}

	if !f.taintedAt.IsZero() && now.Sub(f.taintedAt) < taintMemory {
		s.UntrustedContext = true
		s.TaintReason = f.taintReason
	}
	return s
}

// RecordDenial remembers that this agent was told no (blocked, or step-up denied/expired).
func (t *BehaviorTracker) RecordDenial(clientID, tool, action string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	kept := t.denials[clientID][:0]
	for _, d := range t.denials[clientID] {
		if now.Sub(d.at) < denialMemory {
			kept = append(kept, d)
		}
	}
	t.denials[clientID] = append(kept, denial{at: now, tool: tool, action: action})
}

// ClearDenials forgets an agent's past denials. Called when a human explicitly re-authorizes the
// agent with a fresh consent: that is a deliberate "yes, try again", not the agent ignoring a "no".
func (t *BehaviorTracker) ClearDenials(clientID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.denials, clientID)
}

// Taint marks a token family as having untrusted content (e.g. a prompt injection found in a
// tool result, or output from an internet-facing tool) in its context window.
func (t *BehaviorTracker) Taint(familyID, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.family(familyID)
	f.taintedAt = time.Now()
	f.taintReason = reason
}

// Reset clears all observed behaviour (workspace reset).
func (t *BehaviorTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.families = make(map[string]*familyBehavior)
	t.denials = make(map[string][]denial)
}
