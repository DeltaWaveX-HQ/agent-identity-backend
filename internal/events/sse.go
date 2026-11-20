package events

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TelemetryEvent represents a live event pushed to the Next.js Command Center via SSE.
type TelemetryEvent struct {
	ID            string         `json:"id"`
	Timestamp     string         `json:"timestamp"`
	StepNumber    int            `json:"step_number,omitempty"`
	FromLane      string         `json:"from_lane"` // user | agent | as | risk | gw | res
	ToLane        string         `json:"to_lane"`
	Label         string         `json:"label"`
	Who           string         `json:"who"`
	Headline      string         `json:"headline"`
	PlainText     string         `json:"plain_text"`
	UnderTheHood  string         `json:"under_the_hood"`
	FlowNode      string         `json:"flow_node"` // start | attest | score1 | consent | code | token | exchange | call | runtime | allow | revoke | refresh | end
	Status        string         `json:"status"`    // info | ok | warn | bad
	StatusText    string         `json:"status_text"`
	LatencyUs     int64          `json:"latency_us,omitempty"`
	TokenRaw      string         `json:"token_raw,omitempty"`
	TokenClaims   any            `json:"token_claims,omitempty"`
	DPoPRaw       string         `json:"dpop_raw,omitempty"`
	DPoPClaims    any            `json:"dpop_claims,omitempty"`
	RiskDecision  any            `json:"risk_decision,omitempty"`
	FamilyGraph   any            `json:"family_graph,omitempty"`
	PhonePrompt   *PhonePrompt   `json:"phone_prompt,omitempty"`
}

// PhonePrompt triggers the interactive Smartphone Simulator in Next.js (RAR Consent or OpenID CIBA Step-Up).
type PhonePrompt struct {
	PromptID             string `json:"prompt_id"`
	Type                 string `json:"type"` // "rar_consent" | "ciba_step_up" | "dismiss"
	Title                string `json:"title"`
	User                 string `json:"user"`
	AgentID              string `json:"agent_id"`
	ParentAgentID        string `json:"parent_agent_id,omitempty"`
	TaskDescription      string `json:"task_description"`
	RequestedResource    string `json:"requested_resource"`
	RequestedActions     []string `json:"requested_actions"`
	TTLDisplay           string `json:"ttl_display"`
	RiskScore            float64 `json:"risk_score"`
	RiskReasons          []string `json:"risk_reasons,omitempty"`
	ExpiresInSeconds     int    `json:"expires_in_seconds"`
}

type Hub struct {
	mu      sync.RWMutex
	clients map[chan TelemetryEvent]struct{}
	history []TelemetryEvent
	seq     int
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[chan TelemetryEvent]struct{}),
		history: make([]TelemetryEvent, 0, 128),
	}
}

func (h *Hub) Publish(ev TelemetryEvent) {
	h.mu.Lock()
	h.seq++
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("ev_%d_%d", time.Now().UnixMilli(), h.seq)
	}
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	h.history = append(h.history, ev)
	if len(h.history) > 250 {
		h.history = h.history[len(h.history)-250:]
	}
	clients := make([]chan TelemetryEvent, 0, len(h.clients))
	for ch := range h.clients {
		clients = append(clients, ch)
	}
	h.mu.Unlock()

	for _, ch := range clients {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (h *Hub) ClearHistory() {
	h.mu.Lock()
	h.history = make([]TelemetryEvent, 0, 128)
	h.seq = 0
	h.mu.Unlock()
}

func (h *Hub) GetHistory() []TelemetryEvent {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]TelemetryEvent, len(h.history))
	copy(out, h.history)
	return out
}

func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan TelemetryEvent, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	hist := make([]TelemetryEvent, len(h.history))
	copy(hist, h.history)
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()

	// Send initial history burst
	for _, ev := range hist {
		data, _ := json.Marshal(ev)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			data, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
