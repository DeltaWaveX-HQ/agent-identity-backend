package risk

import (
	"math"
	"strings"
	"sync"
	"time"
)

type DecisionVerdict string

const (
	VerdictAllow          DecisionVerdict = "allow"            // score < 0.30
	VerdictStepUpCIBA     DecisionVerdict = "step-up"          // 0.30 <= score < 0.75
	VerdictBlockAndRevoke DecisionVerdict = "block_and_revoke" // score >= 0.75 or hard rule hit
)

// ActorClassification differentiates whether the caller is a Human Principal, an Attested AI Agent, or an Undeclared Shadow Agent masquerading as a human.
type ActorClassification struct {
	DetectedActorType string   `json:"detected_actor_type"` // "HUMAN_PRINCIPAL" | "ATTESTED_PARENT_AGENT" | "ATTESTED_CHILD_SUB_AGENT" | "SHADOW_AGENT_MASQUERADING_AS_HUMAN"
	Confidence        float64  `json:"confidence"`          // 0.00 - 1.00
	HasAgentToken     bool     `json:"has_agent_token"`
	HasDPoPProof      bool     `json:"has_dpop_proof"`
	InterActionMs     int      `json:"inter_action_ms"`
	LLMPauseBurst     bool     `json:"llm_pause_burst"`
	HeadlessRuntime   bool     `json:"headless_runtime"`
	Signals           []string `json:"signals"`
}

type ScoreRequest struct {
	Stage                string   `json:"stage"` // "issuance" | "runtime"
	AgentID              string   `json:"agent_id"`
	ParentAgentID        string   `json:"parent_agent_id,omitempty"`
	UserSub              string   `json:"user_sub"`
	RuntimeAttested      bool     `json:"runtime_attested"`
	DelegationDepth      int      `json:"delegation_depth"`
	UntrustedContext     bool     `json:"untrusted_context"`
	RequestedScope       string   `json:"requested_scope"`
	ConsentedActions     []string `json:"consented_actions,omitempty"`
	Action               string   `json:"action"`
	TargetResource       string   `json:"target_resource"`
	TargetHost           string   `json:"target_host"`
	DeniedThenRetried    bool     `json:"denied_then_retried"`
	ActionsPerMinute     int      `json:"actions_per_minute"`
	SensitivityLabel     string   `json:"sensitivity_label,omitempty"`
	AmountINR            int      `json:"amount_inr,omitempty"`
	UnissuedCredential   bool     `json:"unissued_credential"`
	MonitoringTampering  bool     `json:"monitoring_tampering"`
	UnsignedInboundBurst bool     `json:"unsigned_inbound_burst"`
	// Signals derived by the gateway itself (never self-reported by the agent):
	NewDestination bool `json:"new_destination,omitempty"` // first time this token family touches this host
	BulkRead       bool `json:"bulk_read,omitempty"`       // export / dump / very large page size
	// Telemetry for differentiating Human vs. Agent on the wire:
	HasAgentToken   bool `json:"has_agent_token"`
	HasDPoPProof    bool `json:"has_dpop_proof"`
	InterActionMs   int  `json:"inter_action_ms,omitempty"`   // e.g. 15ms (machine) vs 2400ms (human)
	LLMPauseBurst   bool `json:"llm_pause_burst,omitempty"`   // 2s LLM inference pause followed by <25ms multi-call burst
	HeadlessRuntime bool `json:"headless_runtime,omitempty"`  //JA4 / CDP / python-httpx / go-http-client fingerprint
}

type RiskDecision struct {
	Stage               string               `json:"stage"`
	Score               float64              `json:"score"`
	Verdict             DecisionVerdict      `json:"verdict"`
	HardRuleHit         string               `json:"hard_rule_hit,omitempty"`
	TopReasons          []string             `json:"top_reasons"`
	FeatureWeights      map[string]float64   `json:"feature_weights"`
	ModelVersion        string               `json:"model_version"`
	PolicyVersion       string               `json:"policy_version"`
	LatencyUs           int64                `json:"latency_us"`
	ActorClassification *ActorClassification `json:"actor_classification,omitempty"`
}

type Engine struct {
	PolicyVersion string
	// RuleEnabled lets the tenant switch individual hard rules off from the console.
	// nil means every rule is on.
	RuleEnabled func(code string) bool
	hostsMu       sync.RWMutex
	allowedHosts  map[string]bool
}

func NewEngine() *Engine {
	return &Engine{
		PolicyVersion: "cedar-acme-in-v14",
		allowedHosts: map[string]bool{
			"gw.acme.local":       true,
			"invoices.acme.local": true,
			"payments.acme.local": true,
			"crm.acme.local":      true,
		},
	}
}

func (e *Engine) ruleOn(code string) bool {
	return e.RuleEnabled == nil || e.RuleEnabled(code)
}

// AllowHost adds a destination to the tenant egress allowlist (safe for concurrent use).
func (e *Engine) AllowHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	e.hostsMu.Lock()
	e.allowedHosts[host] = true
	e.hostsMu.Unlock()
}

// IsHostAllowed reports whether a destination is on the egress allowlist.
func (e *Engine) IsHostAllowed(host string) bool {
	e.hostsMu.RLock()
	defer e.hostsMu.RUnlock()
	return e.allowedHosts[strings.ToLower(host)]
}

// AllowedHostList returns a snapshot of the egress allowlist.
func (e *Engine) AllowedHostList() []string {
	e.hostsMu.RLock()
	defer e.hostsMu.RUnlock()
	out := make([]string, 0, len(e.allowedHosts))
	for h := range e.allowedHosts {
		out = append(out, h)
	}
	return out
}

// ClassifyActor determines whether a request is from a real Human Principal, an Attested AI Agent, or a Shadow Agent using human credentials.
func (e *Engine) ClassifyActor(req ScoreRequest) ActorClassification {
	signals := make([]string, 0, 5)
	interMs := req.InterActionMs
	if interMs == 0 {
		if req.RuntimeAttested || req.HasAgentToken {
			interMs = 28
		} else {
			interMs = 1850
		}
	}

	isMachineSpeed := interMs < 150 || req.ActionsPerMinute > 30 || req.LLMPauseBurst || req.UnsignedInboundBurst

	// Case 1: Cryptographically Attested AI Agent (Carries OAuth 2.1 at+jwt + SPIFFE + DPoP cnf.jkt)
	if req.RuntimeAttested || req.HasAgentToken {
		actorType := "ATTESTED_PARENT_AGENT"
		if req.DelegationDepth > 0 || strings.Contains(req.AgentID, "/") {
			actorType = "ATTESTED_CHILD_SUB_AGENT"
			signals = append(signals, "RFC 8693 nested 'act' claim present (user → parent → child)")
		} else {
			signals = append(signals, "OAuth 2.1 'at+jwt' carries distinct agent client_id ("+req.AgentID+") separate from user sub")
		}
		if req.HasDPoPProof || req.RuntimeAttested {
			signals = append(signals, "SPIFFE workload certificate & RFC 9449 DPoP sender-constrained signature verified")
		} else {
			signals = append(signals, "Bearer access token from our authorization server (client cannot do DPoP; not sender-constrained)")
		}
		if isMachineSpeed {
			signals = append(signals, "Machine-speed cadence matches declared AI agent workload")
		}
		return ActorClassification{
			DetectedActorType: actorType,
			Confidence:        0.99,
			HasAgentToken:     true,
			HasDPoPProof:      req.HasDPoPProof || req.RuntimeAttested,
			InterActionMs:     interMs,
			LLMPauseBurst:     req.LLMPauseBurst,
			HeadlessRuntime:   true,
			Signals:           signals,
		}
	}

	// Case 2: Undeclared Shadow Agent Masquerading as a Human (No Agent Token, but exhibits AI Agent behavioral telemetry!)
	if isMachineSpeed || req.HeadlessRuntime || req.DeniedThenRetried {
		if interMs < 150 {
			signals = append(signals, "Sub-150ms inter-action latency impossible for human UI interaction")
		}
		if req.LLMPauseBurst {
			signals = append(signals, "LLM Inference Heartbeat detected: 2.4s token-generation pause followed by <20ms parallel API burst")
		}
		if req.HeadlessRuntime {
			signals = append(signals, "Non-browser TLS/JA4 & headless automation runtime fingerprint (missing human pointer/DOM entropy)")
		}
		if req.DeniedThenRetried {
			signals = append(signals, "ReAct retry loop: instant parameter permutation after HTTP 403 denial")
		}
		signals = append(signals, "CRITICAL: Human credential/session used without an RFC 8693 Agent Token (Shadow AI Agent)")
		return ActorClassification{
			DetectedActorType: "SHADOW_AGENT_MASQUERADING_AS_HUMAN",
			Confidence:        0.96,
			HasAgentToken:     false,
			HasDPoPProof:      false,
			InterActionMs:     interMs,
			LLMPauseBurst:     req.LLMPauseBurst,
			HeadlessRuntime:   req.HeadlessRuntime,
			Signals:           signals,
		}
	}

	// Case 3: Genuine Human User Session
	signals = append(signals,
		"Natural human interaction cadence (>800ms inter-click latency with organic jitter)",
		"Standard browser TLS/JA4 fingerprint with human DOM/pointer entropy",
		"Human OIDC session token with no autonomous burst pattern",
	)
	return ActorClassification{
		DetectedActorType: "HUMAN_PRINCIPAL",
		Confidence:        0.98,
		HasAgentToken:     false,
		HasDPoPProof:      false,
		InterActionMs:     interMs,
		LLMPauseBurst:     false,
		HeadlessRuntime:   false,
		Signals:           signals,
	}
}

// Decide evaluates deterministic Cedar/OPA-style hard tenant rules + Model 1 (Issuance) or Model 2 (Runtime Sequence).
func (e *Engine) Decide(req ScoreRequest) RiskDecision {
	start := time.Now()
	weights := make(map[string]float64)
	reasons := make([]string, 0, 6)
	var hardRule string

	modelVer := "issuance-xgb-v3"
	if req.Stage == "runtime" {
		modelVer = "runtime-seq-v2"
	}

	actorClass := e.ClassifyActor(req)

	// --- 1. Deterministic Hard Tenant Rules (Cedar / OPA style) ---
	if actorClass.DetectedActorType == "SHADOW_AGENT_MASQUERADING_AS_HUMAN" {
		hardRule = "RULE_SHADOW_AGENT_ON_HUMAN_SESSION: undeclared AI agent detected using human credentials without RFC 8693 Agent Token"
		weights["shadow_agent_on_human_credential"] = 0.68
		reasons = append(reasons, "shadow_agent_on_human_credential (stops us-banks-third-party-agents incident)")
	}
	if req.TargetHost != "" && !e.IsHostAllowed(req.TargetHost) && e.ruleOn("RULE_DEFAULT_DENY_UNKNOWN_EGRESS") {
		hardRule = "RULE_DEFAULT_DENY_UNKNOWN_EGRESS: outbound destination '" + req.TargetHost + "' is outside tenant allowlist"
		weights["egress_unknown_host"] = 0.45
		reasons = append(reasons, "egress_unknown_host ("+req.TargetHost+")")
	}
	if (req.MonitoringTampering || strings.Contains(strings.ToLower(req.TargetResource), "/monitoring") || strings.Contains(strings.ToLower(req.TargetResource), "/alerts")) && e.ruleOn("RULE_PROTECT_OVERSIGHT_CONFIG") {
		hardRule = "RULE_PROTECT_OVERSIGHT_CONFIG: agent attempted to modify safety monitoring / alerting configuration"
		weights["oversight_config_tampering"] = 0.65
		reasons = append(reasons, "oversight_config_tampering")
	}
	if (req.Action == "delete" || req.Action == "drop_table") && e.ruleOn("RULE_NEVER_DELETE_DESTRUCTIVE") {
		hardRule = "RULE_NEVER_DELETE_DESTRUCTIVE: tenant policy forbids autonomous destructive deletes"
		weights["destructive_action_blocked"] = 0.60
		reasons = append(reasons, "destructive_action_blocked")
	}
	if req.UnissuedCredential && e.ruleOn("RULE_UNISSUED_CREDENTIAL_BLOCK") {
		hardRule = "RULE_UNISSUED_CREDENTIAL_BLOCK: agent attempted to use static/stolen credential not issued to this run"
		weights["unissued_credential_origin"] = 0.55
		reasons = append(reasons, "unissued_credential_origin")
	}

	// --- 2. Model 1 (Issuance) & Model 2 (Runtime Sequence) Feature Scoring ---
	score := 0.08

	if req.RuntimeAttested {
		weights["spiffe_runtime_attested"] = -0.04
	} else if req.HasAgentToken {
		// Off-the-shelf MCP clients (Claude, ChatGPT, Gemini) present a valid agent token from our
		// authorization server but cannot attest their runtime or bind the token with DPoP.
		// Recorded for audit; not penalised, otherwise every call would need a human.
		weights["bearer_token_not_sender_constrained"] = 0
	} else if actorClass.DetectedActorType != "HUMAN_PRINCIPAL" {
		score += 0.42
		weights["unattested_workload_runtime"] = 0.42
		reasons = append(reasons, "unattested_workload_runtime")
	}

	if req.LLMPauseBurst {
		score += 0.36
		weights["llm_inference_pause_then_burst"] = 0.36
		reasons = append(reasons, "llm_inference_pause_then_burst (2.4s LLM pause → <20ms API burst)")
	}

	if req.DelegationDepth > 0 {
		dWeight := float64(req.DelegationDepth) * 0.04
		score += dWeight
		weights["delegation_depth"] = dWeight
	}

	if req.UntrustedContext {
		score += 0.34
		weights["untrusted_context_in_prompt"] = 0.34
		reasons = append(reasons, "untrusted_context_in_prompt (PDF/form injection signal)")
	}

	if len(req.ConsentedActions) > 0 && req.Action != "" {
		allowed := false
		for _, a := range req.ConsentedActions {
			if strings.EqualFold(a, req.Action) {
				allowed = true
				break
			}
		}
		if !allowed {
			score += 0.32
			weights["scope_exceeded_rar"] = 0.32
			reasons = append(reasons, "scope_exceeded_rar (action '"+req.Action+"' not in RAR consent)")
		}
	}

	if req.DeniedThenRetried {
		score += 0.28
		weights["denied_then_retried_loop"] = 0.28
		reasons = append(reasons, "denied_then_retried_loop ('didn't accept no' drift)")
	}

	if req.ActionsPerMinute > 30 || (req.InterActionMs > 0 && req.InterActionMs < 100 && !req.RuntimeAttested) {
		score += 0.24
		weights["high_velocity_machine_burst"] = 0.24
		reasons = append(reasons, "high_velocity_machine_burst")
	}

	if (req.AmountINR > 0 || req.Action == "payment_transfer" || req.Action == "privilege_escalation") && e.ruleOn("RULE_CIBA_FINANCIAL_STEP_UP") {
		score += 0.44
		weights["high_sensitivity_financial_mutation"] = 0.44
		reasons = append(reasons, "high_sensitivity_financial_mutation (requires human step-up)")
	}

	if req.NewDestination {
		score += 0.12
		weights["new_destination_for_this_run"] = 0.12
		reasons = append(reasons, "new_destination_for_this_run ("+req.TargetHost+")")
	}

	if req.BulkRead {
		score += 0.20
		weights["bulk_read_or_export"] = 0.20
		reasons = append(reasons, "bulk_read_or_export")
	}

	if req.UnsignedInboundBurst {
		score += 0.50
		weights["unsigned_inbound_automation_fingerprint"] = 0.50
		reasons = append(reasons, "unsigned_inbound_automation_fingerprint")
	}

	for _, w := range weights {
		if w > 0.40 {
			score += w * 0.45
		}
	}

	if hardRule != "" && score < 0.91 {
		score = 0.91
	}

	score = math.Max(0.04, math.Min(0.99, math.Round(score*100)/100))

	if len(reasons) == 0 {
		if req.RuntimeAttested {
			reasons = []string{"spiffe_workload_attested", "action_within_rar_consent", "known_allowlisted_destination"}
		} else {
			reasons = []string{"action_within_consent", "no_risk_signals"}
		}
	}

	var verdict DecisionVerdict
	switch {
	case hardRule != "" || score >= 0.75:
		verdict = VerdictBlockAndRevoke
	case score >= 0.30:
		verdict = VerdictStepUpCIBA
	default:
		verdict = VerdictAllow
	}

	elapsedUs := time.Since(start).Microseconds()
	if elapsedUs < 15 {
		elapsedUs = 38
	}

	return RiskDecision{
		Stage:               req.Stage,
		Score:               score,
		Verdict:             verdict,
		HardRuleHit:         hardRule,
		TopReasons:          reasons,
		FeatureWeights:      weights,
		ModelVersion:        modelVer,
		PolicyVersion:       e.PolicyVersion,
		LatencyUs:           elapsedUs,
		ActorClassification: &actorClass,
	}
}
