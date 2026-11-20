package risk

import "testing"

func TestBehaviorSignals(t *testing.T) {
	bt := NewBehaviorTracker()

	s := bt.Observe("fam1", "agent:a", "files__read_file", "read", "")
	if s.NewDestination || s.DeniedThenRetried || s.UntrustedContext || s.ActionsPerMinute != 1 {
		t.Fatalf("first call should be clean, got %+v", s)
	}

	bt.Observe("fam1", "agent:a", "web__fetch", "read", "docs.acme.in")
	s = bt.Observe("fam1", "agent:a", "web__fetch", "read", "api.github.com")
	if !s.NewDestination {
		t.Fatalf("second distinct host should be a new destination")
	}

	bt.RecordDenial("agent:a", "bank__initiate_payment", "payment_transfer")
	s = bt.Observe("fam2", "agent:a", "bank__initiate_payment", "payment_transfer", "")
	if !s.DeniedThenRetried {
		t.Fatalf("retry after denial must be flagged even on a new token family")
	}

	bt.ClearDenials("agent:a")
	if s = bt.Observe("fam3", "agent:a", "bank__initiate_payment", "payment_transfer", ""); s.DeniedThenRetried {
		t.Fatalf("fresh human consent should clear denial memory")
	}

	bt.Taint("fam1", "prompt injection in files__read_file")
	s = bt.Observe("fam1", "agent:a", "bank__list_accounts", "read", "")
	if !s.UntrustedContext {
		t.Fatalf("tainted family must report untrusted context")
	}
}

func TestDecisionTiersForGatewayActions(t *testing.T) {
	e := NewEngine()
	base := ScoreRequest{Stage: "runtime", AgentID: "agent:dcr-claude-code", UserSub: "user:a@b.in", HasAgentToken: true}

	read := base
	read.Action, read.ConsentedActions = "read", []string{"read", "write"}
	if d := e.Decide(read); d.Verdict != VerdictAllow {
		t.Fatalf("consented read should be allowed, got %s (%.2f)", d.Verdict, d.Score)
	}

	pay := base
	pay.Action, pay.AmountINR, pay.ConsentedActions = "payment_transfer", 45000, []string{"read", "payment_transfer"}
	if d := e.Decide(pay); d.Verdict != VerdictStepUpCIBA {
		t.Fatalf("consented payment should need a human, got %s (%.2f)", d.Verdict, d.Score)
	}

	taintedPay := pay
	taintedPay.UntrustedContext = true
	if d := e.Decide(taintedPay); d.Verdict != VerdictBlockAndRevoke {
		t.Fatalf("payment after prompt injection should be blocked, got %s (%.2f)", d.Verdict, d.Score)
	}

	exfil := base
	exfil.Action, exfil.TargetHost, exfil.ConsentedActions = "export", "pastebin.com", []string{"read", "export"}
	if d := e.Decide(exfil); d.Verdict != VerdictBlockAndRevoke || d.HardRuleHit == "" {
		t.Fatalf("export to unknown host must hit the egress hard rule, got %s", d.Verdict)
	}

	outside := base
	outside.Action, outside.ConsentedActions = "write", []string{"read"}
	if d := e.Decide(outside); d.Verdict != VerdictStepUpCIBA {
		t.Fatalf("write outside consent should ask a human, got %s (%.2f)", d.Verdict, d.Score)
	}
}
