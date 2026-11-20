package crypto

import (
	"testing"
	"time"
)

func TestJWKSAndDPoPBinding(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	jwks := km.PublicJWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys (active + staged), got %d", len(jwks.Keys))
	}

	agentKey, err := GenerateAgentDPoPKeypair("agent:test")
	if err != nil {
		t.Fatalf("GenerateAgentDPoPKeypair failed: %v", err)
	}

	priv, kid := km.ActiveSigner()
	claims := AgentAccessTokenClaims{
		Iss:      "https://auth.agentidentity.local",
		Sub:      "user:priya@acme.in",
		ClientID: "agent:test",
		Aud:      "https://gw.acme.local/tools/invoices",
		Scope:    "invoices.read",
		JTI:      "tok_1",
		FamilyID: "fam_1",
		IAT:      time.Now().Unix(),
		EXP:      time.Now().Add(5 * time.Minute).Unix(),
		CNF:      map[string]string{"jkt": agentKey.Thumbprint},
	}

	jwtStr, err := SignAccessToken(priv, kid, claims)
	if err != nil {
		t.Fatalf("SignAccessToken failed: %v", err)
	}

	_, verifiedClaims, err := VerifyAccessToken(&priv.PublicKey, jwtStr)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed: %v", err)
	}
	if verifiedClaims.CNF["jkt"] != agentKey.Thumbprint {
		t.Fatalf("expected cnf.jkt=%s, got %s", agentKey.Thumbprint, verifiedClaims.CNF["jkt"])
	}

	// Valid DPoP proof from agentKey
	dpopStr, _, err := agentKey.CreateDPoPProof("GET", "https://gw.acme.local/tools/invoices", jwtStr)
	if err != nil {
		t.Fatalf("CreateDPoPProof failed: %v", err)
	}
	if _, _, err := VerifyDPoPProof(dpopStr, "GET", "https://gw.acme.local/tools/invoices", jwtStr, agentKey.Thumbprint); err != nil {
		t.Fatalf("VerifyDPoPProof failed on valid proof: %v", err)
	}

	// Attacker key replay must fail cnf.jkt verification
	attackerKey, _ := GenerateAgentDPoPKeypair("attacker:evil")
	forgedDPoP, _, _ := attackerKey.CreateDPoPProof("GET", "https://gw.acme.local/tools/invoices", jwtStr)
	if _, _, err := VerifyDPoPProof(forgedDPoP, "GET", "https://gw.acme.local/tools/invoices", jwtStr, agentKey.Thumbprint); err == nil {
		t.Fatalf("expected VerifyDPoPProof to reject attacker key with mismatched cnf.jkt")
	}
}
