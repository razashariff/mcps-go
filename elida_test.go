package mcps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- ELIDA Middleware Creation ---

func TestNewELIDAMiddleware(t *testing.T) {
	mw, err := NewELIDAMiddleware(ELIDAConfig{
		PassportID:      "test-middleware",
		SignRequests:    true,
		VerifyResponses: true,
		PinTools:        true,
		NonceWindow:     5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewELIDAMiddleware failed: %v", err)
	}
	if mw.passport.ID != "test-middleware" {
		t.Fatalf("expected passport ID test-middleware, got %s", mw.passport.ID)
	}
	if mw.passport.TrustLevel != TrustIdentified {
		t.Fatalf("expected default trust level L1, got %d", mw.passport.TrustLevel)
	}
	if mw.keyPair == nil {
		t.Fatal("key pair should be generated")
	}
}

func TestNewELIDAMiddlewareDefaultWindow(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{PassportID: "test"})
	// Default nonce window should be 5 minutes
	if mw.nonces.windowMs != (5 * time.Minute).Milliseconds() {
		t.Fatalf("expected 5 minute default window, got %dms", mw.nonces.windowMs)
	}
}

// --- ProcessRequest ---

func TestProcessRequestSigning(t *testing.T) {
	threats := []ThreatEvent{}
	audits := []AuditEvent{}

	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:   "test-agent",
		SignRequests: true,
		OnThreat:     func(e ThreatEvent) { threats = append(threats, e) },
		OnAudit:      func(e AuditEvent) { audits = append(audits, e) },
	})

	body := []byte(`{"method":"tools/call","params":{"name":"search_entities"}}`)
	headers := http.Header{}

	result, err := mw.ProcessRequest(body, headers)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}

	// Check MCPS headers were set
	if headers.Get("X-MCPS-Version") != Version {
		t.Fatalf("expected X-MCPS-Version %s, got %s", Version, headers.Get("X-MCPS-Version"))
	}
	if headers.Get("X-MCPS-Passport-ID") != "test-agent" {
		t.Fatalf("expected X-MCPS-Passport-ID test-agent, got %s", headers.Get("X-MCPS-Passport-ID"))
	}
	if headers.Get("X-MCPS-Nonce") == "" {
		t.Fatal("X-MCPS-Nonce should be set")
	}
	if headers.Get("X-MCPS-Signature") == "" {
		t.Fatal("X-MCPS-Signature should be set")
	}

	// Check audit event was emitted
	if len(audits) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(audits))
	}
	if audits[0].Direction != "REQUEST" {
		t.Fatalf("expected REQUEST direction, got %s", audits[0].Direction)
	}
	if !audits[0].Signed {
		t.Fatal("audit should show signed=true")
	}

	// No threats expected
	if len(threats) != 0 {
		t.Fatalf("expected 0 threats, got %d", len(threats))
	}
}

func TestProcessRequestNoSigningPassthrough(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:   "test-agent",
		SignRequests: false, // signing disabled
	})

	body := []byte(`{"method":"tools/call"}`)
	headers := http.Header{}

	result, err := mw.ProcessRequest(body, headers)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}
	if string(result) != string(body) {
		t.Fatal("body should pass through unchanged when signing disabled")
	}
	if headers.Get("X-MCPS-Signature") != "" {
		t.Fatal("should not set signature header when signing disabled")
	}
}

func TestProcessRequestNonJSONPassthrough(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:   "test-agent",
		SignRequests: true,
	})

	body := []byte("this is not json")
	headers := http.Header{}

	result, err := mw.ProcessRequest(body, headers)
	if err != nil {
		t.Fatalf("non-JSON should pass through: %v", err)
	}
	if string(result) != string(body) {
		t.Fatal("non-JSON body should be unchanged")
	}
}

func TestProcessRequestToolPinning(t *testing.T) {
	threats := []ThreatEvent{}

	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID: "test-agent",
		PinTools:   true,
		OnThreat:   func(e ThreatEvent) { threats = append(threats, e) },
	})

	// First call -- pins the tool
	body1 := []byte(`{"method":"tools/call","params":{"name":"search_entities","arguments":{"query":"test"}}}`)
	_, err := mw.ProcessRequest(body1, http.Header{})
	if err != nil {
		t.Fatalf("first request should succeed: %v", err)
	}

	// Second call with same tool -- should pass
	_, err = mw.ProcessRequest(body1, http.Header{})
	if err != nil {
		t.Fatalf("same tool should pass: %v", err)
	}

	// Third call with mutated tool -- should detect
	body2 := []byte(`{"method":"tools/call","params":{"name":"search_entities","arguments":{"query":"test"},"injected":"evil"}}`)
	_, err = mw.ProcessRequest(body2, http.Header{})
	if err != ErrToolIntegrity {
		t.Fatalf("expected ErrToolIntegrity, got %v", err)
	}

	if len(threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(threats))
	}
	if threats[0].Type != "TOOL_MUTATION" {
		t.Fatalf("expected TOOL_MUTATION threat, got %s", threats[0].Type)
	}
}

// --- ProcessResponse ---

func TestProcessResponseUnsigned(t *testing.T) {
	audits := []AuditEvent{}

	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:      "test-agent",
		VerifyResponses: true,
		OnAudit:         func(e AuditEvent) { audits = append(audits, e) },
	})

	body := []byte(`{"result":{"content":[{"text":"ok"}]}}`)
	headers := http.Header{}

	result, err := mw.ProcessResponse(body, headers)
	if err != nil {
		t.Fatalf("unsigned response should pass: %v", err)
	}
	if string(result) != string(body) {
		t.Fatal("body should pass through")
	}

	if len(audits) != 1 {
		t.Fatalf("expected 1 audit, got %d", len(audits))
	}
	if audits[0].Signed {
		t.Fatal("should report unsigned")
	}
}

func TestProcessResponseReplayDetection(t *testing.T) {
	threats := []ThreatEvent{}

	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:      "test-agent",
		VerifyResponses: true,
		OnThreat:        func(e ThreatEvent) { threats = append(threats, e) },
	})

	body := []byte(`{"result":"ok"}`)
	nonce := "fixed-nonce-for-replay-test"

	headers1 := http.Header{}
	headers1.Set("X-MCPS-Signature", "somesig")
	headers1.Set("X-MCPS-Nonce", nonce)
	headers1.Set("X-MCPS-Passport-ID", "server-1")

	// First response -- should pass
	_, err := mw.ProcessResponse(body, headers1)
	if err != nil {
		t.Fatalf("first response should pass: %v", err)
	}

	// Replay -- same nonce
	headers2 := http.Header{}
	headers2.Set("X-MCPS-Signature", "somesig")
	headers2.Set("X-MCPS-Nonce", nonce)
	headers2.Set("X-MCPS-Passport-ID", "server-1")

	_, err = mw.ProcessResponse(body, headers2)
	if err != ErrReplayAttack {
		t.Fatalf("expected ErrReplayAttack, got %v", err)
	}

	if len(threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(threats))
	}
	if threats[0].Type != "REPLAY" {
		t.Fatalf("expected REPLAY threat, got %s", threats[0].Type)
	}
}

// --- VerifyIncomingPassport ---

func TestVerifyIncomingPassportNoHeader(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:    "test",
		MinTrustLevel: TrustUnsigned, // L0 allowed
	})

	err := mw.VerifyIncomingPassport(http.Header{})
	if err != nil {
		t.Fatalf("L0 should allow missing passport: %v", err)
	}
}

func TestVerifyIncomingPassportRequiredButMissing(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:    "test",
		MinTrustLevel: TrustIdentified, // L1 required
	})

	err := mw.VerifyIncomingPassport(http.Header{})
	if err != ErrInsufficientTrust {
		t.Fatalf("expected ErrInsufficientTrust when passport required but missing, got %v", err)
	}
}

func TestVerifyIncomingPassportPresent(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:    "test",
		MinTrustLevel: TrustIdentified,
	})

	headers := http.Header{}
	headers.Set("X-MCPS-Passport-ID", "agent-123")

	err := mw.VerifyIncomingPassport(headers)
	if err != nil {
		t.Fatalf("passport present should pass L1 check: %v", err)
	}
}

// --- AgentSign Verification ---

func TestVerifyPassportViaAgentSign(t *testing.T) {
	// Mock AgentSign server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "valid-passport" {
			json.NewEncoder(w).Encode(agentSignResponse{
				Valid:      true,
				TrustLevel: TrustVerified,
				AgentID:    "agent-001",
				Issuer:     "agentsign.dev",
				ExpiresAt:  time.Now().Add(1 * time.Hour).Unix(),
			})
		} else if id == "low-trust" {
			json.NewEncoder(w).Encode(agentSignResponse{
				Valid:      true,
				TrustLevel: TrustIdentified, // L1 only
				AgentID:    "agent-002",
			})
		} else {
			json.NewEncoder(w).Encode(agentSignResponse{Valid: false})
		}
	}))
	defer server.Close()

	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:    "test",
		MinTrustLevel: TrustVerified, // L2 required
		AgentSignURL:  server.URL,
	})

	// Valid passport with sufficient trust
	headers := http.Header{}
	headers.Set("X-MCPS-Passport-ID", "valid-passport")
	err := mw.VerifyIncomingPassport(headers)
	if err != nil {
		t.Fatalf("valid L2 passport should pass: %v", err)
	}

	// Valid passport but insufficient trust
	headers2 := http.Header{}
	headers2.Set("X-MCPS-Passport-ID", "low-trust")
	err = mw.VerifyIncomingPassport(headers2)
	if err != ErrInsufficientTrust {
		t.Fatalf("expected ErrInsufficientTrust for L1 passport with L2 requirement, got %v", err)
	}

	// Invalid passport
	headers3 := http.Header{}
	headers3.Set("X-MCPS-Passport-ID", "invalid-passport")
	err = mw.VerifyIncomingPassport(headers3)
	if err != ErrInsufficientTrust {
		t.Fatalf("expected ErrInsufficientTrust for invalid passport, got %v", err)
	}
}

func TestVerifyPassportViaAgentSignServerDown(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:    "test",
		MinTrustLevel: TrustVerified,
		AgentSignURL:  "http://localhost:1", // unreachable
	})

	headers := http.Header{}
	headers.Set("X-MCPS-Passport-ID", "some-passport")
	err := mw.VerifyIncomingPassport(headers)
	if err != ErrInsufficientTrust {
		t.Fatalf("should fail when AgentSign is unreachable, got %v", err)
	}
}

// --- Stats ---

func TestStats(t *testing.T) {
	mw, _ := NewELIDAMiddleware(ELIDAConfig{
		PassportID:      "test-agent",
		SignRequests:    true,
		VerifyResponses: true,
		PinTools:        true,
	})

	stats := mw.Stats()
	if stats["mcps_version"] != Version {
		t.Fatalf("expected version %s, got %v", Version, stats["mcps_version"])
	}
	if stats["passport_id"] != "test-agent" {
		t.Fatalf("expected passport_id test-agent, got %v", stats["passport_id"])
	}
	if stats["signing_enabled"] != true {
		t.Fatal("signing should be enabled")
	}
	if stats["verify_enabled"] != true {
		t.Fatal("verify should be enabled")
	}
	if stats["pin_tools"] != true {
		t.Fatal("pin_tools should be enabled")
	}
}
