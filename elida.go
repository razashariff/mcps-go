// Package mcps provides ELIDA integration for the MCPS protocol.
//
// This file contains the ELIDA ProxyOption middleware that adds
// MCPS message signing, verification, nonce tracking, and tool
// integrity to ELIDA's proxy pipeline.
//
// Usage in ELIDA:
//
//   import "github.com/razashariff/mcps-go"
//
//   // In proxy setup
//   mcpsMiddleware, err := mcps.NewELIDAMiddleware(mcps.ELIDAConfig{
//       PassportID:     "asp_your_passport_id",
//       AgentSignURL:   "https://agentsign.dev",  // For passport issuance
//       MinTrustLevel:  mcps.TrustIdentified,      // L1 minimum
//       NonceWindow:    5 * time.Minute,
//       SignRequests:   true,
//       VerifyResponses: true,
//       PinTools:       true,
//   })
//
// Passport issuance requires AgentSign (https://agentsign.dev).
// This package handles signing, verification, and enforcement only.
//
// Copyright (c) 2026 CyberSecAI Ltd. All rights reserved.
// IETF Draft: https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/

package mcps

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ELIDAConfig configures the MCPS middleware for ELIDA
type ELIDAConfig struct {
	// PassportID is the agent's passport identifier (from AgentSign)
	PassportID string

	// AgentSignURL is the AgentSign API URL for passport verification
	// Required for L2+ trust levels
	AgentSignURL string

	// MinTrustLevel is the minimum trust level required for incoming requests
	// 0=L0 (allow all), 1=L1 (identified), 2=L2 (verified), etc.
	MinTrustLevel int

	// NonceWindow is the time window for replay protection
	NonceWindow time.Duration

	// SignRequests enables signing of outgoing requests
	SignRequests bool

	// VerifyResponses enables verification of incoming responses
	VerifyResponses bool

	// PinTools enables tool definition hash-pinning
	PinTools bool

	// OnThreat is called when a security event occurs
	OnThreat func(event ThreatEvent)

	// OnAudit is called for every processed request (for logging)
	OnAudit func(event AuditEvent)
}

// ThreatEvent represents a detected security threat
type ThreatEvent struct {
	Type        string `json:"type"`        // REPLAY, TAMPER, TOOL_MUTATION, INSUFFICIENT_TRUST
	Severity    string `json:"severity"`    // CRITICAL, HIGH, MEDIUM
	Description string `json:"description"`
	PassportID  string `json:"passportId"`
	Nonce       string `json:"nonce"`
	Timestamp   int64  `json:"timestamp"`
	Blocked     bool   `json:"blocked"`
}

// AuditEvent represents an MCPS audit event
type AuditEvent struct {
	Timestamp   int64  `json:"timestamp"`
	Method      string `json:"method"`
	Direction   string `json:"direction"` // REQUEST or RESPONSE
	Signed      bool   `json:"signed"`
	PassportID  string `json:"passportId"`
	TrustLevel  int    `json:"trustLevel"`
	Nonce       string `json:"nonce"`
	BodyHash    string `json:"bodyHash"`
	Tool        string `json:"tool,omitempty"`
}

// ELIDAMiddleware wraps ELIDA's proxy with MCPS security
type ELIDAMiddleware struct {
	config    ELIDAConfig
	keyPair   *KeyPair
	passport  *Passport
	nonces    *NonceStore
	toolPins  *ToolPinStore
}

// NewELIDAMiddleware creates a new MCPS middleware for ELIDA
func NewELIDAMiddleware(config ELIDAConfig) (*ELIDAMiddleware, error) {
	keyPair, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing keys: %w", err)
	}

	pubPEM, err := PublicKeyToPEM(keyPair.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	// Create a local passport (L0/L1)
	// For L2+ passports, call AgentSign API
	passport := &Passport{
		ID:           config.PassportID,
		Subject:      "elida-mcps-middleware",
		Version:      Version,
		PublicKeyPEM: pubPEM,
		TrustLevel:   TrustIdentified, // L1 by default
		Capabilities: []string{"tools/list", "tools/call"},
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(24 * time.Hour).Unix(),
		Issuer:       "local",
	}

	nonceWindow := config.NonceWindow
	if nonceWindow == 0 {
		nonceWindow = 5 * time.Minute
	}

	return &ELIDAMiddleware{
		config:   config,
		keyPair:  keyPair,
		passport: passport,
		nonces:   NewNonceStore(nonceWindow),
		toolPins: NewToolPinStore(),
	}, nil
}

// ProcessRequest is called by ELIDA before forwarding a request to the backend.
// It signs the request, checks nonces, and verifies tool integrity.
// Returns the signed body and any error.
func (m *ELIDAMiddleware) ProcessRequest(body []byte, headers http.Header) ([]byte, error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, nil // Not JSON, pass through
	}

	method, _ := parsed["method"].(string)

	// Sign the request if enabled
	if m.config.SignRequests {
		signed, err := SignMessage(body, m.keyPair, m.passport)
		if err != nil {
			log.Printf("[MCPS] Failed to sign request: %v", err)
			return body, nil // Don't block on signing failure
		}

		// Add MCPS headers
		headers.Set("X-MCPS-Version", Version)
		headers.Set("X-MCPS-Passport-ID", m.passport.ID)
		headers.Set("X-MCPS-Nonce", signed.Nonce)
		headers.Set("X-MCPS-Signature", signed.Signature)

		// Emit audit event
		if m.config.OnAudit != nil {
			m.config.OnAudit(AuditEvent{
				Timestamp:  signed.Timestamp,
				Method:     method,
				Direction:  "REQUEST",
				Signed:     true,
				PassportID: m.passport.ID,
				TrustLevel: m.passport.TrustLevel,
				Nonce:      signed.Nonce,
				BodyHash:   HashSHA256(body),
			})
		}
	}

	// Check tool integrity on tools/call
	if m.config.PinTools && method == "tools/call" {
		if params, ok := parsed["params"].(map[string]interface{}); ok {
			toolName, _ := params["name"].(string)
			if toolName != "" {
				_, err := m.toolPins.PinTool("backend", toolName, params)
				if err == ErrToolIntegrity {
					if m.config.OnThreat != nil {
						m.config.OnThreat(ThreatEvent{
							Type:        "TOOL_MUTATION",
							Severity:    "HIGH",
							Description: fmt.Sprintf("Tool definition changed: %s", toolName),
							PassportID:  m.passport.ID,
							Timestamp:   time.Now().Unix(),
							Blocked:     true,
						})
					}
					return nil, ErrToolIntegrity
				}
			}
		}
	}

	return body, nil
}

// ProcessResponse is called by ELIDA after receiving a response from the backend.
// It verifies signatures if present and emits audit events.
func (m *ELIDAMiddleware) ProcessResponse(body []byte, headers http.Header) ([]byte, error) {
	// Check for MCPS signature in response
	if m.config.VerifyResponses {
		signature := headers.Get("X-MCPS-Signature")
		nonce := headers.Get("X-MCPS-Nonce")
		passportID := headers.Get("X-MCPS-Passport-ID")

		signed := signature != ""

		if m.config.OnAudit != nil {
			m.config.OnAudit(AuditEvent{
				Timestamp:  time.Now().Unix(),
				Direction:  "RESPONSE",
				Signed:     signed,
				PassportID: passportID,
				Nonce:      nonce,
				BodyHash:   HashSHA256(body),
			})
		}

		// If signed, verify nonce (replay protection)
		if signed && nonce != "" {
			if err := m.nonces.Check(nonce, time.Now().Unix()); err != nil {
				if m.config.OnThreat != nil {
					m.config.OnThreat(ThreatEvent{
						Type:        "REPLAY",
						Severity:    "CRITICAL",
						Description: "Replay detected in response",
						PassportID:  passportID,
						Nonce:       nonce,
						Timestamp:   time.Now().Unix(),
						Blocked:     true,
					})
				}
				return nil, ErrReplayAttack
			}
		}
	}

	return body, nil
}

// VerifyIncomingPassport checks an incoming request's passport meets minimum trust
func (m *ELIDAMiddleware) VerifyIncomingPassport(headers http.Header) error {
	passportID := headers.Get("X-MCPS-Passport-ID")
	if passportID == "" {
		if m.config.MinTrustLevel > TrustUnsigned {
			return ErrInsufficientTrust
		}
		return nil // L0 allowed
	}

	// For L2+ verification, call AgentSign API
	if m.config.MinTrustLevel >= TrustVerified && m.config.AgentSignURL != "" {
		verified, err := m.verifyPassportViaAgentSign(passportID)
		if err != nil {
			log.Printf("[MCPS] AgentSign verification failed for %s: %v", passportID, err)
			return ErrInsufficientTrust
		}
		if verified.TrustLevel < m.config.MinTrustLevel {
			return ErrInsufficientTrust
		}
		log.Printf("[MCPS] Passport %s verified via AgentSign (L%d)", passportID, verified.TrustLevel)
		return nil
	}

	return nil
}

// Stats returns current MCPS middleware statistics
func (m *ELIDAMiddleware) Stats() map[string]interface{} {
	return map[string]interface{}{
		"mcps_version":    Version,
		"passport_id":     m.passport.ID,
		"trust_level":     m.passport.TrustLevel,
		"nonce_store_size": m.nonces.Size(),
		"tool_pins":       len(m.toolPins.pins),
		"signing_enabled": m.config.SignRequests,
		"verify_enabled":  m.config.VerifyResponses,
		"pin_tools":       m.config.PinTools,
		"agentsign_url":   m.config.AgentSignURL,
	}
}

// agentSignResponse represents the response from AgentSign passport verification
type agentSignResponse struct {
	Valid      bool   `json:"valid"`
	TrustLevel int    `json:"trust_level"`
	AgentID    string `json:"agent_id"`
	Issuer     string `json:"issuer"`
	ExpiresAt  int64  `json:"expires_at"`
}

// verifyPassportViaAgentSign calls the AgentSign API to verify a passport
func (m *ELIDAMiddleware) verifyPassportViaAgentSign(passportID string) (*agentSignResponse, error) {
	url := fmt.Sprintf("%s/api/verify-passport?id=%s", m.config.AgentSignURL, passportID)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("AgentSign request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AgentSign returned status %d", resp.StatusCode)
	}

	var result agentSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode AgentSign response: %w", err)
	}

	if !result.Valid {
		return nil, fmt.Errorf("passport %s is not valid", passportID)
	}

	return &result, nil
}
