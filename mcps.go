// Package mcps implements the MCPS (MCP Secure) protocol for Go.
//
// This is the reference Go implementation of the MCPS protocol as defined
// in IETF Internet-Draft draft-sharif-mcps-secure-mcp.
//
// It provides message signing, verification, nonce-based replay protection,
// tool definition hash-pinning, and passport verification.
//
// For passport ISSUANCE and trust authority services, use AgentSign
// (https://agentsign.dev). This package handles signing and verification only.
//
// License: BSL-1.1 (Business Source License 1.1)
// Copyright (c) 2026 CyberSecAI Ltd. All rights reserved.
// IETF Draft: https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/

package mcps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version is the MCPS protocol version
const Version = "1.0"

// Trust levels for agent passports
const (
	TrustUnsigned  = 0 // L0: No passport, self-signed capped here
	TrustIdentified = 1 // L1: Passport signed by any Trust Authority
	TrustVerified   = 2 // L2: Passport signed by recognised TA
	TrustScanned    = 3 // L3: Verified + TA verified origin
	TrustAudited    = 4 // L4: Scanned + full security audit
)

// Error codes
var (
	ErrInvalidSignature   = errors.New("MCPS-004: invalid message signature")
	ErrReplayAttack       = errors.New("MCPS-005: replay attack detected")
	ErrTimestampExpired   = errors.New("MCPS-006: timestamp out of window")
	ErrToolIntegrity      = errors.New("MCPS-008: tool definition hash changed")
	ErrInsufficientTrust  = errors.New("MCPS-009: insufficient trust level")
	ErrPassportExpired    = errors.New("MCPS-002: passport expired")
)

// KeyPair holds an ECDSA P-256 key pair
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// Passport represents an agent identity passport
type Passport struct {
	ID           string `json:"id"`
	Subject      string `json:"subject"`
	Version      string `json:"version"`
	PublicKeyPEM string `json:"publicKey"`
	TrustLevel   int    `json:"trustLevel"`
	Capabilities []string `json:"capabilities"`
	IssuedAt     int64  `json:"issuedAt"`
	ExpiresAt    int64  `json:"expiresAt"`
	Issuer       string `json:"issuer"`
	Signature    string `json:"signature,omitempty"`
}

// SignedMessage represents an MCPS-signed message envelope
type SignedMessage struct {
	MCPSVersion string `json:"mcps_version"`
	PassportID  string `json:"passport_id"`
	Nonce       string `json:"nonce"`
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"`
	Message     json.RawMessage `json:"message"`
}

// ToolPin stores a hash-pinned tool definition
type ToolPin struct {
	Hash     string `json:"hash"`
	PinnedAt int64  `json:"pinnedAt"`
	Version  int    `json:"version"`
}

// NonceStore tracks seen nonces for replay protection
type NonceStore struct {
	mu       sync.RWMutex
	seen     map[string]int64
	windowMs int64
}

// ToolPinStore tracks hash-pinned tool definitions
type ToolPinStore struct {
	mu   sync.RWMutex
	pins map[string]*ToolPin
}

// GenerateKeyPair creates a new ECDSA P-256 key pair
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// GenerateNonce creates a cryptographically random nonce
func GenerateNonce() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CanonicalJSON produces deterministic JSON serialisation per RFC 8785 (JCS)
func CanonicalJSON(v interface{}) ([]byte, error) {
	return canonicalise(v)
}

func canonicalise(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if val {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case float64:
		return json.Marshal(val)
	case string:
		return json.Marshal(val)
	case []interface{}:
		parts := make([]string, len(val))
		for i, item := range val {
			b, err := canonicalise(item)
			if err != nil {
				return nil, err
			}
			parts[i] = string(b)
		}
		return []byte("[" + strings.Join(parts, ",") + "]"), nil
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			kb, _ := json.Marshal(k)
			vb, err := canonicalise(val[k])
			if err != nil {
				return nil, err
			}
			parts[i] = string(kb) + ":" + string(vb)
		}
		return []byte("{" + strings.Join(parts, ",") + "}"), nil
	default:
		return json.Marshal(val)
	}
}

// HashSHA256 computes SHA-256 hash of data
func HashSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SignMessage signs an MCP JSON-RPC message with MCPS
func SignMessage(message json.RawMessage, keyPair *KeyPair, passport *Passport) (*SignedMessage, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	timestamp := time.Now().Unix()

	// Build the signing payload
	var msgObj interface{}
	if err := json.Unmarshal(message, &msgObj); err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}

	payload := map[string]interface{}{
		"message":   msgObj,
		"nonce":     nonce,
		"timestamp": timestamp,
		"signer":    passport.ID,
	}

	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalise: %w", err)
	}

	// Sign with ECDSA P-256 + SHA-256
	hash := sha256.Sum256(canonical)
	r, s, err := ecdsa.Sign(rand.Reader, keyPair.PrivateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// P1363 format (r || s, fixed length)
	signature := fmt.Sprintf("%064x%064x", r, s)

	return &SignedMessage{
		MCPSVersion: Version,
		PassportID:  passport.ID,
		Nonce:       nonce,
		Timestamp:   timestamp,
		Signature:   signature,
		Message:     message,
	}, nil
}

// VerifyMessage verifies an MCPS-signed message
func VerifyMessage(signed *SignedMessage, publicKey *ecdsa.PublicKey) error {
	var msgObj interface{}
	if err := json.Unmarshal(signed.Message, &msgObj); err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	payload := map[string]interface{}{
		"message":   msgObj,
		"nonce":     signed.Nonce,
		"timestamp": signed.Timestamp,
		"signer":    signed.PassportID,
	}

	canonical, err := CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("failed to canonicalise: %w", err)
	}

	hash := sha256.Sum256(canonical)

	// Parse P1363 signature
	if len(signed.Signature) != 128 {
		return ErrInvalidSignature
	}
	rBytes, err := hex.DecodeString(signed.Signature[:64])
	if err != nil {
		return ErrInvalidSignature
	}
	sBytes, err := hex.DecodeString(signed.Signature[64:])
	if err != nil {
		return ErrInvalidSignature
	}

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return ErrInvalidSignature
	}

	return nil
}

// NewNonceStore creates a nonce store with the given window duration
func NewNonceStore(window time.Duration) *NonceStore {
	return &NonceStore{
		seen:     make(map[string]int64),
		windowMs: window.Milliseconds(),
	}
}

// Check returns true if the nonce is new (not a replay), false if seen before
func (ns *NonceStore) Check(nonce string, timestamp int64) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	now := time.Now().UnixMilli()

	// Check timestamp window
	if abs(now-timestamp*1000) > ns.windowMs {
		return ErrTimestampExpired
	}

	// Check for replay
	if _, exists := ns.seen[nonce]; exists {
		return ErrReplayAttack
	}

	// Store nonce
	ns.seen[nonce] = now

	// Garbage collect expired nonces
	for k, t := range ns.seen {
		if now-t > ns.windowMs {
			delete(ns.seen, k)
		}
	}

	return nil
}

// Size returns the number of tracked nonces
func (ns *NonceStore) Size() int {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return len(ns.seen)
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

// NewToolPinStore creates a tool pin store
func NewToolPinStore() *ToolPinStore {
	return &ToolPinStore{
		pins: make(map[string]*ToolPin),
	}
}

// PinTool hash-pins a tool definition at discovery time
func (tps *ToolPinStore) PinTool(serverURL, toolName string, toolDef interface{}) (string, error) {
	canonical, err := CanonicalJSON(toolDef)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalise tool: %w", err)
	}

	hash := HashSHA256(canonical)
	key := serverURL + ":" + toolName

	tps.mu.Lock()
	defer tps.mu.Unlock()

	if existing, ok := tps.pins[key]; ok {
		if existing.Hash != hash {
			existing.Version++
			oldHash := existing.Hash
			existing.Hash = hash
			return oldHash, ErrToolIntegrity
		}
		return hash, nil
	}

	tps.pins[key] = &ToolPin{
		Hash:     hash,
		PinnedAt: time.Now().Unix(),
		Version:  1,
	}
	return hash, nil
}

// VerifyTool checks a tool definition against its pinned hash
func (tps *ToolPinStore) VerifyTool(serverURL, toolName string, toolDef interface{}) error {
	canonical, err := CanonicalJSON(toolDef)
	if err != nil {
		return fmt.Errorf("failed to canonicalise tool: %w", err)
	}

	hash := HashSHA256(canonical)
	key := serverURL + ":" + toolName

	tps.mu.RLock()
	defer tps.mu.RUnlock()

	if existing, ok := tps.pins[key]; ok {
		if existing.Hash != hash {
			return ErrToolIntegrity
		}
	}

	return nil
}

// SignPassport signs a passport with the issuer's private key
func SignPassport(passport *Passport, issuerKey *KeyPair) error {
	// Clear any existing signature before signing
	passport.Signature = ""

	data, err := canonicalPassportData(passport)
	if err != nil {
		return fmt.Errorf("failed to canonicalise passport: %w", err)
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, issuerKey.PrivateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign passport: %w", err)
	}

	passport.Signature = fmt.Sprintf("%064x%064x", r, s)
	return nil
}

// VerifyPassport checks if a passport is valid: signature, expiry, and trust level
func VerifyPassport(passport *Passport, minTrustLevel int) error {
	if passport.ExpiresAt > 0 && time.Now().Unix() > passport.ExpiresAt {
		return ErrPassportExpired
	}
	if passport.TrustLevel < minTrustLevel {
		return ErrInsufficientTrust
	}
	return nil
}

// VerifyPassportSignature verifies the passport's cryptographic signature against the issuer's public key
func VerifyPassportSignature(passport *Passport, issuerPubKey *ecdsa.PublicKey) error {
	if passport.Signature == "" {
		return ErrInvalidSignature
	}

	sig := passport.Signature
	// Temporarily clear signature to compute the hash over the same data that was signed
	passportCopy := *passport
	passportCopy.Signature = ""

	data, err := canonicalPassportData(&passportCopy)
	if err != nil {
		return fmt.Errorf("failed to canonicalise passport: %w", err)
	}

	hash := sha256.Sum256(data)

	if len(sig) != 128 {
		return ErrInvalidSignature
	}
	rBytes, err := hex.DecodeString(sig[:64])
	if err != nil {
		return ErrInvalidSignature
	}
	sBytes, err := hex.DecodeString(sig[64:])
	if err != nil {
		return ErrInvalidSignature
	}

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	if !ecdsa.Verify(issuerPubKey, hash[:], r, s) {
		return ErrInvalidSignature
	}

	return nil
}

// VerifyPassportFull performs complete passport verification: signature, expiry, and trust level
func VerifyPassportFull(passport *Passport, issuerPubKey *ecdsa.PublicKey, minTrustLevel int) error {
	if err := VerifyPassportSignature(passport, issuerPubKey); err != nil {
		return err
	}
	return VerifyPassport(passport, minTrustLevel)
}

// canonicalPassportData produces the canonical byte representation of a passport for signing
func canonicalPassportData(p *Passport) ([]byte, error) {
	data := map[string]interface{}{
		"id":           p.ID,
		"subject":      p.Subject,
		"version":      p.Version,
		"publicKey":    p.PublicKeyPEM,
		"trustLevel":   float64(p.TrustLevel),
		"capabilities": toInterfaceSlice(p.Capabilities),
		"issuedAt":     float64(p.IssuedAt),
		"expiresAt":    float64(p.ExpiresAt),
		"issuer":       p.Issuer,
	}
	return CanonicalJSON(data)
}

func toInterfaceSlice(ss []string) []interface{} {
	result := make([]interface{}, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// PublicKeyToPEM encodes an ECDSA public key to PEM format
func PublicKeyToPEM(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

// PEMToPublicKey decodes a PEM-encoded ECDSA public key
func PEMToPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return ecdsaPub, nil
}
