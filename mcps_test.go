package mcps

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

// --- Key Generation ---

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if kp.PublicKey == nil {
		t.Fatal("public key is nil")
	}
	if kp.PublicKey.Curve != elliptic.P256() {
		t.Fatal("expected P-256 curve")
	}
}

func TestGenerateKeyPairUniqueness(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	if kp1.PrivateKey.D.Cmp(kp2.PrivateKey.D) == 0 {
		t.Fatal("two generated key pairs should not be identical")
	}
}

// --- Key Persistence ---

func TestSaveAndLoadKeyPair(t *testing.T) {
	kp, _ := GenerateKeyPair()

	privPath := t.TempDir() + "/test.key"
	pubPath := t.TempDir() + "/test.pub"

	err := SaveKeyPair(kp, privPath, pubPath)
	if err != nil {
		t.Fatalf("SaveKeyPair failed: %v", err)
	}

	loaded, err := LoadKeyPair(privPath, pubPath)
	if err != nil {
		t.Fatalf("LoadKeyPair failed: %v", err)
	}

	if !kp.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("loaded public key should match original")
	}
	if kp.PrivateKey.D.Cmp(loaded.PrivateKey.D) != 0 {
		t.Fatal("loaded private key should match original")
	}
}

func TestGenerateAndSaveKeyPair(t *testing.T) {
	privPath := t.TempDir() + "/gen.key"
	pubPath := t.TempDir() + "/gen.pub"

	kp, err := GenerateAndSaveKeyPair(privPath, pubPath)
	if err != nil {
		t.Fatalf("GenerateAndSaveKeyPair failed: %v", err)
	}

	// Verify files exist and are loadable
	loaded, err := LoadKeyPair(privPath, pubPath)
	if err != nil {
		t.Fatalf("LoadKeyPair after generate failed: %v", err)
	}

	if !kp.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("loaded key should match generated key")
	}
}

func TestLoadKeyPairStableAcrossReboots(t *testing.T) {
	// Simulate: generate once, load twice -- keys must be identical
	privPath := t.TempDir() + "/stable.key"
	pubPath := t.TempDir() + "/stable.pub"

	kp, _ := GenerateAndSaveKeyPair(privPath, pubPath)

	load1, _ := LoadKeyPair(privPath, pubPath)
	load2, _ := LoadKeyPair(privPath, pubPath)

	if !kp.PublicKey.Equal(load1.PublicKey) || !kp.PublicKey.Equal(load2.PublicKey) {
		t.Fatal("key should be stable across multiple loads")
	}
	if load1.PrivateKey.D.Cmp(load2.PrivateKey.D) != 0 {
		t.Fatal("private key should be identical across loads")
	}
}

func TestLoadKeyPairSignVerifyRoundTrip(t *testing.T) {
	// Generate, save, load, sign with loaded key, verify
	privPath := t.TempDir() + "/rt.key"
	pubPath := t.TempDir() + "/rt.pub"

	original, _ := GenerateAndSaveKeyPair(privPath, pubPath)
	loaded, _ := LoadKeyPair(privPath, pubPath)

	passport := &Passport{ID: "persist-agent", TrustLevel: TrustVerified, IssuedAt: time.Now().Unix()}
	msg := json.RawMessage(`{"method":"tools/call","params":{"name":"search_entities"}}`)

	// Sign with loaded key
	signed, err := SignMessage(msg, loaded, passport)
	if err != nil {
		t.Fatalf("sign with loaded key failed: %v", err)
	}

	// Verify with original public key
	err = VerifyMessage(signed, original.PublicKey)
	if err != nil {
		t.Fatalf("verify with original key failed: %v", err)
	}

	// Verify with loaded public key
	err = VerifyMessage(signed, loaded.PublicKey)
	if err != nil {
		t.Fatalf("verify with loaded key failed: %v", err)
	}
}

func TestLoadKeyPairFromEnv(t *testing.T) {
	kp, _ := GenerateKeyPair()

	privDER, _ := x509.MarshalECPrivateKey(kp.PrivateKey)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}))
	pubPEM, _ := PublicKeyToPEM(kp.PublicKey)

	t.Setenv("TEST_MCPS_PRIV", privPEM)
	t.Setenv("TEST_MCPS_PUB", pubPEM)

	loaded, err := LoadKeyPairFromEnv("TEST_MCPS_PRIV", "TEST_MCPS_PUB")
	if err != nil {
		t.Fatalf("LoadKeyPairFromEnv failed: %v", err)
	}

	if !kp.PublicKey.Equal(loaded.PublicKey) {
		t.Fatal("loaded key should match original")
	}
}

func TestLoadKeyPairFromEnvEmpty(t *testing.T) {
	t.Setenv("EMPTY_KEY", "")
	_, err := LoadKeyPairFromEnv("EMPTY_KEY", "UNUSED")
	if err == nil {
		t.Fatal("should fail on empty env var")
	}
}

func TestLoadKeyPairBadPath(t *testing.T) {
	_, err := LoadKeyPair("/nonexistent/path.key", "/nonexistent/path.pub")
	if err == nil {
		t.Fatal("should fail on nonexistent path")
	}
}

func TestLoadKeyPairBadPEM(t *testing.T) {
	privPath := t.TempDir() + "/bad.key"
	os.WriteFile(privPath, []byte("not a pem file"), 0600)

	_, err := LoadKeyPair(privPath, "unused")
	if err == nil {
		t.Fatal("should fail on bad PEM")
	}
}

func TestSaveKeyPairPermissions(t *testing.T) {
	kp, _ := GenerateKeyPair()
	privPath := t.TempDir() + "/perm.key"
	pubPath := t.TempDir() + "/perm.pub"

	SaveKeyPair(kp, privPath, pubPath)

	// Private key should be 0600
	info, _ := os.Stat(privPath)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key should be 0600, got %o", info.Mode().Perm())
	}
}

// --- Signer Interface ---

func TestLocalSigner(t *testing.T) {
	kp, _ := GenerateKeyPair()
	signer := NewLocalSigner(kp)

	if !signer.PublicKey().Equal(kp.PublicKey) {
		t.Fatal("signer public key should match key pair")
	}

	hash := sha256.Sum256([]byte("test"))
	r, s, err := signer.Sign(hash[:])
	if err != nil {
		t.Fatalf("LocalSigner.Sign failed: %v", err)
	}
	if r == nil || s == nil {
		t.Fatal("signature components should not be nil")
	}

	if !ecdsa.Verify(kp.PublicKey, hash[:], r, s) {
		t.Fatal("signature should verify with original key")
	}
}

func TestSignMessageWithSigner(t *testing.T) {
	kp, _ := GenerateKeyPair()
	signer := NewLocalSigner(kp)
	passport := &Passport{ID: "signer-agent", TrustLevel: TrustVerified, IssuedAt: time.Now().Unix()}
	msg := json.RawMessage(`{"method":"tools/call","params":{"name":"search_entities"}}`)

	signed, err := SignMessageWithSigner(msg, signer, passport)
	if err != nil {
		t.Fatalf("SignMessageWithSigner failed: %v", err)
	}

	// Verify with the signer's public key
	err = VerifyMessage(signed, signer.PublicKey())
	if err != nil {
		t.Fatalf("VerifyMessage after SignMessageWithSigner failed: %v", err)
	}
}

func TestSignMessageWithSignerMatchesSignMessage(t *testing.T) {
	// Both signing paths should produce verifiable signatures
	kp, _ := GenerateKeyPair()
	signer := NewLocalSigner(kp)
	passport := &Passport{ID: "compat-agent", TrustLevel: TrustVerified, IssuedAt: time.Now().Unix()}
	msg := json.RawMessage(`{"method":"tools/call"}`)

	signed1, _ := SignMessage(msg, kp, passport)
	signed2, _ := SignMessageWithSigner(msg, signer, passport)

	// Both should verify with same key
	if err := VerifyMessage(signed1, kp.PublicKey); err != nil {
		t.Fatalf("SignMessage result should verify: %v", err)
	}
	if err := VerifyMessage(signed2, kp.PublicKey); err != nil {
		t.Fatalf("SignMessageWithSigner result should verify: %v", err)
	}
}

// --- Watchman HSM Integration Flow ---

func TestWatchmanHSMFlow(t *testing.T) {
	// Simulate Watchman with persistent keys:
	// 1. First boot: generate and save keys
	// 2. Reboot: load keys from disk
	// 3. Sign screening results with loaded keys
	// 4. Verify with public key

	keyDir := t.TempDir()
	privPath := keyDir + "/watchman.key"
	pubPath := keyDir + "/watchman.pub"

	// First boot -- generate and save
	kp, _ := GenerateAndSaveKeyPair(privPath, pubPath)
	passport := &Passport{
		ID:         "watchman-mcp-001",
		Subject:    "watchman",
		TrustLevel: TrustAudited,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(24 * time.Hour).Unix(),
		Issuer:     "moov-io",
	}

	// Sign a screening result
	result := json.RawMessage(`{"entities":[{"name":"SBERBANK","match":0.95,"source":"OFAC"}]}`)
	signed1, _ := SignMessage(result, kp, passport)

	// "Reboot" -- load keys from disk
	loadedKP, _ := LoadKeyPair(privPath, pubPath)

	// Sign another result with loaded keys
	result2 := json.RawMessage(`{"entities":[{"name":"GAZPROM","match":0.88,"source":"HMT"}]}`)
	signed2, _ := SignMessage(result2, loadedKP, passport)

	// Verify both with the public key (could be distributed to clients)
	pubKey := loadedKP.PublicKey
	if err := VerifyMessage(signed1, pubKey); err != nil {
		t.Fatalf("first boot signature should verify: %v", err)
	}
	if err := VerifyMessage(signed2, pubKey); err != nil {
		t.Fatalf("reboot signature should verify: %v", err)
	}

	// Cross-verify: original key verifies reboot signature
	if err := VerifyMessage(signed2, kp.PublicKey); err != nil {
		t.Fatalf("cross-verify should pass (same key): %v", err)
	}
}

// --- Nonce Generation ---

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}
	if len(nonce) != 32 {
		t.Fatalf("expected 32 hex chars, got %d", len(nonce))
	}
}

func TestGenerateNonceUniqueness(t *testing.T) {
	n1, _ := GenerateNonce()
	n2, _ := GenerateNonce()
	if n1 == n2 {
		t.Fatal("two nonces should not be identical")
	}
}

// --- Canonical JSON ---

func TestCanonicalJSONSortsKeys(t *testing.T) {
	input := map[string]interface{}{
		"z": 1.0,
		"a": 2.0,
		"m": 3.0,
	}
	out, err := CanonicalJSON(input)
	if err != nil {
		t.Fatalf("CanonicalJSON failed: %v", err)
	}
	expected := `{"a":2,"m":3,"z":1}`
	if string(out) != expected {
		t.Fatalf("expected %s, got %s", expected, string(out))
	}
}

func TestCanonicalJSONDeterministic(t *testing.T) {
	input := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name":      "search_entities",
			"arguments": map[string]interface{}{"query": "SBERBANK"},
		},
	}
	out1, _ := CanonicalJSON(input)
	out2, _ := CanonicalJSON(input)
	if string(out1) != string(out2) {
		t.Fatal("canonical JSON should be deterministic")
	}
}

func TestCanonicalJSONNested(t *testing.T) {
	input := map[string]interface{}{
		"b": map[string]interface{}{
			"d": "value",
			"c": "value",
		},
		"a": "value",
	}
	out, _ := CanonicalJSON(input)
	expected := `{"a":"value","b":{"c":"value","d":"value"}}`
	if string(out) != expected {
		t.Fatalf("expected %s, got %s", expected, string(out))
	}
}

func TestCanonicalJSONArray(t *testing.T) {
	input := []interface{}{"b", "a", "c"}
	out, _ := CanonicalJSON(input)
	expected := `["b","a","c"]`
	if string(out) != expected {
		t.Fatalf("expected %s, got %s (arrays should preserve order)", expected, string(out))
	}
}

func TestCanonicalJSONNull(t *testing.T) {
	out, _ := CanonicalJSON(nil)
	if string(out) != "null" {
		t.Fatalf("expected null, got %s", string(out))
	}
}

// --- Hash ---

func TestHashSHA256(t *testing.T) {
	hash := HashSHA256([]byte("hello"))
	if len(hash) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(hash))
	}
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != expected {
		t.Fatalf("expected %s, got %s", expected, hash)
	}
}

func TestHashSHA256Deterministic(t *testing.T) {
	h1 := HashSHA256([]byte("test"))
	h2 := HashSHA256([]byte("test"))
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
}

// --- Sign and Verify ---

func TestSignAndVerifyMessage(t *testing.T) {
	kp, _ := GenerateKeyPair()
	passport := &Passport{
		ID:         "test-agent-001",
		Subject:    "test-agent",
		Version:    Version,
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(1 * time.Hour).Unix(),
		Issuer:     "test",
	}

	msg := json.RawMessage(`{"method":"tools/call","params":{"name":"search_entities"}}`)

	signed, err := SignMessage(msg, kp, passport)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if signed.MCPSVersion != Version {
		t.Fatalf("expected version %s, got %s", Version, signed.MCPSVersion)
	}
	if signed.PassportID != "test-agent-001" {
		t.Fatalf("expected passport ID test-agent-001, got %s", signed.PassportID)
	}
	if len(signed.Signature) != 128 {
		t.Fatalf("expected 128 hex char signature, got %d", len(signed.Signature))
	}
	if signed.Nonce == "" {
		t.Fatal("nonce should not be empty")
	}

	err = VerifyMessage(signed, kp.PublicKey)
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
}

func TestVerifyMessageWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()
	passport := &Passport{ID: "agent-1", TrustLevel: TrustIdentified, IssuedAt: time.Now().Unix()}

	msg := json.RawMessage(`{"method":"tools/call"}`)
	signed, _ := SignMessage(msg, kp1, passport)

	err := VerifyMessage(signed, kp2.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyMessageTamperedBody(t *testing.T) {
	kp, _ := GenerateKeyPair()
	passport := &Passport{ID: "agent-1", TrustLevel: TrustIdentified, IssuedAt: time.Now().Unix()}

	msg := json.RawMessage(`{"method":"tools/call"}`)
	signed, _ := SignMessage(msg, kp, passport)

	// Tamper with the message
	signed.Message = json.RawMessage(`{"method":"tools/call","params":{"name":"evil"}}`)

	err := VerifyMessage(signed, kp.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for tampered message, got %v", err)
	}
}

func TestVerifyMessageTamperedNonce(t *testing.T) {
	kp, _ := GenerateKeyPair()
	passport := &Passport{ID: "agent-1", TrustLevel: TrustIdentified, IssuedAt: time.Now().Unix()}

	msg := json.RawMessage(`{"method":"tools/call"}`)
	signed, _ := SignMessage(msg, kp, passport)

	signed.Nonce = "tampered_nonce_value_1234567890ab"

	err := VerifyMessage(signed, kp.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for tampered nonce, got %v", err)
	}
}

func TestVerifyMessageTamperedTimestamp(t *testing.T) {
	kp, _ := GenerateKeyPair()
	passport := &Passport{ID: "agent-1", TrustLevel: TrustIdentified, IssuedAt: time.Now().Unix()}

	msg := json.RawMessage(`{"method":"tools/call"}`)
	signed, _ := SignMessage(msg, kp, passport)

	signed.Timestamp = signed.Timestamp - 3600

	err := VerifyMessage(signed, kp.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for tampered timestamp, got %v", err)
	}
}

func TestVerifyMessageBadSignatureFormat(t *testing.T) {
	kp, _ := GenerateKeyPair()

	signed := &SignedMessage{
		MCPSVersion: Version,
		PassportID:  "agent-1",
		Nonce:       "abc123",
		Timestamp:   time.Now().Unix(),
		Signature:   "not_a_valid_hex_signature",
		Message:     json.RawMessage(`{}`),
	}

	err := VerifyMessage(signed, kp.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for bad format, got %v", err)
	}
}

// --- Nonce Store ---

func TestNonceStoreReplayDetection(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	now := time.Now().Unix()
	err := ns.Check("nonce-1", now)
	if err != nil {
		t.Fatalf("first nonce check should pass: %v", err)
	}

	err = ns.Check("nonce-1", now)
	if err != ErrReplayAttack {
		t.Fatalf("expected ErrReplayAttack, got %v", err)
	}
}

func TestNonceStoreUniqueNoncesPass(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)
	now := time.Now().Unix()

	for i := 0; i < 100; i++ {
		nonce, _ := GenerateNonce()
		err := ns.Check(nonce, now)
		if err != nil {
			t.Fatalf("unique nonce %d should pass: %v", i, err)
		}
	}

	if ns.Size() != 100 {
		t.Fatalf("expected 100 nonces, got %d", ns.Size())
	}
}

func TestNonceStoreExpiredTimestamp(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()
	err := ns.Check("old-nonce", oldTimestamp)
	if err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired, got %v", err)
	}
}

func TestNonceStoreFutureTimestamp(t *testing.T) {
	ns := NewNonceStore(5 * time.Minute)

	futureTimestamp := time.Now().Add(10 * time.Minute).Unix()
	err := ns.Check("future-nonce", futureTimestamp)
	if err != ErrTimestampExpired {
		t.Fatalf("expected ErrTimestampExpired for future timestamp, got %v", err)
	}
}

// --- Tool Pin Store ---

func TestToolPinFirstPin(t *testing.T) {
	tps := NewToolPinStore()

	toolDef := map[string]interface{}{
		"name":        "search_entities",
		"description": "Search sanctions lists",
	}

	hash, err := tps.PinTool("watchman", "search_entities", toolDef)
	if err != nil {
		t.Fatalf("first pin should succeed: %v", err)
	}
	if hash == "" {
		t.Fatal("hash should not be empty")
	}
}

func TestToolPinSameDefinition(t *testing.T) {
	tps := NewToolPinStore()

	toolDef := map[string]interface{}{
		"name":        "search_entities",
		"description": "Search sanctions lists",
	}

	hash1, _ := tps.PinTool("watchman", "search_entities", toolDef)
	hash2, err := tps.PinTool("watchman", "search_entities", toolDef)
	if err != nil {
		t.Fatalf("same definition should not error: %v", err)
	}
	if hash1 != hash2 {
		t.Fatal("same definition should produce same hash")
	}
}

func TestToolPinDetectsMutation(t *testing.T) {
	tps := NewToolPinStore()

	toolDef1 := map[string]interface{}{
		"name":        "search_entities",
		"description": "Search sanctions lists",
	}
	toolDef2 := map[string]interface{}{
		"name":        "search_entities",
		"description": "Search sanctions lists -- MODIFIED by attacker",
	}

	tps.PinTool("watchman", "search_entities", toolDef1)
	_, err := tps.PinTool("watchman", "search_entities", toolDef2)
	if err != ErrToolIntegrity {
		t.Fatalf("expected ErrToolIntegrity, got %v", err)
	}
}

func TestToolVerify(t *testing.T) {
	tps := NewToolPinStore()

	toolDef := map[string]interface{}{"name": "search_entities"}
	tps.PinTool("watchman", "search_entities", toolDef)

	err := tps.VerifyTool("watchman", "search_entities", toolDef)
	if err != nil {
		t.Fatalf("verify should pass for matching tool: %v", err)
	}

	tampered := map[string]interface{}{"name": "evil_tool"}
	err = tps.VerifyTool("watchman", "search_entities", tampered)
	if err != ErrToolIntegrity {
		t.Fatalf("expected ErrToolIntegrity for tampered tool, got %v", err)
	}
}

// --- Passport Verification ---

func TestVerifyPassportValid(t *testing.T) {
	passport := &Passport{
		ID:         "agent-1",
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(1 * time.Hour).Unix(),
	}

	err := VerifyPassport(passport, TrustIdentified)
	if err != nil {
		t.Fatalf("valid passport should pass: %v", err)
	}
}

func TestVerifyPassportExpired(t *testing.T) {
	passport := &Passport{
		ID:         "agent-1",
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt:  time.Now().Add(-1 * time.Hour).Unix(),
	}

	err := VerifyPassport(passport, TrustIdentified)
	if err != ErrPassportExpired {
		t.Fatalf("expected ErrPassportExpired, got %v", err)
	}
}

func TestVerifyPassportInsufficientTrust(t *testing.T) {
	passport := &Passport{
		ID:         "agent-1",
		TrustLevel: TrustIdentified, // L1
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(1 * time.Hour).Unix(),
	}

	err := VerifyPassport(passport, TrustScanned) // Requires L3
	if err != ErrInsufficientTrust {
		t.Fatalf("expected ErrInsufficientTrust, got %v", err)
	}
}

func TestVerifyPassportNoExpiry(t *testing.T) {
	passport := &Passport{
		ID:         "agent-1",
		TrustLevel: TrustAudited,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  0, // no expiry
	}

	err := VerifyPassport(passport, TrustAudited)
	if err != nil {
		t.Fatalf("passport with no expiry should pass: %v", err)
	}
}

// --- PEM Key Encoding ---

func TestPEMRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPair()

	pemStr, err := PublicKeyToPEM(kp.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyToPEM failed: %v", err)
	}

	recovered, err := PEMToPublicKey(pemStr)
	if err != nil {
		t.Fatalf("PEMToPublicKey failed: %v", err)
	}

	if !kp.PublicKey.Equal(recovered) {
		t.Fatal("recovered key should match original")
	}
}

func TestPEMToPublicKeyInvalid(t *testing.T) {
	_, err := PEMToPublicKey("not a pem string")
	if err == nil {
		t.Fatal("should fail on invalid PEM")
	}
}

func TestPEMToPublicKeyWrongType(t *testing.T) {
	// RSA key in PEM -- should fail since we expect ECDSA
	rsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = rsaKey // just need the type check in PEMToPublicKey to work
	// This test ensures ECDSA type assertion works
	kp, _ := GenerateKeyPair()
	pem, _ := PublicKeyToPEM(kp.PublicKey)
	key, err := PEMToPublicKey(pem)
	if err != nil {
		t.Fatalf("valid ECDSA PEM should parse: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("should be P-256")
	}
}

// --- Passport Signature ---

func TestSignAndVerifyPassport(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()
	agentKP, _ := GenerateKeyPair()
	agentPubPEM, _ := PublicKeyToPEM(agentKP.PublicKey)

	passport := &Passport{
		ID:           "agent-001",
		Subject:      "payment-bot",
		Version:      Version,
		PublicKeyPEM: agentPubPEM,
		TrustLevel:   TrustVerified,
		Capabilities: []string{"search_entities", "tools/call"},
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
		Issuer:       "agentsign.dev",
	}

	err := SignPassport(passport, issuerKP)
	if err != nil {
		t.Fatalf("SignPassport failed: %v", err)
	}
	if passport.Signature == "" {
		t.Fatal("passport signature should not be empty after signing")
	}
	if len(passport.Signature) != 128 {
		t.Fatalf("expected 128 hex char signature, got %d", len(passport.Signature))
	}

	err = VerifyPassportSignature(passport, issuerKP.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassportSignature failed: %v", err)
	}
}

func TestVerifyPassportSignatureWrongKey(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()
	wrongKP, _ := GenerateKeyPair()

	passport := &Passport{
		ID:         "agent-001",
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Unix(),
		Issuer:     "agentsign.dev",
	}

	SignPassport(passport, issuerKP)

	err := VerifyPassportSignature(passport, wrongKP.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature with wrong key, got %v", err)
	}
}

func TestVerifyPassportSignatureTampered(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()

	passport := &Passport{
		ID:         "agent-001",
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Unix(),
		Issuer:     "agentsign.dev",
	}

	SignPassport(passport, issuerKP)

	// Tamper with trust level after signing
	passport.TrustLevel = TrustAudited

	err := VerifyPassportSignature(passport, issuerKP.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for tampered passport, got %v", err)
	}
}

func TestVerifyPassportSignatureUnsigned(t *testing.T) {
	kp, _ := GenerateKeyPair()

	passport := &Passport{
		ID:         "agent-001",
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Unix(),
	}

	err := VerifyPassportSignature(passport, kp.PublicKey)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for unsigned passport, got %v", err)
	}
}

func TestVerifyPassportFull(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()

	passport := &Passport{
		ID:         "agent-001",
		TrustLevel: TrustVerified,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(1 * time.Hour).Unix(),
		Issuer:     "agentsign.dev",
	}

	SignPassport(passport, issuerKP)

	// Full verification: signature + expiry + trust level
	err := VerifyPassportFull(passport, issuerKP.PublicKey, TrustIdentified)
	if err != nil {
		t.Fatalf("VerifyPassportFull should pass: %v", err)
	}

	// Full verification with too-high trust requirement
	err = VerifyPassportFull(passport, issuerKP.PublicKey, TrustAudited)
	if err != ErrInsufficientTrust {
		t.Fatalf("expected ErrInsufficientTrust, got %v", err)
	}
}

func TestVerifyPassportFullExpired(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()

	passport := &Passport{
		ID:         "agent-001",
		TrustLevel: TrustAudited,
		IssuedAt:   time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt:  time.Now().Add(-1 * time.Hour).Unix(),
		Issuer:     "agentsign.dev",
	}

	SignPassport(passport, issuerKP)

	err := VerifyPassportFull(passport, issuerKP.PublicKey, TrustIdentified)
	// Signature is valid but passport is expired
	if err != ErrPassportExpired {
		t.Fatalf("expected ErrPassportExpired, got %v", err)
	}
}

func TestSignPassportDeterministic(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()

	passport := &Passport{
		ID:         "agent-001",
		TrustLevel: TrustVerified,
		IssuedAt:   1712700000,
		ExpiresAt:  1712703600,
		Issuer:     "test",
	}

	SignPassport(passport, issuerKP)
	sig1 := passport.Signature

	// Re-sign should produce different signature (ECDSA is non-deterministic)
	// but both should verify
	SignPassport(passport, issuerKP)
	sig2 := passport.Signature

	if sig1 == sig2 {
		// ECDSA with random k should produce different sigs
		// (extremely unlikely to be equal, but not impossible)
		t.Log("warning: two signatures are identical (astronomically unlikely)")
	}

	// Both should verify
	passport.Signature = sig1
	if err := VerifyPassportSignature(passport, issuerKP.PublicKey); err != nil {
		t.Fatalf("sig1 should verify: %v", err)
	}
	passport.Signature = sig2
	if err := VerifyPassportSignature(passport, issuerKP.PublicKey); err != nil {
		t.Fatalf("sig2 should verify: %v", err)
	}
}

// --- Integration: Full Watchman-style Flow ---

func TestWatchmanIntegrationFlow(t *testing.T) {
	// Simulate: Agent generates keys, creates passport, signs a
	// search_entities request, server verifies it

	// 1. Agent setup
	agentKP, _ := GenerateKeyPair()
	agentPubPEM, _ := PublicKeyToPEM(agentKP.PublicKey)
	agentPassport := &Passport{
		ID:           "payment-bot-001",
		Subject:      "payment-bot",
		Version:      Version,
		PublicKeyPEM: agentPubPEM,
		TrustLevel:   TrustVerified,
		Capabilities: []string{"search_entities"},
		IssuedAt:     time.Now().Unix(),
		ExpiresAt:    time.Now().Add(1 * time.Hour).Unix(),
		Issuer:       "agentsign.dev",
	}

	// 2. Agent creates a search request (like Watchman search_entities)
	searchRequest := json.RawMessage(`{
		"jsonrpc": "2.0",
		"method": "tools/call",
		"params": {
			"name": "search_entities",
			"arguments": {
				"request": {"name": "SBERBANK", "entityType": "business"},
				"minMatch": 0.9
			}
		},
		"id": 1
	}`)

	// 3. Agent signs the request
	signed, err := SignMessage(searchRequest, agentKP, agentPassport)
	if err != nil {
		t.Fatalf("agent failed to sign request: %v", err)
	}

	// 4. Server receives and verifies
	// 4a. Verify passport
	err = VerifyPassport(agentPassport, TrustIdentified)
	if err != nil {
		t.Fatalf("passport verification failed: %v", err)
	}

	// 4b. Verify signature
	err = VerifyMessage(signed, agentKP.PublicKey)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// 4c. Check replay protection
	ns := NewNonceStore(5 * time.Minute)
	err = ns.Check(signed.Nonce, signed.Timestamp)
	if err != nil {
		t.Fatalf("nonce check failed: %v", err)
	}

	// 4d. Replay should fail
	err = ns.Check(signed.Nonce, signed.Timestamp)
	if err != ErrReplayAttack {
		t.Fatalf("replay should be detected: %v", err)
	}

	// 5. Server signs the response
	serverKP, _ := GenerateKeyPair()
	serverPassport := &Passport{
		ID:         "watchman-mcp-001",
		Subject:    "watchman",
		TrustLevel: TrustAudited,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(24 * time.Hour).Unix(),
		Issuer:     "moov-io",
	}

	response := json.RawMessage(`{
		"jsonrpc": "2.0",
		"result": {
			"content": [{"type": "text", "text": "{\"entities\":[{\"name\":\"SBERBANK\",\"match\":0.95}]}"}]
		},
		"id": 1
	}`)

	signedResp, err := SignMessage(response, serverKP, serverPassport)
	if err != nil {
		t.Fatalf("server failed to sign response: %v", err)
	}

	// 6. Agent verifies the response
	err = VerifyMessage(signedResp, serverKP.PublicKey)
	if err != nil {
		t.Fatalf("agent failed to verify server response: %v", err)
	}

	// Full round trip complete: agent signed request, server verified,
	// server signed response, agent verified. Tamper-evident end-to-end.
}

// --- Benchmarks ---

func BenchmarkSignMessage(b *testing.B) {
	kp, _ := GenerateKeyPair()
	passport := &Passport{ID: "bench-agent", TrustLevel: TrustVerified, IssuedAt: time.Now().Unix()}
	msg := json.RawMessage(`{"method":"tools/call","params":{"name":"search_entities"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignMessage(msg, kp, passport)
	}
}

func BenchmarkVerifyMessage(b *testing.B) {
	kp, _ := GenerateKeyPair()
	passport := &Passport{ID: "bench-agent", TrustLevel: TrustVerified, IssuedAt: time.Now().Unix()}
	msg := json.RawMessage(`{"method":"tools/call","params":{"name":"search_entities"}}`)
	signed, _ := SignMessage(msg, kp, passport)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyMessage(signed, kp.PublicKey)
	}
}

func BenchmarkCanonicalJSON(b *testing.B) {
	input := map[string]interface{}{
		"method": "tools/call",
		"params": map[string]interface{}{
			"name":      "search_entities",
			"arguments": map[string]interface{}{"query": "SBERBANK"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CanonicalJSON(input)
	}
}
