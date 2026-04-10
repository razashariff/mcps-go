# mcps-go

Go implementation of the MCPS (MCP Secure) protocol. Cryptographic message signing, verification, replay protection, and tool integrity for MCP servers and agents.

Reference implementation of [IETF Internet-Draft draft-sharif-mcps-secure-mcp](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/).

## Install

```
go get github.com/razashariff/mcps-go
```

## Quick Start

### Sign a message (agent side)

```go
import mcps "github.com/razashariff/mcps-go"

// Generate keys (or load from HSM via PKCS#11)
kp, _ := mcps.GenerateKeyPair()

// Create passport
passport := &mcps.Passport{
    ID:         "payment-bot-001",
    TrustLevel: mcps.TrustVerified,
    IssuedAt:   time.Now().Unix(),
    ExpiresAt:  time.Now().Add(1 * time.Hour).Unix(),
}

// Sign any MCP JSON-RPC message
msg := json.RawMessage(`{"method":"tools/call","params":{"name":"search_entities"}}`)
signed, _ := mcps.SignMessage(msg, kp, passport)
```

### Persistent keys (stable across reboots)

```go
// First boot: generate and save to disk
kp, _ := mcps.GenerateAndSaveKeyPair("watchman.key", "watchman.pub")

// Subsequent boots: load from disk
kp, _ = mcps.LoadKeyPair("watchman.key", "watchman.pub")

// Or load from environment variables (Docker, K8s secrets)
kp, _ = mcps.LoadKeyPairFromEnv("MCPS_PRIVATE_KEY", "MCPS_PUBLIC_KEY")
```

### HSM / KMS support (pluggable Signer interface)

```go
// Implement the Signer interface for your HSM/KMS:
type Signer interface {
    Sign(hash []byte) (r, s *big.Int, err error)
    PublicKey() *ecdsa.PublicKey
}

// Use with any backend:
signed, _ := mcps.SignMessageWithSigner(msg, myHSMSigner, passport)

// Built-in local signer:
signer := mcps.NewLocalSigner(kp)
signed, _ = mcps.SignMessageWithSigner(msg, signer, passport)
```

### Verify a message (server side)

```go
// Verify signature
err := mcps.VerifyMessage(signed, agentPublicKey)
if err != nil {
    // MCPS-004: invalid signature, MCPS-005: replay, etc.
}

// Check replay protection
nonces := mcps.NewNonceStore(5 * time.Minute)
err = nonces.Check(signed.Nonce, signed.Timestamp)

// Verify passport trust level
err = mcps.VerifyPassport(passport, mcps.TrustIdentified)
```

### Tool integrity (detect tool poisoning)

```go
pins := mcps.NewToolPinStore()

// Pin at discovery time
pins.PinTool("watchman", "search_entities", toolDefinition)

// Verify on every call -- detects mutations
err := pins.VerifyTool("watchman", "search_entities", toolDefinition)
if err == mcps.ErrToolIntegrity {
    // Tool definition changed since discovery -- possible attack
}
```

## Features

- ECDSA P-256 + SHA-256 signing and verification
- Canonical JSON (RFC 8785 JCS) for deterministic serialisation
- Nonce-based replay protection with configurable time windows
- Tool definition hash-pinning (detects tool poisoning attacks)
- Agent passport signing and verification with trust levels (L0-L4)
- Persistent keys -- stable across reboots (PEM file or env var)
- Pluggable Signer interface for HSM, KMS, PKCS#11, or any external backend
- PEM key encoding/decoding (EC PRIVATE KEY and PKCS8)
- Zero external dependencies -- pure Go stdlib
- FIPS-compatible algorithms (P-256, SHA-256)

## Trust Levels

| Level | Name | Description |
|-------|------|-------------|
| L0 | Unsigned | No passport |
| L1 | Identified | Passport signed by any Trust Authority |
| L2 | Verified | Passport signed by recognised TA |
| L3 | Scanned | Verified + TA verified origin |
| L4 | Audited | Scanned + full security audit |

## Error Codes

| Code | Error | Description |
|------|-------|-------------|
| MCPS-002 | ErrPassportExpired | Passport has expired |
| MCPS-004 | ErrInvalidSignature | Signature verification failed |
| MCPS-005 | ErrReplayAttack | Duplicate nonce detected |
| MCPS-006 | ErrTimestampExpired | Timestamp outside valid window |
| MCPS-008 | ErrToolIntegrity | Tool definition hash changed |
| MCPS-009 | ErrInsufficientTrust | Trust level below minimum |

## Related

- [mcp-secure](https://www.npmjs.com/package/mcp-secure) -- JavaScript/Node.js implementation
- [mcps-secure](https://pypi.org/project/mcps-secure/) -- Python implementation
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) -- Section 7
- [IETF Draft](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/)

## License

Apache-2.0. See [LICENSE](LICENSE).

Copyright (c) 2026 CyberSecAI Ltd.
