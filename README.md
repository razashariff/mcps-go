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
- Agent passport verification with trust levels (L0-L4)
- PEM key encoding/decoding
- ELIDA proxy middleware (optional)
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

BSL-1.1 (Business Source License 1.1). See [LICENSE](LICENSE).

Copyright (c) 2026 CyberSecAI Ltd.
