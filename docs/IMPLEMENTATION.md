# Sknock — Go Implementation Guide

## Module Structure

```
sknock/
├── cmd/
│   ├── sknockd/         # daemon binary entry point
│   │   └── main.go
│   └── sknock/          # client binary entry point
│       └── main.go
├── internal/
│   ├── spa/             # ECIES packet build + parse (core crypto)
│   │   ├── packet.go    # BuildPacket, ParsePacket, SPAData
│   │   └── packet_test.go
│   ├── config/          # TOML config loading + validation
│   │   ├── server.go    # ServerConfig, RuleConfig, SecurityConfig
│   │   ├── users.go     # UsersConfig, UserEntry
│   │   └── client.go    # ClientConfig, ServerEntry
│   ├── listener/        # UDP listener + goroutine dispatch
│   │   ├── listener.go  # Listen(), packet loop
│   │   └── handler.go   # processPacket() pipeline
│   ├── nonce/           # Anti-replay nonce store
│   │   └── store.go     # sync.Map + TTL cleanup goroutine
│   ├── ratelimit/       # Per-IP token bucket
│   │   └── bucket.go    # Allow(ip) bool
│   ├── totp/            # TOTP wrapper (thin layer over pquerna/otp)
│   │   └── totp.go      # Verify(seed, code) bool, Current(seed) string
│   ├── exec/            # Action execution + undo scheduler
│   │   └── action.go    # Run(template, vars), Schedule(delay, template, vars)
│   └── audit/           # Structured audit log
│       └── log.go       # Log(event AuditEvent)
├── go.mod
├── go.sum
└── Makefile
```

## Dependencies

```
go 1.21+

# TOTP
github.com/pquerna/otp v1.4.0

# TOML parsing
github.com/BurntSushi/toml v1.3.2

# QR code (for sknockd user add — optional)
github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e

# CLI (for both binaries)
github.com/spf13/cobra v1.8.0
```

All crypto is Go stdlib:
```
crypto/ecdh         (X25519 — Go 1.20+)
crypto/aes
crypto/cipher       (AES-GCM)
golang.org/x/crypto/hkdf
crypto/rand
encoding/binary     (uint64 big-endian)
```

No CGO required. Builds to a single static binary.

## Key Implementation Notes

### spa/packet.go

```go
const (
    PacketSize      = 186
    EphPubSize      = 32
    NonceSize       = 12
    PayloadSize     = 122
    TagSize         = 16
    VersionSize     = 4
    Version         = "\x00\x02\x00\x00"

    // Payload field sizes
    UIDSize         = 64
    OTPSize         = 6
    TimestampSize   = 8
    RuleSize        = 44

    TimestampWindow = 30 // seconds
)

type SPAData struct {
    UID       string
    OTP       string
    Timestamp uint64
    Rule      string
}
```

Use `crypto/ecdh` (Go 1.20+) not the older `golang.org/x/crypto/curve25519`:
```go
curve := ecdh.X25519()
serverPub, _ := curve.NewPublicKey(serverPubBytes)
ephPriv, _ := curve.GenerateKey(rand.Reader)
shared, _ := ephPriv.ECDH(serverPub)
```

HKDF inline (no extra dep for this):
```go
import "golang.org/x/crypto/hkdf"
r := hkdf.New(sha256.New, shared, []byte("spa-v2"), []byte("spa-v2-aes-key"))
aesKey := make([]byte, 32)
io.ReadFull(r, aesKey)
```

### nonce/store.go

```go
type Store struct {
    mu      sync.Mutex
    entries map[string]time.Time  // nonce hex → expiry
    ttl     time.Duration
}

// CheckAndStore returns false if nonce already seen (replay).
// Returns true and stores the nonce if it's new.
func (s *Store) CheckAndStore(nonce []byte) bool {
    key := hex.EncodeToString(nonce)
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, exists := s.entries[key]; exists {
        return false  // replay
    }
    s.entries[key] = time.Now().Add(s.ttl)
    return true
}

// StartCleanup runs a goroutine that purges expired nonces every ttl/2.
func (s *Store) StartCleanup(ctx context.Context) { ... }
```

### ratelimit/bucket.go

```go
// Per-IP token bucket using golang.org/x/time/rate
// or a simple manual implementation to avoid the extra dep.

type Limiter struct {
    mu      sync.Mutex
    buckets map[string]*tokenBucket
    rate    float64  // tokens/second
    burst   int
}

func (l *Limiter) Allow(ip string) bool { ... }
```

Clean up inactive IP buckets periodically (goroutine, every 5 minutes).

### listener/handler.go — Full Pipeline

```go
func (l *Listener) processPacket(data []byte, addr *net.UDPAddr) {
    // 1. Size + version (cheap)
    if len(data) != spa.PacketSize { return }
    if !bytes.Equal(data[182:], spa.VersionBytes) { return }

    // 2. IP blacklist
    if l.cfg.Security.IsBlacklisted(addr.IP) { return }

    // 3. Token bucket rate limit
    if !l.limiter.Allow(addr.IP.String()) { return }

    // 4. ECIES decrypt (expensive — only reached if passed rate limit)
    pkt, err := spa.ParsePacket(data, l.serverPrivKey)
    if err != nil { return }  // silent drop

    // 5. Nonce dedup
    nonce := data[spa.EphPubSize : spa.EphPubSize+spa.NonceSize]
    if !l.nonces.CheckAndStore(nonce) { return }

    // 6. TOTP verify
    user, ok := l.users[pkt.UID]
    if !ok { return }
    if !totp.Verify(user.Seed, pkt.OTP) { return }

    // 7. Rule lookup
    rule, ok := l.rules[pkt.Rule]
    if !ok { return }

    // 8. User permission
    if !rule.AllowsUser(pkt.UID) { return }

    // 9. IP whitelist (global)
    if !l.cfg.Security.AllowsIP(addr.IP) { return }

    // 10. Execute action
    vars := map[string]string{
        "ip":        addr.IP.String(),
        "uid":       pkt.UID,
        "timestamp": fmt.Sprintf("%d", pkt.Timestamp),
        "rule":      pkt.Rule,
    }
    if err := exec.Run(rule.Action, vars); err != nil {
        l.audit.Log(AuditEvent{...Error: err})
        return
    }

    // 11. Schedule undo
    if rule.UndoAfter > 0 && rule.UndoAction != "" {
        exec.Schedule(time.Duration(rule.UndoAfter)*time.Second, rule.UndoAction, vars)
    }

    // 12. Audit log
    l.audit.Log(AuditEvent{
        Time:      time.Now(),
        UID:       pkt.UID,
        SrcIP:     addr.IP.String(),
        Rule:      pkt.Rule,
        Timestamp: pkt.Timestamp,
    })
}
```

### exec/action.go

```go
func Run(template string, vars map[string]string) error {
    cmd := substituteVars(template, vars)
    // Security: use exec.Command("sh", "-c", cmd)
    // Consider: validate vars contain no shell metacharacters
    // or use a whitelist approach for production hardening
    out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
    if err != nil {
        return fmt.Errorf("action failed: %w (output: %s)", err, out)
    }
    return nil
}

func Schedule(delay time.Duration, template string, vars map[string]string) {
    go func() {
        time.Sleep(delay)
        Run(template, vars)
    }()
}

func substituteVars(template string, vars map[string]string) string {
    result := template
    for k, v := range vars {
        // Only allow known safe characters in var values
        // ip: IPv4/IPv6 address, uid: alphanumeric+underscore, timestamp: digits
        result = strings.ReplaceAll(result, "{"+k+"}", v)
    }
    return result
}
```

**Security note:** validate var values against a strict allowlist before substitution
to prevent shell injection via malicious UID/IP values in packet (even post-decrypt):
- `{ip}` → must match IPv4/IPv6 regex
- `{uid}` → must match `[a-zA-Z0-9_-]+`
- `{timestamp}` → must match `[0-9]+`

## Build

```makefile
.PHONY: all clean install

all: bin/sknockd bin/sknock

bin/sknockd:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/sknockd ./cmd/sknockd

bin/sknock:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/sknock ./cmd/sknock

install:
	install -m 755 bin/sknockd /usr/local/bin/sknockd
	install -m 755 bin/sknock /usr/local/bin/sknock

clean:
	rm -rf bin/
```

`CGO_ENABLED=0` produces a fully static binary. No libc dependency.

## Testing Strategy

```
internal/spa/         → unit test BuildPacket + ParsePacket roundtrip
                        test: wrong size drops, bad version drops, expired timestamp
                        test: replay detection via nonce store
internal/nonce/       → unit test CheckAndStore, TTL expiry, concurrent access
internal/ratelimit/   → unit test Allow(), burst behavior
internal/totp/        → unit test Verify() with known seed+code
internal/exec/        → integration test Run() with safe commands
                        test: variable substitution, shell injection prevention
```

Run with: `go test ./...`

## Go Version Requirement

Go 1.21+ for:
- `crypto/ecdh` X25519 support (1.20+)
- `log/slog` structured logging (1.21+)

## Audit Log Format (JSONL)

```json
{"time":"2026-03-28T14:32:01Z","event":"knock_accepted","uid":"alice","src_ip":"203.0.113.5","rule":"open_ssh","packet_ts":1743170121}
{"time":"2026-03-28T14:37:01Z","event":"undo_executed","uid":"alice","src_ip":"203.0.113.5","rule":"open_ssh"}
{"time":"2026-03-28T14:38:00Z","event":"knock_rejected","src_ip":"198.51.100.1","reason":"otp_failed"}
{"time":"2026-03-28T14:39:00Z","event":"knock_rejected","src_ip":"198.51.100.2","reason":"rate_limited"}
```

JSONL (one JSON object per line) — easy to parse with `jq`, ship to syslog, or ingest into any log system.
