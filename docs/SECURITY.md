# Sknock — Security Model

## Threat Model

| Threat | Mitigated? | How |
|--------|-----------|-----|
| Passive eavesdropper captures packets | Yes | ECIES — payload fully encrypted, no metadata |
| Attacker replays captured packet | Yes | Nonce dedup (sync.Map 60s TTL) + timestamp ±30s |
| Attacker forges a valid packet | Yes | AES-256-GCM authentication tag — forged packets fail decryption |
| Attacker brute-forces TOTP | Partial | TOTP has 10^6 space; rate limiting + nonce dedup limits attempts |
| Future key compromise exposes past traffic | Yes | Perfect forward secrecy — ephemeral X25519 per packet |
| Attacker identifies two packets from same user | Yes | Different ephemeral pub per packet — unlinkable |
| DoS via packet flood (CPU exhaustion) | Yes | iptables rate limit + token bucket before crypto |
| Attacker reads OTP seed from server | Partial | Seeds in 0600 file; no encryption at rest in v1 |
| Attacker scans for open service | Yes | Silent-drop — no response to any packet; port appears closed |

## Crypto Stack

```
X25519 (ECDH)         — key exchange, 128-bit security
HKDF-SHA256           — key derivation from shared secret
AES-256-GCM           — authenticated encryption, 256-bit key
TOTP (RFC 6238)       — HMAC-SHA1, 6-digit, 30s window, ±1 period tolerance
```

## Defense Layers (ordered by processing cost)

### Layer 1: Kernel (free — iptables)
```bash
# Drop excess packets before they reach sknockd
iptables -A INPUT -p udp --dport 58432 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p udp --dport 58432 -j DROP
```
This absorbs volumetric floods at kernel level. The process never sees the excess.

### Layer 2: IP Blacklist (microseconds — before any crypto)
```
if src_ip in blacklist → drop, no further processing
```
Simple hash set lookup. Applied before anything else.

### Layer 3: Packet Validation (microseconds — before any crypto)
```
if len(packet) != 186 → drop
if packet[182:186] != VERSION → drop
```
Drops garbage without touching X25519. A random 186-byte probe still fails here
unless the last 4 bytes happen to be 0x00 0x02 0x00 0x00.

### Layer 4: Token Bucket Rate Limit (microseconds — before any crypto)
```
if tokens(src_ip) == 0 → drop
```
Per-source-IP token bucket. Limits the number of ECIES operations any single IP
can force the daemon to perform per second. Prevents CPU exhaustion even if the
attacker sends correctly-sized packets with valid version bytes.

### Layer 5: ECIES Decryption (expensive — ~0.1ms per packet)
```
X25519 DH + HKDF + AES-256-GCM decrypt
if decryption fails → drop (silent)
```
This is the only expensive operation. Layers 1-4 ensure it's only reached for
packets that pass rate limiting.

### Layer 6: Timestamp Check (nanoseconds)
```
if |now - packet.timestamp| > 30s → drop
```
Limits the replay window to 60 seconds total (2 × 30s TOTP window).

### Layer 7: Nonce Dedup (nanoseconds — sync.Map lookup)
```
if nonce in seen_nonces → drop (replay)
seen_nonces[nonce] = expiry(now + 60s)
```
The 12-byte nonce from the packet is stored in memory with a 60s TTL.
The same packet cannot be replayed within that window.
Since the timestamp window is also 30s, a packet that passes the timestamp
check will never be valid after the nonce expires.

### Layer 8: TOTP Verification (microseconds)
```
if !totp.Validate(packet.otp, user.seed) → drop
```
Validates the 6-digit code against the user's seed. valid_window=1 (±30s).
At this point we have already verified the packet is authentic (ECIES passed)
and fresh (timestamp + nonce). TOTP is an additional factor.

### Layer 9: Rule and Permission Check (nanoseconds)
```
if rule not in config.rules → drop
if user not in rule.allowed_users → drop
if ip_whitelist configured and src_ip not in whitelist → drop
```

### Layer 10: Action Execution
```
exec(rule.action.format(ip, uid, timestamp))
audit_log.write(...)
if rule.undo_after > 0: schedule(undo_action, undo_after)
```

## TOTP Brute Force Analysis

TOTP space: 10^6 (000000–999999).
With valid_window=1, ~3 codes are valid at any time (prev, current, next).
Attacker must also have a valid encrypted packet (requires knowing server pubkey).

With rate limiting at 5 pps per source IP:
- 5 attempts/second × 60s nonce TTL = 300 unique packets before IPs cycle
- At 300 attempts/min, full 10^6 space takes ~55 hours
- But TOTP code changes every 30s → attacker must hit within the same window
- Effectively: 300 attempts per 30s window = 0.03% success probability per window

In practice, TOTP brute force is not a viable attack here.

## Seed Storage

In v1, seeds are stored in plaintext in `/etc/sknock/users.toml` (0600, root only).


## What fwknop Does Differently

| Feature | fwknop | Sknock |
|---------|--------|--------|
| Key exchange | Static HMAC key or GPG | ECIES X25519 (forward secret) |
| Forward secrecy | No (static key) | Yes (ephemeral per packet) |
| Setup complexity | PKI or pre-shared key | TOTP seed only |
| Binary | C, dynamic linking | Go, static binary |
| Config | fwknop.conf syntax | TOML |
| TOTP support | No | Yes (primary auth factor) |

Sknock's security model is strictly stronger than fwknop's default HMAC mode.
