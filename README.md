# Sknock

Single Packet Authorization (SPA) daemon and client for Linux. One 186-byte encrypted UDP datagram — authenticated with TOTP and encrypted with ECIES (X25519 + AES-256-GCM) — triggers a server-side action. No open ports, no PKI, no persistent connections.

## How it works

```
client                              server (UDP 58432, silent)
  │                                   │
  │   186-byte ECIES datagram         │
  │ ────────────────────────────────► │
  │   ephemeral X25519 + AES-256-GCM  │  → decrypt
  │   TOTP code inside                │  → verify identity
  │                                   │  → execute action
  │   (no response, ever)             │     e.g. ufw allow from {ip}
```

The server never responds. To a port scanner, the listening port appears closed.

## Quick Start

See **[Quick Start Guide](docs/QUICKSTART.md)** for step-by-step installation and usage.

**Server (3 commands):**

```bash
sudo sknockd init
sudo sknockd user add alice        # prints provision token for the user
sudo systemctl enable --now sknockd
```

**Client (2 commands):**

```bash
sknock add prod sknock://NDYuMjI1...   # one-time setup (token from server admin, shows QR)
sknock prod open_ssh 482901            # knock (OTP from authenticator app)
```

## Security

### Crypto stack

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key exchange | X25519 ECDH | Ephemeral per packet — perfect forward secrecy |
| Key derivation | HKDF-SHA256 | Shared secret → AES key |
| Encryption | AES-256-GCM | Authenticated encryption of payload |
| Authentication | TOTP (RFC 6238) | Time-based one-time password, 6-digit, 30s window |

Every packet uses a fresh ephemeral X25519 keypair. If the server private key leaks in the future, previously captured packets remain undecryptable.

### Defense layers (ordered by cost)

1. **Kernel rate limit** — iptables drops floods before they reach the process
2. **IP blacklist** — hash lookup, before any crypto
3. **Packet validation** — exact 186-byte size + version magic bytes
4. **Token bucket** — per-IP rate limit before ECIES (protects CPU)
5. **ECIES decryption** — X25519 DH + HKDF + AES-256-GCM (~0.1ms)
6. **Timestamp check** — ±30s window rejects stale packets
7. **Nonce dedup** — 12-byte nonce stored 60s, prevents replay
8. **TOTP verify** — second factor against user's individual seed
9. **Rule + permission check** — per-rule user allowlist
10. **Action execution** — variable validation with strict regex before shell substitution

### What an observer sees

```
[32B random][12B random][122B random][16B random][0x00 0x02 0x00 0x00]
```

No IP, no username, no rule name, no identity. The only non-random field is the 4-byte version marker. Two packets from the same user are unlinkable.

### Why Sknock over alternatives

| | knockd | fwknop | Sknock |
|---|---|---|---|
| Crypto | None | HMAC or GPG | ECIES X25519 + AES-256-GCM |
| Forward secrecy | No | No | Yes (ephemeral per packet) |
| TOTP | No | No | Yes |
| Replay protection | No | Partial | Nonce dedup + timestamp |
| Setup | Port sequence | Complex PKI | `sknockd init` + TOML |
| Binary | C daemon (dead since 2017) | C tools | Go static binary, zero deps |

## Documentation

- **[Quick Start](docs/QUICKSTART.md)** — install, configure, knock
- [Security Model](docs/SECURITY.md) — threat model and defense layers
- [CLI Reference](docs/CLI.md) — all commands and flags

## Default Port

**UDP 58432**

## License

MIT
