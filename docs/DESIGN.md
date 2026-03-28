# Sknock — Design Document

## What it is

Sknock is a modern Single Packet Authorization (SPA) daemon for Linux servers.
A single encrypted UDP packet — authenticated with TOTP — triggers a configurable
action (firewall rule, script, webhook). No connection needed, no open ports exposed.

## Why it exists

| Tool | Problem |
|------|---------|
| knockd | Dead (~2017). Sequence of ports — sniff once, replay forever. No crypto. |
| fwknop | Solid crypto but: C binary, complex PKI setup, heavy config. |
| Sknock | Modern Go binary. ECIES + TOTP. TOML config. Zero deps to install. |

Key differentiator: **perfect forward secrecy in a single UDP packet** without PKI.
Every packet uses a fresh ephemeral X25519 keypair — even if the server private key
leaks in the future, captured past packets remain undecryptable.

## Goals

- Single static Go binary (`sknockd` daemon + `sknock` client)
- Zero runtime dependencies (no Python, no libraries to install)
- TOML config — explicit, no YAML footguns
- Silent-drop semantics — server never responds to invalid packets
- Action per rule — arbitrary shell command with `{ip}`, `{uid}`, `{timestamp}`
- Optional auto-undo after N seconds (e.g. close firewall rule)
- Per-rule user allowlist
- IP rate limiting at process level (in addition to iptables recommendation)
- Audit log — every accepted knock logged with uid, src IP, rule, timestamp

## Non-Goals

- PKI / certificate management
- Persistent state / database
- HTTP API or web UI
- Multi-port knocking sequences
- Windows support (Linux only, systemd unit provided)

## Standard Port

**UDP 58432** — different from Anchor (62201), not assigned by IANA to any service.
Configurable in config.

## Two Binaries

```
sknockd   — daemon: listens on UDP, verifies packets, executes actions
sknock    — client: reads local config, sends knock to a named server
```

Both built from the same Go module. Single `go build ./...` produces both.

## Architecture Overview

```
UDP packet (186 bytes)
        │
        ▼
  [iptables rate limit]     ← kernel-level, before process sees it
        │
        ▼
  net.ListenPacket (Go)
        │
        ▼
  goroutine per packet
        │
  ┌─────┴──────────────────────────────────────────┐
  │  1. Size check (186 bytes exact)               │
  │  2. Version bytes check (0x00 0x02 0x00 0x00)  │
  │  3. IP blacklist check                          │
  │  4. Token bucket rate limit (per source IP)    │
  │  5. ECIES decrypt (X25519 + AES-256-GCM)       │  ← crypto starts here
  │  6. Timestamp check (±30s)                     │
  │  7. Nonce dedup (sync.Map TTL 60s)             │
  │  8. TOTP verify (user seed from config)        │
  │  9. Rule lookup (by rule name from packet)     │
  │  10. User permission check (allowed_users)     │
  │  11. IP whitelist check (if configured)        │
  │  12. Execute action                            │
  │  13. Schedule undo_action (if undo_after > 0) │
  │  14. Audit log                                 │
  └────────────────────────────────────────────────┘

Silent drop on any failure (no response to sender).
```

## Packet Format

See `PACKET.md` for the full 186-byte layout.

## Config Format

See `CONFIG.md` for the full TOML spec.

## Security Model

See `SECURITY.md` for the threat model and security layer analysis.

## Implementation Guide

See `IMPLEMENTATION.md` for Go package structure and dependency list.
