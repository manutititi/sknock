# Sknock

Modern Single Packet Authorization (SPA) daemon for Linux servers.

One encrypted UDP packet — authenticated with TOTP — opens a firewall port,
runs a script, or triggers any configurable action. No open ports, no PKI,
no complex setup.

## How it works

```
client                           server
  │                                │
  │  186-byte UDP datagram         │
  │ ─────────────────────────────► │
  │  ECIES(X25519 + AES-256-GCM)   │
  │  TOTP code inside              │  → decrypt → verify OTP → run action
  │                                │  → "ufw allow from {ip} port 22"
```

The server never responds. To a port scanner, UDP 58432 appears closed.

## Why not knockd / fwknop?

| | knockd | fwknop | Sknock |
|---|---|---|---|
| Crypto | None | HMAC or GPG | ECIES X25519 |
| Forward secrecy | No | No | Yes (ephemeral per packet) |
| TOTP | No | No | Yes |
| Setup | Simple | Complex PKI | TOML config |
| Binary | C daemon | C tools | Go static binary |
| Maintained | Dead (2017) | Active | Active |

## Quick Start

**Server:**
```bash
sknockd genkey                    # generate keypair
sknockd user add alice            # add user, get TOTP seed + QR
# edit /etc/sknock/sknock.toml
systemctl enable --now sknockd
```

**Client:**
```bash
# edit ~/.config/sknock/config.toml
sknock knock prod open_ssh        # knock!
```

## Documentation

- [Design](docs/DESIGN.md) — architecture and goals
- [Packet Format](docs/PACKET.md) — 186-byte ECIES packet layout
- [Security Model](docs/SECURITY.md) — threat model and defense layers
- [Configuration](docs/CONFIG.md) — full TOML config reference
- [CLI Reference](docs/CLI.md) — sknockd and sknock commands
- [Implementation Guide](docs/IMPLEMENTATION.md) — Go packages and build

## References (from Anchor project)

The crypto and packet format are derived from Anchor's SPA v2 implementation:

- [spa.py](docs/references/spa.py) — original ECIES packet builder/parser (Python)
- [knock.py](docs/references/knock.py) — original UDP listener (Python/asyncio)
- [otp.py](docs/references/otp.py) — TOTP seed management (Python)
- [client_spa.py](docs/references/client_spa.py) — client-side packet builder (Python)

## Default Port

**UDP 58432**

## License

MIT
