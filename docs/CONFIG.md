# Sknock Configuration Reference

## File Locations

| File | Location | Permissions |
|------|----------|-------------|
| Daemon config | `/etc/sknock/sknock.toml` | 0600, root:root |
| Users/seeds | `/etc/sknock/users.toml` | 0600, root:root |
| Client config | `~/.config/sknock/config.toml` | 0600 |
| Audit log | `/var/log/sknock/audit.log` | append-only |

---

## Daemon Config (`/etc/sknock/sknock.toml`)

```toml
[server]
listen_addr = "0.0.0.0"
listen_port = 58432           # UDP — Sknock default
log_file    = "/var/log/sknock/sknock.log"
log_level   = "info"          # debug | info | warn | error
audit_log   = "/var/log/sknock/audit.log"

# Server SPA X25519 private key (base64, 32 bytes raw).
# Generate with: sknockd genkey
# REQUIRED — if missing, daemon refuses to start.
spa_privkey_b64 = "base64encodedprivkeyhere=="

[security]
timestamp_window  = 30    # seconds, must match TOTP period (30)
nonce_ttl         = 60    # seconds — nonce anti-replay memory window

# Rate limiting — applied per source IP before any crypto
rate_limit_pps    = 5     # packets per second per source IP allowed through
rate_limit_burst  = 10    # burst allowance before rate limiting kicks in

# IP-level access control (evaluated before ECIES decryption)
ip_blacklist = ["203.0.113.5", "198.51.100.0/24"]
ip_whitelist = []         # if non-empty, only these IPs can knock at all


# ---------------------------------------------------------------------------
# Rules — each [[rules]] block defines one triggerable action
# ---------------------------------------------------------------------------

[[rules]]
name         = "open_ssh"
action       = "ufw allow from {ip} to any port 22 comment 'sknock:{uid}'"
undo_action  = "ufw delete allow from {ip} to any port 22"
undo_after   = 120          # seconds; 0 = permanent (no undo)
allowed_users = ["alice", "bob"]   # empty = all valid users allowed

[[rules]]
name         = "open_https"
action       = "ufw allow from {ip} to any port 443 comment 'sknock:{uid}'"
undo_action  = "ufw delete allow from {ip} to any port 443"
undo_after   = 300
allowed_users = []          # all users

[[rules]]
name         = "wake_server"
action       = "/usr/local/bin/wol.sh 00:11:22:33:44:55"
undo_action  = ""           # no undo
undo_after   = 0
allowed_users = ["alice"]

[[rules]]
name         = "run_deploy"
action       = "/opt/deploy/trigger.sh {uid} {timestamp}"
undo_after   = 0
allowed_users = ["ci_bot"]
```

### Action Template Variables

| Variable | Value |
|----------|-------|
| `{ip}` | Source IP of the UDP packet |
| `{uid}` | Username from the decrypted payload |
| `{timestamp}` | Unix timestamp from the decrypted payload |
| `{rule}` | Rule name |

---

## Users Config (`/etc/sknock/users.toml`)

```toml
# This file is 0600 root:root — seeds are sensitive.
# Manage with: sknockd user add/del/list

[users.alice]
otp_seed = "JBSWY3DPEHPK3PXP"   # base32 TOTP seed
uid      = 1                      # numeric, informational only

[users.bob]
otp_seed = "MFRGGZDFMZTWQ2LK"
uid      = 2

[users.ci_bot]
otp_seed = "NBSWY3DPEB3W64TMMQ=="
uid      = 3
```

---

## Client Config (`~/.config/sknock/config.toml`)

```toml
# Default server to use when --server is not specified
default = "prod"

[servers.prod]
host           = "203.0.113.10"
port           = 58432
uid            = "alice"
seed           = "JBSWY3DPEHPK3PXP"   # base32 TOTP seed (0600 file)
server_pubkey  = "base64encodedX25519pubkeyhere=="

[servers.staging]
host           = "10.0.1.5"
port           = 58432
uid            = "alice"
seed           = "JBSWY3DPEHPK3PXP"
server_pubkey  = "differentbase64pubkey=="
```

**File must be 0600** — it contains the TOTP seed (equivalent to a password).
`sknock` refuses to run if the file is world/group readable.

---

## Environment Variables

All config values can be overridden via env vars (useful for CI/automation):

| Var | Overrides |
|-----|-----------|
| `SKNOCK_PRIVKEY` | `server.spa_privkey_b64` |
| `SKNOCK_PORT` | `server.listen_port` |
| `SKNOCK_LOG_LEVEL` | `server.log_level` |
| `SKNOCK_SEED` | client seed (for `sknock knock` one-off use) |

---

## Generating Keys

```bash
# Generate server keypair (output: private key to .env, public key to share)
sknockd genkey

# Output example:
# SPA private key (add to /etc/sknock/sknock.toml → spa_privkey_b64):
#   spa_privkey_b64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoA..."
#
# SPA public key (share with clients → server_pubkey in ~/.config/sknock/config.toml):
#   server_pubkey = "dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVz..."
```

---

## Minimal Working Example

**Server** (`/etc/sknock/sknock.toml`):
```toml
[server]
listen_port = 58432
spa_privkey_b64 = "GENERATED_BY_sknockd_genkey"

[[rules]]
name        = "open_ssh"
action      = "ufw allow from {ip} to any port 22"
undo_after  = 300

[security]
```

**Server** (`/etc/sknock/users.toml`):
```toml
[users.alice]
otp_seed = "JBSWY3DPEHPK3PXP"
```

**Client** (`~/.config/sknock/config.toml`):
```toml
[servers.myserver]
host          = "myserver.example.com"
port          = 58432
uid           = "alice"
seed          = "JBSWY3DPEHPK3PXP"
server_pubkey = "PUBLIC_KEY_FROM_sknockd_genkey"
```

**Knock:**
```bash
sknock knock myserver open_ssh
# → SSH port open for your IP for 5 minutes
```
