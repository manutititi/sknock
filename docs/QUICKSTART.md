# Sknock — Quick Start Guide

## What You Need

- A Linux server with root access.
- A workstation (Linux or macOS) to knock from
- Go 1.21+ to compile (only needed once)

## Build

Clone the repo and build both binaries:

```bash
git clone <repo-url> && cd sknock
make all
```

This produces two binaries in `bin/`:

| Binary | What it is | Where it goes |
|--------|-----------|---------------|
| `bin/sknockd` | Server daemon | Copy to the server |
| `bin/sknock` | Client CLI | Keep on your workstation |

If your workstation is not Linux, or has a different architecture than the server, cross-compile the server binary:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/sknockd ./cmd/sknockd
```

---

## Server Setup

Copy `bin/sknockd` to the server and run everything as root.

### Step 1: Install the binary

```bash
scp bin/sknockd root@your-server:/usr/local/bin/sknockd
# then on the server:
chmod 755 /usr/local/bin/sknockd
```

### Step 2: Initialize

```bash
sknockd init
```

This generates the X25519 keypair and creates the config files:

```
/etc/sknock/sknock.toml   ← server config (private key, security settings)
/etc/sknock/rules.toml    ← rules (actions triggered by knocks)
/etc/sknock/users.toml    ← user database (TOTP seeds)
```

The default config includes an `open_ssh` rule that opens port 22 for the knocking IP for 5 minutes. Edit `/etc/sknock/rules.toml` to change it.

### Step 3: Add a user

```bash
sknockd user add alice
```

This prints a **provision token** — a single `sknock add` command that the user runs on their machine. The QR code for the authenticator app is shown on the client side when the user runs `sknock add`.

Send the `sknock add` command to the user via a secure channel.

### Step 4: Open the port and start

```bash
ufw allow 58432/udp
```

Create the systemd service:

```bash
cat > /etc/systemd/system/sknockd.service << 'EOF'
[Unit]
Description=Sknock SPA Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sknockd run
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sknockd
```

Verify:

```bash
systemctl status sknockd
```

Server is ready.

---

## Client Setup

On your workstation — `bin/sknock` was already built in the Build step. You do NOT need Go or the repo on the client machine, just the binary.

### Step 1: Install the binary

```bash
sudo cp bin/sknock /usr/local/bin/sknock
sudo chmod 755 /usr/local/bin/sknock
```

### Step 2: Add the server

Copy the command from the `sknockd user add` output and paste it:

```bash
sknock add prod sknock://NDYuMjI1LjIxNC4xNDQ6NTg0MzI6eGszei9q...
```

The token contains the server IP, port, public key, your username, and TOTP seed — all in one string.

Verify with:

```bash
sknock ls
```

### Step 3: Knock

Open your authenticator app, get the current code, and type it last:

```bash
sknock prod open_ssh 482901
```

The OTP is the last argument so you type it fresh. The knock opens port 22 for your IP on the server for 5 minutes.

That's it.

---

## Adding More Users

On the server:

```bash
sknockd user add bob
systemctl restart sknockd
```

Give bob the QR code and the `sknock add <name> sknock://...` command.

## Adding More Rules

Edit `/etc/sknock/rules.toml` and add a new `[[rule]]` block:

```toml
[[rule]]
name          = "open_https"
action        = "ufw allow from {ip} to any port 443 comment 'sknock:{uid}'"
undo_action   = "ufw delete allow from {ip} to any port 443"
undo_after    = 300
allowed_users = []
# execute_as  = "deploy"   # run as a specific system user (via sudo -u)
```

Then restart:

```bash
systemctl restart sknockd
```

Template variables available in actions: `{ip}`, `{uid}`, `{timestamp}`, `{rule}`.

If `execute_as` is set, the action and undo commands run as that system user (via kernel setuid, no sudo needed). This is useful for actions that should not run as root.

## Audit Log

Every knock is logged to `/var/log/sknock/audit.log` as JSON:

```bash
tail -f /var/log/sknock/audit.log
```

```json
{"event":"knock_accepted","rule":"open_ssh","src_ip":"47.62.195.75","time":"2026-03-28T19:54:06Z","uid":"alice"}
{"event":"knock_rejected","reason":"otp_failed","src_ip":"198.51.100.1","time":"2026-03-28T19:55:00Z"}
```

## Troubleshooting

| Problem | Check |
|---------|-------|
| Knock not arriving | `systemctl status sknockd` and `ufw status \| grep 58432` |
| `otp_failed` in audit log | Clocks out of sync — TOTP allows ±30s max |
| `unknown_user` | User not in `/etc/sknock/users.toml` — run `sknockd user add` and restart |
| `unknown_rule` | Rule name doesn't match any `[[rule]]` in config |
| Permission denied | Config files must be mode 0600 |

## Security Checklist

- [ ] Config files are 0600 and owned by root
- [ ] Private key not committed to version control
- [ ] TOTP seeds shared via secure channel only
- [ ] `ufw allow 58432/udp` is the only port open for sknock
- [ ] `undo_after` is set on firewall rules
- [ ] `allowed_users` is set on sensitive rules
