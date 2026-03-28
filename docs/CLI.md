# Sknock CLI Reference

## sknockd — Daemon

```
Usage: sknockd [flags] <command>

Commands:
  run         Start the knock listener daemon (foreground)
  genkey      Generate a new X25519 server keypair
  user add    Add a user and generate their TOTP seed
  user del    Remove a user
  user list   List all users
  verify      Validate config files without starting
  version     Print version info

Flags:
  --config   Path to sknock.toml (default: /etc/sknock/sknock.toml)
  --users    Path to users.toml  (default: /etc/sknock/users.toml)
  --log-level  Override log level
```

### sknockd run

```bash
sknockd run
sknockd run --config /etc/sknock/sknock.toml
```

Starts the daemon in foreground. Use systemd to run as a service (see below).
Logs to file + stderr. On SIGTERM/SIGINT, drains goroutines and exits cleanly.

### sknockd genkey

```bash
sknockd genkey
```

Generates a new X25519 keypair. Prints:
```
Private key (add to sknock.toml → spa_privkey_b64):
  spa_privkey_b64 = "YWJjZGVm..."

Public key (share with clients → server_pubkey):
  server_pubkey = "dGVzdHRl..."
```

### sknockd user add

```bash
sknockd user add alice
```

Generates a random TOTP seed for alice, appends to users.toml, prints:
```
User: alice
Seed: JBSWY3DPEHPK3PXP

Provisioning URL (for QR):
  otpauth://totp/Sknock:alice?secret=JBSWY3DPEHPK3PXP&issuer=Sknock

[QR code printed in terminal]

Share the seed with alice to add to their authenticator app.
Share the server public key and host:port so they can configure the client.
```

### sknockd user del

```bash
sknockd user del alice
```

Removes alice from users.toml. Active sessions (undo timers) are not affected.

### sknockd verify

```bash
sknockd verify
```

Parses and validates all config files, prints a summary. Exits 0 if valid.
Use in CI/CD or before reloading the service.

---

## sknock — Client

```
Usage: sknock [flags] <command>

Commands:
  knock       Send an SPA knock to a server
  ls          List configured servers
  otp         Print the current OTP code for a server (debug)
  version     Print version info

Flags:
  --config    Path to client config (default: ~/.config/sknock/config.toml)
  --server    Override which server to use
```

### sknock knock 

```bash
sknock knock <server> <rule>
sknock knock prod open_ssh
sknock knock staging open_https --retries 5
```

Reads server config (host, port, uid, seed, pubkey), generates current TOTP,
builds 186-byte packet, sends 3× UDP with 200ms gap.

Flags:
```
--retries N    Number of UDP sends (default 3)
--delay N      Milliseconds between retries (default 200)
--server NAME  Server from config to use
```

Output on success:
```
Knock sent to prod:58432 → rule "open_ssh"
```

The client never knows if the knock succeeded (UDP, no response by design).
Use `--retries 5` on unreliable networks.

### sknock ls

```bash
sknock ls
```

Lists all configured servers:
```
NAME       HOST                  PORT   UID
prod       203.0.113.10          58432  alice
staging    10.0.1.5              58432  alice
```

### sknock otp

```bash
sknock otp prod
```

Prints the current TOTP code for debugging clock sync issues:
```
Current OTP for prod (alice): 123456  [expires in 18s]
```

---

## systemd Unit

`/etc/systemd/system/sknockd.service`:

```ini
[Unit]
Description=Sknock SPA Daemon
After=network.target
Documentation=https://github.com/youruser/sknock

[Service]
Type=simple
ExecStart=/usr/local/bin/sknockd run
Restart=on-failure
RestartSec=5

# Hardening
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/sknock /etc/sknock
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now sknockd
```

---

## Quick Setup (Server)

```bash
# 1. Install
cp sknockd /usr/local/bin/sknockd
chmod 755 /usr/local/bin/sknockd

# 2. Create config dirs
mkdir -p /etc/sknock /var/log/sknock
chmod 700 /etc/sknock

# 3. Generate server keypair
sknockd genkey
# → copy spa_privkey_b64 into /etc/sknock/sknock.toml

# 4. Create config
cat > /etc/sknock/sknock.toml << EOF
[server]
listen_port = 58432
spa_privkey_b64 = "YOUR_GENERATED_PRIVKEY"

[[rules]]
name       = "open_ssh"
action     = "ufw allow from {ip} to any port 22 comment 'sknock:{uid}'"
undo_after = 300
EOF
chmod 600 /etc/sknock/sknock.toml

# 5. Add user
sknockd user add alice
# → gives you seed + QR

# 6. Start
systemctl enable --now sknockd

# 7. iptables rate limit (recommended)
iptables -I INPUT -p udp --dport 58432 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -I INPUT -p udp --dport 58432 -j DROP
```

## Quick Setup (Client)

```bash
# 1. Install
cp sknock /usr/local/bin/sknock
chmod 755 /usr/local/bin/sknock

# 2. Create config
mkdir -p ~/.config/sknock
cat > ~/.config/sknock/config.toml << EOF
default = "prod"

[servers.prod]
host          = "myserver.example.com"
port          = 58432
uid           = "alice"
seed          = "SEED_FROM_sknockd_user_add"
server_pubkey = "PUBKEY_FROM_sknockd_genkey"
EOF
chmod 600 ~/.config/sknock/config.toml

# 3. Add seed to authenticator app (optional — client reads seed directly)
# Use the otpauth:// URL from `sknockd user add`

# 4. Knock
sknock knock prod open_ssh
```
