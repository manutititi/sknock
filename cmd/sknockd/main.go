package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/manu/sknock/internal/config"
	execpkg "github.com/manu/sknock/internal/exec"
	"github.com/manu/sknock/internal/nonce"
	"github.com/manu/sknock/internal/ratelimit"
	"github.com/manu/sknock/internal/spa"
	totppkg "github.com/manu/sknock/internal/totp"
)

const (
	defaultConfigDir  = "/etc/sknock"
	defaultConfigPath = "/etc/sknock/sknock.toml"
	defaultUsersPath  = "/etc/sknock/users.toml"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit()
	case "genkey":
		cmdGenkey()
	case "user":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: sknockd user <add|del|list> [args]\n")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "add":
			cmdUserAdd()
		case "list":
			cmdUserList()
		default:
			fmt.Fprintf(os.Stderr, "Unknown user command: %s\n", os.Args[2])
			os.Exit(1)
		}
	case "run":
		cmdRun()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: sknockd <command>

Commands:
  init                 First-time setup: generate keys and config files
  genkey               Generate a new X25519 keypair (standalone)
  user add <name>      Add a user and generate their TOTP seed + QR
  user list            List configured users
  run [--config path] [--users path]  Start the knock listener

Flags for run:
  --config   Path to sknock.toml (default: %s)
  --users    Path to users.toml  (default: %s)
`, defaultConfigPath, defaultUsersPath)
}

// ---------------------------------------------------------------------------
// init — first-time setup
// ---------------------------------------------------------------------------

func cmdInit() {
	configDir := defaultConfigDir
	if len(os.Args) >= 3 {
		configDir = os.Args[2]
	}

	configPath := configDir + "/sknock.toml"
	usersPath := configDir + "/users.toml"

	// Check if already initialized
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config already exists at %s\n", configPath)
		fmt.Fprintf(os.Stderr, "Remove it first if you want to reinitialize.\n")
		os.Exit(1)
	}

	// Generate keypair
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	// Create config directory
	if err := os.MkdirAll(configDir, 0700); err != nil {
		log.Fatalf("create config dir: %v", err)
	}

	rulesPath := configDir + "/rules.toml"

	// Write sknock.toml
	configContent := fmt.Sprintf(`[server]
listen_addr     = "0.0.0.0"
listen_port     = 58432
log_level       = "info"
audit_log       = "/var/log/sknock/audit.log"
spa_privkey_b64 = "%s"
rules_file      = "rules.toml"

[security]
timestamp_window = 30    # seconds — max clock skew allowed
nonce_ttl        = 60    # seconds — anti-replay nonce memory
rate_limit_pps   = 5     # packets/sec per source IP
rate_limit_burst = 10    # burst allowance
# ip_blacklist = ["203.0.113.5"]   # blocked IPs (checked before crypto)
# ip_whitelist = []                # if set, only these IPs can knock
`, privB64)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		log.Fatalf("write config: %v", err)
	}

	// Write rules.toml
	rulesContent := `# Sknock rules — each [[rule]] block defines a triggerable action.
# Template variables: {ip}, {uid}, {timestamp}, {rule}
# allowed_users = [] means all users can trigger the rule.
# execute_as    = "user" runs the action as that system user (via setuid).

[[rule]]
name          = "open_ssh"
action        = "ufw allow from {ip} to any port 22 comment 'sknock:{uid}'"
undo_action   = "ufw delete allow from {ip} to any port 22"
undo_after    = 300
allowed_users = []
# execute_as  = "root"
`
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0600); err != nil {
		log.Fatalf("write rules: %v", err)
	}

	// Write empty users.toml
	usersContent := `# Manage users with: sknockd user add <name>
# Each user has a TOTP seed for authentication.
`
	if err := os.WriteFile(usersPath, []byte(usersContent), 0600); err != nil {
		log.Fatalf("write users: %v", err)
	}

	// Create log dir
	os.MkdirAll("/var/log/sknock", 0750)

	fmt.Println("Sknock initialized successfully!")
	fmt.Println()
	fmt.Printf("  Config:     %s\n", configPath)
	fmt.Printf("  Rules:      %s\n", rulesPath)
	fmt.Printf("  Users:      %s\n", usersPath)
	fmt.Printf("  Public key: %s\n", pubB64)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Edit rules in %s\n", rulesPath)
	fmt.Println("  2. Add users:  sknockd user add <name>")
	fmt.Println("  3. Start:      sknockd run")
	fmt.Println()
	fmt.Println("Open the listening port:")
	fmt.Println("  sudo ufw allow 58432/udp")
}

// ---------------------------------------------------------------------------
// genkey
// ---------------------------------------------------------------------------

func cmdGenkey() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())

	fmt.Printf("Private key (spa_privkey_b64):\n  %s\n\n", privB64)
	fmt.Printf("Public key (server_pubkey):\n  %s\n", pubB64)
}

// ---------------------------------------------------------------------------
// user add
// ---------------------------------------------------------------------------

func cmdUserAdd() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: sknockd user add <username> [--config-dir path]\n")
		os.Exit(1)
	}

	username := os.Args[3]
	configDir := defaultConfigDir
	for i := 4; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--config-dir" {
			configDir = os.Args[i+1]
		}
	}

	configPath := configDir + "/sknock.toml"
	usersPath := configDir + "/users.toml"

	// Load server config to get pubkey
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v\nRun 'sknockd init' first.", err)
	}

	// Derive pubkey for display
	privBytes, err := base64.StdEncoding.DecodeString(cfg.Server.SPAPrivkeyB64)
	if err != nil {
		log.Fatalf("decode private key: %v", err)
	}
	serverPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())

	// Load existing users
	users, err := config.LoadOrCreateUsersConfig(usersPath)
	if err != nil {
		log.Fatalf("load users: %v", err)
	}

	if _, exists := users.Users[username]; exists {
		fmt.Fprintf(os.Stderr, "User %q already exists.\n", username)
		os.Exit(1)
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Sknock",
		AccountName: username,
	})
	if err != nil {
		log.Fatalf("generate TOTP: %v", err)
	}

	seed := key.Secret()
	_ = key.URL() // URL is embedded in the provision token for client-side QR

	// Add user to config
	nextUID := len(users.Users) + 1
	users.Users[username] = config.UserEntry{
		OTPSeed: seed,
		UID:     nextUID,
	}

	if err := config.SaveUsersConfig(usersPath, users); err != nil {
		log.Fatalf("save users: %v", err)
	}

	fmt.Printf("User %q added successfully!\n\n", username)

	// Build provision token
	host := detectHost()
	port := cfg.Server.ListenPort
	token := config.BuildProvisionToken(host, port, pubB64, username, seed)

	fmt.Println("Send this command to the user (the QR code will be shown on their side):")
	fmt.Println()
	fmt.Printf("  sknock add <name> %s\n", token)
	fmt.Println()
	fmt.Println("If the server is behind NAT, replace the IP in the token.")
}

func cmdUserList() {
	configDir := defaultConfigDir
	for i := 3; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--config-dir" {
			configDir = os.Args[i+1]
		}
	}

	usersPath := configDir + "/users.toml"
	users, err := config.LoadUsersConfig(usersPath)
	if err != nil {
		log.Fatalf("load users: %v", err)
	}

	if len(users.Users) == 0 {
		fmt.Println("No users configured.")
		return
	}

	fmt.Printf("%-20s %-5s %s\n", "USERNAME", "UID", "SEED")
	fmt.Printf("%-20s %-5s %s\n", "--------", "---", "----")
	for name, u := range users.Users {
		// Show only first/last 4 chars of seed for security
		seed := u.OTPSeed
		if len(seed) > 8 {
			seed = seed[:4] + "..." + seed[len(seed)-4:]
		}
		fmt.Printf("%-20s %-5d %s\n", name, u.UID, seed)
	}
}

// detectHost returns the best guess for this server's reachable address.
// Prefers the outbound IP (likely the one clients will connect to).
func detectHost() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		addr := conn.LocalAddr().(*net.UDPAddr)
		return addr.IP.String()
	}
	if h, err := os.Hostname(); err == nil && h != "localhost" {
		return h
	}
	return "<server-ip>"
}

// ---------------------------------------------------------------------------
// run — main listener
// ---------------------------------------------------------------------------

func cmdRun() {
	configPath := defaultConfigPath
	usersPath := defaultUsersPath

	for i := 2; i < len(os.Args)-1; i++ {
		switch os.Args[i] {
		case "--config":
			configPath = os.Args[i+1]
			i++
		case "--users":
			usersPath = os.Args[i+1]
			i++
		}
	}

	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		log.Fatalf("config: %v\nRun 'sknockd init' first.", err)
	}

	users, err := config.LoadUsersConfig(usersPath)
	if err != nil {
		log.Fatalf("users: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(cfg.Server.SPAPrivkeyB64)
	if err != nil {
		log.Fatalf("decode private key: %v", err)
	}
	serverPriv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		log.Fatalf("load private key: %v", err)
	}

	pubB64 := base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes())
	log.Printf("Server public key: %s", pubB64)
	log.Printf("Loaded %d users, %d rules", len(users.Users), len(cfg.Rules))

	rules := make(map[string]*config.RuleConfig, len(cfg.Rules))
	for i := range cfg.Rules {
		rules[cfg.Rules[i].Name] = &cfg.Rules[i]
		log.Printf("  rule: %s", cfg.Rules[i].Name)
	}

	blacklist := make(map[string]bool, len(cfg.Security.IPBlacklist))
	for _, ip := range cfg.Security.IPBlacklist {
		blacklist[ip] = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nonceTTL := time.Duration(cfg.Security.NonceTTL) * time.Second
	nonceStore := nonce.NewStore(nonceTTL)
	nonceStore.StartCleanup(ctx)

	limiter := ratelimit.NewLimiter(cfg.Security.RateLimitPPS, cfg.Security.RateLimitBurst)
	limiter.StartCleanup(ctx, 5*time.Minute)

	var auditFile *os.File
	if cfg.Server.AuditLog != "" {
		os.MkdirAll(filepath.Dir(cfg.Server.AuditLog), 0750)
		auditFile, err = os.OpenFile(cfg.Server.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			log.Fatalf("open audit log: %v", err)
		}
		defer auditFile.Close()
	}

	addr := net.JoinHostPort(cfg.Server.ListenAddr, fmt.Sprintf("%d", cfg.Server.ListenPort))
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	log.Printf("Listening on UDP %s", addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Printf("Shutting down...")
		cancel()
		conn.Close()
	}()

	handler := &packetHandler{
		serverPriv: serverPriv,
		users:      users,
		rules:      rules,
		blacklist:  blacklist,
		nonceStore: nonceStore,
		limiter:    limiter,
		auditFile:  auditFile,
	}

	buf := make([]byte, 512)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("read error: %v", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go handler.process(data, remoteAddr)
	}
}

// ---------------------------------------------------------------------------
// packet handler
// ---------------------------------------------------------------------------

type packetHandler struct {
	serverPriv *ecdh.PrivateKey
	users      *config.UsersConfig
	rules      map[string]*config.RuleConfig
	blacklist  map[string]bool
	nonceStore *nonce.Store
	limiter    *ratelimit.Limiter
	auditFile  *os.File
}

func (h *packetHandler) process(data []byte, addr net.Addr) {
	srcIP := extractIP(addr.String())

	if len(data) != spa.PacketSize {
		return
	}

	if h.blacklist[srcIP] {
		return
	}

	if !h.limiter.Allow(srcIP) {
		h.audit("knock_rejected", srcIP, "", "", "rate_limited")
		return
	}

	pkt, err := spa.ParsePacket(data, h.serverPriv)
	if err != nil {
		return
	}

	nonceBytes := spa.Nonce(data)
	if !h.nonceStore.CheckAndStore(nonceBytes) {
		h.audit("knock_rejected", srcIP, pkt.UID, "", "replay")
		return
	}

	user, ok := h.users.Users[pkt.UID]
	if !ok {
		h.audit("knock_rejected", srcIP, pkt.UID, "", "unknown_user")
		return
	}
	if !totppkg.Verify(user.OTPSeed, pkt.OTP) {
		h.audit("knock_rejected", srcIP, pkt.UID, "", "otp_failed")
		log.Printf("[DROP] OTP failed src=%s uid=%s", srcIP, pkt.UID)
		return
	}

	rule, ok := h.rules[pkt.Rule]
	if !ok {
		h.audit("knock_rejected", srcIP, pkt.UID, pkt.Rule, "unknown_rule")
		return
	}

	if !rule.AllowsUser(pkt.UID) {
		h.audit("knock_rejected", srcIP, pkt.UID, pkt.Rule, "user_not_allowed")
		return
	}

	vars := map[string]string{
		"ip":        srcIP,
		"uid":       pkt.UID,
		"timestamp": fmt.Sprintf("%d", pkt.Timestamp),
		"rule":      pkt.Rule,
	}

	if rule.Action != "" {
		if err := execpkg.Run(rule.Action, vars, rule.ExecuteAs); err != nil {
			h.audit("action_failed", srcIP, pkt.UID, pkt.Rule, err.Error())
			log.Printf("[ERROR] action failed src=%s uid=%s rule=%s: %v", srcIP, pkt.UID, pkt.Rule, err)
			return
		}
	}

	if rule.UndoAfter > 0 && rule.UndoAction != "" {
		execpkg.Schedule(time.Duration(rule.UndoAfter)*time.Second, rule.UndoAction, vars, rule.ExecuteAs)
		log.Printf("[UNDO SCHEDULED] rule=%s uid=%s in %ds", pkt.Rule, pkt.UID, rule.UndoAfter)
	}

	h.audit("knock_accepted", srcIP, pkt.UID, pkt.Rule, "")
	log.Printf("[ACCEPTED] src=%s uid=%s rule=%s", srcIP, pkt.UID, pkt.Rule)
}

func (h *packetHandler) audit(event, srcIP, uid, rule, reason string) {
	if h.auditFile == nil {
		return
	}

	entry := map[string]string{
		"time":   time.Now().UTC().Format(time.RFC3339),
		"event":  event,
		"src_ip": srcIP,
	}
	if uid != "" {
		entry["uid"] = uid
	}
	if rule != "" {
		entry["rule"] = rule
	}
	if reason != "" {
		entry["reason"] = reason
	}

	line, _ := json.Marshal(entry)
	line = append(line, '\n')
	h.auditFile.Write(line)
}

func extractIP(addrStr string) string {
	if idx := strings.LastIndex(addrStr, ":"); idx >= 0 {
		ip := addrStr[:idx]
		return strings.Trim(ip, "[]")
	}
	return addrStr
}
