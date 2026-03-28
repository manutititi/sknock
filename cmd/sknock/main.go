package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/manu/sknock/internal/config"
	"github.com/manu/sknock/internal/spa"
)

const (
	defaultRetries = 3
	retryDelay     = 200 * time.Millisecond
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "add":
		cmdAdd()
	case "ls":
		cmdList()
	case "help", "--help", "-h":
		printUsage()
	default:
		cmdKnock()
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: sknock <command>

Setup:
  sknock add <name> <token>     Add a server (token from your admin)
  sknock ls                     List configured servers

Knock:
  sknock <server> <rule> <otp>  Send a knock (OTP from authenticator app)

Examples:
  sknock add prod sknock://NDYuMjI1LjIxNC4xNDQ6NTg0MzI6eGsz...
  sknock prod open_ssh 482901
`)
}

// ---------------------------------------------------------------------------
// add — provision from token or manual args
//   sknock add <name> <token>
// ---------------------------------------------------------------------------

func cmdAdd() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: sknock add <name> <token>\n")
		fmt.Fprintf(os.Stderr, "\nThe token is provided by the server admin (sknockd user add output).\n")
		os.Exit(1)
	}

	name := os.Args[2]
	token := os.Args[3]

	entry, seed, err := config.DecodeProvisionToken(token)
	if err != nil {
		log.Fatalf("Invalid provision token: %v", err)
	}

	// Validate pubkey
	decoded, err := base64.StdEncoding.DecodeString(entry.ServerPubkey)
	if err != nil || len(decoded) != 32 {
		log.Fatalf("Invalid server public key in token")
	}

	cfgPath := config.ClientConfigPath()
	cfg, err := config.LoadOrCreateClientConfig(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	cfg.Servers[name] = *entry

	if cfg.Default == "" {
		cfg.Default = name
	}

	if err := config.SaveClientConfig(cfgPath, cfg); err != nil {
		log.Fatalf("save config: %v", err)
	}

	fmt.Printf("Server %q added to %s\n\n", name, cfgPath)
	fmt.Printf("  Host:   %s:%d\n", entry.Host, entry.Port)
	fmt.Printf("  UID:    %s\n", entry.UID)
	pk := entry.ServerPubkey
	if len(pk) > 12 {
		pk = pk[:8] + "..." + pk[len(pk)-4:]
	}
	fmt.Printf("  Pubkey: %s\n", pk)

	// Show TOTP QR code for authenticator app — seed is NOT saved to disk
	provURL := fmt.Sprintf("otpauth://totp/Sknock:%s?secret=%s&issuer=Sknock&algorithm=SHA1&digits=6&period=30", entry.UID, seed)
	qr, err := qrcode.New(provURL, qrcode.Medium)
	if err == nil {
		fmt.Println()
		fmt.Println("Scan this QR with your authenticator app (Google Authenticator, Authy, etc.):")
		fmt.Println()
		fmt.Println(qr.ToSmallString(false))
		fmt.Println("⚠  The TOTP seed is NOT saved. You must use your authenticator app for OTP codes.")
	}

	fmt.Printf("\nKnock with:\n  sknock %s <rule> <otp>\n", name)
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

func cmdList() {
	cfgPath := config.ClientConfigPath()
	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		fmt.Printf("No config found at %s\n", cfgPath)
		fmt.Println("Add a server with: sknock add <name> <token>")
		return
	}

	if len(cfg.Servers) == 0 {
		fmt.Println("No servers configured.")
		return
	}

	fmt.Printf("%-15s %-25s %-7s %-10s %s\n", "NAME", "HOST", "PORT", "UID", "DEFAULT")
	fmt.Printf("%-15s %-25s %-7s %-10s %s\n", "----", "----", "----", "---", "-------")
	for name, s := range cfg.Servers {
		def := ""
		if name == cfg.Default {
			def = "*"
		}
		fmt.Printf("%-15s %-25s %-7d %-10s %s\n", name, s.Host, s.Port, s.UID, def)
	}
}

// ---------------------------------------------------------------------------
// knock — sknock <server> <rule> <otp>
// ---------------------------------------------------------------------------

func isOTP(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func cmdKnock() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: sknock <server> <rule> <otp>\n")
		os.Exit(1)
	}

	serverName := os.Args[1]
	rule := os.Args[2]
	otpCode := os.Args[3]

	if !isOTP(otpCode) {
		log.Fatalf("OTP must be exactly 6 digits, got %q", otpCode)
	}

	cfgPath := config.ClientConfigPath()
	cfg, err := config.LoadClientConfig(cfgPath)
	if err != nil {
		log.Fatalf("No config found. Run 'sknock add' first.\n  Config path: %s", cfgPath)
	}

	server, ok := cfg.Servers[serverName]
	if !ok {
		available := make([]string, 0, len(cfg.Servers))
		for name := range cfg.Servers {
			available = append(available, name)
		}
		log.Fatalf("Server %q not found. Available: %s", serverName, strings.Join(available, ", "))
	}

	// Check config file permissions
	info, err := os.Stat(cfgPath)
	if err == nil {
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			fmt.Fprintf(os.Stderr, "WARNING: %s has permissions %o (should be 600)\n  Fix: chmod 600 %s\n\n", cfgPath, perm, cfgPath)
		}
	}

	serverPub, err := base64.StdEncoding.DecodeString(server.ServerPubkey)
	if err != nil {
		log.Fatalf("Invalid server public key in config: %v", err)
	}

	pkt, err := spa.BuildPacket(server.UID, otpCode, rule, serverPub)
	if err != nil {
		log.Fatalf("Build packet: %v", err)
	}

	addr := net.JoinHostPort(server.Host, fmt.Sprintf("%d", server.Port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	for i := range defaultRetries {
		if _, err := conn.Write(pkt); err != nil {
			log.Fatalf("Send: %v", err)
		}
		if i < defaultRetries-1 {
			time.Sleep(retryDelay)
		}
	}

	fmt.Printf("Knock sent to %s -> rule %q\n", serverName, rule)
}
