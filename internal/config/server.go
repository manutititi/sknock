package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type ServerConfig struct {
	Server   ServerSection   `toml:"server"`
	Security SecuritySection `toml:"security"`
	Rules    []RuleConfig    `toml:"rule"`
}

type ServerSection struct {
	ListenAddr    string `toml:"listen_addr"`
	ListenPort    int    `toml:"listen_port"`
	LogFile       string `toml:"log_file"`
	LogLevel      string `toml:"log_level"`
	AuditLog      string `toml:"audit_log"`
	SPAPrivkeyB64 string `toml:"spa_privkey_b64"`
	RulesFile     string `toml:"rules_file"`
}

type SecuritySection struct {
	TimestampWindow int      `toml:"timestamp_window"`
	NonceTTL        int      `toml:"nonce_ttl"`
	RateLimitPPS    float64  `toml:"rate_limit_pps"`
	RateLimitBurst  int      `toml:"rate_limit_burst"`
	IPBlacklist     []string `toml:"ip_blacklist"`
	IPWhitelist     []string `toml:"ip_whitelist"`
}

type RuleConfig struct {
	Name         string   `toml:"name"`
	Action       string   `toml:"action"`
	UndoAction   string   `toml:"undo_action"`
	UndoAfter    int      `toml:"undo_after"`
	AllowedUsers []string `toml:"allowed_users"`
	ExecuteAs    string   `toml:"execute_as"`
}

// AllowsUser returns true if the user is allowed by this rule.
// Empty allowed_users means all users are allowed.
func (r *RuleConfig) AllowsUser(uid string) bool {
	if len(r.AllowedUsers) == 0 {
		return true
	}
	for _, u := range r.AllowedUsers {
		if u == uid {
			return true
		}
	}
	return false
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	var cfg ServerConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}

	// Defaults
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = "0.0.0.0"
	}
	if cfg.Server.ListenPort == 0 {
		cfg.Server.ListenPort = 58432
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}
	if cfg.Security.TimestampWindow == 0 {
		cfg.Security.TimestampWindow = 30
	}
	if cfg.Security.NonceTTL == 0 {
		cfg.Security.NonceTTL = 60
	}
	if cfg.Security.RateLimitPPS == 0 {
		cfg.Security.RateLimitPPS = 5
	}
	if cfg.Security.RateLimitBurst == 0 {
		cfg.Security.RateLimitBurst = 10
	}

	// Env overrides
	if v := os.Getenv("SKNOCK_PRIVKEY"); v != "" {
		cfg.Server.SPAPrivkeyB64 = v
	}
	if v := os.Getenv("SKNOCK_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.Server.ListenPort)
	}
	if v := os.Getenv("SKNOCK_LOG_LEVEL"); v != "" {
		cfg.Server.LogLevel = v
	}

	if cfg.Server.SPAPrivkeyB64 == "" {
		return nil, fmt.Errorf("spa_privkey_b64 is required (set in config or SKNOCK_PRIVKEY env)")
	}

	// Load rules from separate file if specified
	if cfg.Server.RulesFile != "" {
		rulesPath := cfg.Server.RulesFile
		if !filepath.IsAbs(rulesPath) {
			rulesPath = filepath.Join(filepath.Dir(path), rulesPath)
		}
		var rulesFile struct {
			Rules []RuleConfig `toml:"rule"`
		}
		if _, err := toml.DecodeFile(rulesPath, &rulesFile); err != nil {
			return nil, fmt.Errorf("load rules file %s: %w", rulesPath, err)
		}
		cfg.Rules = append(cfg.Rules, rulesFile.Rules...)
	}

	return &cfg, nil
}
