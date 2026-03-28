package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

const tokenPrefix = "sknock://"

type ClientConfig struct {
	Default string                 `toml:"default"`
	Servers map[string]ServerEntry `toml:"servers"`
}

type ServerEntry struct {
	Host         string `toml:"host"`
	Port         int    `toml:"port"`
	UID          string `toml:"uid"`
	ServerPubkey string `toml:"server_pubkey"`
}

func ClientConfigPath() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sknock", "config.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sknock", "config.toml")
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	var cfg ClientConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("load client config %s: %w", path, err)
	}
	if cfg.Servers == nil {
		cfg.Servers = make(map[string]ServerEntry)
	}
	return &cfg, nil
}

func LoadOrCreateClientConfig(path string) (*ClientConfig, error) {
	cfg, err := LoadClientConfig(path)
	if err != nil {
		if os.IsNotExist(err) || cfg == nil {
			return &ClientConfig{Servers: make(map[string]ServerEntry)}, nil
		}
		return nil, err
	}
	return cfg, nil
}

// SaveClientConfig writes the config to disk with proper permissions.
func SaveClientConfig(path string, cfg *ClientConfig) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}

// BuildProvisionToken encodes server connection details into a single token.
// Format: sknock://<base64(host:port:pubkey:uid:seed)>
func BuildProvisionToken(host string, port int, pubkey, uid, seed string) string {
	raw := fmt.Sprintf("%s:%d:%s:%s:%s", host, port, pubkey, uid, seed)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeProvisionToken parses a provision token into a ServerEntry and the TOTP seed.
// The seed is returned separately and NOT stored in the ServerEntry — it should only
// be shown to the user (QR code) and never saved to disk, preserving true 2FA.
func DecodeProvisionToken(token string) (entry *ServerEntry, seed string, err error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return nil, "", fmt.Errorf("token must start with %s", tokenPrefix)
	}

	encoded := strings.TrimPrefix(token, tokenPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("invalid token encoding: %w", err)
	}

	parts := strings.SplitN(string(raw), ":", 5)
	if len(parts) != 5 {
		return nil, "", fmt.Errorf("invalid token format: expected host:port:pubkey:uid:seed")
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("invalid port in token: %w", err)
	}

	return &ServerEntry{
		Host:         parts[0],
		Port:         port,
		ServerPubkey: parts[2],
		UID:          parts[3],
	}, parts[4], nil
}
