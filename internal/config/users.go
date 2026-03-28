package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type UsersConfig struct {
	Users map[string]UserEntry `toml:"users"`
}

type UserEntry struct {
	OTPSeed string `toml:"otp_seed"`
	UID     int    `toml:"uid"`
}

func LoadUsersConfig(path string) (*UsersConfig, error) {
	var cfg UsersConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("load users %s: %w", path, err)
	}
	if cfg.Users == nil {
		cfg.Users = make(map[string]UserEntry)
	}
	return &cfg, nil
}

func LoadOrCreateUsersConfig(path string) (*UsersConfig, error) {
	cfg, err := LoadUsersConfig(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &UsersConfig{Users: make(map[string]UserEntry)}, nil
		}
		// File exists but may have no [users] section yet — that's ok
		return &UsersConfig{Users: make(map[string]UserEntry)}, nil
	}
	return cfg, nil
}

func SaveUsersConfig(path string, cfg *UsersConfig) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("write users config: %w", err)
	}
	defer f.Close()

	enc := toml.NewEncoder(f)
	return enc.Encode(cfg)
}
