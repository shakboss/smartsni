package lib

import (
	"fmt"
	"strings"
)

type FrontingConfig struct {
	Enabled        bool     `json:"enabled"`
	FrontHost      string   `json:"frontHost"`
	FrontSni       string   `json:"frontSni"`
	UpstreamHost   string   `json:"upstreamHost"`
	AllowedOrigins []string `json:"allowedOrigins"`
}

func ValidateFronting(cfg *FrontingConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.FrontHost == "" {
		return fmt.Errorf("fronting: frontHost is required")
	}
	if cfg.FrontSni == "" {
		return fmt.Errorf("fronting: frontSni is required")
	}
	if cfg.UpstreamHost == "" {
		return fmt.Errorf("fronting: upstreamHost is required")
	}
	return nil
}

func (cfg *FrontingConfig) GetHostHeader() string {
	if cfg.Enabled && cfg.UpstreamHost != "" {
		return cfg.UpstreamHost
	}
	return cfg.FrontHost
}

func (cfg *FrontingConfig) IsAllowedOrigin(origin string) bool {
	if !cfg.Enabled {
		return true
	}
	origin = strings.ToLower(origin)
	for _, allowed := range cfg.AllowedOrigins {
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}
