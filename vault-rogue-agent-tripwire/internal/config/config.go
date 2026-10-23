package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config holds all tripwire configuration loaded from YAML.
type Config struct {
	ListenAddr           string   `yaml:"listen_addr"`
	VaultAddr            string   `yaml:"vault_addr"`
	DryRun               bool     `yaml:"dry_run"`
	EvalRolePattern      string   `yaml:"eval_role_pattern"`
	LeasePrefixTemplate  string   `yaml:"lease_prefix_template"`
	KVMounts             []string `yaml:"kv_mounts"`
	Decoys               []string `yaml:"decoys"`
	Notify               Notify   `yaml:"notify"`
	Ingest               Ingest   `yaml:"ingest"`

	// Compiled eval role pattern — set by Load, not from YAML.
	evalRoleRe *regexp.Regexp
}

// Notify holds notification configuration.
type Notify struct {
	WebhookURL string `yaml:"webhook_url"`
}

// Ingest holds ingest-pipeline configuration.
type Ingest struct {
	BufferSize int `yaml:"buffer_size"`
}

// EvalRoleRe returns the compiled eval role regexp.
func (c *Config) EvalRoleRe() *regexp.Regexp {
	return c.evalRoleRe
}

// Load reads and validates the YAML config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// validate applies defaults and checks required fields.
func (c *Config) validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:9090"
	}
	if c.VaultAddr == "" {
		c.VaultAddr = "http://127.0.0.1:8200"
	}
	if c.EvalRolePattern == "" {
		c.EvalRolePattern = `^eval-[a-z0-9-]+$`
	}
	if c.LeasePrefixTemplate == "" {
		c.LeasePrefixTemplate = "database/creds/{{.Role}}"
	}
	if c.Ingest.BufferSize <= 0 {
		c.Ingest.BufferSize = 10000
	}

	re, err := regexp.Compile(c.EvalRolePattern)
	if err != nil {
		return fmt.Errorf("invalid eval_role_pattern %q: %w", c.EvalRolePattern, err)
	}
	c.evalRoleRe = re

	if len(c.Decoys) == 0 {
		return fmt.Errorf("at least one decoy path must be configured")
	}

	return nil
}
