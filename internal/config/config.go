// Copyright 2026 The Vault Gateway Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config defines the gateway's configuration schema and the loading,
// defaulting, environment-override, and validation logic. Configuration is
// read from a YAML file; a curated set of VG_-prefixed environment variables
// override file values.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vault-gateway/vault-gateway/internal/cache"
)

// Duration is a time.Duration that unmarshals from YAML strings such as "30s"
// or "5m" via time.ParseDuration.
type Duration time.Duration

// UnmarshalYAML parses a duration from a scalar string (e.g. "300s").
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML renders the duration back to its string form.
func (d Duration) MarshalYAML() (interface{}, error) { return d.Std().String(), nil }

// Std returns the value as a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the root configuration document.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Backend     string            `yaml:"backend"`
	AWS         AWSConfig         `yaml:"aws"`
	Azure       AzureConfig       `yaml:"azure"`
	Vault       VaultConfig       `yaml:"vault"`
	GCP         GCPConfig         `yaml:"gcp"`
	Auth        AuthConfig        `yaml:"auth"`
	Logging     LoggingConfig     `yaml:"logging"`
	Metrics     MetricsConfig     `yaml:"metrics"`
	HealthCheck HealthCheckConfig `yaml:"healthCheck"`
	RateLimit   RateLimitConfig   `yaml:"rateLimit"`
	CORS        CORSConfig        `yaml:"cors"`
}

// ServerConfig controls the Vault-compatible HTTPS API server.
type ServerConfig struct {
	Port                int       `yaml:"port"`
	Host                string    `yaml:"host"`
	TLS                 TLSConfig `yaml:"tls"`
	ReadTimeout         Duration  `yaml:"readTimeout"`
	WriteTimeout        Duration  `yaml:"writeTimeout"`
	IdleTimeout         Duration  `yaml:"idleTimeout"`
	MaxRequestBodySize  int64     `yaml:"maxRequestBodySize"`
	ShutdownGracePeriod Duration  `yaml:"shutdownGracePeriod"`
}

// TLSConfig configures transport security for the API server.
type TLSConfig struct {
	Enabled      bool     `yaml:"enabled"`
	CertFile     string   `yaml:"certFile"`
	KeyFile      string   `yaml:"keyFile"`
	MinVersion   string   `yaml:"minVersion"`
	CipherSuites []string `yaml:"cipherSuites"`
}

// CacheConfig is the file-level cache configuration; ToCache converts it to the
// internal cache.Config consumed by backends.
type CacheConfig struct {
	Enabled     bool     `yaml:"enabled"`
	TTL         Duration `yaml:"ttl"`
	MaxEntries  int      `yaml:"maxEntries"`
	NegativeTTL Duration `yaml:"negativeTTL"`
}

// ToCache maps the file-level cache config to the runtime cache.Config.
func (c CacheConfig) ToCache() cache.Config {
	return cache.Config{
		Enabled:     c.Enabled,
		TTL:         c.TTL.Std(),
		NegativeTTL: c.NegativeTTL.Std(),
		MaxEntries:  c.MaxEntries,
	}
}

// AWSConfig configures the AWS Secrets Manager backend.
type AWSConfig struct {
	Region       string      `yaml:"region"`
	SecretPrefix string      `yaml:"secretPrefix"`
	EndpointURL  string      `yaml:"endpointURL"`
	MaxRetries   int         `yaml:"maxRetries"`
	Cache        CacheConfig `yaml:"cache"`
}

// AzureConfig configures the Azure Key Vault backend.
type AzureConfig struct {
	VaultURL       string      `yaml:"vaultURL"`
	NamingStrategy string      `yaml:"namingStrategy"`
	SecretPrefix   string      `yaml:"secretPrefix"`
	Cache          CacheConfig `yaml:"cache"`
}

// VaultConfig configures the real-Vault passthrough backend.
type VaultConfig struct {
	Address       string      `yaml:"address"`
	AuthPath      string      `yaml:"authPath"`
	Role          string      `yaml:"role"`
	TLSSkipVerify bool        `yaml:"tlsSkipVerify"`
	CACert        string      `yaml:"caCert"`
	Token         string      `yaml:"token"`
	SecretPrefix  string      `yaml:"secretPrefix"`
	Cache         CacheConfig `yaml:"cache"`
}

// GCPConfig configures the GCP Secret Manager backend.
type GCPConfig struct {
	ProjectID    string      `yaml:"projectID"`
	SecretPrefix string      `yaml:"secretPrefix"`
	Cache        CacheConfig `yaml:"cache"`
}

// AuthConfig controls token issuance and role bindings.
type AuthConfig struct {
	TokenTTL             Duration              `yaml:"tokenTTL"`
	TokenCleanupInterval Duration              `yaml:"tokenCleanupInterval"`
	MaxTokensPerIdentity int                   `yaml:"maxTokensPerIdentity"`
	Roles                map[string]RoleConfig `yaml:"roles"`
}

// RoleConfig binds a named role to namespaces, service accounts, and paths.
type RoleConfig struct {
	AllowedNamespaces      []string `yaml:"allowedNamespaces"`
	AllowedServiceAccounts []string `yaml:"allowedServiceAccounts"`
	AllowedPaths           []string `yaml:"allowedPaths"`
	TokenTTL               Duration `yaml:"tokenTTL"`
}

// LoggingConfig controls structured logging output.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig controls the metrics/health side server.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    string `yaml:"path"`
}

// HealthCheckConfig controls backend connectivity checks.
type HealthCheckConfig struct {
	BackendCheck         bool     `yaml:"backendCheck"`
	BackendCheckTimeout  Duration `yaml:"backendCheckTimeout"`
	BackendCheckInterval Duration `yaml:"backendCheckInterval"`
}

// RateLimitConfig controls the per-IP token-bucket rate limiter.
type RateLimitConfig struct {
	Enabled           bool    `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
	Burst             int     `yaml:"burst"`
}

// CORSConfig controls cross-origin handling (disabled by default).
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowedOrigins"`
}

// Supported backend identifiers.
const (
	BackendAWS   = "aws"
	BackendAzure = "azure"
	BackendVault = "vault"
	BackendGCP   = "gcp"
)

// Load reads, defaults, env-overrides, and validates the config at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is operator-provided
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return parse(data)
}

// parse unmarshals raw YAML and finishes loading (defaults, env, validation).
func parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	cfg.applyEnvOverrides(os.LookupEnv)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDefaults fills sensible defaults for unset fields.
func (c *Config) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 8200
	}
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = Duration(30 * time.Second)
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = Duration(30 * time.Second)
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = Duration(120 * time.Second)
	}
	if c.Server.MaxRequestBodySize == 0 {
		c.Server.MaxRequestBodySize = 1 << 20 // 1 MiB
	}
	if c.Server.ShutdownGracePeriod == 0 {
		c.Server.ShutdownGracePeriod = Duration(15 * time.Second)
	}
	if c.Server.TLS.MinVersion == "" {
		c.Server.TLS.MinVersion = "1.2"
	}
	if c.Auth.TokenTTL == 0 {
		c.Auth.TokenTTL = Duration(3600 * time.Second)
	}
	if c.Auth.TokenCleanupInterval == 0 {
		c.Auth.TokenCleanupInterval = Duration(60 * time.Second)
	}
	if c.Auth.MaxTokensPerIdentity == 0 {
		c.Auth.MaxTokensPerIdentity = 100
	}
	if c.Azure.NamingStrategy == "" {
		c.Azure.NamingStrategy = "flat"
	}
	if c.Vault.AuthPath == "" {
		c.Vault.AuthPath = "kubernetes"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Metrics.Port == 0 {
		c.Metrics.Port = 9090
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}
	if c.HealthCheck.BackendCheckTimeout == 0 {
		c.HealthCheck.BackendCheckTimeout = Duration(5 * time.Second)
	}
	if c.HealthCheck.BackendCheckInterval == 0 {
		c.HealthCheck.BackendCheckInterval = Duration(30 * time.Second)
	}
	if c.RateLimit.RequestsPerSecond == 0 {
		c.RateLimit.RequestsPerSecond = 100
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 200
	}
}

// applyEnvOverrides applies the curated set of VG_-prefixed overrides. lookup
// is injected so tests can supply a deterministic environment.
func (c *Config) applyEnvOverrides(lookup func(string) (string, bool)) {
	if v, ok := lookup("VG_BACKEND"); ok {
		c.Backend = v
	}
	if v, ok := lookup("VG_SERVER_HOST"); ok {
		c.Server.Host = v
	}
	if v, ok := lookup("VG_SERVER_PORT"); ok {
		if p, err := strconv.Atoi(v); err == nil {
			c.Server.Port = p
		}
	}
	if v, ok := lookup("VG_METRICS_PORT"); ok {
		if p, err := strconv.Atoi(v); err == nil {
			c.Metrics.Port = p
		}
	}
	if v, ok := lookup("VG_LOG_LEVEL"); ok {
		c.Logging.Level = v
	}
	if v, ok := lookup("VG_LOG_FORMAT"); ok {
		c.Logging.Format = v
	}
	if v, ok := lookup("VG_TLS_CERT_FILE"); ok {
		c.Server.TLS.CertFile = v
	}
	if v, ok := lookup("VG_TLS_KEY_FILE"); ok {
		c.Server.TLS.KeyFile = v
	}
	if v, ok := lookup("VG_AWS_REGION"); ok {
		c.AWS.Region = v
	}
	if v, ok := lookup("VG_AZURE_VAULTURL"); ok {
		c.Azure.VaultURL = v
	}
	if v, ok := lookup("VG_VAULT_ADDRESS"); ok {
		c.Vault.Address = v
	}
	if v, ok := lookup("VG_VAULT_TOKEN"); ok {
		c.Vault.Token = v
	}
	if v, ok := lookup("VG_GCP_PROJECTID"); ok {
		c.GCP.ProjectID = v
	}
}

// Validate enforces the fail-fast rules described in the configuration docs.
func (c *Config) Validate() error {
	switch c.Backend {
	case BackendAWS, BackendAzure, BackendVault, BackendGCP:
	case "":
		return fmt.Errorf("backend must be set (one of aws, azure, vault, gcp)")
	default:
		return fmt.Errorf("unsupported backend %q (must be one of aws, azure, vault, gcp)", c.Backend)
	}

	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range 1-65535", c.Server.Port)
	}
	if c.Metrics.Port < 1 || c.Metrics.Port > 65535 {
		return fmt.Errorf("metrics.port %d out of range 1-65535", c.Metrics.Port)
	}
	if c.Server.Port == c.Metrics.Port {
		return fmt.Errorf("server.port and metrics.port must differ (both %d)", c.Server.Port)
	}

	if c.Server.TLS.Enabled {
		if err := fileExists(c.Server.TLS.CertFile, "server.tls.certFile"); err != nil {
			return err
		}
		if err := fileExists(c.Server.TLS.KeyFile, "server.tls.keyFile"); err != nil {
			return err
		}
		if _, err := parseTLSVersion(c.Server.TLS.MinVersion); err != nil {
			return err
		}
	}

	for _, d := range []struct {
		name string
		val  Duration
	}{
		{"server.readTimeout", c.Server.ReadTimeout},
		{"server.writeTimeout", c.Server.WriteTimeout},
		{"server.idleTimeout", c.Server.IdleTimeout},
		{"server.shutdownGracePeriod", c.Server.ShutdownGracePeriod},
		{"auth.tokenTTL", c.Auth.TokenTTL},
		{"auth.tokenCleanupInterval", c.Auth.TokenCleanupInterval},
	} {
		if d.val <= 0 {
			return fmt.Errorf("%s must be a positive duration", d.name)
		}
	}

	if len(c.Auth.Roles) == 0 {
		return fmt.Errorf("auth.roles must define at least one role")
	}
	for name, role := range c.Auth.Roles {
		if len(role.AllowedNamespaces) == 0 {
			return fmt.Errorf("auth.roles.%s: at least one allowedNamespaces entry required", name)
		}
		if len(role.AllowedPaths) == 0 {
			return fmt.Errorf("auth.roles.%s: at least one allowedPaths entry required", name)
		}
		if len(role.AllowedServiceAccounts) == 0 {
			return fmt.Errorf("auth.roles.%s: at least one allowedServiceAccounts entry required", name)
		}
	}

	if err := c.validateBackend(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateBackend() error {
	switch c.Backend {
	case BackendAzure:
		if c.Azure.VaultURL == "" {
			return fmt.Errorf("azure.vaultURL is required when backend is azure")
		}
		if c.Azure.NamingStrategy != "flat" && c.Azure.NamingStrategy != "json" {
			return fmt.Errorf("azure.namingStrategy must be \"flat\" or \"json\"")
		}
	case BackendVault:
		if c.Vault.Address == "" {
			return fmt.Errorf("vault.address is required when backend is vault")
		}
		if c.Vault.Role == "" && c.Vault.Token == "" {
			return fmt.Errorf("vault.role (or vault.token) is required when backend is vault")
		}
	case BackendGCP:
		if c.GCP.ProjectID == "" {
			return fmt.Errorf("gcp.projectID is required when backend is gcp")
		}
	case BackendAWS:
		// Region is resolved by the SDK default chain if unset; no hard requirement.
	}
	return nil
}

func fileExists(path, field string) error {
	if path == "" {
		return fmt.Errorf("%s is required when TLS is enabled", field)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

// parseTLSVersion maps a "1.2"/"1.3" string to the crypto/tls constant.
func parseTLSVersion(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "", "1.2":
		return 0x0303, nil // tls.VersionTLS12
	case "1.3":
		return 0x0304, nil // tls.VersionTLS13
	case "1.0", "1.1":
		return 0, fmt.Errorf("TLS minVersion %q is not allowed; use 1.2 or 1.3", v)
	default:
		return 0, fmt.Errorf("invalid TLS minVersion %q", v)
	}
}

// TLSMinVersion returns the crypto/tls version constant for the configured
// minimum. It assumes Validate has already accepted the value.
func (c *Config) TLSMinVersion() uint16 {
	ver, _ := parseTLSVersion(c.Server.TLS.MinVersion)
	if ver == 0 {
		return 0x0303
	}
	return ver
}
