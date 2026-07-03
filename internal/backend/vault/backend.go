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

// Package vault implements the SecretBackend interface as a passthrough to a
// real HashiCorp Vault server. It authenticates with Vault using the
// Kubernetes auth method (the gateway's pod service-account token) and reads
// secrets from a KV v2 mount. A static token may be supplied instead, which is
// used primarily for development and tests.
package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// backendName is the identifier reported by Name and used as the metrics label.
const backendName = "vault"

// kvMount is the KV v2 mount this backend reads from.
const kvMount = "secret"

// defaultAuthPath is the default Kubernetes auth mount path in Vault.
const defaultAuthPath = "kubernetes"

// saTokenPath is the in-cluster location of the pod service-account JWT used
// for Kubernetes auth.
const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: well-known path, not a credential

// Config is the real-Vault passthrough backend configuration.
type Config struct {
	// Address is the Vault server URL (e.g. "https://vault.svc:8200").
	Address string
	// AuthPath is the Kubernetes auth mount path in Vault. Defaults to
	// "kubernetes".
	AuthPath string
	// Role is the Vault role the gateway authenticates as.
	Role string
	// TLSSkipVerify disables TLS certificate verification. Insecure; logs a
	// warning when enabled.
	TLSSkipVerify bool
	// CACert is the path to a CA certificate file used to verify the Vault
	// server. Empty uses the system root pool.
	CACert string
	// Token is an optional static Vault token. When set, Kubernetes login is
	// skipped entirely. Intended for tests and development.
	Token string
	// SecretPrefix is prepended to every requested path before reading from the
	// KV v2 mount. Typically an environment prefix such as "prod/".
	SecretPrefix string
	// Cache configures the in-memory secret cache embedded by the backend.
	Cache cache.Config
}

// Backend is a passthrough SecretBackend backed by a real Vault server. It is
// safe for concurrent use: the Vault client and the cache are both
// concurrency-safe.
type Backend struct {
	client *vaultapi.Client
	cache  *cache.Cache
	prefix string
	metric *metrics.Metrics
	logger *slog.Logger

	// cancel stops the background token-renewal goroutine. It is nil when a
	// static token is used (no renewal is performed).
	cancel context.CancelFunc
}

// Ensure Backend satisfies the contract at compile time.
var _ backend.SecretBackend = (*Backend)(nil)

// New constructs a real-Vault passthrough backend. The metrics pointer may be
// nil, in which case metric recording is skipped. A nil logger falls back to
// slog.Default.
//
// When cfg.Token is set the backend uses it directly. Otherwise it
// authenticates via the Kubernetes auth method using the pod service-account
// token; if that token file is absent (i.e. the gateway is not running inside a
// cluster) New returns an error.
func New(ctx context.Context, cfg Config, m *metrics.Metrics, logger *slog.Logger) (backend.SecretBackend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.AuthPath == "" {
		cfg.AuthPath = defaultAuthPath
	}

	apiCfg := vaultapi.DefaultConfig()
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("vault: default config: %w", apiCfg.Error)
	}
	apiCfg.Address = cfg.Address

	if cfg.TLSSkipVerify {
		logger.Warn("vault TLS certificate verification is disabled; do not use in production")
	}
	if err := apiCfg.ConfigureTLS(&vaultapi.TLSConfig{
		Insecure: cfg.TLSSkipVerify,
		CACert:   cfg.CACert,
	}); err != nil {
		return nil, fmt.Errorf("vault: configure tls: %w", err)
	}

	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}

	b := &Backend{
		client: client,
		cache:  cache.New(cfg.Cache),
		prefix: cfg.SecretPrefix,
		metric: m,
		logger: logger,
	}

	if cfg.Token != "" {
		// Static token: skip Kubernetes login and any renewal.
		client.SetToken(cfg.Token)
		b.logger.Info("vault backend initialized with static token",
			"address", cfg.Address, "tls_skip_verify", cfg.TLSSkipVerify)
		return b, nil
	}

	secret, err := b.login(ctx, cfg)
	if err != nil {
		return nil, err
	}

	// Start background renewal only when the issued token is renewable.
	if secret != nil && secret.Auth != nil && secret.Auth.Renewable {
		renewCtx, cancel := context.WithCancel(context.Background())
		b.cancel = cancel
		if err := b.startRenewal(renewCtx, secret); err != nil {
			cancel()
			b.cancel = nil
			b.logger.Warn("vault token renewal could not be started", "error", err)
		}
	}

	b.logger.Info("vault backend initialized with kubernetes auth",
		"address", cfg.Address, "auth_path", cfg.AuthPath, "role", cfg.Role,
		"tls_skip_verify", cfg.TLSSkipVerify)
	return b, nil
}

// login authenticates against Vault's Kubernetes auth method and sets the
// resulting client token. It is isolated so tests can bypass it by supplying a
// static Token in the Config passed to New.
func (b *Backend) login(ctx context.Context, cfg Config) (*vaultapi.Secret, error) {
	jwt, err := os.ReadFile(saTokenPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("vault: no static token set and service-account token %q not found (not running in a cluster?): %w", saTokenPath, err)
		}
		return nil, fmt.Errorf("vault: read service-account token: %w", err)
	}

	loginPath := fmt.Sprintf("auth/%s/login", cfg.AuthPath)
	secret, err := b.client.Logical().WriteWithContext(ctx, loginPath, map[string]interface{}{
		"role": cfg.Role,
		"jwt":  string(jwt),
	})
	if err != nil {
		return nil, fmt.Errorf("vault: kubernetes login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("vault: kubernetes login returned no client token")
	}

	b.client.SetToken(secret.Auth.ClientToken)
	return secret, nil
}

// startRenewal launches a background goroutine that keeps the login token
// renewed until ctx is canceled (via Close).
func (b *Backend) startRenewal(ctx context.Context, secret *vaultapi.Secret) error {
	watcher, err := b.client.NewLifetimeWatcher(&vaultapi.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		return fmt.Errorf("vault: new lifetime watcher: %w", err)
	}

	go watcher.Start()
	go func() {
		defer watcher.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-watcher.DoneCh():
				if err != nil {
					b.logger.Warn("vault token renewal stopped", "error", err)
				}
				return
			case <-watcher.RenewCh():
				b.logger.Debug("vault token renewed")
			}
		}
	}()
	return nil
}

// GetSecret reads the KV v2 secret at path and returns its key-value pairs.
func (b *Backend) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	path = b.prefix + path
	if value, hit, isNegative := b.cache.Get(path); hit {
		b.recordCacheHit()
		if isNegative {
			return nil, backend.ErrSecretNotFound
		}
		return value, nil
	}
	b.recordCacheMiss()

	secret, err := b.client.KVv2(kvMount).Get(ctx, path)
	if err != nil {
		if isNotFound(err) {
			b.cache.SetNegative(path)
			return nil, backend.ErrSecretNotFound
		}
		// The Vault client does not embed secret values in errors.
		b.logger.Warn("vault get secret failed", "path", path, "error", err)
		return nil, fmt.Errorf("vault: get secret: %w", backend.ErrBackendUnavailable)
	}
	if secret == nil || secret.Data == nil {
		b.cache.SetNegative(path)
		return nil, backend.ErrSecretNotFound
	}

	result := convertData(secret.Data)
	b.cache.Set(path, result)
	b.updateCacheEntries()
	return result, nil
}

// isNotFound reports whether err represents a missing secret: either the
// KVv2 sentinel or a raw 404 response from Vault.
func isNotFound(err error) bool {
	if errors.Is(err, vaultapi.ErrSecretNotFound) {
		return true
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == 404 {
		return true
	}
	return false
}

// convertData flattens a KV v2 data map to string values. Non-string values are
// rendered with fmt.Sprintf("%v").
func convertData(data map[string]interface{}) map[string]string {
	out := make(map[string]string, len(data))
	for k, v := range data {
		if s, ok := v.(string); ok {
			out[k] = s
			continue
		}
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// HealthCheck verifies connectivity to the Vault server.
func (b *Backend) HealthCheck(ctx context.Context) error {
	if _, err := b.client.Sys().HealthWithContext(ctx); err != nil {
		b.logger.Warn("vault health check failed", "error", err)
		return fmt.Errorf("vault: health check: %w", backend.ErrBackendUnavailable)
	}
	return nil
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return backendName }

// Close stops the token-renewal goroutine, if any.
func (b *Backend) Close() error {
	if b.cancel != nil {
		b.cancel()
	}
	return nil
}

func (b *Backend) recordCacheHit() {
	if b.metric != nil {
		b.metric.CacheHits.WithLabelValues(backendName).Inc()
	}
}

func (b *Backend) recordCacheMiss() {
	if b.metric != nil {
		b.metric.CacheMisses.WithLabelValues(backendName).Inc()
	}
}

func (b *Backend) updateCacheEntries() {
	if b.metric != nil {
		b.metric.CacheEntries.WithLabelValues(backendName).Set(float64(b.cache.Len()))
	}
}
