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

// Command vault-gateway is a Vault API-compatible shim that routes secret reads
// to cloud-native secret backends (AWS Secrets Manager, Azure Key Vault, GCP
// Secret Manager, or a real HashiCorp Vault).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/api"
	"github.com/vault-gateway/vault-gateway/internal/auth"
	"github.com/vault-gateway/vault-gateway/internal/backend"
	awsbackend "github.com/vault-gateway/vault-gateway/internal/backend/aws"
	azurebackend "github.com/vault-gateway/vault-gateway/internal/backend/azure"
	gcpbackend "github.com/vault-gateway/vault-gateway/internal/backend/gcp"
	vaultbackend "github.com/vault-gateway/vault-gateway/internal/backend/vault"
	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
	"github.com/vault-gateway/vault-gateway/internal/server"
	"github.com/vault-gateway/vault-gateway/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  string
		kubeconfig  string
		showVersion bool
	)
	flag.StringVar(&configPath, "config", os.Getenv("VAULT_GATEWAY_CONFIG"), "path to config file (env VAULT_GATEWAY_CONFIG)")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig for out-of-cluster development")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return nil
	}
	if configPath == "" {
		return fmt.Errorf("no config provided: set --config or VAULT_GATEWAY_CONFIG")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.Logging)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	m := metrics.New()
	m.SetInfo(version.Version, cfg.Backend, version.GoVersion())

	be, err := buildBackend(ctx, cfg, m, logger)
	if err != nil {
		return fmt.Errorf("init backend %q: %w", cfg.Backend, err)
	}

	validator, err := auth.NewK8sTokenValidator(kubeconfig, nil, cfg.HealthCheck.BackendCheckTimeout.Std())
	if err != nil {
		return fmt.Errorf("init kubernetes token validator: %w", err)
	}

	tokenStore := auth.NewTokenStore(cfg.Auth.MaxTokensPerIdentity)
	rbac := auth.NewRBAC(buildRoles(cfg))

	handlers := api.NewHandlers(api.Config{
		Backend:             be,
		Validator:           validator,
		Tokens:              tokenStore,
		RBAC:                rbac,
		Metrics:             m,
		Logger:              logger,
		DefaultTokenTTL:     cfg.Auth.TokenTTL.Std(),
		RoleTokenTTL:        roleTTLs(cfg),
		BackendHealthCheck:  cfg.HealthCheck.BackendCheck,
		BackendCheckTimeout: cfg.HealthCheck.BackendCheckTimeout.Std(),
		ClusterID:           generateClusterID(),
	})

	mw := server.NewMiddleware(logger, m, cfg.Server.MaxRequestBodySize, cfg.Server.TLS.Enabled, cfg.RateLimit, cfg.CORS)
	router := server.NewRouter(handlers)
	srv := server.New(cfg, logger, router, mw, m, be)

	// Background cleanup of expired tokens.
	stopCleanup := startTokenCleanup(ctx, tokenStore, m, cfg.Auth.TokenCleanupInterval.Std())
	defer stopCleanup()

	logStartupBanner(logger, cfg)

	return srv.Start(ctx)
}

// buildBackend constructs the configured secret backend.
func buildBackend(ctx context.Context, cfg *config.Config, m *metrics.Metrics, logger *slog.Logger) (backend.SecretBackend, error) {
	switch cfg.Backend {
	case config.BackendAWS:
		return awsbackend.New(ctx, awsbackend.Config{
			Region:       cfg.AWS.Region,
			SecretPrefix: cfg.AWS.SecretPrefix,
			EndpointURL:  cfg.AWS.EndpointURL,
			MaxRetries:   cfg.AWS.MaxRetries,
			Cache:        cfg.AWS.Cache.ToCache(),
		}, m, logger)
	case config.BackendAzure:
		return azurebackend.New(ctx, azurebackend.Config{
			VaultURL:       cfg.Azure.VaultURL,
			NamingStrategy: cfg.Azure.NamingStrategy,
			SecretPrefix:   cfg.Azure.SecretPrefix,
			Cache:          cfg.Azure.Cache.ToCache(),
		}, m, logger)
	case config.BackendVault:
		return vaultbackend.New(ctx, vaultbackend.Config{
			Address:       cfg.Vault.Address,
			AuthPath:      cfg.Vault.AuthPath,
			Role:          cfg.Vault.Role,
			TLSSkipVerify: cfg.Vault.TLSSkipVerify,
			CACert:        cfg.Vault.CACert,
			Token:         cfg.Vault.Token,
			SecretPrefix:  cfg.Vault.SecretPrefix,
			Cache:         cfg.Vault.Cache.ToCache(),
		}, m, logger)
	case config.BackendGCP:
		return gcpbackend.New(ctx, gcpbackend.Config{
			ProjectID:    cfg.GCP.ProjectID,
			SecretPrefix: cfg.GCP.SecretPrefix,
			Cache:        cfg.GCP.Cache.ToCache(),
		}, m, logger)
	default:
		return nil, fmt.Errorf("unsupported backend %q", cfg.Backend)
	}
}

// buildRoles converts config role definitions into the RBAC role table.
func buildRoles(cfg *config.Config) map[string]auth.Role {
	roles := make(map[string]auth.Role, len(cfg.Auth.Roles))
	for name, r := range cfg.Auth.Roles {
		roles[name] = auth.Role{
			AllowedNamespaces:      r.AllowedNamespaces,
			AllowedServiceAccounts: r.AllowedServiceAccounts,
			AllowedPaths:           r.AllowedPaths,
		}
	}
	return roles
}

// roleTTLs extracts per-role token TTL overrides.
func roleTTLs(cfg *config.Config) map[string]time.Duration {
	out := make(map[string]time.Duration, len(cfg.Auth.Roles))
	for name, r := range cfg.Auth.Roles {
		if r.TokenTTL > 0 {
			out[name] = r.TokenTTL.Std()
		}
	}
	return out
}

// startTokenCleanup runs periodic expired-token purging until ctx is canceled.
func startTokenCleanup(ctx context.Context, store *auth.TokenStore, m *metrics.Metrics, interval time.Duration) func() {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				store.CleanupExpired()
				if m != nil {
					m.ActiveTokens.Set(float64(store.TokenCount()))
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
}

// newLogger builds a slog logger from logging config.
func newLogger(lc config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch lc.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if lc.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func logStartupBanner(logger *slog.Logger, cfg *config.Config) {
	logger.Info("vault-gateway starting",
		"version", version.Version,
		"commit", version.GitCommit,
		"backend", cfg.Backend,
		"api_addr", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		"metrics_addr", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Metrics.Port),
		"tls", cfg.Server.TLS.Enabled,
	)
}

// generateClusterID returns a random cluster identifier for health responses.
func generateClusterID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "vault-gateway-cluster"
	}
	return hex.EncodeToString(b[:])
}
