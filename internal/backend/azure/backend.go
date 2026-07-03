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

// Package azure implements the SecretBackend interface on top of Azure Key
// Vault. It supports two naming strategies: "flat", where each Vault key is a
// distinct Key Vault secret, and "json", where every key/value pair for a path
// lives in a single Key Vault secret whose value is a JSON object.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// backendName is the identifier used for logging and metric labels.
const backendName = "azure"

const (
	strategyFlat = "flat"
	strategyJSON = "json"
)

// Config configures the Azure Key Vault backend.
type Config struct {
	// VaultURL is the Key Vault DNS endpoint, e.g.
	// "https://my-vault.vault.azure.net/".
	VaultURL string
	// NamingStrategy selects how Vault paths map onto Key Vault secrets. Valid
	// values are "flat" and "json". Empty defaults to "flat".
	NamingStrategy string
	// SecretPrefix is prepended to every requested path before encoding into a
	// Key Vault secret name. Typically an environment prefix such as "prod/".
	SecretPrefix string
	// Cache configures the in-memory secret cache.
	Cache cache.Config
}

// kvClient is the subset of Azure Key Vault behavior the backend depends on.
// It is deliberately narrow so unit tests can supply an in-memory fake without
// reconstructing the SDK's pager machinery.
type kvClient interface {
	// GetSecret returns the value of the named secret. version may be empty to
	// fetch the latest version.
	GetSecret(ctx context.Context, name, version string) (string, error)
	// ListSecretNames returns the names of every secret in the vault.
	ListSecretNames(ctx context.Context) ([]string, error)
}

// Backend is the Azure Key Vault implementation of backend.SecretBackend.
type Backend struct {
	client   kvClient
	strategy string
	prefix   string
	cache    *cache.Cache
	metrics  *metrics.Metrics
	logger   *slog.Logger
}

// Ensure Backend satisfies the contract.
var _ backend.SecretBackend = (*Backend)(nil)

// New constructs an Azure Key Vault backend using DefaultAzureCredential for
// authentication (environment, workload identity, managed identity, etc.).
func New(ctx context.Context, cfg Config, m *metrics.Metrics, logger *slog.Logger) (backend.SecretBackend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.VaultURL == "" {
		return nil, errors.New("azure: VaultURL is required")
	}

	strategy := cfg.NamingStrategy
	if strategy == "" {
		strategy = strategyFlat
	}
	if strategy != strategyFlat && strategy != strategyJSON {
		return nil, fmt.Errorf("azure: invalid naming strategy %q (want %q or %q)", strategy, strategyFlat, strategyJSON)
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build credential: %w", err)
	}
	client, err := azsecrets.NewClient(cfg.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: build key vault client: %w", err)
	}

	return newWithClient(&azsecretsAdapter{client: client}, strategy, cfg.SecretPrefix, cfg.Cache, m, logger), nil
}

// newWithClient builds a Backend around an arbitrary kvClient. It is the
// injection point used by tests.
func newWithClient(client kvClient, strategy, prefix string, cacheCfg cache.Config, m *metrics.Metrics, logger *slog.Logger) *Backend {
	if logger == nil {
		logger = slog.Default()
	}
	if strategy == "" {
		strategy = strategyFlat
	}
	return &Backend{
		client:   client,
		strategy: strategy,
		prefix:   prefix,
		cache:    cache.New(cacheCfg),
		metrics:  m,
		logger:   logger.With("backend", backendName),
	}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return backendName }

// Close releases resources. The Azure SDK client requires no teardown.
func (b *Backend) Close() error { return nil }

// HealthCheck verifies connectivity by listing secret names.
func (b *Backend) HealthCheck(ctx context.Context) error {
	if _, err := b.client.ListSecretNames(ctx); err != nil {
		return fmt.Errorf("%w: azure health check: %v", backend.ErrBackendUnavailable, err)
	}
	return nil
}

// GetSecret retrieves all key/value pairs at path, consulting the cache first.
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

	switch b.strategy {
	case strategyJSON:
		return b.getJSON(ctx, path)
	default:
		return b.getFlat(ctx, path)
	}
}

// getFlat assembles a path's map by listing the vault and collecting every
// secret whose name carries the path's flat prefix.
func (b *Backend) getFlat(ctx context.Context, path string) (map[string]string, error) {
	names, err := b.client.ListSecretNames(ctx)
	if err != nil {
		return nil, mapError("list secrets", err)
	}

	prefix := flatSecretPrefix(path)
	result := make(map[string]string)
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		key, ok := flatDecodeKey(path, name)
		if !ok {
			continue
		}
		value, gerr := b.client.GetSecret(ctx, name, "")
		if gerr != nil {
			// A secret listed but vanished before retrieval is treated as
			// absent rather than fatal.
			if isNotFound(gerr) {
				continue
			}
			return nil, mapError("get secret", gerr)
		}
		result[key] = value
	}

	if len(result) == 0 {
		b.cache.SetNegative(path)
		return nil, backend.ErrSecretNotFound
	}

	b.cache.Set(path, result)
	b.updateCacheEntries()
	return result, nil
}

// getJSON fetches the single secret holding the path's JSON object.
func (b *Backend) getJSON(ctx context.Context, path string) (map[string]string, error) {
	name := jsonSecretName(path)
	value, err := b.client.GetSecret(ctx, name, "")
	if err != nil {
		if isNotFound(err) {
			b.cache.SetNegative(path)
			return nil, backend.ErrSecretNotFound
		}
		return nil, mapError("get secret", err)
	}

	result := make(map[string]string)
	if uerr := json.Unmarshal([]byte(value), &result); uerr != nil {
		// Never log the secret value itself.
		return nil, fmt.Errorf("%w: azure: decode json secret %q: %v", backend.ErrBackendUnavailable, name, uerr)
	}

	b.cache.Set(path, result)
	b.updateCacheEntries()
	return result, nil
}

// mapError translates an Azure SDK error into a backend sentinel error.
func mapError(op string, err error) error {
	if isNotFound(err) {
		return backend.ErrSecretNotFound
	}
	return fmt.Errorf("%w: azure: %s: %v", backend.ErrBackendUnavailable, op, err)
}

// isNotFound reports whether err is an Azure HTTP 404 response.
func isNotFound(err error) bool {
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		return respErr.StatusCode == 404
	}
	return false
}

func (b *Backend) recordCacheHit() {
	if b.metrics != nil {
		b.metrics.CacheHits.WithLabelValues(backendName).Inc()
	}
}

func (b *Backend) recordCacheMiss() {
	if b.metrics != nil {
		b.metrics.CacheMisses.WithLabelValues(backendName).Inc()
	}
}

func (b *Backend) updateCacheEntries() {
	if b.metrics != nil {
		b.metrics.CacheEntries.WithLabelValues(backendName).Set(float64(b.cache.Len()))
	}
}

// azsecretsAdapter adapts *azsecrets.Client to the narrow kvClient interface.
type azsecretsAdapter struct {
	client *azsecrets.Client
}

var _ kvClient = (*azsecretsAdapter)(nil)

// GetSecret fetches the named secret's value.
func (a *azsecretsAdapter) GetSecret(ctx context.Context, name, version string) (string, error) {
	resp, err := a.client.GetSecret(ctx, name, version, nil)
	if err != nil {
		return "", err
	}
	if resp.Value == nil {
		return "", nil
	}
	return *resp.Value, nil
}

// ListSecretNames iterates the secret-properties pager and extracts each name.
func (a *azsecretsAdapter) ListSecretNames(ctx context.Context) ([]string, error) {
	pager := a.client.NewListSecretPropertiesPager(nil)
	var names []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, prop := range page.Value {
			if prop == nil || prop.ID == nil {
				continue
			}
			names = append(names, prop.ID.Name())
		}
	}
	return names, nil
}
