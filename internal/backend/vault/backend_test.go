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

package vault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
)

// kvV2Body is a canned KV v2 read response for a successful secret read.
const kvV2Body = `{
  "request_id": "00000000-0000-0000-0000-000000000000",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "data": {
      "username": "admin",
      "password": "s3cr3t",
      "port": 5432,
      "enabled": true
    },
    "metadata": {
      "created_time": "2026-06-26T00:00:00Z",
      "version": 1,
      "destroyed": false
    }
  },
  "warnings": null
}`

// newBackend builds a Backend pointed at srv using a static token so the
// Kubernetes login path is skipped.
func newBackend(t *testing.T, srv *httptest.Server, c cache.Config) *Backend {
	t.Helper()
	b, err := New(context.Background(), Config{
		Address: srv.URL,
		Token:   "test-token",
		Cache:   c,
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b.(*Backend)
}

func TestGetSecretSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/data/app/db" {
			http.Error(w, `{"errors":["unexpected path"]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kvV2Body))
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{})
	defer b.Close()

	got, err := b.GetSecret(context.Background(), "app/db")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	want := map[string]string{
		"username": "admin",
		"password": "s3cr3t",
		"port":     "5432",
		"enabled":  "true",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d keys, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestGetSecretNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{})
	defer b.Close()

	_, err := b.GetSecret(context.Background(), "missing")
	if !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("got err %v, want ErrSecretNotFound", err)
	}
}

func TestGetSecretBackendUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":["internal error"]}`))
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{})
	defer b.Close()

	_, err := b.GetSecret(context.Background(), "app/db")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("got err %v, want ErrBackendUnavailable", err)
	}
}

func TestGetSecretCacheHit(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kvV2Body))
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{
		Enabled:    true,
		TTL:        time.Minute,
		MaxEntries: 10,
	})
	defer b.Close()

	if _, err := b.GetSecret(context.Background(), "app/db"); err != nil {
		t.Fatalf("first GetSecret: %v", err)
	}
	if _, err := b.GetSecret(context.Background(), "app/db"); err != nil {
		t.Fatalf("second GetSecret: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("server hit %d times, want 1 (second read should be cached)", n)
	}
}

func TestNameAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(kvV2Body))
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{})
	if b.Name() != "vault" {
		t.Errorf("Name() = %q, want %q", b.Name(), "vault")
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}

func TestHealthCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
			return
		}
		http.Error(w, `{"errors":["unexpected path"]}`, http.StatusNotFound)
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{})
	defer b.Close()

	if err := b.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestGetSecretAppliesPrefix(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kvV2Body))
	}))
	defer srv.Close()

	b, err := New(context.Background(), Config{
		Address:      srv.URL,
		Token:        "test-token",
		SecretPrefix: "prod/",
		Cache:        cache.Config{},
	}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b.(*Backend).Close()

	if _, err := b.GetSecret(context.Background(), "shared/postgres"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if seenPath != "/v1/secret/data/prod/shared/postgres" {
		t.Fatalf("path = %q, want /v1/secret/data/prod/shared/postgres", seenPath)
	}
}

func TestGetSecretEmptyPrefixUnchanged(t *testing.T) {
	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kvV2Body))
	}))
	defer srv.Close()

	b := newBackend(t, srv, cache.Config{})
	defer b.Close()

	if _, err := b.GetSecret(context.Background(), "shared/postgres"); err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if seenPath != "/v1/secret/data/shared/postgres" {
		t.Fatalf("path = %q, want /v1/secret/data/shared/postgres", seenPath)
	}
}
