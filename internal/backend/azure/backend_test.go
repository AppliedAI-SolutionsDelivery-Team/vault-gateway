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

package azure

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
)

// fakeClient is an in-memory kvClient for tests.
type fakeClient struct {
	secrets   map[string]string
	listErr   error
	getErr    error
	listCalls int
	getCalls  int
}

func (f *fakeClient) GetSecret(_ context.Context, name, _ string) (string, error) {
	f.getCalls++
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.secrets[name]
	if !ok {
		return "", &azcore.ResponseError{StatusCode: 404}
	}
	return v, nil
}

func (f *fakeClient) ListSecretNames(_ context.Context) ([]string, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	names := make([]string, 0, len(f.secrets))
	for n := range f.secrets {
		names = append(names, n)
	}
	return names, nil
}

func disabledCache() cache.Config {
	return cache.Config{Enabled: false}
}

func enabledCache() cache.Config {
	return cache.Config{Enabled: true, TTL: time.Minute, NegativeTTL: time.Minute, MaxEntries: 100}
}

func TestGetSecretFlatMultiKey(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"opus-workflow-engine--db-password": "s3cr3t",
		"opus-workflow-engine--db-host":     "db.internal",
		// A secret for a different path must be ignored.
		"other-service--token": "nope",
	}}
	b := newWithClient(fake, strategyFlat, "", disabledCache(), nil, nil)

	got, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if err != nil {
		t.Fatalf("GetSecret error: %v", err)
	}
	want := map[string]string{
		"db_password": "s3cr3t",
		"db_host":     "db.internal",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetSecret = %v, want %v", got, want)
	}
}

func TestGetSecretFlatNotFound(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"other-service--token": "x",
	}}
	b := newWithClient(fake, strategyFlat, "", disabledCache(), nil, nil)

	_, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("err = %v, want ErrSecretNotFound", err)
	}
}

func TestGetSecretFlatListError(t *testing.T) {
	fake := &fakeClient{listErr: errors.New("network down")}
	b := newWithClient(fake, strategyFlat, "", disabledCache(), nil, nil)

	_, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("err = %v, want ErrBackendUnavailable", err)
	}
}

func TestGetSecretJSON(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"opus--workflow-engine": `{"db_password":"s3cr3t","db_host":"db.internal"}`,
	}}
	b := newWithClient(fake, strategyJSON, "", disabledCache(), nil, nil)

	got, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if err != nil {
		t.Fatalf("GetSecret error: %v", err)
	}
	want := map[string]string{
		"db_password": "s3cr3t",
		"db_host":     "db.internal",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetSecret = %v, want %v", got, want)
	}
}

func TestGetSecretJSONNotFound(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{}}
	b := newWithClient(fake, strategyJSON, "", disabledCache(), nil, nil)

	_, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("err = %v, want ErrSecretNotFound", err)
	}
}

func TestGetSecretJSONBackendError(t *testing.T) {
	fake := &fakeClient{getErr: errors.New("boom")}
	b := newWithClient(fake, strategyJSON, "", disabledCache(), nil, nil)

	_, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("err = %v, want ErrBackendUnavailable", err)
	}
}

func TestGetSecretJSONInvalidJSON(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"opus--workflow-engine": "not json",
	}}
	b := newWithClient(fake, strategyJSON, "", disabledCache(), nil, nil)

	_, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("err = %v, want ErrBackendUnavailable", err)
	}
}

func TestGetSecretCachesPositive(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"opus--workflow-engine": `{"k":"v"}`,
	}}
	b := newWithClient(fake, strategyJSON, "", enabledCache(), nil, nil)
	ctx := context.Background()

	if _, err := b.GetSecret(ctx, "opus/workflow-engine"); err != nil {
		t.Fatalf("first GetSecret: %v", err)
	}
	firstCalls := fake.getCalls

	// Remove the secret: a second call must still succeed from cache.
	delete(fake.secrets, "opus--workflow-engine")

	got, err := b.GetSecret(ctx, "opus/workflow-engine")
	if err != nil {
		t.Fatalf("second GetSecret: %v", err)
	}
	if got["k"] != "v" {
		t.Fatalf("cached value = %v, want k=v", got)
	}
	if fake.getCalls != firstCalls {
		t.Fatalf("expected no additional GetSecret calls, got %d (was %d)", fake.getCalls, firstCalls)
	}
}

func TestGetSecretCachesNegative(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{}}
	b := newWithClient(fake, strategyFlat, "", enabledCache(), nil, nil)
	ctx := context.Background()

	if _, err := b.GetSecret(ctx, "missing/path"); !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("first err = %v, want ErrSecretNotFound", err)
	}
	firstListCalls := fake.listCalls

	if _, err := b.GetSecret(ctx, "missing/path"); !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("second err = %v, want ErrSecretNotFound", err)
	}
	if fake.listCalls != firstListCalls {
		t.Fatalf("expected negative cache to avoid re-listing, got %d (was %d)", fake.listCalls, firstListCalls)
	}
}

func TestHealthCheck(t *testing.T) {
	okFake := &fakeClient{secrets: map[string]string{"a": "b"}}
	b := newWithClient(okFake, strategyFlat, "", disabledCache(), nil, nil)
	if err := b.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck error: %v", err)
	}

	badFake := &fakeClient{listErr: errors.New("unreachable")}
	bb := newWithClient(badFake, strategyFlat, "", disabledCache(), nil, nil)
	if err := bb.HealthCheck(context.Background()); !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("HealthCheck err = %v, want ErrBackendUnavailable", err)
	}
}

func TestNameAndClose(t *testing.T) {
	b := newWithClient(&fakeClient{}, strategyFlat, "", disabledCache(), nil, nil)
	if b.Name() != "azure" {
		t.Fatalf("Name() = %q, want azure", b.Name())
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
}

func TestGetSecretAppliesPrefixFlat(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"prod-shared-postgres--password": "s3cr3t",
	}}
	b := newWithClient(fake, strategyFlat, "prod/", disabledCache(), nil, nil)

	got, err := b.GetSecret(context.Background(), "shared/postgres")
	if err != nil {
		t.Fatalf("GetSecret error: %v", err)
	}
	if got["password"] != "s3cr3t" {
		t.Fatalf("got %v, want password=s3cr3t", got)
	}
}

func TestGetSecretAppliesPrefixJSON(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"prod--shared--postgres": `{"password":"s3cr3t"}`,
	}}
	b := newWithClient(fake, strategyJSON, "prod/", disabledCache(), nil, nil)

	got, err := b.GetSecret(context.Background(), "shared/postgres")
	if err != nil {
		t.Fatalf("GetSecret error: %v", err)
	}
	if got["password"] != "s3cr3t" {
		t.Fatalf("got %v, want password=s3cr3t", got)
	}
}

func TestGetSecretEmptyPrefixUnchanged(t *testing.T) {
	fake := &fakeClient{secrets: map[string]string{
		"shared-postgres--password": "s3cr3t",
	}}
	b := newWithClient(fake, strategyFlat, "", disabledCache(), nil, nil)

	got, err := b.GetSecret(context.Background(), "shared/postgres")
	if err != nil {
		t.Fatalf("GetSecret error: %v", err)
	}
	if got["password"] != "s3cr3t" {
		t.Fatalf("got %v, want password=s3cr3t", got)
	}
}

func TestNewValidatesInput(t *testing.T) {
	if _, err := New(context.Background(), Config{}, nil, nil); err == nil {
		t.Fatal("expected error for empty VaultURL")
	}
	if _, err := New(context.Background(), Config{VaultURL: "https://v.vault.azure.net/", NamingStrategy: "bogus"}, nil, nil); err == nil {
		t.Fatal("expected error for invalid naming strategy")
	}
}
