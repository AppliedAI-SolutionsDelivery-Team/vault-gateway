# Vault Gateway — Handoff

**Date:** 2026-07-02
**Repo:** https://github.com/danesh01aaico/vault-gateway
**Branch:** main

---

## What this is

A production-grade Go service that exposes a HashiCorp Vault-compatible HTTP API and routes secret reads to cloud-native backends — AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or real HashiCorp Vault.

Works with Bank-Vaults `vault-env` to inject secrets into pod environment variables at runtime. **No Kubernetes Secret objects are ever created.** Secrets live only in pod process memory.

---

## Current state

| Area | Status |
|---|---|
| Go implementation | Done |
| All 4 backends (AWS/Azure/GCP/Vault) | Done |
| vault-inject binary (bank-vaults vault-env, in-house) | Done |
| Security hardening (TLS, securityContext, NetworkPolicy, PSS, PDB, rate limit, audit log) | Done |
| k3d end-to-end test | Passing |
| Local binary test | Passing |
| CI (lint/test/build/helm/docker) | Green |
| README | Done |
| Helm charts | Done |
| **SecretPrefix generic path strategy** | **Done — local only, NOT committed/pushed** |
| AWS dev deployment | Pending team approval |

---

## ⚠️ UNCOMMITTED CHANGES — commit these first

The following 8 files are modified but not committed. Verify tests pass, then commit and push.

```bash
# Verify
/opt/homebrew/bin/go test ./...

# Stage only the changed source files (not the vault-inject binary)
git add cmd/vault-gateway/main.go \
        internal/config/config.go \
        internal/backend/azure/backend.go \
        internal/backend/azure/backend_test.go \
        internal/backend/vault/backend.go \
        internal/backend/vault/backend_test.go \
        deploy/helm/vault-gateway/values-azure.yaml \
        deploy/helm/vault-gateway/values-vault.yaml

git commit -m "feat: add SecretPrefix to Azure and Vault backends for generic path strategy"
git push
```

**What these changes do:**
- `internal/config/config.go` — added `SecretPrefix string` to `AzureConfig` and `VaultConfig`
- `internal/backend/azure/backend.go` — `SecretPrefix` in Config, `prefix` field on Backend, applied in `GetSecret` before path encoding
- `internal/backend/vault/backend.go` — same pattern, applied in `GetSecret` before KV v2 call
- `cmd/vault-gateway/main.go` — wired both new config fields into backend constructors
- `internal/backend/azure/backend_test.go` — 3 new prefix tests, 12 `newWithClient` call sites updated (added `""` prefix arg)
- `internal/backend/vault/backend_test.go` — 2 new prefix tests
- `deploy/helm/vault-gateway/values-azure.yaml` and `values-vault.yaml` — `secretPrefix: ""` added

AWS and GCP already had `SecretPrefix` — this makes all four backends consistent.

---

## Secret path strategy (designed and implemented this session)

### The problem
Previously secrets needed Reflector to replicate across multiple namespaces. With vault-gateway + this prefix strategy, each pod reads directly from the backend — zero K8s Secrets, no Reflector.

### Generic naming convention
```
{env}/{scope}/{secret-name}

prod/shared/postgres/credentials   ← all namespaces can read
prod/shared/kafka/credentials
prod/ns/app-team-a/api-key         ← only app-team-a can read
prod/ns/platform/admin-credentials
```

### Per-backend translation (already implemented in code)
| Backend | How | Example result |
|---|---|---|
| AWS SM | `/` native, prepend prefix | `prod/shared/postgres/credentials` |
| Azure KV flat | prepend prefix, `/`→`-` | `prod-shared-postgres-credentials--key` |
| Azure KV json | prepend prefix, `/`→`--` | `prod--shared--postgres--credentials` |
| GCP SM | prepend prefix, `/`→`-` via secretID() | `prod-shared-postgres-credentials` |
| Vault KV v2 | `/` native, prepend prefix | `prod/shared/postgres/credentials` |

### Gateway RBAC config per namespace (not yet written — next step after commit)
```yaml
auth:
  roles:
    app-team-a:
      allowedNamespaces: [app-team-a]
      allowedServiceAccounts: [app-team-a-sa]
      allowedPaths:
        - "prod/shared/**"
        - "prod/ns/app-team-a/**"
    platform:
      allowedNamespaces: [platform]
      allowedServiceAccounts: [platform-sa]
      allowedPaths:
        - "prod/shared/**"
        - "prod/ns/platform/**"
```

### Pod annotation (how apps reference secrets)
```yaml
env:
  - name: DB_PASSWORD
    value: "vault:secret/data/shared/postgres/credentials#password"
  - name: API_KEY
    value: "vault:secret/data/ns/app-team-a/api-key#value"
```
Gateway config sets `secretPrefix: "prod/"` so pods never need to include the env segment.

---

## How bank-vaults injection works (no external SDK)

`cmd/vault-inject/main.go` builds to `/vault-env` in the Docker image — our own vault-env implementation:

1. **Init container** runs `vault-env copy /vault/` → copies binary to emptyDir shared volume
2. **Main container** is wrapped: `/vault/vault-env <original-cmd>`
3. vault-env reads pod SA JWT → `POST /v1/auth/kubernetes/login` → gets token (5 min TTL)
4. Resolves `vault:<path>#<key>` env vars → fetches from gateway → substitutes values
5. Strips all `VAULT_*` vars from child process env (auth material never reaches app)
6. `syscall.Exec` into app — vault-env becomes the app process

In k3d (no webhook): pod spec does this manually via `dev/k8s/04-test-pod.yaml`.
In production: bank-vaults mutating webhook patches pods automatically from annotations.

**Single Docker image, two binaries:**
- `/vault-gateway` → default entrypoint (the gateway server)
- `/vault-env` → used by webhook / init-container

---

## Running the tests

```bash
# Check k3d is up
k3d cluster list   # expect: dev-cluster 1/1 2/2 true

# Start LocalStack (no persistent container — always use docker run)
docker run -d --name localstack -p 4566:4566 -e SERVICES=secretsmanager localstack/localstack
until curl -s http://localhost:4566/_localstack/health | grep -q '"secretsmanager": "running"'; do sleep 2; done

# Unit tests (all 16 packages)
/opt/homebrew/bin/go test ./...

# Full k3d end-to-end
KUBECONFIG=/Users/daneshwar/.config/k3d/kubeconfig-dev-cluster.yaml make deploy-k3d
```

Expected k3d assertions:
```
[PASS] DB_PASSWORD = s3cr3t
[PASS] DB_USER = admin
[PASS] APP_ENV = local-k3d
[PASS] VAULT_* config vars stripped from app env
[PASS] Zero Kubernetes Secrets in default namespace
```

---

## Next step: AWS dev deployment (pending approval)

Waiting on team Slack approval for AWS dev environment access. Once approved:

### 1. Push image to ECR
```bash
aws ecr create-repository --repository-name vault-gateway --region <region>
docker build -t <account>.dkr.ecr.<region>.amazonaws.com/vault-gateway:latest .
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
docker push <account>.dkr.ecr.<region>.amazonaws.com/vault-gateway:latest
```

### 2. Create IAM role (IRSA)
```json
{
  "Effect": "Allow",
  "Action": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
  "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:dev/*"
}
```
Trust policy: OIDC provider for the EKS cluster, subject `system:serviceaccount:vault-system:vault-gateway`.
Annotate SA: `eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/vault-gateway-role`
Remove `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` from Deployment env.

### 3. Install cert-manager + TLS
```bash
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true
# Then create Issuer + Certificate for vault-gateway.vault-system.svc.cluster.local
```

### 4. Install Bank-Vaults webhook
```bash
helm repo add banzaicloud-stable https://kubernetes-charts.banzaicloud.com
helm install vault-secrets-webhook banzaicloud-stable/vault-secrets-webhook \
  --namespace vault-system \
  -f deploy/examples/bank-vaults-webhook-values.yaml
```

### 5. Helm install vault-gateway
```bash
helm install vault-gateway deploy/helm/vault-gateway \
  --namespace vault-system --create-namespace \
  -f deploy/helm/vault-gateway/values-aws.yaml \
  --set config.aws.secretPrefix="dev/"
```

### 6. Test pod
```yaml
env:
  - name: DB_PASSWORD
    value: "vault:secret/data/shared/postgres#password"
```
Assert: resolved at runtime, zero K8s Secrets, audit log entry in gateway logs.

---

## Architecture

```
Pod admission
  → Bank-Vaults webhook injects vault-inject init container
  → vault-inject reads SA JWT
  → POST /v1/auth/kubernetes/login  → vault-gateway (validates JWT via kube-apiserver TokenReview)
  → GET  /v1/secret/data/<path>     → vault-gateway (RBAC check → fetch from AWS SM / Azure KV / etc.)
  → vault-inject syscall.Exec() into app with secrets in env
  → App runs — DB_PASSWORD=s3cr3t in memory only
  → Kubernetes Secret: never created
```

---

## Repository layout

```
cmd/vault-gateway/       Gateway server binary
cmd/vault-inject/        Init container binary (bank-vaults vault-env, in-house)
internal/
  api/                   HTTP handlers (secrets.go, auth.go, health.go)
  auth/                  JWT validation, RBAC, token store
  backend/
    aws/                 AWS Secrets Manager (has SecretPrefix)
    azure/               Azure Key Vault — flat + json naming, now has SecretPrefix
    gcp/                 GCP Secret Manager (has SecretPrefix)
    vault/               HashiCorp Vault KV v2 passthrough, now has SecretPrefix
  cache/                 In-memory TTL cache (30s default)
  config/                Config loading + validation
  metrics/               Prometheus metrics
  secretpath/            Hardened path validator (allowlist)
  server/                HTTP server, middleware, router
deploy/
  helm/vault-gateway/            Main Helm chart
  helm/vault-gateway-stack/      Umbrella chart (gateway + webhook)
  examples/                      IRSA setup, Azure WI setup, sample deployment
dev/
  local-test.sh          Binary-only e2e (no cluster pods)
  deploy-k3d.sh          Full k3d deployment + assertion
  k8s/                   Manifests: 01-rbac, 02-config, 03-deploy, 04-test-pod, 05-netpol, 06-pdb, 07-priorityclass
  config/                gateway-k3d.yaml, gateway-local.yaml
```

---

## Security posture

| Control | Detail |
|---|---|
| TLS 1.2+ | Self-signed in k3d; cert-manager in production |
| Zero K8s Secrets | Nothing in etcd |
| Token TTL | 5 minutes |
| Path validator | Allowlist — blocks traversal, null bytes, shell metacharacters |
| Rate limiting | 50 rps / burst 100 |
| Container hardening | runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, seccompProfile RuntimeDefault |
| NetworkPolicy | Only `vault.io/inject=true` pods reach port 8200 |
| PSS restricted | Enforced on vault-system namespace |
| PDB | minAvailable: 1 |
| PriorityClass | Gateway before app pods |
| Audit log | Every login and read logged — values and tokens never logged |
| Secret cache | 30s TTL |
| CSP header | default-src 'none' |
| Distroless image | gcr.io/distroless/static-debian12:nonroot, UID 65534 |

---

## Dev environment

| Thing | Value |
|---|---|
| Go binary | `/opt/homebrew/bin/go` (not on PATH by default) |
| k3d context name | `k3d-dev-cluster` |
| k3d kubeconfig | `/Users/daneshwar/.config/k3d/kubeconfig-dev-cluster.yaml` |
| LocalStack | No persistent container — always `docker run`, not `docker start` |
| golangci-lint | Installed via `go install` — do NOT use pre-built binary (incompatible with go 1.26) |

---

## Critical safety rule

`dev/deploy-k3d.sh` enforces `[[ "$CONTEXT" == k3d-* ]]` before touching any cluster. Do not bypass.

A prior session accidentally deployed to production EKS cluster `opus-workloads-delta-7bq25` — user had to manually delete the resources. **Never deploy to any real cluster without explicit user confirmation of the kube context.**
