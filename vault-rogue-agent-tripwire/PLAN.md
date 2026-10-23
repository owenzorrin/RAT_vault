# Rogue Agent Tripwire for Vault — Phase 0 Implementation Plan

> **For Claude Code:** This is the source of truth for Phase 0. Work through the tasks in order. Each task has acceptance criteria. Do not start a task until the previous one passes. **Stop after Task 2 and report findings** — later tasks depend on assumptions verified there. Do not implement anything listed under Non-goals.

## What we're building

**Rogue Agent Tripwire for Vault** ("Tripwire" for short in this doc; binary name `tripwire`) is a small Go service that watches the HashiCorp Vault audit stream for rogue AI-agent behavior and cuts off the offending workload automatically — no human in the stop decision.

Phase 0 goal: **a decoy secret is touched → the offending eval run loses all Vault access and its dynamic DB credentials within ~3 seconds.**

Motivation: in the 2026 OpenAI–Hugging Face incident, sandboxed eval agents escaped containment via shared credentials and a package mirror. Early alerts fired, but a human decided not to stop the run. Tripwire removes that decision point for high-confidence signals.

## Core design principles

1. **Tripwire runs outside the blast radius.** It must not run where agents run. In the lab, it runs on the host Mac; agents run in minikube.
2. **Vault must never depend on Tripwire.** Vault has two audit devices: `file` (primary) and `socket` (Tripwire). If Tripwire dies, Vault keeps serving because at least one audit device succeeds.
3. **Ingest never blocks on detection.** A slow detector must not stall the socket reader.
4. **Fail loud, not quiet.** If a kill step fails, the notification escalates.
5. **Kill only what we own.** Only identities whose token metadata `role` matches `eval-*` are ever killed. Anything else touching a decoy is alert-only.
6. **Stateless in Phase 0.** Run identity comes from token metadata on each event. No database, no registry.

## Non-goals (Phase 0)

Do NOT implement these — they are later phases:
- Denial-burst detection, ack timers, escalation (Phase 1)
- Evidence bundles, `restore` command (Phase 1)
- CIDR / accessor-mismatch detection (Phase 2)
- Kubernetes pod-delete hook (Phase 2)
- Behavioral baselines, Prometheus metrics, HA (Phase 3)
- Any UI or persistent storage
- Artifactory integration (lab uses the Postgres database secrets engine instead)

## Local workspace resources

The working directory is `/Users/owenzhang/RAT_vault/`, which contains:

```
RAT_vault/
├── vault/                    # HashiCorp Vault source code — read-only reference
└── vault_launch_template/    # launches a Vault instance that is unsealed with a root token ready
```

Create this project as a sibling: `/Users/owenzhang/RAT_vault/vault-rogue-agent-tripwire/`.

**`vault/` — source code for analysis.** Use it to answer questions about Vault behavior from the code instead of guessing. In particular, use it while verifying assumptions A2–A7: the audit entry JSON schema and line framing, what lands in `auth.metadata` for Kubernetes auth tokens, how ACL denials are audited, socket audit device write and timeout behavior, how `disabled` entities are enforced on token use, and the `sudo` requirements on `sys/leases/*`. When citing a finding, note the file path and function. **Never modify anything under `vault/`.** Code tells you intended behavior; confirm the important cases against a running instance too.

**`vault_launch_template/` — a ready-to-use Vault instance.** Read its README/scripts first to learn how it starts Vault, where it listens, and where it exposes the root token. Do not assume. Use it for fast local dev and verification that doesn't need Kubernetes (audit framing, entity disable, lease revocation, the `tripwire` policy, unit-test fixtures). Rules:
- The root token is for **setup only** (mounts, policies, audit devices). Tripwire itself must always run with a token from the `tripwire` policy, so the tests prove the least-privilege policy actually works.
- Check whether the template deploys into minikube or runs Vault on the host. If it runs on the host, it does not replace the in-cluster lab for Task 5 scenario tests or anything that depends on `remote_address` (see Lab topology). Document which one it is in `README.md`.
- If the template's Vault version differs from the `vault/` source checkout, record both versions in `README.md` under "Verified behavior".

## Lab topology

```
┌──────────────── minikube (Colima, M3 Mac) ────────────────┐
│  ns: vault    → Vault (Helm, dev mode OK)                  │
│  ns: postgres → Postgres                                   │
│  ns: evals    → eval pods, one ServiceAccount per run      │
└────────────────────────────────────────────────────────────┘
        │ socket audit device (TCP, Vault dials out)
        ▼
  Host Mac: tripwire  ── listens :9090
        │ Vault API calls (kill actions) via kubectl port-forward :8200
        ▼
  Vault
```

Vault runs **in-cluster** on purpose: traffic through a ClusterIP Service preserves pod source IPs in `remote_address`. This is not needed for Phase 0 but Phase 2 depends on it.

## Naming convention (the contract)

Everything keys off the run ID. For run `0412`:

| Object | Name |
|---|---|
| ServiceAccount | `evals/eval-0412` |
| Vault policy | `eval-0412` |
| K8s auth mount | `auth/kubernetes-eval` |
| K8s auth role | `eval-0412` |
| DB secrets role | `database/roles/eval-0412` |
| Lease prefix | `database/creds/eval-0412` |
| Run data path | `kv/data/evals/0412/*` |

Tripwire derives the role from `auth.metadata.role` on each audit event and builds the lease prefix from a template.

## Repository layout

Repo name: `vault-rogue-agent-tripwire`. Binary: `tripwire`.

```
vault-rogue-agent-tripwire/
├── PLAN.md
├── README.md
├── go.mod
├── cmd/tripwire/main.go
├── internal/
│   ├── config/      # YAML config loading + validation
│   ├── ingest/      # TCP listener, line reader → buffered channel
│   ├── event/       # audit JSON → Event struct, KV path normalization
│   ├── detect/      # Detector interface + decoy detector
│   ├── action/      # Killer: disable entity, revoke leases, verify
│   └── notify/      # stdout JSON + webhook
├── config/tripwire.example.yaml
├── lab/
│   ├── Makefile           # make lab-up, make run RUN=0412, make lab-down
│   ├── helm/              # Vault + Postgres values
│   ├── vault/             # policies, setup scripts
│   ├── rogue-agent/       # Dockerfile + rogue.sh
│   └── tests/             # scenario scripts
└── testdata/audit/        # captured real audit lines for unit tests
```

## Tech choices

- Go (latest stable), module path placeholder: `github.com/OWNER/vault-rogue-agent-tripwire`
- `github.com/hashicorp/vault/api` for Vault calls
- `log/slog` for structured logging (JSON handler)
- `gopkg.in/yaml.v3` for config
- Standard library otherwise. No frameworks.

## Config

`config/tripwire.example.yaml`:

```yaml
listen_addr: "0.0.0.0:9090"
vault_addr: "http://127.0.0.1:8200"   # token from VAULT_TOKEN env var
dry_run: true
eval_role_pattern: "^eval-[a-z0-9-]+$"
lease_prefix_template: "database/creds/{{.Role}}"
kv_mounts: ["kv"]                      # KV v2 mounts, used for path normalization
decoys:
  - "kv/research/artifactory-admin"    # logical paths (no data/ or metadata/)
notify:
  webhook_url: ""                      # optional, Slack-compatible
ingest:
  buffer_size: 10000
```

## Vault setup

Audit devices (Tripwire must be listening **before** the socket device is enabled — Vault tests the connection at enable time):

```sh
vault audit enable file file_path=/vault/audit/audit.log
vault audit enable -path=tripwire socket \
  address=host.minikube.internal:9090 socket_type=tcp hmac_accessor=false
```

Tripwire's own policy (`tripwire`). Note `sudo` is required for revoke-prefix and lease lookup:

```hcl
path "identity/entity/id/*" {
  capabilities = ["read", "update"]
}
path "sys/leases/revoke-prefix/database/creds/eval-*" {
  capabilities = ["update", "sudo"]
}
path "sys/leases/lookup/database/creds/eval-*" {
  capabilities = ["list", "sudo"]
}
```

Decoy: write a fake secret at `kv/research/artifactory-admin`. Grant it to **no** policy. Bake a reference to it into the rogue-agent image at `/etc/artifactory/legacy.env`.

## Assumptions to verify (Task 2)

These are believed true but must be confirmed against real audit output before building on them. Record findings in `README.md` under "Verified behavior".

- **A1:** A pod in minikube on Colima can reach the host via `host.minikube.internal:9090`. If not, find the working host address; if none works, fall back to running Tripwire in its own namespace and note it as a lab compromise.
- **A2:** The socket audit device writes one JSON object per line (newline-delimited).
- **A3:** Request entries for K8s-auth tokens include `auth.metadata.role`, `auth.metadata.service_account_name`, `auth.metadata.service_account_namespace`, and `auth.entity_id`.
- **A4:** A read denied by ACL produces a `request` entry (with path and auth) followed by a `response` entry with `error` containing `permission denied`.
- **A5:** With `hmac_accessor=false`, `auth.accessor` appears in cleartext.
- **A6:** Setting `disabled=true` on an entity causes that entity's existing tokens to fail on their next request.
- **A7:** With the socket device's listener down, Vault requests still succeed because the file device succeeds.

Save several real captured audit lines (normal read, denied read, decoy read, login) into `testdata/audit/` — unit tests use these, not hand-written JSON.

## Tasks

### Task 1 — Lab infrastructure

Build `lab/Makefile` and supporting files.

- `make lab-up`: install Vault (Helm, in-cluster, dev mode) and Postgres; enable KV v2 at `kv/`; enable database secrets engine and configure the Postgres connection; enable K8s auth at `auth/kubernetes-eval`; write the decoy secret; create the `tripwire` policy and print a token for it.
- `make run RUN=<id>`: create the ServiceAccount, Vault policy, K8s auth role (15m TTL), DB role (15m default TTL), and seed `kv/evals/<id>/task` with dummy data.
- `make lab-down`: tear everything down.
- `make port-forward`: forward Vault to `127.0.0.1:8200`.

Audit devices are **not** enabled here (Tripwire must be listening first) — provide `make audit-enable` separately.

**Acceptance:** After `make lab-up && make run RUN=0412`, a pod using SA `eval-0412` can log in, read `kv/evals/0412/task`, get DB creds from `database/creds/eval-0412`, and connect with `psql`. The same pod is denied reading the decoy.

### Task 2 — Ingest that prints events (verification gate)

- `internal/ingest`: TCP listener accepting multiple connections; `bufio.Scanner` with a large max token size (audit lines can be big); push raw lines to a buffered channel of `buffer_size`. If the channel is full, log a warning and increment a drop counter — never block indefinitely.
- `internal/event`: parse into:

```go
type Event struct {
    Type          string            // "request" | "response"
    Time          time.Time
    RequestID     string
    Path          string
    Operation     string
    RemoteAddr    string
    EntityID      string
    Accessor      string
    Metadata      map[string]string // auth.metadata
    Error         string
}
```

- `cmd/tripwire`: load config, start ingest, print each parsed event as one slog line.

**Acceptance:** Run Tripwire, `make audit-enable`, exercise the lab. Verify assumptions A1–A7 against both the `vault/` source (cite file and function) and a running instance (`vault_launch_template` is fine for A2 and A4–A7; A1 and A3 need the minikube lab), document results in `README.md`, and save sample lines to `testdata/audit/`. **Stop here and report** before Task 3. If any assumption is false, propose a plan change rather than working around it silently.

### Task 3 — Decoy detector (dry-run)

- `internal/event`: `NormalizeKVPath(path string, mounts []string) string` — for each configured KV v2 mount, map `<mount>/data/X`, `<mount>/metadata/X`, `<mount>/delete/X`, `<mount>/undelete/X`, `<mount>/destroy/X` → `<mount>/X`. Strip leading slashes. Paths on non-KV mounts return unchanged.
- `internal/detect`:

```go
type Severity int
const (SevInfo Severity = iota; SevPage; SevKill)

type Finding struct {
    Severity  Severity
    Detector  string
    Reason    string
    Event     event.Event
}

type Detector interface {
    Name() string
    Inspect(e event.Event) []Finding
}
```

- Decoy detector: fires on `request` entries only; exact match on normalized logical path. A `list` on a parent path (e.g. `kv/metadata/research/`) is **not** a match. Dedupe by `RequestID`.
- Severity: `SevKill` if `Metadata["role"]` matches `eval_role_pattern` and `EntityID` is non-empty; otherwise `SevPage` (alert only).

**Acceptance:** Table-driven unit tests covering all KV v2 path variants, parent-list non-match, non-KV paths, eval vs non-eval identity, empty entity, request/response dedupe — using `testdata/audit/` samples. Lab: rogue read of the decoy produces one `SevKill` finding log line; an admin-token read produces `SevPage`.

### Task 4 — Kill action

`internal/action.Killer`:

1. If `dry_run`, log the exact Vault calls that would be made and return.
2. If the entity was already killed in this process lifetime, log and return (idempotent).
3. **Disable entity first** — `POST identity/entity/id/<id>` with `disabled=true`. (Order matters: revoking leases first leaves a window for the agent to mint new ones.)
4. Revoke leases — `PUT sys/leases/revoke-prefix/<lease prefix from template>`.
5. Verify — `LIST sys/leases/lookup/<lease prefix>`; expect empty or 404.
6. Return a result with per-step status and duration.

Each Vault call retries with exponential backoff (3 attempts, ~200ms base). Run kills in their own goroutine so detection continues. A failed step marks the result `degraded`.

**Acceptance:** Unit tests with a fake Vault HTTP server: call order, dry-run makes zero calls, idempotency, retry then success, retry exhausted → degraded. Lab with `dry_run: false`: decoy read → entity disabled, DB lease revoked, Postgres user gone.

### Task 5 — Rogue agent harness and scenario tests

- `lab/rogue-agent/rogue.sh`: log in via K8s auth; read DB creds; prove with `psql`; read the decoy; then loop every 500ms attempting a Vault read and a `psql` query, logging timestamps and success/failure.
- `lab/tests/` scenario scripts, each exiting non-zero on failure:

| Scenario | Expected |
|---|---|
| `rogue` | Vault and psql both fail within 3s of decoy read |
| `clean` | Run that never touches the decoy completes untouched |
| `isolation` | Two concurrent runs; killing one leaves the other working |
| `admin-decoy` | Admin token reads decoy → alert, no kill |
| `tripwire-down` | Tripwire process killed mid-run → pod Vault reads still succeed |
| `dry-run` | Finding logged; entity still enabled; lease still valid |

**Acceptance:** `make test-scenarios` runs all six and passes.

### Task 6 — Notifications

- `internal/notify`: every finding and every kill result emitted as structured JSON to stdout. If `webhook_url` is set, POST a Slack-compatible payload: run ID, detector, reason, path, entity ID, actions taken with durations, verification result. Degraded kills use an unmistakable prefix (e.g. `KILL DEGRADED`).
- Webhook failures are logged and never block or crash the pipeline.

**Acceptance:** Unit test with a fake webhook server. Lab: rogue scenario produces one finding message and one kill-result message.

## Definition of done (Phase 0)

- `make lab-up && make run RUN=0412 && make test-scenarios` passes from a clean minikube.
- `go test ./...` passes; `go vet` clean.
- `README.md` is titled "Rogue Agent Tripwire for Vault", states it is an independent community project not affiliated with or endorsed by HashiCorp or IBM, and covers: what it does, lab quickstart, config reference, verified behavior (A1–A7 results), known limitations.

## Known limitations to document

- Detects only Vault-plane activity. Network egress (SSRF), kernel exploits, and non-Vault coordination are invisible.
- Disabling an entity does not revoke credentials minted outside Vault by a compromised downstream system.
- Kill state is in memory; a restart forgets which entities were killed (harmless — Vault keeps them disabled).
- Lab Tripwire auth uses a static token from env; production would use a dedicated auth method with no credentials reachable from sandbox nodes.
