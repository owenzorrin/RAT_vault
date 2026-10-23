# Rogue Agent Tripwire for Vault

> **Independent community project.** Not affiliated with or endorsed by HashiCorp or IBM.

A small Go service that watches HashiCorp Vault's audit stream for rogue AI-agent behavior and autonomously cuts off the offending workload — no human in the stop decision.

**Phase 0 goal:** a decoy secret is touched → the offending eval run loses all Vault access and its dynamic DB credentials within ~3 seconds.

---

## What it does

1. Listens on a TCP socket (`:9090` by default) for Vault's socket audit device stream.
2. Parses each newline-delimited JSON audit entry into a structured `Event`.
3. Runs detectors against each event. The Phase 0 detector watches for reads of configured decoy paths.
4. On a `SevKill` finding (eval-role identity touched a decoy):
   - Disables the Vault entity (blocks all existing tokens immediately).
   - Revokes all database credential leases under `database/creds/<role>/`.
   - Verifies the leases are gone.
5. Emits structured JSON notifications to stdout and optionally to a Slack-compatible webhook.

---

## Lab quickstart

**Prerequisites:** `minikube`, `helm`, `kubectl`, Vault CLI, `psql`, Go ≥ 1.23.

```sh
# 1. Start minikube (Colima driver on M-series Mac)
minikube start --driver=colima

# 2. Bootstrap the lab
cd lab
make lab-up

# 3. Forward Vault to localhost (keep this terminal open)
make port-forward &

# 4. Build and start tripwire (separate terminal, from repo root)
go build -o tripwire ./cmd/tripwire
export VAULT_TOKEN=$(jq -r .auth.client_token /tmp/tripwire-token.json)
./tripwire config/tripwire.yaml

# 5. Enable audit devices (tripwire must be listening first)
cd lab
make audit-enable

# 6. Provision an eval run
make run RUN=0412

# 7. Run all scenario tests (Task 5 — after full implementation)
make test-scenarios
```

---

## Config reference

Copy `config/tripwire.example.yaml` and adjust:

| Key | Default | Description |
|---|---|---|
| `listen_addr` | `0.0.0.0:9090` | TCP address for the Vault socket audit device |
| `vault_addr` | `http://127.0.0.1:8200` | Vault API address |
| `dry_run` | `true` | Log kill actions without executing them |
| `eval_role_pattern` | `^eval-[a-z0-9-]+$` | Regexp matching killable role names |
| `lease_prefix_template` | `database/creds/{{.Role}}` | Go template for the lease revocation prefix |
| `kv_mounts` | `["kv"]` | KV v2 mounts for path normalization |
| `decoys` | _(required)_ | Logical KV paths to watch (no `data/`/`metadata/` prefix) |
| `notify.webhook_url` | _(empty)_ | Optional Slack-compatible webhook URL |
| `ingest.buffer_size` | `10000` | Channel depth between TCP reader and detector |

The Vault token is read from the `VAULT_TOKEN` environment variable.

---

## Vault setup

Tripwire must be listening **before** enabling the socket audit device (Vault tests the connection at enable time):

```sh
vault audit enable file file_path=/vault/audit/audit.log
vault audit enable -path=tripwire socket \
  address=host.minikube.internal:9090 socket_type=tcp hmac_accessor=false
```

Or use `make audit-enable` (from `lab/`).

### Tripwire policy

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

---

## Verified behavior

Verified locally with Vault v1.21.6+ent (binary at `vault_launch_template`).
A1 and A3 require the minikube lab — marked pending until Task 5.

| ID | Assumption | Status | Evidence |
|---|---|---|---|
| A1 | Host reachable from pod on TCP | ✅ confirmed | On Colima/k3s: `host.minikube.internal` does not resolve. `10.42.0.1` is the k3s `cni0` bridge (inside the VM), not the Mac. The Mac host is `192.168.5.2` (QEMU usernet gateway) — `nc -zv 192.168.5.2 9090` from `vault-0` returns `open`. `TRIPWIRE_ADDR` set to `192.168.5.2:9090`. |
| A2 | Socket audit device writes one JSON object per line (newline-delimited) | ✅ confirmed | `python3` parsed all 18 audit lines; zero lines failed JSON decode; no line spans multiple newlines. `testdata/audit/` captured from live run. |
| A3 | K8s-auth tokens include `auth.metadata.role` / `service_account_name` / `service_account_namespace` / `auth.entity_id` | ✅ confirmed | K8s auth login response (in-cluster, k3s): `metadata.role="eval-0412"`, `metadata.service_account_name="eval-0412"`, `metadata.service_account_namespace="evals"`, `entity_id="e2d9fb2a-5b2f-a86d-9e68-a2c0f4237b57"`. SevKill finding triggered in tripwire log from eval pod decoy read. |
| A4 | ACL deny produces `request` + `response` entries with `permission denied` | ✅ confirmed | Restricted token reading decoy produced request entry (path=`sys/internal/ui/mounts/kv/research/artifactory-admin`) then response entry with `error: "permission denied"`. See `testdata/audit/denied-read-response.json`. |
| A5 | `hmac_accessor=false` → `auth.accessor` in cleartext on socket device | ✅ confirmed | Socket device with `hmac_accessor=false`: tripwire log shows `accessor: uK6Qq4InurF0yBWNGks6YeAf` (cleartext). File device same event: `accessor: hmac-sha256:74a50f8a…` (HMACd). |
| A6 | `disabled=true` on entity → existing tokens fail immediately on next request | ✅ confirmed | `vault write identity/entity/id/<id> disabled=true` → subsequent `vault token lookup` with that entity's token returned `403 permission denied`. |
| A7 | Socket device down → Vault requests still succeed (file device fallback) | ✅ confirmed | Killed tripwire process; `vault kv get` returned success. Vault documentation (and [`vault/vault/audit.go`](../vault/vault/audit.go)): requests succeed when at least one audit device succeeds. |

---

## Known limitations

- Detects only Vault-plane activity. Network egress (SSRF), kernel exploits, and non-Vault lateral movement are invisible.
- Disabling an entity does not revoke credentials minted outside Vault by a compromised downstream system.
- Kill state is in-process memory; a restart forgets which entities were killed (harmless — Vault keeps them disabled).
- Lab Tripwire auth uses a static token from env; production would use a dedicated auth method with no credentials reachable from sandbox nodes.
- Phase 0 is stateless and single-instance. No HA, no Prometheus metrics, no behavioral baselines (Phase 3).

---

## Lab topology

```
┌──────────────── minikube (Colima, M3 Mac) ────────────────┐
│  ns: vault    → Vault (Helm, dev mode)                     │
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

Vault runs in-cluster so traffic through a ClusterIP Service preserves pod source IPs in `remote_address` (needed for Phase 2 CIDR detection).

### vault_launch_template

The `vault_launch_template/` directory at the repo root launches a **host-local** Vault instance (not in minikube): `vault server -config=config.hcl`, unsealed with the key in `unseal.sc`.

- **Use for:** fast local verification of assumptions A2 and A4–A7, unit test fixtures, and local dev without spinning up minikube.
- **Do not use for:** A1 (requires a pod in minikube) or A3 (requires Kubernetes auth with a real ServiceAccount JWT).
- It does **not** replace the in-cluster lab for scenario tests or anything that depends on `remote_address`.

---

## Vault source version

| Component | Version |
|---|---|
| `vault/` source checkout | v2.3.0-beta1 (from `vault/version/VERSION`) |
| `vault_launch_template` binary | v1.21.6+ent (Enterprise), built 2026-05-18 |
| Running persistent instance at `:8200` | v2.0.4+ent (separate host process — not used for verification) |

> The verification runs (A2, A4–A7) used the `vault_launch_template` binary at v1.21.6+ent on a fresh raft instance at `:8300`. Source-level citations reference `vault/` at v2.3.0-beta1.
