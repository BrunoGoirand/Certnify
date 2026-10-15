# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Stack

Bash/Make PKI toolkit (Certnify). No build step — scripts run directly. Runtime: OpenSSL 1.1.1 or 3.x (LibreSSL is explicitly refused). Tests require Python 3.8+. Qualified platform: macOS, Bash 3.2.57, GNU Make 3.81.

## Test Commands

```sh
make test-smoke                  # End-to-end smoke test (all fixture types)
make test-stage0                 # Source packaging + root generation regression
make test-stage1                 # Parser/selection regressions (pki-records.awk)
make test-stage2                 # Path/lock/generation-transition regressions
make test-stage3                 # Make adapters, batch, concurrency/retry
make test-stage4                 # Strict verification, CRL, idempotence
make test-stage5                 # Key/policy, SAN, CN, config staging
make test-stage6                 # Failure injection + recovery
make test-stage7                 # Audit: orphan serials, weak keys, UTF-8
make test-stage8                 # Cleanup, duration, UTC/2038, strict CRL
make test-stage9                 # Batch migration
make test-stage10                # Hold/release, relocation
make test-stage11                # Durable operations (power-loss fencing)
make test-stage12                # Authority issuance categories
make test-stage13                # Security: hooks, publication, FIFO hardening
```

To run a single test method: `python3 -B test/stageN.py ClassName.test_method_name`

## Critical Architecture Constraints

- **Every PKI operation acquires a single workspace-level `mkdir`-based lock** (`.locks/root-ca.lock/`) before touching any state. Never bypass `pki_begin` / `pki_exit`.
- **`pki_begin` must be called at the top of every leaf script** (after sourcing `pki-env.sh`); this triggers the lock, recovery guard, and durable-op fence.
- All scripts source `bin/pki-env.sh`, which itself sources `bin/pki-state.sh`, `bin/pki-policy.sh`, etc. via a chain — do not source individual helpers directly.
- **Shell hooks** (`ISSUE_CMD`, `PUBLISH_CMD`, `PUBLISH_FETCH_CMD`) require `ALLOW_ADMIN_HOOKS=1` to run — omitting it raises a hard error by default.
- **LibreSSL is not supported** — the env bootstrap dies if `openssl version` returns LibreSSL.
- Intermediate directories are always named `intm-<KIND>-ca` (e.g. `intm-web-ca`). The kind is inferred from the directory name; mismatches between directory name and `ca.meta` KIND field are fatal.
- Action→KIND mapping is fixed: `server→web`, `user→auth`, `dev→code`, `email→smime`, `doc→archive`.

## Source Manifest (Critical for Tests)

`test/source-manifest.txt` is the **explicit packaging contract** — every new runtime file (script, profile, test) must be added there manually. No globs or git-tracked-file enumeration. Missing entries or symlinked paths cause stage-0 to fail.

- `profiles/root/base.cnf` must always be present in the manifest (hard-coded assertion).
- Generated PKI data (`root/`, `intm-*/`, `pki-data/`, `.locks/`, `.recovery/`) must never appear in the manifest.

## Code Style (Shell)

- All scripts: `set -euo pipefail` at top, `#!/usr/bin/env bash`.
- Variable references: use `${VAR:-}` (never bare `$VAR`) for potentially-unset vars to satisfy `set -u`.
- Makefile passes all variables to scripts via environment using `override VAR := $(value VAR); export VAR` — never use Make variable interpolation inside recipe shell code.
- Log helpers: `die()` writes `[ERR]` to stderr and exits; `info()` prints `[OK ]`; `warn()` prints `[!! ]` to stderr — use these, not raw `echo`.
- Path safety: always call `workspace_path` / `data_path` before using any caller-supplied path. Never pass user-supplied strings through `awk -v` — use `ENVIRON` instead (see `pki-records.awk` header).
- AWK scripts receive parameters through environment variables (`ENVIRON`), not `-v` flags, to avoid shell-escape injection.

## Test Isolation Rules

- Smoke and stage tests copy only manifest-listed source files into a temp directory via `test/workspace.py copy` — they never operate on the live workspace.
- Tests run with a stripped environment: only `PATH`, `TMPDIR`, `OPENSSL`, `LC_ALL` are retained. Inherited `CA*` vars, profile overrides, and Make flags are stripped.
- `umask 077` is set globally in `pki-env.sh`; private key files must be mode `0600`.
- Reserved ancillary paths (`notes/`, `draft/`, `image/`, `.vscode/`) cannot hold PKI state — `data_path` will die if asked to write there.
