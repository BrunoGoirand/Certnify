# Repository guidance

## Project and sources of truth

Certnify is a local private-PKI toolkit: Bash scripts and a Make interface drive
OpenSSL, with Python helpers for durability and publication. It manages roots,
intermediates, certificates, revocation, CRLs and authority lifecycle operations.

- Start with `README.md`, `specifications/README.md` and `test/README.md`.
- The English chapters in `specifications/` define current contracts. Chapter 10
  maps acceptance scenarios to tests and records qualification limits.
- `specifications/guides/` and the English/French READMEs document usage.
- `draft/` is ignored, local planning material; proposals there are not implemented
  features or authoritative contracts. Preserve it.

## Code map

- `Makefile`: public command adapters, defaults and parameter forwarding.
- `bin/gen-*.sh`: authority and leaf issuance; specialized wrappers share
  `gen-leaf.sh` and `pki-env.sh`.
- `bin/pki-*.sh`, `bin/pki-*.awk`, `bin/pki-*.py`: shared parsing, policy,
  state, validity, recovery, persistence and publication support.
- Other `bin/` scripts implement verification, revocation, CRLs and lifecycle
  operations such as rollover, rollback and batch reissuance.
- `profiles/`: OpenSSL configuration fragments for new authorities and leaves.
  Changing a fragment does not update an existing authority's `openssl.cnf`.
- `test/stage0.py` through `test/stage14.py`: isolated regression suites;
  `test/smoke.sh`: end-to-end smoke tests; `test/workspace.py`: fixture helpers.

## Working conventions

Verify the physical working directory, Git root and status before editing;
preserve unrelated changes. Keep fixes scoped and update the owning specification
and relevant usage documentation when observable behavior changes. Keep English
and French documentation aligned for affected workflows.

Write source comments and repository documentation in English, except for
explicitly maintained translations such as the French documentation. When modifying
code, translate non-English comments in the affected sections into English.
Preserve useful comments and keep them aligned with behavior; explain reasons and
constraints rather than restating syntax.

Preserve Bash 3.2 and GNU Make 3.81 compatibility. Python requires 3.8 or newer.
The backend gate accepts stable OpenSSL 1.1.1, 3.x and 4.1.x; other families and
LibreSSL are rejected. Admission is not qualification of every accepted build;
see chapter 09's support table and chapter 10's dated acceptance evidence.
Preserving migration and its matrix/benchmark require admitted 3.x or 4.1.x.
Use `OPENSSL=/absolute/path/to/openssl` when needed. Accepted versions are not all
qualified platforms; consult the recorded acceptance evidence.

Follow nearby code conventions, including quoted expansions and strict error
handling. Treat CNs, paths, SANs and Make parameters as data, never shell code.
Preserve omitted-versus-empty input semantics and direct-script/Make parity.
Keep policy and persistence logic in shared helpers rather than duplicating it in
wrappers. Preserve fail-closed validation, issuer bindings, category restrictions,
serial uniqueness and explicit partial-failure reporting.

## Protect operational PKI data

This checkout may contain real authority state. Do development and regression
work in disposable fixtures, never by issuing or revoking against local authorities.
Operational mutations require authorization for the intended operation and scope.
Use native previews where supported; `DRY_RUN` is not universal.

Do not print, copy into reports, stage or distribute private keys or recovery
journals. Generated data belongs under `root/`, `intm-*/`, `intermediate/`,
`pki-data/`, `out/`, `.locks/` and `.recovery/`, not in source packages.
Custom authority paths need an explicit exclusion before generating data.

Never reset counters, remove index rows, clear pending recovery evidence or steal
locks to make a command succeed. Signing failures can leave committed issuance;
CRL/publication failures do not undo revocation. Consult the reliability contract
and recovery guide before any recovery action. `make clean` previews;
`make clean CLEAN_APPLY=1` deletes authority material and is not development cleanup.

## Validation

Run commands from the repository root. There is no compilation step.

```sh
make help
make test-stage0                    # source packaging and fixture isolation
make test-stage5                    # example: key/profile/SAN policy regressions
python3 -B test/stage1.py Records.test_serials_are_exact_and_monotonic
make test-smoke                     # broader end-to-end validation
git diff --check
```

Select relevant `make test-stageN` targets (0–14) using `test/README.md`; run broader
suites when shared behavior changes. Use `bash -n path/to/changed-script.sh` for
shell syntax checks. Add regression coverage for behavior changes, including
rejection paths and assertions on permitted state changes.

Fixtures must use `test/workspace.py` and its explicit
`test/source-manifest.txt`. Add new runtime, profile and test files to that manifest
deliberately. Never recursively copy this checkout into a fixture or infer source
contents from tracked files: that can include operational data. Use generated
fixture keys only; publication tests use local stubs.

Report exactly which checks ran and their outcome. Distinguish targeted tests,
full suites and historical evidence. Disposable tests do not establish real
power-loss, network-filesystem or remote-publication qualification.

## Code navigation with Serena

Prefer the local Serena MCP server for code exploration.
Read its initial instructions before the first coding task and verify
that the active project matches this repository.
Use symbol overviews, targeted symbol reads and reference searches
before reading entire source files.
Use text search for documentation, configuration and unsupported files.
If Serena is unavailable, state that briefly and use local tools.

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
make test-stage14                # Leaf inventory exports
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
