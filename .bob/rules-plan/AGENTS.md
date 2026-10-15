# Project Architecture Rules (Non-Obvious Only)

- **Single workspace-level lock serializes all PKI operations** — there is no per-authority or per-operation lock granularity. Two concurrent `make server` calls on different intermediates will queue, not run in parallel.
- **`ROOT_DIR` is always the Makefile/repo root** — all authority directories (`root/`, `intm-*/`, `pki-data/`) live as siblings to `bin/`, `profiles/`, `test/` under that root. Absolute paths outside that root are refused.
- **Durable operation fencing is mandatory for writes** — `durability_begin` writes intent before any state change; `durability_finish` completes the fence. A failed barrier leaves the lock held for manual review (no auto-repair).
- **Authority directories follow a strict naming convention**: `intm-<KIND>-ca` for active, `intm-<KIND>-ca-legacy-<YYYYMMDD>` for rollover originals, `intm-<KIND>-ca-pre-rollback-<YYYYMMDD>` for rollback snapshots. Pattern-rule targets (e.g. `rollover-web`) extract KIND from the stem.
- **The `ca.meta` file is a key/value store** (not shell): read with AWK (`awk -F= '$1=="KIND"'`), never sourced as shell. Duplicate keys or empty values are fatal.
- **Copy-extensions model**: SANs are injected into the CSR and propagated to the signed cert via `copy_extensions = copy` in `openssl.cnf` — the signing CA does not independently re-specify extensions.
- **`test/source-manifest.txt` is a packaging contract, not a test fixture list** — it governs what gets copied into disposable test workspaces. Architectural boundary: source files go in the manifest; generated PKI state never does.
- **LibreSSL is hard-refused** at env bootstrap — any plan involving macOS system OpenSSL must account for this; use Homebrew OpenSSL 3.x or override `OPENSSL=`.
