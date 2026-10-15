# Project Coding Rules (Non-Obvious Only)

- **Never source individual helpers directly** — always `source bin/pki-env.sh` then call `pki_begin`. The env file chains `pki-state.sh`, `pki-policy.sh`, `pki-durable.sh` etc. internally.
- **AWK scripts use `ENVIRON`, never `awk -v`** — pass all inputs through environment variables to avoid shell-escape injection (pattern from `bin/pki-records.awk`).
- **`$(value VAR)` in the Makefile** — all Make variables are frozen with `override VAR := $(value VAR); export VAR` before recipes. Recipe shell code reads `$${VAR:-}`; never interpolate Make variables into shell source.
- **`umask 077` is set globally** in `pki-env.sh` — any file created inside a PKI operation inherits restrictive permissions automatically.
- **`workspace_path` / `data_path` are mandatory** for any caller-supplied path — they validate no `..`, no symlinks, no reserved dirs, and that the path stays inside `ROOT_DIR`.
- **`shell hooks` are opt-in** — `ISSUE_CMD`/`PUBLISH_CMD`/`PUBLISH_FETCH_CMD` cause a hard `die` unless `ALLOW_ADMIN_HOOKS=1` is explicitly set.
- **Add every new script/profile/test to `test/source-manifest.txt`** — the explicit packaging manifest. Omitting a file silently breaks stage-0 tests.
- **`CERTNIFY_TARGET=$@`** is exported from the Makefile so pattern-rule scripts can read the stem (e.g. `rollover-web` → KIND=web) without re-parsing arguments.
- **Lock is `mkdir`-based** (`.locks/root-ca.lock/`) — works on macOS/Bash 3.2 without `flock`. Never remove or work around it.
