# Project Documentation Rules (Non-Obvious Only)

- **`specifications/` are the authoritative contracts** — they define behavior language-independently; the Bash/Make scripts are adapters, not the spec. Read specs before claiming behavior.
- **`bin/` contains both public-facing entry points and private helpers** — `pki-*.sh/awk/py` files are internal helpers sourced/called by leaf scripts, not invoked directly by users.
- **`profiles/` holds OpenSSL config fragments** assembled at runtime — they are source files distributed with the package, not generated data. Their path is overridable via `CERTNIFY_PROFILES_DIR`.
- **`test/workspace.py` is both a test utility and a CLI tool** — `python3 test/workspace.py copy|snapshot|diff` is used directly in smoke tests, not just imported.
- **French comments are normal** — the codebase uses both English and French in comments/docs; README-fr.md is the French README, `specifications/guides/` has both languages.
- **`draft/`, `notes/` are non-versioned ancillary directories** — they appear in `.gitignore` and are explicitly blocked by path admission rules from holding PKI state.
- **Stage numbers are not sequential by complexity** — stage-6 covers recovery/failure injection, stage-11 covers durable fencing; stages 12–13 cover authority categories and security hardening (added later).
