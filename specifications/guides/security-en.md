# Operator security contract

Updated 2026-09-22 for RIS-02, RIS-03 and RIS-04. RIS-01 (private-key encryption)
is deliberately unchanged at the operator's request. Existing keys, archives and
recovery copies are not rewritten or deleted by these changes.

## Account and execution boundary (RIS-02)

Certnify is a local administrator toolkit. The account, Make options, shell
startup environment, PATH executables, OpenSSL, source files, profiles and
installed configuration must be trusted. Its cooperative lock does not exclude
other programs using the same account. File hashes and read-only modes are
consistency checks, not evidence against an attacker controlling that account.

Use a dedicated account with access restricted to the PKI operators. Keep source
releases and executables controlled by the administrator; allow no concurrent
editor, synchronization client, backup writer or other external writer to change
operational state. Backups must be taken from a consistent, quiescent state and
kept outside the live workspace. No live policy-update workflow is provided:
do not edit installed configuration during toolkit operations. Review a proposed
policy against the archived issuance policies and qualify it in a disposable
copy before any separately controlled maintenance.

`ISSUE_CMD`, `PUBLISH_CMD` and `PUBLISH_FETCH_CMD` are refused before backend calls
or mutations unless `ALLOW_ADMIN_HOOKS=1`. This explicit opt-in prevents accidental
hook execution; it is not a sandbox and cannot constrain a compromised caller.
Only pass reviewed administrator-owned shell code. Row values for issuance remain
environment data and must be quoted by the adapter. Neither a hook nor arbitrary
Make/environment overrides may be exposed as parameters of an untrusted service.
Such a service needs its own fixed command/parameter allowlist and access policy;
Certnify does not provide that interface.

## Persistence scope and admission (RIS-03)

The physical workspace remains the conservative operational scope, including
custom/nested authorities, every retained generation, recovery copies and
receipts, exports and temporary operational files. Exclusions are `.git`,
`.locks`, exact distribution-manifest files, and the reserved ancillary trees
`notes`, `draft`, `image`, `.vscode`. Keep unrelated material in these ancillary
trees or outside the workspace. Their regular/special files are never opened or
synchronized. The scanner still inspects names and directories to reject known
legacy authority markers; this is a migration guard, not arbitrary secret-file
discovery. Mounted ancillary directories are rejected, and aliases are not
followed. Data-path validation forbids placing authority data there, directly or
via aliases. Relocate any older authority there through reviewed offline
maintenance before upgrading; do not simply remove its markers.

Before admitting a write, the persistence helper exercises the existing storage
scope and device barrier. Unsupported operational entries and I/O failures refuse
the command before its fence or authority mutation. Later failures retain the
existing conservative recovery behavior. No persistence barrier is removed.
This detects existing failures, not future failures or a malicious concurrent
writer. Hardware power loss, network storage and Linux remain unqualified here.

Annex file count no longer increases file synchronization calls. Directory/name
inspection still costs time, and retained PKI history still increases full-tree
barrier cost. The preflight adds a pass. There is no throughput guarantee or
automatic retention/deletion: reducing operational-history cost requires a
separately qualified persistence/retention design. Stage 13 tests scope coverage
with 100 ancillary files and retained nested state, plus FIFO and injected EIO.

One local macOS temporary-directory measurement on 2026-09-22, using a single
`Store.flush()` and 1 KiB synthetic history files, took 0.021 s for 0 files,
0.031 s for 100 files and 0.142 s for 1000 files. This is a single-run scope-cost
observation under concurrent tests, not an issuance benchmark or capacity limit.

## Verified publication adapter (RIS-04)

Configure both an idempotent uploader and a reader of the destination used by
consumers. The reader writes only the fetched file bytes to stdout, diagnostics
to stderr, and fails on remote/transport errors. It must authenticate the actual
destination; do not point it at the local source. `%FILE%` denotes a generated
basename, quoted by the runner. Both hooks run in `OUT_DIR` with stdin closed.

```sh
INT_DIR=intm-web-ca ALLOW_ADMIN_HOOKS=1 PUBLISH_TIMEOUT=60 \
  PUBLISH_CMD='your-publisher %FILE%' \
  PUBLISH_FETCH_CMD='your-remote-reader %FILE%' \
  bin/intm-publish-final-crl.sh
```

These adapter names are placeholders to replace with your reviewed integration.
`PUBLISH_TIMEOUT` is a shared 1–3600 second budget (default 60) for all six upload
and read-back pairs, under the workspace lock. Upload exit zero is insufficient:
the reader must also exit zero and return the exact expected size and SHA-256.
The first failure stops publication, records failure and returns nonzero. A
read-back larger than expected is stopped without buffering the whole response.
Ordinary descendants in the hook process group are killed on completion, timeout
or cancellation. Adapters must not detach/daemonize; this is not process isolation
against malicious code or a bound on uninterruptible kernel/filesystem I/O.

The receipt records generated status lines and verified artifact hashes; free-form
uploader output and runner diagnostics go to stderr, not into the receipt.
All six must pass, and local
artifacts/resume state must still match before reporting complete publication.
Re-run with the same `FINAL_CRL`, `OUT_DIR` and adapters after a partial failure;
the local CRL number is not incremented. Retry overwrites must be safe for the
destination. Do not infer that an unsuccessful attempt transferred nothing.

Read-back establishes what the configured reader observed at that time. It
cannot prove that a dishonest adapter contacted a remote system, ensure later
availability, or make the six remote writes atomic. Local-adapter regressions
are not qualification of a production remote service.
