# 09 — Compatibility and limitations

## Required compatibility

Retain operation coverage, explicit routing/defaults, profiles and extension
criticality, key reuse/rotation controls, chain order, strict requested CRL checks,
issuer-scoped serial uniqueness, exact CN ambiguity handling, and failure outcomes.
The interoperable formats are defined in chapter 03. Internal storage/language may
change only with explicit import/export behavior; filenames are not identities.

| Input or state | Required treatment |
| --- | --- |
| Existing raw CN filenames | Preserve on import/lookup; use safe mapped names for new artifacts |
| Existing complete unversioned configuration | Validate required sections and paths; retain operator policy |
| Changed source profile fragments | Affect new configurations only; installed policy changes require a supported toolkit operation or separately documented offline maintenance under chapter 01, never routine direct edits |
| Legacy meta/regular chain layout | Normalize companions without inventing a new issuer or losing original material |
| Archived issuer generations | Preserve leaf binding to the actual issuing certificate and key |
| Missing/ambiguous history or stale absolute configuration paths | Fail closed; require explicit reconciliation/rebinding |
| Large/leading-zero hexadecimal serial | Preserve numeric identity within checked unsigned 64-bit range; never lower counters |
| Nonempty CHAIN | Reject; no arbitrary trust-chain override |
| Ambiguous CN | Report candidates; require explicit supported SERIAL/FILE selection |
| Explicit SAN list | Suppress implicit CN SAN; reject unsupported syntax rather than drop it |
| Failed issuance or directory move | Resume only a complete verified installation plan; otherwise preserve evidence for manual review |
| Failed CRL publication | Preserve committed local CRL; resume with FINAL_CRL only with matching local resume state; otherwise generate a fresh CRL; retain per-artifact outcomes |
| Four-column reissuance | Default preserving migration requires source certificate and archived profile; explicit `REISSUE_MODE=cn-only` permits reviewed loss |

## Deliberate exclusions

No root rollover, arbitrary crash reconciliation, live/concurrent workspace
relocation, or lossless full-policy batch migration is implemented. Individual
certificateHold release, verified installation recovery and explicit offline
workspace rebinding are supported with the guards in chapters 02, 06 and 08. A final CRL is advisory, not persistent retirement.
These are scope boundaries, not a list of unfinished correction tasks.

There is no atomic multi-file transaction, hardware power-cut qualification,
distributed locking, network-filesystem qualification or protection against
concurrent external writers. Checked persistence barriers and a durable interrupted-
command fence are implemented as described in chapter 08.
External writes are prohibited by the operating contract in chapter 01, whether
concurrent or offline; their exclusion relies on deployment isolation and is not
guaranteed by the current shell code. Durability now requires Python 3.8+ on Linux
or macOS and a single local filesystem honoring persistence barriers. Other
platforms fail closed; real power-loss behavior still requires qualification.
Publication commands are privileged operator code; exit zero is not independently
verified remote delivery. Repeated publication must be safe for the chosen command.
Read-only permissions do not establish immutability or tamper evidence.

Shared scalar controls are type-checked before mutation; configuration fragments
remain trusted operator input. DN/SAN validation is the bounded subset in chapter
04, not Unicode normalization, complete mailbox/URI syntax
or proof of domain ownership. Excessive requested validity is refused against the full chain; it is not silently capped.
Explicit identity/application-purpose checks and a strict verification mode are
available; default verification remains chain-only. CRL endpoints are not
automatically embedded or fetched. Additional services outside scope are listed
in chapter 01.

## Qualification and security boundaries

The tested platform is macOS with Bash 3.2.57, GNU Make 3.81, OpenSSL 3.6.4 and
Python 3.14.7 for tests. The executable gate accepts OpenSSL 1.1.1/3.x and rejects
LibreSSL; that acceptance is not testing or a vendor-support claim. Other backend
versions, Linux/newer Bash, actual remote publishers and network filesystems need
their own qualification. Test commands and acceptance coverage are in chapter 10.

Keys are unencrypted files under restrictive permissions. Use the documented data
locations or add explicit exclusions for custom locations before generation. Git
ignore rules do not remove tracked secrets or constitute a history audit. Source
packages use an explicit manifest and never copy operational PKI state.
