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
| Changed source profile fragments | Affect new configurations only; installed policy changes require reviewed edits |
| Legacy meta/regular chain layout | Normalize companions without inventing a new issuer or losing original material |
| Archived issuer generations | Preserve leaf binding to the actual issuing certificate and key |
| Missing/ambiguous history or stale absolute configuration paths | Fail closed; require explicit reconciliation/rebinding |
| Large/leading-zero hexadecimal serial | Preserve numeric identity within checked unsigned 64-bit range; never lower counters |
| Nonempty CHAIN | Reject; no arbitrary trust-chain override |
| Ambiguous CN | Report candidates; require explicit supported SERIAL/FILE selection |
| Explicit SAN list | Suppress implicit CN SAN; reject unsupported syntax rather than drop it |
| Failed issuance or directory move | Preserve pending evidence and require manual review before mutation retry |
| Failed CRL publication | Preserve committed local CRL; resume with FINAL_CRL and per-artifact outcomes |
| Four-column reissuance | Declare CN-only loss; never imply preservation of original SAN/profile/subject/key policy |

## Deliberate exclusions

No root rollover, release from certificateHold/removeFromCRL, automatic crash
reconciliation, automatic arbitrary workspace relocation, or lossless full-policy
batch migration is implemented. A final CRL is advisory, not persistent retirement.
These are scope boundaries, not a list of unfinished correction tasks.

There is no multi-file transaction, fsync/power-loss guarantee, distributed locking,
network-filesystem qualification or protection against concurrent external writers.
Publication commands are privileged operator code; exit zero is not independently
verified remote delivery. Repeated publication must be safe for the chosen command.
Read-only permissions do not establish immutability or tamper evidence.

The CLI does not uniformly type-check every input. DN/SAN validation is the bounded
subset in chapter 04, not full Unicode normalization, complete mailbox/URI syntax
or proof of domain ownership. Issued validity is not capped to issuer expiry.
Verification supplies no hostname/application-purpose check. CRL endpoints are not
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
