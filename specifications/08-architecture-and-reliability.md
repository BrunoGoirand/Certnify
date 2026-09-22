# 08 — Architecture and reliability

## Suggested component contracts

These interfaces describe a replacement architecture; they are not existing public APIs.

| Component | Responsibilities and contract |
| --- | --- |
| Command adapter | Parse operation/options; distinguish omitted, empty, and explicitly set values; translate historical defaults |
| Workspace resolver | Canonicalize containment, identify authority directories/generations, resolve relative artifact paths |
| Policy engine | Subject/SAN validation, profile selection, duplicate rules, key reuse/rotation decisions |
| Crypto provider | Generate/inspect keys, create requests, sign/parse/verify certificates and CRLs; no business-path decisions |
| Authority repository | Issuance records, counters, disabled state, metadata, historical generation bindings |
| Artifact store | Restrictive temporary files, durable installation, backups, chain ordering, symlinks where supported |
| Issuance service | Root/intermediate/leaf workflows and postconditions |
| Revocation service | Single/bulk database transitions and CRL refresh |
| Lifecycle service | Rollover/rollback with recovery journal |
| Batch runner | Deterministic inventory selection, item results, dry-run planning |
| Publication adapter | Explicit configured destination/command, per-artifact result, retry boundary |

Suggested core types are AuthorityId, AuthorityGenerationId, CertificateId(issuerGeneration, serial), DistinguishedName, SubjectAlternativeNames, KeySpec, CertificateProfile, ValidityRequest, RevocationReason, IssuanceResult, VerificationResult, and BatchResult. Paths are artifact locators, not cryptographic identities. Serial values must not be represented as floating-point numbers.

Every mutating service should accept a resolved authority handle and immutable request, validate preconditions, reserve/update issuer state under serialization, install artifacts, then return committed state and post-processing results. No helper should infer a different workspace after a transaction has begun.

## Transaction lock

The exclusive-writer operating contract in chapter 01 is mandatory. The lock
serializes supported toolkit operations; it does not enforce that contract against
processes with direct write access. Permission checks or change detection alone
cannot establish exclusive ownership. Deployment isolation must also cover
publication hooks, synchronization tools and the invoking account.

Every low-level CA transaction, including ordinary readers, uses the physical workspace's
`.locks/root-ca.lock`. A single coarse lock deliberately serializes authorities,
root revocation, CRL updates, and directory transitions. Aliases share this lock.
Rollover invokes the ordinary generator in the same shell while retaining it.
Batch reissuance releases its preflight lock before child commands and pins the
expected issuer certificate identity; a changed issuer aborts child issuance.
The batch as a whole is not atomic. Supported DRY_RUN planning is an unlocked,
read-only advisory view, as defined in chapter 06.

`LOCK_TIMEOUT` is an integer number of seconds (default 30). Normal exit and
handled INT/TERM release the lock. Locks left by a crash are never stolen based
on PID existence or age. On timeout, inspect the lock's `pid` and establish that
no operation still owns it before manual removal. There is no distributed-lock
or hostile external-writer guarantee. Publication hooks execute while locked;
they must not recursively invoke toolkit transactions.

## Opening established authorities

Layout initialization is limited to absent or empty authority directories.
Missing index, certificate counter or CRL counter is an error on an existing
authority, including during root/intermediate generation. Never reconstruct an
empty database or reset a counter as an implicit repair. A key/certificate-bearing
authority also requires its retained policy. Issuance checks numeric collisions
against retained certificate and binding artifacts before maintenance or signing.
These checks detect missing state and next-serial conflicts; they are not a full
forensic reconstruction of a truncated or externally modified database.

## Commit boundaries

Preflight rejection is not issuance. Configuration/layout preparation and
`AUTO_UPDATEDB` maintenance can nevertheless precede signing. Once OpenSSL starts
signing, failure is an **uncertain outcome**, not proof that nothing happened.
OpenSSL can update `newcerts`, `index.txt` and `serial` before returning failure or
before Certnify installs the named certificate, binding, policy record, chain and
metadata. A committed certificate remains issued even if installation or chain
verification fails. Never restore an earlier counter or remove its index row to
retry. Revocation likewise commits before optional CRL refresh; a failed refresh
does not undo revocation. A generated CRL can consume its counter before output
validation or publication fails.

The physical-workspace lock serializes toolkit operations. Direct OpenSSL calls
or external file modifications bypass this protection. A killed process can
leave a lock; the toolkit never steals it. Confirm the recorded owner is no
longer running before manually removing a stale lock directory.

Root creation, intermediate/leaf issuance and lifecycle moves record a pending
operation in `.recovery/pending` before key replacement, signing or the first
move. Its operation ID, paths, expected serial and phase/events survive ordinary
command failures. Signing is marked uncertain before the backend runs, committed
after the returned certificate serial is read, then installed and verified.
Root self-signing writes no issuer database record; its key and staged certificate are
recorded separately. Move events record source and destination before rename.
Only successful completion clears the pending journal. SIGKILL leaves it intact.
Subsequent locked toolkit commands refuse an unresolved journal before changing
PKI state. Preflight errors before this boundary do not create a pending journal.

The diagnostic journal is a recovery aid; only a completed persistence barrier
establishes the software durability boundary. A phase may lag a committed operation. A port must
inspect actual database and artifacts, not equate a missing success receipt with
permission to reissue. Batch issuance also retains its per-item review receipts.

## File replacement guarantees and limits

Keys are generated to a same-directory temporary file and renamed only after
successful generation. A failed intermediate rekey leaves the old canonical
key/certificate/chain/metadata intact until signing and verification of the
replacement succeed. Old pairs are archived together in a staged generation
directory. Leaf forced replacement backs up any existing key and stages its key
and CSR. A complete serial-named key/CSR/certificate/fullchain set is retained.
Only after chain verification does it seal the installation plan and replace
all four conventional paths from the same checked key/certificate set. Certificate, binding, policy
record, metadata and chain replacement use staged single-file renames; latest
aliases are created under a temporary sibling directory and renamed individually.

There is **no atomic multi-file transaction**. The durable fence described below
blocks further operations after abrupt interruption; it does not undo partial writes. Installing
an intermediate or forced-replacement leaf key and certificate, publishing a
chain and metadata, renaming
rotated leaf artifacts, and moving/rebinding authorities have interruption
windows. The pending journal blocks ordinary retries; complete verified plans
can be resumed as described below. Archives retain old identities. It does not make mixed intermediate files safe
for consumers that bypass toolkit locking. Permissions 0400/0444 are ordinary
read-only permissions, not immutable storage. Failed operations may retain
private `.key.*`/`.replacement.*` and public temporary files for inspection.

Revocation and normal CRL refresh remain explicitly retryable without this
issuance journal: the existing R row is recognized, no second revocation is
performed, and a refresh generates a new CRL with a higher counter. A CRL refresh
may fail after revocation; the error says which local change remains committed.

## Journal representation

### Power-loss resilience: durable fence and verified checkpoints

The software protocol is implemented by `bin/pki-durable.py` and its shell adapter.
Python 3.8+ is now a runtime dependency. The supported persistence primitives are
`fsync` on Linux and `fsync` followed by a checked `F_FULLFSYNC` device barrier on
macOS. No silent fallback or option to disable durability is provided. Hardware
power-cut qualification remains outstanding; storage must honor these barriers.

Under the workspace lock, each mutating command persists `.recovery/power-loss`
and its containing directories **before** layout preparation or backend execution.
This fence covers initialization, OpenSSL index/counter/newcerts updates, normal
revocation/CRL operations, lifecycle moves, inventory and batch receipts, cleanup
and relocation. Ordinary verification checks admission without creating a fence.
Supported unlocked previews and recovery reporting remain read-only.

On an orderly exit, including a reported ordinary command failure, the helper
synchronizes workspace regular files and directories bottom-up before retiring the
fence. Existing operation-specific recovery journals still block uncertain signing
outcomes. Synchronizing a partial result does not repair it or turn failure into
success. Signal exits retain the fence. A persistence error makes the command fail,
retains blocking state and prevents new operations; when possible a
`.recovery/power-loss-error` diagnostic latches the error against an exit-time retry.
Only a successful exit with `Local state durably synchronized` is a completed
mutating command acknowledgment; earlier progress messages are not acknowledgments.

The conservative synchronization scope is the physical workspace, excluding `.git`,
`.locks` and the exact source files listed in the trusted distribution manifest.
Symlinks are never followed; their parent directories are synchronized. Nested
mounts and unsupported special files are rejected. Keep operational state separate
from distribution source files and on one local filesystem. Operational path
resolution rejects `.git`, `.locks` and exact distribution source paths, including
aliases resolving into those exclusions. The scan cost grows
with retained PKI history; this implementation favors a complete persistence
boundary over per-file write tracking. No files outside the workspace are covered.

Before installing a verified plan, the toolkit persists backend state, source
copies, guards, manifest and `ready`, then binds the ready-file digest into the
fence. After an abrupt stop, `resume` requires this durable checkpoint **and** all
existing semantic/hash/identity checks. A ready file alone is insufficient when
a power-loss fence remains. Plans created before checkpoint completion, damaged
artifacts and interrupted backend updates remain blocked for manual review.
Recovery never signs again, rolls back counters or reconstructs the database.
When an orderly failure has retired its fence but left a verified plan, resumption
seals a fresh durable checkpoint before installation. A second interruption during
that resume can therefore follow the same verified recovery path.
An interruption after moving the completed journal but before retiring the fence
may conservatively require manual review; completion receipts must be retained.

Normal CRL retry behavior is preserved after orderly errors. After abrupt loss,
even a revocation or CRL operation without an issuance journal is blocked by the
fence. Remote publication starts only after a local persistence barrier; remote
acknowledgment and retries remain the publisher's responsibility.

`RECOVERY_ACTION=acknowledge` records the explicit review and synchronizes the
reconciled state before retiring a power-loss fence. This is an administrator
assertion, not an automatic integrity check. Review records are retained as
`.recovery/power-loss-reviewed-<ID>`. Stale locks are never stolen.

The target is durable successful local operations, or verified resumption/explicit
blocking of interrupted operations, assuming exclusive toolkit writes and a
qualified storage stack. There is no atomic multi-file database transaction, no
automatic repair of arbitrary OpenSSL damage and no guarantee against destroyed
media or privileged tampering. Independent backups remain necessary. SIGKILL and
injected barrier-error tests establish software behavior, not real power-cut
qualification. Synced folders and network filesystems remain unqualified.

See [Linux fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html) and
[Apple's persistence guidance](https://developer.apple.com/documentation/xcode/reducing-disk-writes).

### Current representation

`.recovery/pending/operation` contains an `id=YYYYMMDDTHHMMSSZ-pid` line and an
`operation=...` description. `phase` contains the latest `phase=...` line, replaced
through a sibling temporary file. `events` appends phase/path/expected-serial notes.
These are diagnostic text, never shell input or a database transaction log.
Phase updates are synchronized, but a phase does not prove backend consistency. An acknowledged directory also contains the operator's
`review` note. Preserve unrecognized diagnostics during import; use actual CA
artifacts to establish commit state. A completed installation plan additionally
contains `manifest`, `guards`, `files/` and a last-published `ready` marker with
schema and SHA-256 digests. Files are copied before sealing, with mode 400 under
private directories. These may include private keys: journals have the same
confidentiality requirements as authority private storage and must remain excluded
from Git, packages and public archives. Paths in plans are workspace-relative;
no journal content is evaluated as shell code.

## Recovery interface

bin/recovery.sh defaults to a read-only report, including with a stale lock.
`RECOVERY_ACTION=resume` completes a sealed plan under the workspace lock.
`AUTO_RECOVER=1` enables the same path before ordinary locked operations; it is
opt-in and never applies when DRY_RUN=1, including on an ordinary locked reader. Supported plans cover validated leaf
publication (normal, rotate and forced replacement), hold release and whole-workspace
configuration rebinding. Cryptographic checks precede sealing; resume checks all
source hashes, state guards, validity deadlines and destination identities before
writing. A destination must still equal its recorded before or after state.
Counter/index guards prevent resuming against intervening issuance or revocation.
Installation uses staged per-file renames and can itself be interrupted and resumed.
Completed journals move to `.recovery/completed-<ID>` as private receipts. Internal directory aliases are replaced
without following their targets; an interruption between unlink and recreation
is supported by the plan, but alias replacement has a temporary missing state.

Recovery never signs a certificate, regenerates a CRL, resets counters, executes
saved commands or steals a stale lock. No ready marker, altered/missing artifacts,
expired validity, uncertain backend outcome, root/intermediate issuance before a
supported plan, or interrupted lifecycle directory moves still require review.
Power-loss resumption additionally requires the durable checkpoint above.
There is no atomic multi-file transaction. Receipt retention is operator-managed,
not automatically pruned.

`RECOVERY_ACTION=relocate` previews whole-workspace rebinding; `RELOCATE_APPLY=1`
applies only after full validation and sealing. See chapter 02.

RECOVERY_ACTION=acknowledge requires the exact reported RECOVERY_ID and nonempty
RECOVERY_NOTE. Under the workspace lock it moves the pending journal to
`.recovery/reviewed-<ID>`. It does not validate or repair CA state; acknowledgment
is an administrator assertion that manual reconciliation is complete. An incorrect
ID, empty note or occupied review destination fails. A journal interrupted before
its ID was written requires manual preservation/reconciliation, not an invented ID.
See [the recovery procedure](guides/recovery-en.md) and its
[French translation](guides/recovery-fr.md).

## Validation and containment

Treat configuration fragments and command templates as trusted administrative inputs. Treat CN, SAN values, inventory fields, metadata, and paths as data. Do not pass them through shell evaluation. Do not source metadata files. A new artifact naming scheme should use safe identifiers and an explicit display-name mapping; import compatibility must retain raw existing filenames without permitting path traversal on creation.

Verify an issuer using its certificate/public key and issuance binding, not a textual subject name alone. Bind archived leaves to their original issuer generation even if the same directory/CN has been reused. If importing OpenSSL text files, validate all fields and cross-check certificates before allowing mutations.

## Observability and cancellation

The shell interface emits human-readable OK/warning/error/debug messages, explicit
verification statuses, per-item batch outcomes and publication receipts. There is
no stable JSON result or cancellation API. Handled INT/TERM release the workspace
lock; SIGKILL can retain the lock and pending journal. A recovery phase can lag
actual writes. No logged success or failure replaces inspection of committed state.

A native implementation should return typed outcomes including authority/generation,
serial, commit certainty, artifact paths and actionable errors without private-key
material. Cancellation must report work already committed. Local generation and
external publication must remain separate outcomes.

## Import and migration requirements

An importer should discover root/active/legacy/rollback directories; parse certificates, keys, index/counters, metadata, and configuration paths; verify key pairs; reconcile archived PEMs and issuer-scoped serials; and flag missing artifacts or stale directory bindings. Never reset an issuer counter below issued history. Do not infer that `meta` and `ca.meta` have different cryptographic authority solely from their names.

Maintain PEM/DER export and chain ordering for external consumers. If replacing OpenSSL's database internally, provide a documented import/export mapping and migration report. Preserve revoked history, disabled markers, timestamps, historical keys, and raw subject/SAN contents. Byte-identical certificates are not required because keys, serial policy, times, and signatures can vary; decoded semantics and trust behavior are the compatibility criteria.

No performance target, maximum population, multi-host locking guarantee, or availability SLA is established in the project. Such requirements must be selected separately rather than inferred from these scripts.

### Data-path admission (AUD-02)

Creation, authority selection, directory moves and verified recovery share the
same data-path admission rule. The workspace source trees (`bin`, `test`,
`profiles`, `specifications`), Git/lock/recovery trees and inventory `out` tree
cannot contain authority data. Both requested names and physical alias targets
are checked. Nested custom authorities and aliases to admitted data remain
supported. Leaf issuance validates future installation and evidence paths,
including serial-derived filenames and replacement outputs, before signing;
recovery repeats validation before installation. These checks do not replace
the workspace lock or protect against noncooperating external writers.

Validation on 2026-09-22: 31 distinct methods passed incrementally across stage 1
(10), stage 2 (9), stage 10 (11) and the stage-11 excluded-path test (1), with
successful reruns after correcting the initial missing `issuers/` preflight
parent. Bash/Python syntax and diff checks passed. Disposable local PKIs only;
no full-suite, smoke, live-CA or hardware qualification is claimed.
