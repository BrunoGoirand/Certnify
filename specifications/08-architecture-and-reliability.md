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

The journal is a recovery aid, not authoritative evidence that a filesystem
write reached durable storage. A phase may lag a committed operation. A port must
inspect actual database and artifacts, not equate a missing success receipt with
permission to reissue. Batch issuance also retains its per-item review receipts.

## File replacement guarantees and limits

Keys are generated to a same-directory temporary file and renamed only after
successful generation. A failed intermediate rekey leaves the old canonical
key/certificate/chain/metadata intact until signing and verification of the
replacement succeed. Old pairs are archived together in a staged generation
directory. Leaf forced replacement backs up any existing key and stages its key
and CSR. A complete serial-named key/CSR/certificate/fullchain set is retained.
Only after chain verification does it enter the canonical-replacement phase and
replace all four conventional paths, checking the resulting key/certificate pair. Certificate, binding, policy
record, metadata and chain replacement use staged single-file renames; latest
aliases are created under a temporary sibling directory and renamed individually.

There is **no multi-file transaction and no fsync/power-loss guarantee**. Installing
an intermediate or forced-replacement leaf key and certificate, publishing a
chain and metadata, renaming
rotated leaf artifacts, and moving/rebinding authorities have interruption
windows. The pending journal blocks automatic retries through those windows and
archives retain old identities. It does not make mixed intermediate files safe
for consumers that bypass toolkit locking. Permissions 0400/0444 are ordinary
read-only permissions, not immutable storage. Failed operations may retain
private `.key.*`/`.replacement.*` and public temporary files for inspection.

Revocation and normal CRL refresh remain explicitly retryable without this
issuance journal: the existing R row is recognized, no second revocation is
performed, and a refresh generates a new CRL with a higher counter. A CRL refresh
may fail after revocation; the error says which local change remains committed.

## Journal representation

`.recovery/pending/operation` contains an `id=YYYYMMDDTHHMMSSZ-pid` line and an
`operation=...` description. `phase` contains the latest `phase=...` line, replaced
through a sibling temporary file. `events` appends phase/path/expected-serial notes.
These are diagnostic text, never shell input or a transaction log with durable
ordering guarantees. An acknowledged directory also contains the operator's
`review` note. Preserve unrecognized diagnostics during import; use actual CA
artifacts to establish commit state. No private key bytes belong in this journal.

## Recovery interface

bin/recovery.sh defaults to a read-only report, including with a stale lock.
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
