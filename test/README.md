# Isolated validation

Python 3.8+ is required both by the tests and by the runtime durability helper.

```sh
make test-stage0
make test-stage1
make test-stage2
make test-stage3
make test-stage4
make test-stage5
make test-stage6
make test-stage7
make test-stage8
make test-stage9
make test-stage10
make test-stage11
make test-stage12
make test-stage13
make test-stage14
make test-smoke
```

`test/source-manifest.txt` is the explicit source-only packaging contract. Add each new runtime/profile/test file deliberately. No recursive workspace copy, Git tracked-file enumeration, or directory wildcard determines fixture contents. Missing entries and symlinked source paths fail before copying. A clean package can be prepared in an absent or empty destination:

```sh
python3 test/workspace.py copy . /tmp/certnify-source-package
```

The root profile is a source file, not data recovered from an operational root. Stage-0 tests check its inclusion, Git eligibility, generation of a fresh root from the package, exclusion of unlisted sentinel data (including data under bin/profiles), failure on missing/symlinked inputs, and snapshot behavior. The Git staging check runs only in a temporary repository.

Smoke fixtures all live under one private temporary session and are removed on exit, including secondary cases. Commands run with a clean environment retaining only PATH, TMPDIR, OPENSSL and LC_ALL, so inherited CA paths, profile overrides and Make flags do not affect them. Use an absolute OPENSSL path or a binary available through PATH. Tests use generated keys only.

Smoke requires `verify-intermediate-revoked` to succeed for an unrevoked
intermediate and print the exact certificate-specific `: OK` line. After
revocation it requires a nonzero exit, the revocation diagnostic and no success
line. Output containing `OK` alone cannot override a failed command status.

The snapshot helper records file hashes, permissions, link targets, index/counter contents, and SHA-256 identities of decoded certificates. It never prints private key bytes or follows links. Use it only on disposable fixtures:

```sh
python3 test/workspace.py snapshot /tmp/fixture /tmp/before.json
# Run a regression operation against the fixture.
python3 test/workspace.py snapshot /tmp/fixture /tmp/after.json
python3 test/workspace.py diff /tmp/before.json /tmp/after.json
```

Smoke command snapshots are transient and a failed command prints changed paths before session cleanup. Future regression tests should assert the expected state changes, rather than merely recording them.

## Validated environment and limits

Stage 0 checks current acceptance-table method counts, Make suite targets and
the launch blocks in both project READMEs and this guide. This is a static
consistency check, not execution of the listed suites or a new qualification.

The qualified platform is macOS, Bash 3.2.57, GNU Make 3.81, OpenSSL 3.6.4 and
Python 3.14.7. The stable OpenSSL 1.1.1/3.x/4.1.x executable gate does not qualify
every accepted version. Newer Bash, other platforms/backends, network filesystems, power loss and
actual remote publication remain unqualified. See the
[acceptance map](../specifications/10-acceptance-and-traceability.md).

Stage 2's `BackendAdmission` class tests stable/unsupported version banners,
failed/missing version commands, full-response parsing, executable/library
agreement and unchanged snapshots on rejection through Make and direct scripts.
Synthetic banners only test admission policy. Its real-backend cases test
bootstrap, direct root creation and retained lock/journal/fence guards using the
selected `OPENSSL`; stage 0 also tests real Make root creation.

## OpenSSL backend matrix

Admitted OpenSSL 3.x and 4.1.x backends run seven methods, including preserving
migration. The benchmark uses the same feature selector after checking runtime
admission in a manifest-only disposable source package. See the
[admission contract](../specifications/09-compatibility-and-limitations.md#openssl-backend-admission).

The opt-in matrix tests actual executables, not directory labels or mocked version
strings. Supply paths explicitly; it neither downloads nor installs a backend:

```sh
python3 -B test/openssl-matrix.py \
  --backend /absolute/path/to/openssl-1.1.1 \
  --backend /absolute/path/to/openssl-3 \
  --backend /absolute/path/to/openssl-4.1 \
  --reject-backend /absolute/path/to/libressl \
  --jobs 2 > /tmp/certnify-openssl-matrix.jsonl
```

Repeat either backend option as needed; one executable is also valid. Missing
executables fail the command. Aliases resolving to the same executable are reported
once and never counted as distinct tested versions; conflicting accept/reject
expectations for the same executable fail before tests. The JSONL report records
platform/Python, resolved executable paths, real version strings, binary SHA-256,
admission outcomes and per-method results. Rejected backends must fail both Make
and direct root generation without changing fixture state. Accepted backends must
bootstrap without mutation before the behavioral checks begin.

The common selection is six methods:

| Method | Backend-dependent contract |
| --- | --- |
| `backend-contract.py Backend.test_crl_signature_issuer_and_time_boundaries` | Real CRL issuer/signature/date parsing; reject corrupted signatures, wrong issuers, past/future reference times, malformed and missing CRLs without mutation |
| `stage4.py Revocation.test_strict_coverage` | Required root/issuer CRLs and revoked-chain outcomes |
| `stage4.py Revocation.test_backend_status_overrides_misleading_output` | Backend failure cannot be converted to verification success by text matching |
| `stage5.py Policy.test_effective_key_metadata_matrix` | RSA, EC curves, Ed25519/Ed448 metadata and reused-key policy |
| `stage8.py Operations.test_application_identity_purpose_and_strict_crls` | DNS/IP/purpose checks and strict full-chain CRL verification |
| `stage12.py IssuanceCategories.test_compiled_custom_profiles_missing_multiple_and_oid_alias_ekus` | ASN.1 extension decoding, compiled profiles, missing/multiple EKUs and OID aliases |

Admitted OpenSSL 3.x and 4.1.x additionally run
`stage9.py Migration.test_complete_subject_sans_curve_fresh_key_dry_run_and_retry`.
Preserving migration is explicitly not applicable on 1.1.1; that entry is not
counted as a passed test. The portable CRL case corrupts DER signature bytes and
supplies reference times to the shared validator, avoiding newer test-only CRL
generation flags that could confuse harness compatibility with product behavior.

Every method uses manifest-only disposable fixtures and a stripped environment.
Workers may run different backends concurrently; methods for a given backend run
serially. Each method has a private temporary tree and a ten-minute timeout;
on timeout its process group is terminated before fixture cleanup. The command
returns nonzero if admission or any selected method fails. JSONL never exports
captured test output, private keys or recovery journals. For diagnostics, rerun
the named failed method with its explicit `OPENSSL` path using the ordinary test
command. This matrix is a targeted compatibility gate, not the full regression
suite, a throughput benchmark or qualification of every accepted version/platform.
See [recorded results and gaps](../specifications/10-acceptance-and-traceability.md#openssl-backend-matrix-2026-10-27).

## Generated-data convention

Keep authority data in workspace `/root/`, `/intm-*/` (including custom kinds, legacy and rollback names), `/intermediate/`, or `/pki-data/` for explicitly selected custom paths. `/out/`, `/.locks/`, `/.recovery/`, and `/test-results/` are excluded too. Private directories and conventional `.key.pem`/backup filenames are ignored as defense in depth.

Git cannot infer that every arbitrary filename/path contains secret data. A nonconventional custom authority location must receive an explicit local exclusion **before** generation, or be moved into the documented data convention. Ignore rules do not remove already tracked files and are not a historical
secret-content audit. Specifications and guides are distributed source material;
generated authority state and recovery journals are not.

Suite 1 covers parser and selection regressions; see [the record contract](../specifications/03-persistence-and-artifacts.md).

Suite 2 covers path, transaction-lock, and generation-transition regressions; see
[the authority state contract](../specifications/08-architecture-and-reliability.md).
Its `ShellContext` cases also check completed-bootstrap detection and refusal of
missing helpers. They cover resetting inherited ownership, idempotent sourcing
with active lock/fence/journal state, preserved cleanup traps, and
ordinary/SIGINT/SIGTERM failure admission.

Suite 3 executes Make adapters, partial batches, receipt concurrency/retry safety,
and FILE/CHAIN compatibility; see [the batch contract](../specifications/07-lifecycle-and-migration.md).

Suite 4 tests strict verification, validated CRL replacement, idempotence and
read-only plans; see [the revocation contract](../specifications/06-verification-and-revocation.md).
It also checks root revoked-entry display through Make and the direct script:
empty/revoked CRLs succeed, missing/malformed CRLs and backend failures with
partial output fail, and inspection preserves fixture state.

Suite 5 tests effective keys/policy, SAN validation, safe CN names and config
staging; see [the policy contract](../specifications/04-cryptography-and-profiles.md).

Suite 6 injects issuance, installation, move and publication failures, including
a killed issuer. See [the recovery contract](../specifications/08-architecture-and-reliability.md).
The rollover handoff test asserts a single shell/lock/fence/journal owner across
the sourced generator, its cleanup trap on success and signing failure, preserved
history and blocked blind retry. Probe assertions exist only in copied fixtures.
Publication uses only disposable local copy stubs. Recovery acknowledgment in these
tests records fixture-specific manual inspection; it is not an automatic repair.

Suite 7 covers audit A01–A06: missing state without mutation, orphan serials,
literal Make parameters/stems, scalar validation, weak generated/reused keys,
weak imported certificates, profile/request SAN conflicts and post-sign mismatch,
UTF-8 validation/identity/idempotence, and direct intermediate defaults.

Suite 8 covers routine-operation hardening: nonmutating cleanup previews and
bounded explicit deletion, duration/expired-issuer refusals before state changes,
UTC conversion across leap years and 2038, DNS/IP/email/purpose checks and strict
CRL verification, CN-only user batch behavior, and historical CRL renewal through
in-place rekey and directory rollover. The smoke archive CA explicitly has a
longer lifetime than its leaves, as required by the new duration admission rule.

## Four-defect regression coverage (2026-09-21)

Suite 6 now includes stale CRL replay refusal, missing resume state, immutable
versioned CRL artifacts during refresh, current PEM/DER consistency, and coherent
forced leaf replacement (including first issuance). Suite 8 checks 3600-day archive
defaults through Make, direct and batch issuance while retaining explicit validity
limits. Seven selected stage-6 scenarios and three selected stage-8 scenarios
passed; this is not a full-suite or smoke rerun. Exact executed scenario names are
recorded in the [acceptance map](../specifications/10-acceptance-and-traceability.md).

## Preserving migration

`make test-stage9` exercises source-backed batch migration in disposable PKIs:
full UTF-8 subjects, mixed SANs, key rotation/parameters, S/MIME profile variants,
absent/critical SANs, custom profiles and extended subjects, dry-run immutability,
retry receipts, missing metadata, policy drift and backend decoding failure.
Requires an admitted OpenSSL 3.x or 4.1.x backend with certificate-to-CSR
extension copying. Compatibility adapter tests explicitly select `cn-only`.
The three `BackendTools` methods exercise tool orchestration with mocked backend
execution: seven versus six selected methods, migration failure/CLI status,
benchmark admission, sample failure and invalid-argument rejection. These are
not additional real-backend crypto qualification scenarios.

## Hold release, verified recovery and workspace relocation

`make test-stage10` uses disposable root/intermediate PKIs and injected rename
failures. It covers held leaf/intermediate release, irreversible revocation refusal,
historical issuer CRLs, read-only previews, independent disable flags, interrupted
index/CRL and key/certificate publication, evidence drift, incomplete/corrupt plans,
and offline workspace rebinding with nested authorities and absolute aliases.
It checks preserved keys/counters/history and successful operations after recovery.
No live authority, real workspace relocation or power-loss fault is exercised.

Maintenance validation on 2026-09-21: 101 distinct test methods across stages 0–10
passed, with targeted reruns after adjustments; syntax, source-manifest, relative
link and diff checks passed. Smoke was not rerun. See the
[maintenance evidence](../specifications/10-acceptance-and-traceability.md#maintenance-validation-2026-09-21)
for exact counts, environment and qualification limits.

Stage 8 also covers exact URI/subject identities, strict verification without SANs,
reference-time validation, invalid timestamps and CRL time-window rejection.

## Durable operations

Stage 11 also checks Make/direct CRL inspection admission: no call to durable
write admission (even transiently), locking during backend inspection, tolerance
of an unrelated FIFO, and rejection with pending journals, fences or held locks.
Generation and applied cleanup must still enter write admission.

`make test-stage11` checks intent/data/completion ordering, failed barriers,
platform-specific full flush failures, checkpoint admission, special-file refusal,
backend interruption without an issuance journal, interrupted sealed installation,
and failed intent/final barriers. Integration tests use real local persistence
calls and disposable PKIs; injected failures live only in test fixtures/mocks.
This tests the software protocol, not actual power loss, disk-cache behavior,
network storage or Linux qualification. Do not power-cycle a live CA to run it.

Durability validation on 2026-09-21: 115 distinct methods across stages 0–11 passed,
including the 13-method durability gate and targeted reruns after final changes.
Smoke also passed before the last admission/review refinements; those refinements
were checked with targeted tests. See the
[durability evidence](../specifications/10-acceptance-and-traceability.md#durability-validation-2026-09-21)
for the precise incremental-validation and hardware/platform limits.

## Retained-history performance measurement

Run the opt-in benchmark from the repository root, selecting an accepted OpenSSL
3.x or 4.1.x executable (preserving migration requires certificate-to-CSR
extension copying):

```sh
OPENSSL=/absolute/path/to/openssl python3 -B test/benchmark-durability.py \
  --rows 1 3 --history-files 0 100 1000 --record-bytes 4096 --repeat 3 \
  > /tmp/certnify-durability.jsonl
```

Each sample creates a fresh manifest-only temporary workspace, generates EC root,
intermediate and leaf keys, rolls over the intermediate, exports its inventory and
times a real preserving reissuance batch. Setup and final chain verification are
outside the timed interval. The batch must issue every row, retain completed
receipts and leave no pending journal or power-loss fence. No live PKI is read or
copied. Temporary fixtures are removed on normal exit, including command failure.
The subprocess environment is stripped as for the regression suites.

Additional synthetic history consists of regular files under
`pki-data/benchmark-history/`, grouped by 100, with the configured size per file.
It models the persistence footprint, not a population of valid authorities; the
real source generation and completed journals remain present too. Setup receives
a real persistence flush before measurement. Results therefore describe warm
filesystem caches, not cold starts. Repetitions alternate history-size order.

The probe wraps `sync_tree` and `sync_path` **only in the copied helper**; every
original barrier still executes. It writes counts/timings to a sibling temporary
log outside the scanned workspace. JSONL exports environment metadata, helper
source hashes and one aggregate record per sample, without fixture paths, keys,
journals or backend output.
`actions` counts helper invocations by action; `trees` counts complete scans;
`history_syncs` must equal `history_files * trees`. `tree_seconds` includes its
file/directory synchronization calls; `sync_seconds` includes all `sync_path`
calls, including device barriers outside tree walks. These times overlap and
must not be added. `full_calls` counts requested full barriers. All timings
include probe overhead; `batch_seconds` also includes shell, OpenSSL and Python
startup. Compare medians/ranges across repetitions, never use timing thresholds
as a correctness gate. Increase history and row counts to match the intended
deployment; storage, file sizes and cryptographic profiles affect results.

This benchmark is separate from numbered regression gates and does not qualify
power loss, network storage or production throughput. See the recorded
[measurement and decision](../specifications/10-acceptance-and-traceability.md#retained-history-measurement-2026-10-27).

## Authority issuance categories

`make test-stage12` covers category-specific success and rejection, direct and
wrapper calls, caller overrides, missing/multiple/any EKUs, numeric OID aliases,
custom profiles, custom paths and aliases, malformed metadata, legacy canonical
metadata, explicit generic authorities, reclassification refusal, preserving batch
preflight and post-signing mismatch fencing. All PKIs and injected backend failures
are disposable fixtures. Stages 5, 7 and 8 use the matching authority for code and
S/MIME fixtures; cross-category rejection is tested explicitly in stage 12.

Two additional stage-12 methods cover make int-generic/make generic and the direct
gen-generic wrapper: explicit profiles, EXT_SECTION precedence, Ed25519, explicit
SANs, custom authority paths, no implicit SAN, required inputs, invalid/CA profiles
and refusal to use a specialized authority. Refusal tests compare workspace state.

## Security risk mitigations

`make test-stage13` covers administrator hook opt-in, literal Make parameters,
ancillary versus operational FIFO handling, old authority markers in ancillary
trees, complete persistence coverage of nested retained state, preflight EIO,
publication configuration admission, false upload success, blocked upload/read,
oversized or wrong read-back, reader failure and verified idempotent retry.
The shared-deadline test also sends SIGTERM and SIGINT during upload and read-back,
requiring nonzero exit, a failed artifact report, no verified result or subsequent
artifact, and termination of ordinary descendants before their delayed write.
Only disposable keys and a local directory adapter are used; remote services,
hardware power loss and Linux are not qualified by these tests.

## Leaf inventory exports

`make test-stage14` covers empty and populated inventories, revoked-entry
selection, stdout and file output, explicit authority selection, legacy issuer
resolution after rollover and replacement of an existing output file. It uses
disposable PKIs and generated keys.
