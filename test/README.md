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
make test-smoke
```

`test/source-manifest.txt` is the explicit source-only packaging contract. Add each new runtime/profile/test file deliberately. No recursive workspace copy, Git tracked-file enumeration, or directory wildcard determines fixture contents. Missing entries and symlinked source paths fail before copying. A clean package can be prepared in an absent or empty destination:

```sh
python3 test/workspace.py copy . /tmp/certnify-source-package
```

The root profile is a source file, not data recovered from an operational root. Stage-0 tests check its inclusion, Git eligibility, generation of a fresh root from the package, exclusion of unlisted sentinel data (including data under bin/profiles), failure on missing/symlinked inputs, and snapshot behavior. The Git staging check runs only in a temporary repository.

Smoke fixtures all live under one private temporary session and are removed on exit, including secondary cases. Commands run with a clean environment retaining only PATH, TMPDIR, OPENSSL and LC_ALL, so inherited CA paths, profile overrides and Make flags do not affect them. Use an absolute OPENSSL path or a binary available through PATH. Tests use generated keys only.

The snapshot helper records file hashes, permissions, link targets, index/counter contents, and SHA-256 identities of decoded certificates. It never prints private key bytes or follows links. Use it only on disposable fixtures:

```sh
python3 test/workspace.py snapshot /tmp/fixture /tmp/before.json
# Run a regression operation against the fixture.
python3 test/workspace.py snapshot /tmp/fixture /tmp/after.json
python3 test/workspace.py diff /tmp/before.json /tmp/after.json
```

Smoke command snapshots are transient and a failed command prints changed paths before session cleanup. Future regression tests should assert the expected state changes, rather than merely recording them.

## Validated environment and limits

The qualified platform is macOS, Bash 3.2.57, GNU Make 3.81, OpenSSL 3.6.4 and
Python 3.14.7. The OpenSSL 1.1.1/3.x executable gate does not qualify every accepted
version. Newer Bash, other platforms/backends, network filesystems, power loss and
actual remote publication remain unqualified. See the
[acceptance map](../specifications/10-acceptance-and-traceability.md).

## Generated-data convention

Keep authority data in workspace `/root/`, `/intm-*/` (including custom kinds, legacy and rollback names), `/intermediate/`, or `/pki-data/` for explicitly selected custom paths. `/out/`, `/.locks/`, `/.recovery/`, and `/test-results/` are excluded too. Private directories and conventional `.key.pem`/backup filenames are ignored as defense in depth.

Git cannot infer that every arbitrary filename/path contains secret data. A nonconventional custom authority location must receive an explicit local exclusion **before** generation, or be moved into the documented data convention. Ignore rules do not remove already tracked files and are not a historical
secret-content audit. Specifications and guides are distributed source material;
generated authority state and recovery journals are not.

Suite 1 covers parser and selection regressions; see [the record contract](../specifications/03-persistence-and-artifacts.md).

Suite 2 covers path, transaction-lock, and generation-transition regressions; see
[the authority state contract](../specifications/08-architecture-and-reliability.md).

Suite 3 executes Make adapters, partial batches, receipt concurrency/retry safety,
and FILE/CHAIN compatibility; see [the batch contract](../specifications/07-lifecycle-and-migration.md).

Suite 4 tests strict verification, validated CRL replacement, idempotence and
read-only plans; see [the revocation contract](../specifications/06-verification-and-revocation.md).

Suite 5 tests effective keys/policy, SAN validation, safe CN names and config
staging; see [the policy contract](../specifications/04-cryptography-and-profiles.md).

Suite 6 injects issuance, installation, move and publication failures, including
a killed issuer. See [the recovery contract](../specifications/08-architecture-and-reliability.md).
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
Requires OpenSSL 3.x. Compatibility adapter tests explicitly select `cn-only`.

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
