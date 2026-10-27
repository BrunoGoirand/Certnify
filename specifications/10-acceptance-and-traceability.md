# 10 — Acceptance and implementation traceability

Acceptance compares decoded fields and trust/revocation outcomes, not PEM bytes.
Use disposable source-only workspaces and newly generated keys. Capture current
time around issuance for lifetime checks. Python 3.8+ is also a runtime dependency
of the durability helper. See [test/README.md](../test/README.md) for execution and packaging.

## Executable gates

The exclusive-writer requirement in chapter 01 also needs deployment acceptance:
verify that non-toolkit accounts cannot write operational state, that no sync or
restore agent writes the live workspace, and that publication hooks only export
artifacts. These checks do not establish protection against privileged users or
arbitrary processes running as the toolkit account. They are deployment criteria,
not claims that the existing regression suites enforce OS isolation.

The implemented durability protocol in chapter 08 has a dedicated stage-11 gate
for persistence ordering, barrier failures and interrupted-command admission.
Actual power-cut behavior requires separate qualification on each storage stack;
process termination and mocked barriers do not satisfy that qualification.

| Command | Scenarios | Primary coverage |
| --- | ---: | --- |
| make test-stage0 | 5 | Source manifest, exclusions, root bootstrap, snapshots, current test-map consistency |
| make test-stage1 | 10 | Strict record parsing, serial arithmetic, CN selection, inventories |
| make test-stage2 | 12 | Canonical paths, generations, concurrency, rollover/rollback, completed bootstrap and same-shell ownership/trap contracts |
| make test-stage3 | 8 | Actual command adapters, batch outcomes/receipts, FILE/CHAIN |
| make test-stage4 | 11 | Trust/CRL errors, idempotent revocation, read-only plans, failed refresh, root CRL display errors and empty/revoked lists |
| make test-stage5 | 10 | Effective key/profile matrix, SANs, names, configuration completeness |
| make test-stage6 | 16 | Interrupted commits, killed issuer, preserved replacements, publication resume, rollover generator ownership and cleanup handoff |
| make test-stage7 | 13 | Audit A01–A06, state loss, Make transport, key strength, SAN equality and UTF-8 |
| make test-stage8 | 14 | Controlled cleanup, chain lifetime admission, DNS/IP/email/URI/subject and reference-time verification, CN-only batch and historical CRLs |
| make test-stage9 | 5 | Preserving batch migration, fresh key parameters, source/profile admission and explicit compatibility mode |
| make test-stage10 | 11 | Hold release, verified installation recovery and workspace relocation |
| make test-stage11 | 15 | Persistence ordering/errors, excluded-path admission, durable checkpoints, backend kill, safe resumption and CRL read/write admission |
| make test-stage12 | 8 | Authority categories, compiled EKUs, custom profiles/paths, immutable category, batch admission, post-signing fencing and explicit generic command |
| make test-stage13 | 7 | Administrator hook opt-in, persistence scope, publication deadlines/cancellation and remote read-back validation |
| make test-stage14 | 9 | Leaf inventories, status selection, stdout/file output, authority selectors and legacy resolution |
| make test-smoke | Integration workflow | Kinds, profiles, SANs, issuance, revocation, rekey, CLI examples and intermediate verification status before/after revocation |

The numeric counts above inventory current `test_*` methods, not execution
results or subtest counts. Stage 0 checks them against the source manifest,
Make targets and documented launch commands. Historical results below retain
their original scope and counts.

The stage-numbered command names are stable test-suite identifiers, not an active
implementation plan. The historical complete behavioral qualification on 2026-09-19
passed all 55 regression scenarios and smoke on the platform listed in chapter 09.
This records test scope, not a guarantee for untested systems or every failure point.

## Retained-history measurement (2026-10-27)

Risk R1 concerns repeated full-workspace persistence, not an established loss of
durability. `test/benchmark-durability.py` now provides an opt-in measurement with
real preserving batches and synthetic retained regular files; see the
[method and command](../test/README.md#retained-history-performance-measurement).
The benchmark asserts successful issuance, completed per-item receipts, no
blocking recovery state, valid resulting chains, and persistence of every
synthetic historical file on every tree scan. It changes only the copied helper
inside each fixture, delegates every actual barrier, and exports aggregate data.

The measurement uses macOS 26.7.1 x86_64, Bash 3.2.57, GNU Make 3.81, Python
3.15.2 and OpenSSL 3.5.9 selected through
`OPENSSL=/usr/local/opt/openssl@3/bin/openssl`. The default executable currently
reports OpenSSL 4.1.0 and was correctly refused by the backend gate; an initial
stage-0 run therefore passed four tests and failed root bootstrap. With the
explicit 3.x backend, full stage0 (5 tests) and stage11 (15 tests) passed.
The benchmark also rejects a nonpositive repetition count and OpenSSL 4.x before
fixture creation. Python 3.8 grammar and local documentation link targets were
checked; this is not execution under Python 3.8. No full-suite or smoke rerun is
claimed for this test-tooling change.

The observed preserving workflow performs an initial admission/completion pair,
then three transactions per row (claim, issuance, receipt completion). Issuance
also flushes five recovery phases and seals one checkpoint. Thus the measured
cases perform `2 + 12 * rows` full tree scans: 14 for one row and 38 for three.
An additional history of H files incurs H synchronizations per scan (14,000 and
38,000 additional file synchronizations respectively for H=1,000). The helper
invocation counts are 4/10 `begin`, 4/10 `finish`, 5/15 `flush` and 1/3 `seal` for
one/three rows. These counts describe successful fresh attempts in this workflow,
not every operation or retry mode.

Executed command (18 successful samples, 36 reissued leaves):

```sh
OPENSSL=/usr/local/opt/openssl@3/bin/openssl python3 -B test/benchmark-durability.py \
  --rows 1 3 --history-files 0 100 1000 --repeat 3 \
  > /tmp/certnify-r1-benchmark.jsonl
```

These measurements preceded the shell-context mitigation below; the performance
matrix was not rerun after that change.
Each added file contains 4,096 bytes. The table uses only repetitions 2 and 3,
run without concurrent test suites. Repetition 1 overlapped stage0/stage11 and is
excluded from timing comparisons; its correctness/count assertions also passed.
Values are medians with observed minimum–maximum in parentheses, in seconds.
Two retained repetitions provide a small local observation, not a confidence
interval or a throughput service level.

| Batch rows | Added history files | Full scans | Whole batch seconds | Tree-walk seconds, including their sync calls |
| ---: | ---: | ---: | --- | --- |
| 1 | 0 | 14 | 15.313 (14.970–15.655) | 0.289 (0.287–0.290) |
| 1 | 100 | 14 | 15.696 (15.068–16.324) | 0.472 (0.448–0.496) |
| 1 | 1,000 | 14 | 17.335 (16.525–18.146) | 2.047 (1.999–2.095) |
| 3 | 0 | 38 | 40.804 (40.750–40.858) | 1.070 (1.065–1.074) |
| 3 | 100 | 38 | 41.341 (41.169–41.513) | 1.550 (1.549–1.551) |
| 3 | 1,000 | 38 | 45.526 (45.403–45.650) | 5.712 (5.693–5.730) |

For three rows, adding 1,000 files adds about 4.64 seconds of tree-walk time and
4.72 seconds of total batch time when comparing these medians. This confirms a
measurable history-dependent cost and its amplification by repeated scans. R1 is
now reproducible and quantified for this fixture; the growing cost remains a
known design limitation. No performance threshold or target deployment volume
was supplied, so this observation does not establish a capacity limit or justify
a new persistence protocol on its own.

The synchronization protocol and scope are unchanged. CRL inspection already
uses read admission in this revision, so it does not incur these write barriers.
Historical authorities and completed recovery journals must remain covered;
excluding them or caching an unchanged-file decision without a durable
write-tracking protocol would require separate design and failure qualification.
Use measurements at the intended history size and storage to budget operational
batch time. The synthetic history, small EC batches, warm caches and probe
overhead limit extrapolation; these results do not qualify large real deployments,
cold storage, power loss, remote services or network filesystems.

## Shell-context coupling mitigation (2026-10-27)

Risk R2 is bounded by the explicit
[bootstrap and ownership contract](08-architecture-and-reliability.md#shell-bootstrap-and-ownership-contract)
and new regression coverage. Bootstrap now recognizes a final readonly,
nonexported readiness marker instead of treating the existence of `pki_begin`
as proof that all helpers and ownership initialization have loaded.

`ShellContext.test_bootstrap_does_not_trust_function_presence_or_inherited_state`
fails against the previous HEAD helper in a manifest-copied disposable fixture
and passes with the new helper. It covers a preexisting/exported function,
inherited marker/ownership values and initialization in a fresh child Bash.
It also removes one helper in a disposable copy and requires a nonzero exit
without a readiness marker. This additional case exposed Bash 3.2 reporting zero
to an EXIT trap when `source` cannot open a file; the ordered loader now checks
helper presence/readability explicitly before sourcing.
Two further ShellContext methods cover re-sourcing with active ownership and
custom traps, nested admission/journaling, normal cleanup, ordinary error,
SIGTERM/SIGINT and blocked retry without state changes.
`Recovery.test_rollover_handoff_keeps_one_owner_and_generator_cleanup` checks
the actual same-shell handoff, the generator's EXIT cleanup on success and
signing failure, retained issuer history and refusal of blind retry.

The global-state architecture remains in place. The change makes bootstrap
completion explicit and provides executable boundaries around ownership and
traps; it does not introduce a returning generator API or distributed locks.
All instrumentation and generated PKI material belong to disposable fixtures.

Validation used macOS, Bash 3.2.57, GNU Make 3.81, Python 3.15.2 and OpenSSL
3.5.9, selected with `OPENSSL=/usr/local/opt/openssl@3/bin/openssl`:

| Executed gate | Result |
| --- | --- |
| `make test-stage0` | 5/5 passed |
| `make test-stage2` | 12/12 passed |
| `make test-stage3` | 8/8 passed |
| `make test-stage6` | 16/16 passed |
| `make test-stage11` | 15/15 passed |

This is incremental validation of 56 distinct methods, not the complete suite.
The missing-helper preflight was added while stage2 was already running;
stage0 and all three ShellContext methods were rerun successfully against the
final loader. Stages 3, 6 and 11 then ran with that loader, including the real
rollover handoff test. Targeted reruns are not counted as additional methods.
`bash -n` passed for the five changed shell files; both changed Python test files
parse with the Python 3.8 grammar. Local documentation link targets and
`git diff --check` passed. Smoke and the other suites were not rerun; no actual
power-loss, network-filesystem or remote-publication qualification is implied.

## OpenSSL backend matrix (2026-10-27)

Risk R3 now has an opt-in executable compatibility gate,
`test/openssl-matrix.py`, with six common behavioral methods and one additional
preserving-migration method on OpenSSL 3.x. The
[selection and execution contract](../test/README.md#openssl-backend-matrix)
cover ASN.1 extensions, key metadata, CRL issuer/signature/date parsing, strict
verification and failure interpretation. A new portable CRL method checks the
inclusive lastUpdate and exclusive nextUpdate boundaries, corrupted signatures,
wrong issuers and malformed/missing inputs without state changes.

The matrix records real executable paths, versions and binary hashes. On this
host, `/usr/local/opt/openssl@3.2` through `openssl@3.6` all resolve to the
installed 3.5.9 executable; the extra `--backend .../openssl@3.2/bin/openssl`
argument was reported as an alias, not another tested version. Conflicting
accept/reject expectations for those aliases return status 2 before fixtures.
Intentionally expecting LibreSSL to be accepted produces a failed admission
record and matrix status 1; a failed probe is not silently skipped.

Environment: macOS 26.7.1 x86_64, Bash 3.2.57, GNU Make 3.81, Python 3.15.2.
OpenSSL 3.5.9 and 4.1.0 came from the existing local installation; LibreSSL 3.3.6
was `/usr/bin/openssl`. OpenSSL 1.1.1w was built from the
[official archived release](https://mta.openssl.org/pipermail/openssl-announce/2023-September/000274.html),
whose archive SHA-256 was verified as
`cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8`.
It was configured with `darwin64-x86_64-cc no-shared no-tests`, built with
`make -j4`, and installed with `make install_sw install_ssldirs` exclusively under
`/tmp/certnify-r3-openssl.sSpJ2u/install`. No system OpenSSL was replaced.
The OpenSSL project's own test suite was not executed; these are Certnify tests.

The first 1.1.1w run used the build-tree executable before installation of its
default `openssl.cnf`. Three methods failed during SAN request inspection because
that configuration was missing. The prefix was then completed and all six common
methods rerun using its installed executable. These exploratory failures are
environment preparation failures, not evidence of a Certnify parsing defect.
The CRL boundary refinement was separately rerun on both accepted backends.

Final observed outcomes (targeted methods, not full suites):

| Actual backend | Behavioral checks | Admission evidence |
| --- | --- | --- |
| OpenSSL 1.1.1w, complete temporary installation | 6/6 common methods passed | Bootstrap accepted; 3.x preserving migration not applicable |
| OpenSSL 3.5.9, existing installation | 7/7 methods passed | Bootstrap accepted |
| OpenSSL 4.1.0, existing installation | Not applicable | Make and direct root generation rejected; fixture unchanged |
| LibreSSL 3.3.6, system executable | Not applicable | Make and direct root generation rejected; fixture unchanged |

Commands executed from the repository root:

```sh
python3 -B test/openssl-matrix.py \
  --backend /usr/local/opt/openssl@3/bin/openssl \
  --backend /usr/local/opt/openssl@3.2/bin/openssl \
  --backend /tmp/certnify-r3-openssl.sSpJ2u/openssl-1.1.1w/apps/openssl \
  --reject-backend /usr/local/bin/openssl --reject-backend /usr/bin/openssl \
  --jobs 2 > /tmp/certnify-r3-matrix.jsonl
# After completing the temporary 1.1.1w installation:
python3 -B test/openssl-matrix.py \
  --backend /tmp/certnify-r3-openssl.sSpJ2u/install/bin/openssl \
  > /tmp/certnify-r3-111-complete.jsonl
```

The first command returned 1 for the three preparation failures above; its 3.5.9
methods and four rejection probes passed. The second command returned 0. The final
CRL boundary method was then rerun directly on both backends (both passed).
These temporary paths record this run; substitute complete installations when
reproducing it elsewhere. Binary hashes and resolved identities remain in JSONL.
There are 13 successful final backend/method combinations, covering seven distinct
methods; targeted reruns and intentional negative CLI probes are not extra methods.

`OPENSSL=/usr/local/opt/openssl@3/bin/openssl make test-stage0` passed 5/5 methods,
including source packaging of both new test tools. Python 3.8 grammar, local
documentation link targets and `git diff --check` passed. No full-suite or smoke
rerun is claimed for this matrix-tooling change. No runtime parser changes were
needed for the completed backend installations.

This targeted matrix extends evidence across the two accepted backend families.
It does not replace the historical full qualification, prove compatibility of
every 1.1.1 patch or 3.x release, or qualify Linux, Python 3.8, other architectures,
storage power loss or remote publishers. Preserving migration remains 3.x-only.
The existing accepted-version filter and runtime parsers are unchanged.

## Acceptance scenarios

| ID | Level | Scenario and expected result |
| --- | --- | --- |
| A01 | Required | Fresh root: parseable CA=true certificate, expected pathlen, matching key, self verification, metadata, restricted key permissions |
| A02 | Required | Repeat root with identical DN: unchanged key/certificate/serial; changed DN fails |
| A03 | Required | Root key exists but certificate absent: reuse actual key, including Ed25519 requested through an RSA-default invocation; metadata reports actual key |
| A04 | Required | ROOT_PATHLEN explicitly empty: no path-length constraint in root extension |
| A05 | Required | Each kind: root-signed CA=true/pathlen=0 intermediate, keyCertSign+cRLSign, intermediate+root chain |
| A06 | Required | Same healthy intermediate beyond threshold: skip; changed DN, near-expiry, force reissue, revocation, or requested rekey produces a new certificate as applicable |
| A07 | Required | FORCE_REUSE_KEY retains the key; ROTATE_KEY or default revoked/algorithm-change handling archives/replaces it unless reuse is forced |
| A08 | Required | Every profile and alias: compare decoded basic constraints, usages, EKU criticality, SKI/AKI, and legacy server extensions to document 04 |
| A09 | Required | RSA, each supported EC curve, Ed25519, Ed448: generated key parses and matching certificate verifies for supported backend/signing combinations |
| A10 | Required | Typed and legacy SAN input: trimming, deduplication, per-type ordering, URI colons, server/email defaults, and resulting decoded SAN contents |
| A11 | Required | Active duplicate CN fails before leaf key replacement; ALLOW_DUPLICATE_CN bypasses; revoked/expired records do not block valid renewal |
| A12 | Required | FORCE_NEW_KEY=0 reuses key; =1 backs up an existing key, retains serial-named artifacts and replaces matching canonical key/CSR/certificate/fullchain; rotate retains canonical artifacts and uses srl-serial-stem artifacts |
| A13 | Required | Leaf fullchain has leaf+intermediate only; CA chain has intermediate+root; file permissions match storage contract |
| A14 | Required | Disabled or revoked intermediate blocks issuance unless explicitly overridden; intermediate replacement removes disabled marker |
| A15 | Required | Verification modes implement OK/REVOKED/ERROR exit table; precondition errors still fail in info mode |
| A16 | Required | Leaf FILE/SERIAL/CN selection, already-R no-op, reason mapping, index filename normalization, optional CRL update |
| A17 | Required | Intermediate-only revocation changes root record and marker without modifying leaf status; bulk operation selects V or V,E as requested |
| A18 | Required | CRL signatures and issuer binding, monotonically advancing CRL number, reason/serial entries, and requested nextUpdate interval |
| A19 | Required | Rollover preserves old generation; subsequent legacy CRL/revocation modifies only legacy state, never active state |
| A20 | Required | Rollback preserves current generation, restores selected generation, validates bindings, and retains any revoked/disabled status |
| A21 | Required | Inventory exports active/latest-legacy/explicit sources with correct statuses, robust DN/time parsing, no header, and successful exit after writing |
| A22 | Required | Nonempty reissue batch processes all rows, dry run executes none, empty input succeeds, missing latest-rollover input fails, failures appear in aggregate status |
| A23 | Required | Policy-preserving migration retains subject/SAN/profile requirements or explicitly reports lossy CN-only mode |
| A24 | Required | Final CRL rejects unexpired V rows unless overridden; CRL_HOURS takes priority; PEM/DER represent same CRL; latest links point to versioned outputs |
| A25 | Required | Publication failure is per-artifact and recoverable; digest sidecars follow the declared stable encoding; no false remote-publication success |
| A26 | Required | Two concurrent issuers never duplicate serials; issuance/revocation/CRL/rollover share coherent locking |
| A27 | Required | Representative failures at commit boundaries: previous keys/history preserved; committed serial never reused; restart reports partial artifacts and requires verified plan resumption or explicit reconciliation |
| A28 | Required | CN regex metacharacters, slashes, quotes, Unicode, and SAN/TSV shell metacharacters remain data and cannot escape storage or execute code |
| A29 | Required | Symlink/path alias/nested/absolute directory inputs resolve consistently and cannot bypass containment or locking |
| A30 | Required | Empty revocation TSV field and high/leading-zero serials parse correctly; counter repair chooses max+1 without truncation |
| A31 | Required | Missing/stale/wrong-issuer CRLs cannot silently satisfy strict revocation verification |
| A32 | Required | All dry-run operations leave keys, indexes, counters, markers, directories, and CRLs unchanged |
| A33 | Required | Import both normal and rollover layouts, archived issuer generations, stale configuration paths, and missing-artifact reports without resetting history |
| A34 | Required | Packaging from a clean checkout includes the root profile and excludes all sensitive generated authority data |
| A35 | Required | Release only certificateHold on a leaf/intermediate; retain permanent revocations, expired status, unrelated disable flags and archived CRLs; publish matching current PEM/DER and reject stale final-CRL replay |
| A36 | Required | Resume sealed installation after index/key/certificate interruption without signing or advancing counters; refuse changed/missing sources, key-alias target drift, expired validity and unsealed plans |
| A37 | Required | Preview/apply offline workspace rebinding, including nested/historical authorities and internal absolute aliases; preserve state, reject unsafe configs, resume partial config/alias installation |
| A38 | Required | Enforce authority-owned issuance categories on compiled profiles and signed leaves; reject category changes and incompatible preserving batches before mutation; retain a blocking journal after unexpected signed usage |

## Evidence limits

A01–A14 are covered by root/bootstrap, key/profile tests and smoke; this is not an
exhaustive backend/extension matrix. A15–A18 and A31–A32 use actual chains, both
required CRLs, revocation, malformed inputs and workspace snapshots. A19–A20 and
A26 use real directory transitions, historical issuers and concurrent toolkit
processes. A21–A23 cover strict inventories, preserving migration, explicit lossy CN-only
mode and partial batches. Stage 9 additionally checks source evidence, full subject
DER, extension equality, key parameters, dry-run snapshots and retry receipts.
A24–A25 use a local publisher stub, exact digest bytes and interrupted alias/DER
publication. A27 injects representative backend/install/move/post-check failures
and SIGKILL; it is not exhaustive instruction-level crash or power-loss testing.
A28–A30 exercise input metacharacters, containment and exact serial boundaries.
A33 rejects stale bindings/missing history and imports supported older layouts;
stage 10 additionally exercises explicit offline whole-workspace rebinding and interrupted-plan resumption. This does not qualify live migration or arbitrary crash repair. A34 checks source packaging,
not historical secret disclosure. No operational CA or actual remote publisher is
used by these tests.

## Source traceability

| Source | Specification coverage |
| --- | --- |
| Makefile | 02 operation surface/defaults; 06 CRL utilities; 07 lifecycle wiring; 09 compatibility boundaries |
| bin/pki-env.sh | 02 selection/validation; 03 layout/index/metadata; 04 keys/configuration; 08 locks |
| bin/gen-root.sh | 05 root workflow; 03 root metadata; 04 root digest/path length |
| bin/gen-intm.sh | 05 intermediate renewal/rekey; 03 archives and aliases |
| bin/gen-leaf.sh | 05 leaf workflow; 04 SAN handling; 03 names, duplicate selection and serials |
| bin/pki-policy.sh | 04 effective key/profile compatibility, authority category resolution and compiled/signed usage admission |
| bin/gen-server.sh, bin/gen-user.sh | 02 defaults/profile precedence; 04 key-sensitive profile selection |
| bin/gen-code.sh | 02 dev/code routing and defaults |
| bin/gen-email.sh, bin/gen-archive.sh | 02 mode parsing; 04 specialized profiles |
| bin/verify.sh | 06 resolution/trust/CRL modes/status |
| bin/revoke-leaf.sh | 06 selection/reason/idempotence/CRL refresh |
| bin/revoke-intm.sh | 06 root-side revocation and marker |
| bin/revoke-intm-and-leafs.sh | 06 bulk statuses, partial failure, dry-run boundaries |
| bin/intm-rollover.sh | 07 generation preservation and common layout |
| bin/intm-rollback-to-legacy.sh | 07 restore and backup behavior |
| bin/list-leafs-by-issuer.sh | 03 TSV; 07 selection/export |
| bin/intm-reissue-leafs.sh | 07 source preflight, environment-based dispatch, receipts and aggregate outcomes |
| bin/pki-migration.sh | 07 source binding/profile/key admission, preserving CSR and subject/extension comparison |
| bin/intm-publish-final-crl.sh | 07 final CRL formats, guards, command publication |
| profiles/root/base.cnf | 04 complete root and root-side intermediate policy |
| profiles/intermediate/base.cnf | 04 intermediate constraints |
| profiles/leaf/*.cnf | 04 exact leaf extension matrix |
| test/smoke.sh | Integration runtime coverage described above |
| README.md, specifications/guides/ | Secondary user documentation, checked against implementation |
| .gitignore | 09 packaging/generated-state exclusions |

Operational workspace PKI material is never a fixture or normative policy source.
The root profile and all specification/guide files are explicit source-manifest entries.

The shared helpers pki-state.sh, pki-records.awk, pki-policy.sh, pki-input.sh,
pki-san.awk, pki-san-output.awk, pki-crl.sh, pki-crl-history.sh, pki-clean.sh,
pki-validity.sh, pki-time.awk and pki-recovery.sh implement the contracts across
scripts.
`bin/recovery.sh` implements the report/acknowledgment interface in chapter 08.

## Audit correction acceptance (2026-09-20)

The A01–A06 correction suite adds semantic and failure-boundary checks to the
original 55 scenarios. In particular, preflight refusals compare authority
snapshots, while a post-sign SAN mismatch must retain the issued history and
pending journal without installing the named certificate. Tests use no live PKI.
Dated execution results and qualification limits are recorded in this chapter.

The routine-operation suite additionally checks cleanup preview/application,
issuer-chain lifetime admission before mutation, explicit application identity
and purpose, strict full-chain CRLs, person-name batch reissuance, and CRL renewal
across retained keys and directory rollovers. Its snapshots concern disposable
fixtures only. The targeted correction results below are separate from full-suite qualification.

## Four-defect correction validation (2026-09-21)

Ten targeted scenarios passed on the local macOS/OpenSSL 3.6.4 environment:

- Stage 6 (seven): `test_resume_refuses_new_revocations_and_newer_crls`,
  `test_refresh_preserves_final_archives_and_updates_both_formats`,
  `test_leaf_rekey_failure_preserves_old_pair`,
  `test_digest_encodings_backend_and_publication_retry`,
  `test_failed_der_and_alias_preserve_latest_and_resume`,
  `test_resume_requires_unchanged_record_and_refresh_failure_preserves_aliases`,
  `test_forced_first_key_has_matching_canonical_and_serial_artifacts`.
- Stage 8 (three): `test_archive_defaults_fit_issuer_and_explicit_duration_is_not_capped`,
  `test_chain_duration_limit_before_mutation`,
  `test_historical_crls_cover_old_and_active_leafs`.

These cover stale CRL rejection without publication or state changes, archive
preservation and current PEM/DER consistency, coherent canonical and serial-named
leaf replacement, publication/conversion failure recovery, and 3600-day archive
defaults through both Make aliases, direct issuance and batch issuance. Explicit
excessive validity still fails before authority mutation. Bash syntax and
`git diff --check` passed. The complete suites and smoke were not rerun; actual
remote publication, power loss and other platforms remain unqualified.

## Preserving migration validation (2026-09-21)

40 distinct scenarios passed on local macOS with OpenSSL 3.6.4, using generated,
source-only temporary PKIs:

- Complete stage 0, 1, 3 and 5 suites: 29 scenarios.
- All five stage-9 migration scenarios: complete UTF-8 subjects and mixed SANs,
  RSA/EC/Ed25519/Ed448 key parameters and fresh keys, S/MIME variants, custom
  profiles, extended subjects, critical/absent SANs, dry-run immutability,
  retries, missing evidence, changed profiles and backend decoding failure.
- Stage 4: `test_dry_runs_leave_no_lock_or_state`.
- Stage 7: `test_profile_san_conflicts_fail_before_signing`,
  `test_empty_request_and_profile_only_sans`,
  `test_post_sign_san_mismatch_is_not_installed`.
- Stage 8: `test_batch_user_without_email_and_cn_only_warning`,
  `test_archive_defaults_fit_issuer_and_explicit_duration_is_not_capped`.

Bash/Python syntax and `git diff --check` also passed. No operational certificates
were migrated. This is targeted qualification, not a complete all-suite/smoke
rerun, a new exhaustive PKI audit, or qualification of other OpenSSL versions.

## Maintenance validation (2026-09-21)

The hold-release, verified-installation recovery and offline workspace-rebinding
changes passed **101 distinct test methods across stages 0–10**, with targeted
reruns after adjustments. Counts by suite: 4, 9, 6, 8, 9, 8, 15, 13, 13, 5 and 11.
The final targeted reruns cover recovery key-alias contents, repeated interruption
of config/directory-alias rebinding, nested and legacy authorities, CRL archive
preservation and stale replay refusal after release, dry-run suppression of auto
recovery, and refusal to resume uncertain backend outcomes.

Stage 10 uses real OpenSSL-generated disposable PKIs. It verifies leaf/intermediate
hold release, expired status, permanent-revocation refusal, independent disable
markers, historical CRLs, matching current PEM/DER, and read-only previews. Fault
injection interrupts after index commit and between key/certificate or config/alias
installation. Recovery preserves serial/CRL counters, rejects changed evidence,
corrupt/unsealed plans and expired artifacts, and never signs again. Relocation
checks unchanged keys/history/counters, spaces in the new path, nested/legacy
CA configurations, absolute file/directory aliases and operations after rebinding.

Executed environment: macOS, Bash 3.2.57, OpenSSL 3.6.4 and Python 3.14.7.
All Bash scripts passed syntax checks; Python test files passed parsing. The source
manifest, relative documentation links and `git diff --check` passed. Smoke was
not rerun. This is local regression evidence, not qualification of power loss,
network filesystems, other OpenSSL/platform versions, live migration, arbitrary
crash repair or a production PKI. Private completion journals retain staged
artifacts and are deliberately excluded from source packages and cleanup targets.

## Durability validation (2026-09-21)

The durable fence, checked persistence barriers and checkpoint admission are
implemented, rather than a proposed extension. `make test-stage11` passed all
**13 methods** on macOS with Python 3.14.7 and OpenSSL 3.6.4. Coverage includes
intent before backend execution, data before fence retirement, file/directory
barriers, macOS full-flush refusal without fallback, error latching, repeatable
manual review after a barrier error, retirement failure, special-file refusal,
and rejection of operational paths inside persistence exclusions.

Disposable integration fixtures also exercise a killed backend with a deliberately
truncated index and no issuance journal, a killed sealed leaf installation,
explicit and automatic recovery without duplicate signing, a second interruption
during resumption of an orderly failure, and failures of the initial/final barriers. A fence cannot be bypassed through an inherited ownership
variable. The ordinary/legacy journal acknowledgment path is separately retested
through stage 6 after adding durable review intent.

These are software protocol and local syscall tests. They do not emulate hardware
write caches or establish real power-cut durability. No live PKI was modified;
Linux, network/synced storage, hardware power cycling, media failure and remote
publisher durability remain unqualified. Source packaging, Python/Bash syntax,
relative documentation links and `git diff --check` were also checked.

The complete stages 0–10 and all 13 stage-11 methods passed: **115 distinct test
methods**, with targeted reruns after the final path-admission, acknowledgment and
repeat-resume adjustments. `make test-smoke` also passed. Smoke ran before those
last admission/review refinements; the corresponding targeted tests passed after
them. This is incremental regression evidence, not a claim that every suite was
rerun against one final frozen revision. The final syntax, source-manifest/local
link and diff checks passed. No hardware power loss or Linux execution was tested.

## Issuance category validation (2026-09-22)

**29 distinct test methods passed**, using source-only disposable PKIs on macOS,
Bash 3.2.57, GNU Make 3.81, OpenSSL 3.6.4 and Python 3.14.7:

- Stage 2: all 6 methods, including concurrent writers, rekey, rollover/rollback
  and legacy metadata normalization.
- Stage 5: all 8 methods through the suite and targeted reruns of the 3 fixtures
  updated to use code/S/MIME authorities instead of cross-category web issuance.
- Stage 7: the 2 updated no-SAN/profile-SAN and UTF-8 identity/idempotence methods.
- Stage 8: the 2 updated email/CN-fallback and URI/subject/reference-time methods.
- Stage 9: all 5 preserving migration methods, including RSA and EdDSA variants.
- Stage 12: all 6 methods through the suite and targeted reruns after fixture
  corrections and the rollback guard. These include compiled OID-alias rejection,
  immutable-state refusal, whole-batch admission and post-signing mismatch handling.

The post-signing test retains the pending signing-outcome-uncertain journal,
publishes no named certificate and blocks the next command. An orderly failure
can retire the power-loss marker while retaining this blocking journal, consistent
with chapter 08. No automatic repair or re-signing was introduced.

This is incremental regression evidence, not a full-suite run on one frozen final
revision. Smoke and the remaining suites were not rerun. Bash/Python syntax, the
93-file source manifest, relative documentation link targets and git diff --check
passed. No operational authority was modified. Direct key use, client-side trust
domain isolation and additional OpenSSL/platform combinations remain outside this
validation; CA certificates have not acquired category-specific constraints.

### Dedicated generic command follow-up (2026-09-22)

The two added stage-12 methods passed with real disposable issuance through make
generic and bin/gen-generic.sh, covering int-generic creation, Ed25519/codeSigning,
serverAuth and explicit DNS SAN, EXT_SECTION precedence, a custom authority path,
required inputs, invalid/CA profiles and specialized-authority rejection without
state changes. The environment matches the category validation above. These two
methods are additional to its 29 distinct methods; other suites and smoke were not
rerun for this follow-up. Make help, Bash/Python syntax, the updated 94-file source
manifest and diff checks passed. No operational PKI was modified.

## Publication cancellation follow-up (2026-10-27)

On macOS with Python 3.15.2 and OpenSSL 3.5.9 explicitly selected via
`OPENSSL=/usr/local/opt/openssl@3/bin/openssl`, `make test-stage0 test-stage13`
passed all 5 and 7 methods respectively. The targeted shared-deadline/cancellation
method also passed independently. Its four cancellation cases cover SIGTERM and
SIGINT during upload and read-back, requiring failed status, no verified or
subsequent artifact report, and no delayed descendant write. Cancellation uses
an exception outside `OSError` so runtime OS-error handling cannot absorb it.

The first suite attempt selected `/usr/local/bin/openssl`, now OpenSSL 4.1.0:
stage 0 rejected that unsupported backend and stage 13 did not start. This was
resolved for validation by selecting the installed OpenSSL 3 executable, not by
changing the backend gate. Python 3.8 grammar checks of the changed Python files
and `git diff --check` passed. No other suites or smoke were rerun; these tests
use disposable files/PKIs and local hooks, not remote publication, power loss or
qualification of other Python versions or platforms.
