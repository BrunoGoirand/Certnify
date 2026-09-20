# 10 — Acceptance and implementation traceability

Acceptance compares decoded fields and trust/revocation outcomes, not PEM bytes.
Use disposable source-only workspaces and newly generated keys. Capture current
time around issuance for lifetime checks. Python is test-only, not a runtime PKI
dependency. See [test/README.md](../test/README.md) for execution and packaging.

## Executable gates

| Command | Scenarios | Primary coverage |
| --- | ---: | --- |
| make test-stage0 | 4 | Source manifest, exclusions, root bootstrap, snapshots |
| make test-stage1 | 9 | Strict record parsing, serial arithmetic, CN selection, inventories |
| make test-stage2 | 6 | Canonical paths, generations, concurrency, rollover/rollback |
| make test-stage3 | 8 | Actual command adapters, batch outcomes/receipts, FILE/CHAIN |
| make test-stage4 | 9 | Trust/CRL errors, idempotent revocation, read-only plans, failed refresh |
| make test-stage5 | 8 | Effective key/profile matrix, SANs, names, configuration completeness |
| make test-stage6 | 11 | Interrupted commits, killed issuer, preserved replacements, publication resume |
| make test-stage7 | 13 | Audit A01–A06, state loss, Make transport, key strength, SAN equality and UTF-8 |
| make test-stage8 | 11 | Controlled cleanup, chain lifetime admission, identity/purpose/strict verification, CN-only batch and historical CRLs |
| make test-smoke | Integration workflow | Kinds, profiles, SANs, issuance, revocation, rekey and CLI examples |

The stage-numbered command names are stable test-suite identifiers, not an active
implementation plan. The historical complete behavioral qualification on 2026-09-19
passed all 55 regression scenarios and smoke on the platform listed in chapter 09.
This records test scope, not a guarantee for untested systems or every failure point.

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
| A12 | Required | FORCE_NEW_KEY=0 reuses key; =1 retains backup and replaces key; rotate retains canonical artifacts and uses srl-serial-stem artifacts |
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
| A27 | Required | Representative failures at commit boundaries: previous keys/history preserved; committed serial never reused; restart reports partial artifacts and requires explicit reconciliation |
| A28 | Required | CN regex metacharacters, slashes, quotes, Unicode, and SAN/TSV shell metacharacters remain data and cannot escape storage or execute code |
| A29 | Required | Symlink/path alias/nested/absolute directory inputs resolve consistently and cannot bypass containment or locking |
| A30 | Required | Empty revocation TSV field and high/leading-zero serials parse correctly; counter repair chooses max+1 without truncation |
| A31 | Required | Missing/stale/wrong-issuer CRLs cannot silently satisfy strict revocation verification |
| A32 | Required | All dry-run operations leave keys, indexes, counters, markers, directories, and CRLs unchanged |
| A33 | Required | Import both normal and rollover layouts, archived issuer generations, stale configuration paths, and missing-artifact reports without resetting history |
| A34 | Required | Packaging from a clean checkout includes the root profile and excludes all sensitive generated authority data |

## Evidence limits

A01–A14 are covered by root/bootstrap, key/profile tests and smoke; this is not an
exhaustive backend/extension matrix. A15–A18 and A31–A32 use actual chains, both
required CRLs, revocation, malformed inputs and workspace snapshots. A19–A20 and
A26 use real directory transitions, historical issuers and concurrent toolkit
processes. A21–A23 cover strict inventories, lossy CN-only mode and partial batches.
A24–A25 use a local publisher stub, exact digest bytes and interrupted alias/DER
publication. A27 injects representative backend/install/move/post-check failures
and SIGKILL; it is not exhaustive instruction-level crash or power-loss testing.
A28–A30 exercise input metacharacters, containment and exact serial boundaries.
A33 rejects stale bindings/missing history and imports supported older layouts;
it does not qualify arbitrary automatic relocation. A34 checks source packaging,
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
| bin/intm-reissue-leafs.sh | 07 environment-based dispatch, receipts and aggregate outcomes |
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
Current execution results are recorded in AUDIT.md after validation.

The routine-operation suite additionally checks cleanup preview/application,
issuer-chain lifetime admission before mutation, explicit application identity
and purpose, strict full-chain CRLs, person-name batch reissuance, and CRL renewal
across retained keys and directory rollovers. Its snapshots concern disposable
fixtures only. See AUDIT.md section 8 for current execution results.
