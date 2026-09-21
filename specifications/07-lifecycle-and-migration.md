# 07 — Authority lifecycle and batch migration

## Rollover and rollback

Rollover requires KIND, INT_CN and a usable workspace root. It operates on the
canonical `intm-<kind>-ca` directory, not an alias; unused legacy options such as
INT_DIR_NEW/MAKE_ALIAS do not select a second destination. It validates the old
configuration/pair and backfills history before journaling the move. The moved
configuration is rebound and validated at its new path; artifacts are normalized.
The ordinary intermediate generator then creates the active authority under the
same retained workspace lock. No leaf migration, revocation or CRL generation is
implied by rollover.

Rollback uses explicit LEGACY_DIR or the reverse-lexicographically latest matching
legacy path. KIND may be inferred from a conventional explicit legacy name. It
validates the legacy pair, root signature and leaf bindings before promotion.
The current active directory is preserved first. Both moves are journaled and
followed by validated configuration rebinding and normalization. Root revocation,
leaf records, counters and disable markers are retained, not reset.

## Directory transitions and layout

Rollover preserves the old authority under `intm-<kind>-ca-legacy-<timestamp>` and
uses the ordinary generator to create the new active authority. Rollback preserves
the current active directory under `...-pre-rollback-<timestamp>` before promoting
the selected legacy directory. Both suffix names gain a numeric suffix on
collision. Lifecycle active names must be real canonical directories, not aliases.
Each moved configuration and its `ca.meta` directory field are rebound.

Both transitions use the common layout and legacy import rules in
[chapter 03](03-persistence-and-artifacts.md).

## Inventory source and output selection

Explicit INT_DIR selects the source. Otherwise KIND selects the latest legacy
directory, falling back to active. Include V rows and optionally R/E via
INCLUDE_REVOKED/INCLUDE_EXPIRED; listing does not run expiry maintenance or prove
cryptographic issuer ownership. The strict four-column format and staged output
replacement are specified in chapter 03. OUT=- emits TSV only, diagnostics to stderr.

With an automatically selected legacy suffix, default output is
`out/<kind>-leafs-<suffix>.tsv`. Otherwise it is `out/<kind>-leafs.tsv`, or `out/leafs.tsv`
without a known kind. Explicit OUT overrides this.

## Batch input discovery

Explicit KIND wins; direct script invocation may infer it from the documented
`<kind>-leafs[-timestamp].tsv` convention. A latest legacy suffix requires its dated
inventory when INPUT is absent or the generic `out/<kind>-leafs.tsv`; missing latest
inventory fails instead of silently using an older list. An explicit alternative
INPUT is accepted. Without a legacy, select the newest nonempty dated inventory,
then generic. Missing input fails; empty input succeeds. ACTIVE_DIR defaults to
`intm-<kind>-ca`. Resolve and validate destination, selected legacy and issuer before
executing nonempty batches.

## Reissue command

`make reissue-leafs-web INPUT=out/custom-name.tsv ACTIVE_DIR=pki-data/web`
passes the target kind and optional inputs in a single shell invocation. The
target kind takes precedence over the input basename. Omitted optional values
are safe. Direct script invocation can infer a kind only from the documented
`<kind>-leafs[-timestamp].tsv` naming convention. `ACTIVE_DIR` controls the actual
built-in issuance destination, not only its preflight checks.

The four-column inventory remains the format in chapter 03. All rows are validated
before running a child command. Built-in issuance passes values as environment
data to the corresponding leaf wrapper; inventory text is never evaluated as
shell code. Web adds DNS:CN; auth/user/smime add email:CN only when the CN
contains @, and otherwise leave the batch SAN empty. Code/archive add no batch
SAN. Email-like values still pass normal SAN validation; arbitrary person names
are no longer forced into email SAN syntax. Existing wrapper policy and configured options still apply. Default
lifetimes are 397, 825, 730, 730, and 3600 days, respectively.

**This is legacy CN-only reissuance, not a complete certificate migration.** It
does not recover original subjects, all SANs, extensions, key policy, or expiry
from four columns. The expiry and old serial identify an input row; they are not
assigned to the new certificate. A warning announces this mode. The destination
uses its current profile/configuration and key-reuse behavior. Old leaves are
not automatically revoked.

`ISSUE_CMD` remains an explicitly supplied, trusted Bash command. It receives
`CN`, `SERIAL`, `EXPIRES`, `INT_DIR`, `ACTIVE_DIR`, `LEGACY_DIR`, and the expected
issuer identity through the environment. Quote variable expansions normally:

```sh
ISSUE_CMD='SAN="DNS:$CN" DAYS=397 bin/gen-server.sh' \
  make reissue-leafs-web INPUT=out/custom-name.tsv
```

The old textual `%CN%`, `%SERIAL%`, and `%EXPIRES%` substitutions are rejected
with migration guidance. Inserting inventory text into arbitrary shell quoting
could execute it as code. Custom commands must honor the destination/issuer and
must return nonzero on failure. Their zero exit status is a command outcome,
not independent proof that they issued a certificate or preserved its policy.

## Per-item results and retry protection

Each selected row reports `[ITEM]` with serial and a status: `planned`,
`completed`, `already_completed`, `failed`, or `needs_review`. The final summary
counts rows in each category. A required failure or unresolved previous attempt
returns nonzero. A row failure does not prevent remaining rows from being tried.
An empty inventory returns success with zero counts. `DRY_RUN=1` reports planned
rows and runs no issuance command or receipt write.

Reissuance receipts live inside the active authority at `reissues/<id>`. The ID
is SHA-256 of newline-terminated issuer certificate ID, resolved legacy directory
(or empty string), old serial, exported expiry, and CN, in that order. The file
contains one newline-terminated state: `started`, `completed`, or `needs_review`.
Claiming an item and updating its receipt use the workspace lock; it is released
before the child transaction. A concurrent run cannot claim an existing receipt.
Changing a command/profile does not reset a receipt for the same input identity.

A successful receipt is skipped on rerun. A nonzero child result or an interrupted
attempt is blocked for manual review, even if the command may have failed before
issuance. A nonzero result can occur after the CA index and serial committed.
Inspect the destination index, certificate archives, binding, and publication
artifacts before retrying. Once the actual result is established, an operator
may mark a completed attempt `completed`, or remove only that attempt receipt
if no issuance committed and a retry is appropriate. Do not delete all receipts
or reset counters to force a batch through. Changed inventory identity or issuer
is a different attempt; receipts are not a general duplicate detector.

Directory transitions may move receipts while a child runs. The parent refuses
to write completion into a replacement authority; the retained `started` receipt
requires review. The workspace recovery journal is described in chapter 08. Automatic reconciliation
is unsupported; batch receipts and the pending journal may both require review.

## Advisory final CRL

`INT_DIR=... bin/intm-publish-final-crl.sh` (or `KIND=...`) prepares a versioned
CRL. `FINAL_MODE=1` refuses when the validated index contains any V row whose
expiry is later than the current UTC time, unless `ALLOW_REMAINING_LEAFS=1`.
Expired V rows do not block and are not rewritten by the guard. Revoked rows do
not count. `DRY_RUN=1` performs this validation and reports the plan without
creating a lock, changing index statuses or generating artifacts.

“Final” is advisory: no retirement/freeze marker, key deletion or issuance ban is
introduced. Issuance, rollback and future CRL renewal retain their normal rules.
The operator remains responsible for ongoing revocation service. `CRL_HOURS`,
when supplied, takes priority over `CRL_DAYS` (default 90).

The versioned PEM is installed only after issuer/signature/time validation.
Timestamp plus process ID names avoid ordinary same-second collisions and an
existing name is refused. The DER and sidecars are staged before latest aliases
are updated. A conversion/install/alias error is a failure even though the local
CRL and its counter may already have committed. Each alias replacement is a
single rename; the PEM and DER alias pair is not transactional.

## Digests and publication receipts

For `ca-<version>.crl.pem` and `ca-<version>.crl`, both SHA-256 sidecars hash the
**exact DER encoding of the CRL**, never the PEM text:

| Sidecar | Exact format |
| --- | --- |
| `.crl.pem.sha256` | 64 uppercase hexadecimal characters plus one LF |
| `.crl.sha256` | Base64 of the 32 digest bytes (44 characters) plus one LF |

These preserve the intended original formats while eliminating backend-dependent
fingerprint labels/colons. All cryptographic conversion, digest and base64 calls
use `OPENSSL`; byte-to-hex formatting uses `od`/`tr`. Previously malformed labeled
sidecars should be regenerated rather than accepted as a second format.

`PUBLISH_CMD` is trusted administrator-supplied shell code. `%FILE%` is replaced
with a generated basename and the command runs in OUT_DIR. All six artifacts
(PEM, DER, both sidecars, both latest aliases) are attempted; each receives a
`published` or `failed` result. Any failure yields nonzero status. The append-only
`.crl.pem.publication` receipt records attempts and outcomes; success means the
configured command exited zero, not independent proof of remote integrity.
Without PUBLISH_CMD the result explicitly says local-only, never remote success.

To resume conversion, local installation or remote publication without generating
a new CRL or consuming another number, supply the same versioned PEM:

```sh
INT_DIR=intm-web-ca FINAL_CRL=crl/ca-<version>.crl.pem \
  PUBLISH_CMD='your-publisher %FILE%' bin/intm-publish-final-crl.sh
```

Reuse the original OUT_DIR if customized. FINAL_CRL must be a versioned PEM in
that directory and pass current issuer, signature and time validation. Its local
`.resume-state` must match the PEM hash, revoked index rows and next CRL counter
(chapter 03). Check this before any alias change or publication. Any intervening
revocation or CRL counter advancement, including after a failed generation,
requires a fresh final CRL. Missing state, including for older releases or an
interruption before state installation, also requires fresh generation. It bypasses
the remaining-leaf issuance guard because it republishes existing bytes. All
six remote artifacts are attempted again; publication commands must tolerate
repeated copies. An admitted retry may select that same CRL as latest; it cannot
roll back to an earlier issuer state. Expired
CRLs cannot be resumed: generate a fresh CRL under normal policy. Remote updates
are neither atomic nor rolled back. No real remote destination is used in tests.
