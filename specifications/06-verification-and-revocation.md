# 06 — Verification, revocation and ordinary CRLs

## Selection and trust

Verification requires INT_DIR or KIND even with FILE. FILE rules are in chapter 02;
CN uses exact indexed selection from chapter 03 and archived serial certificates,
with a same-serial named fallback only when appropriate. A nonempty CHAIN fails.
The bound issuer generation is untrusted chain material and the physical workspace
root is the trust anchor, independent of directory depth. Issuer names alone do
not establish ownership. VERIFY_DNS, VERIFY_IP and VERIFY_EMAIL supply one explicit
expected identity through OpenSSL's verify_hostname, verify_ip or verify_email.
VERIFY_PURPOSE supplies an explicit application purpose; unsupported backend
purposes fail. VERIFY_URI matches a complete URI SAN exactly, case-sensitively, without
normalization. VERIFY_SUBJECT matches the complete RFC2253 subject (without the
OpenSSL `subject=` prefix) exactly, including for certificates without SANs.
All five identity selectors are mutually exclusive. URI/subject mismatch is a
preflight failure in every mode. Subject matching is not certificate pinning.
VERIFY_ATTIME accepts canonical nonnegative Unix seconds through 253402300799
(year 9999). Certificate and CRL validation use that same reference time.
The retained CRLs must cover that time; no historical CRLs are fetched or
reconstructed, and past signing time or trust policy is not established.

## Strict CRL verification

`VERIFY_CRL=0` verifies the certificate chain without checking revocation.
`VERIFY_CRL=1` requires both the workspace root CRL and the selected leaf issuer
CRL. After an in-place rekey, the latter is the historical generation's CRL.
There is no implicit root-only or issuer-only fallback.

Each required CRL must be a single PEM CRL, have the expected issuer name, verify
with that issuer's public key, and satisfy `lastUpdate <= reference time < nextUpdate`.
Missing, malformed, expired, future-dated, wrong-issuer and invalid-signature CRLs
are rejected. This is a local-file contract; the toolkit does not fetch CRL URLs.
The two validated CRLs are combined into one temporary PEM bundle, supplied once
with `-CRLfile` and `-crl_check_all`. The bundle is removed on exit.

Ordinary chain validation explicitly uses authentication level 2 (including key
strength checks), and runs independently before CRL validation of the chain,
so a revocation diagnostic cannot hide an unrelated chain failure. Backend exit
status determines success, regardless of an `OK` substring or a misleading
filename. Only anchored numeric OpenSSL error 23 diagnostics, with no other
numeric validation error and an otherwise valid chain, classify as `REVOKED`.
All other backend failures classify as `ERROR`. The command prints the status
and backend exit status separately.
After completed verification, `VERIFY CHECKS` reports requested coverage, not
individual check results: verification may stop at an earlier failure. It lists
chain=required, revocation=not-requested/full-chain-crl, identity=not-requested
or the selected identity type, and purpose=not-requested or the requested purpose.
An OK result without revocation, identity or a specific purpose includes an
explicit scope reminder. Purpose `any` is not a specific application purpose.
This reporting does not change defaults, status values or exit codes. CN and KIND
remain selectors, never inferred application expectations.


| Mode | OK | REVOKED | ERROR from completed backend verification |
| --- | --- | --- | --- |
| `normal` | success | failure | failure |
| `strict` | success | failure | failure |
| `tolerate_revoked` | success | success | failure |
| `info` | success | success | success (report only) |

The direct verifier returns 0 for success and 2 for a mode-rejected completed
verification. Unknown modes fail at input validation. Make may wrap a script failure in its own status.
Input/preflight failures remain nonzero in **every** mode. In particular `info`
does not waive missing/invalid required CRLs, malformed certificate input,
unresolved issuer history, unsupported options, or invalid selectors. Report-only
success is not evidence of certificate validity; inspect `VERIFY STATUS`.

## Strict application verification

VERIFY_MODE=strict requires exactly one expected identity and a specific purpose
(other than any). It always enables full-chain CRLs, even if VERIFY_CRL=0 was
passed. Except for explicit VERIFY_SUBJECT, it requires the selected identity type in SAN, so CN fallback cannot
satisfy strict verification. The ordinary and CRL backend calls both carry the
identity/purpose checks, -x509_strict and -check_ss_sig. Every missing input,
backend error, identity/purpose mismatch or revocation is a nonzero result.
Normal/tolerate_revoked/info may also request identity/purpose checks, with their
existing exit semantics; info remains report-only. Host matching and wildcard
semantics come from OpenSSL; expected names cannot themselves contain wildcards.

## Validated CRL installation

All toolkit CRL writers use the same generation and publication helper:
standalone root/current/historical CRLs, pre-issuance refresh, leaf/intermediate/
bulk revocation refresh, and the PEM stage of final CRL publication.

Generation writes to a unique temporary file in the output directory. A nonzero
backend result, invalid output, wrong signature/issuer, or invalid validity window
prevents installation. Successful output receives mode 0444 and replaces the
installed path by rename. Existing CRLs remain intact on generation/validation
failure, and temporary output is removed on normal failure and handled signals.
An existing internal latest symlink is replaced, rather than overwriting its
historical target. If the current ca.crl DER companion exists, generate its new
bytes before installing either format and replace its directory entry as well.
Archived PEM/DER/digests remain unchanged. A conversion failure preserves both
current outputs, although the CRL counter may advance. The two final renames are
not atomic as a pair. A directory is not a valid CRL destination.

`AUTO_UPDATEDB=1` failure and requested pre-issuance CRL-refresh failure abort leaf
issuance explicitly. They no longer install an empty CRL or continue silently.
These operations are not database rollbacks: OpenSSL can update its database or
consume a CRL number before a later failure. Do not reset counters to hide gaps.
Atomic rename is not a power-loss durability or multi-artifact transaction
promise. Final CRL publication is specified in chapter 07 and recovery in chapter 08.

## Revocation and repeat calls

Supported reasons are `unspecified`, `keyCompromise`, `CACompromise`,
`affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, and
`AACompromise`. `privilegeWithdrawn` maps to `MAP_PRIV_WITHDRAWN_TO` (default
`cessationOfOperation`); the mapped value is validated too.

Explicit `REASON=removeFromCRL` on the single-leaf and single-intermediate targets
releases only an R row whose exact reason is `certificateHold`, with matching
retained certificate and issuer evidence. It requires `CRL_UPDATE=1`. The staged
index changes only that row to V (or E if expired), clears its revocation field,
and restores its retained locator. A complete CRL is generated against that staged
index, consuming the real CRL counter. The validated index and CRL installation
are sealed in a recoverable plan before publication. Recovery never regenerates
the CRL or reduces its counter; its expiry is checked again before installation.

Per [RFC 5280 section 5.3.1](https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1), `removeFromCRL` entries belong only in delta CRLs.
Certnify instead removes the held entry from the next complete CRL. Other revoked
rows remain unchanged. Failed preparation can consume a CRL number but leaves the
installed index/CRL unchanged and requires review if no complete plan exists.
Permanent revocations, ordinary V/E rows, mapping `privilegeWithdrawn` to a release,
and bulk releases are rejected. Repeating a completed release reports that the
certificate is no longer suspended. Distribute the new CRL; cached older CRLs can
still report suspension until refreshed. An expired certificate is never revived.

Intermediate hold revocation creates a certificate-bound `.disabled` marker when
none exists. Release removes only that matching marker; independent/legacy markers
remain for operator review. Existing journals/index history remain in private
completion receipts. All selection ambiguity still requires FILE or SERIAL.

Leaf and intermediate revocation validate the selected durable record. An R
record is not submitted to OpenSSL again; repeat calls do not rewrite its reason
or revocation date. The policy is consistent across leaf, intermediate, and bulk
commands: `CRL_UPDATE=1` requests CRL refresh even when revocation was already
complete; `CRL_UPDATE=0` skips refresh. Bulk selection remains controlled by
`LEAF_STATUSES`; already-R rows are reported when selected.

A backend revocation error is not retried to inspect its text. The command fails
and directs the operator to inspect the index because a commit may already have
occurred. A later CRL refresh failure also returns nonzero and explicitly states
that revocation remains committed. The previous installed CRL is preserved, so
it may now be stale. A repeat call with CRL_UPDATE=1 can complete refresh without
repeating revocation. Bulk row failures still receive individual results and a
nonzero aggregate status; successful rows are not rolled back.

## Read-only plans

`DRY_RUN=1` is supported by leaf revocation, intermediate revocation, bulk
revocation, batch reissuance and final CRL preparation. It performs input/selection validation and
reports the planned actions without creating a workspace lock, changing indexes,
consuming counters, creating disable markers or receipts, or installing CRLs.
Parsing may use temporary files outside the workspace, removed on exit.

Planning is an advisory read, not a transaction snapshot: another process may
change state while a plan is read. Apply mode always acquires the normal workspace
lock and revalidates the current state. Dry-run planning does not reserve a serial
or authorize later application. Other commands do not acquire dry-run semantics
merely because this environment variable is set.

## Single and intermediate revocation

Leaf selection precedence is FILE > SERIAL > CN. Validate the selected issuer,
certificate and durable record, then revoke with the bound generation key and
shared authority index. Normalize the R locator to unknown while retaining the
archived PEM. CRL_UPDATE=1 refreshes that issuer generation's CRL.

Intermediate-only revocation targets the canonical intermediate certificate in
the root database and creates .disabled; it does not change leaf rows. Root CRL
refresh is optional. A restored legacy directory retains its revoked/disabled
state. Replacement intermediate generation can remove the disable marker, but
cannot undo revocation of an older certificate.

## Bulk revocation

The command snapshots selected rows and preflights historical certificates and
keys before parent revocation. Failed preflight reports affected serials and
`skipped_required` for selected rows; no revocation is attempted. Parent failure
also reports skipped required leaves. A durable R record is treated as already
completed, without retrying OpenSSL based on an error message.

After parent revocation, each selected leaf reports an outcome. Backend failures
are counted and remaining leaves continue. The overall command fails if any
required leaf fails; successfully committed revocations remain committed. CRL
refresh or other post-processing failure also returns nonzero and does not undo
revocations. Reruns consult durable index state, so already-revoked certificates
are not submitted again. Default selection remains V; use `LEAF_STATUSES=V,R`
to include already-completed rows in the report. Dry-run planning does not rewrite
the indexes. 

## Ordinary CRL commands

crl-root uses the root configuration's CRL validity (normally seven days).
crl uses CRL_DAYS (default seven) for the selected intermediate. ISSUER_ID selects
a retained historical signer and generation CRL path. crl-all visits matching
intm-* directories with a configuration, including legacy authorities, not root.
crl-show prints at most the first 120 lines of decoded CRL text. Root revoked-entry
display is informational, not a structured membership API.

verify-intermediate-revoked runs verification with the root CRL: a valid unrevoked
intermediate succeeds and a revoked one fails. Its name does not invert success.
Ordinary CRL operations do not publish remotely or add discovery extensions.

## Explicit renewal of historical coverage

`make crl-all CRL_HISTORY=1 CRL_DAYS=7` renews root, canonical issuers and retained
noncanonical generation CRLs. Discovery includes configured top-level intm-*
authorities and legacy directories. Symlink discovery candidates fail rather than
silently broaden scope. `make crl INT_DIR=pki-data/custom CRL_HISTORY=1` includes
root and the selected custom authority instead; custom paths are not recursively
discovered. Canonical generation duplicates are skipped because the current CRL
path supplies their coverage. All retained generations are included, even expired
ones; this operation is publication maintenance, not an authorization to issue.

Preflight checks the complete selected list: configuration/index, paths, generation
fingerprints, issuer keys and durable leaf bindings. Missing historical material
fails before any CRL generation. Every planned output is reported. CRL_DAYS applies
to all selected outputs, root included. ISSUER_ID and CRL_HISTORY cannot be mixed.
Each output uses the existing validated replacement helper. A later backend or
installation failure returns nonzero while retaining already-renewed CRLs and any
consumed counters. There is no multi-file rollback or remote publication guarantee.
The default crl-all behavior remains canonical intermediate CRLs without root.
