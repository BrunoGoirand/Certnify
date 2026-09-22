<a href="https://certnify.org/"><img alt="Certnify logo" src="image/Certnify.png" width="400"></a>

# Certnify

[Français](README-fr.md)

Certnify is a local private-PKI toolkit written in Bash, with a Make interface and
an OpenSSL backend. It manages a self-signed root, issuing intermediate authorities,
and the issuance, verification, revocation and replacement of certificates.

It supports TLS server/client authentication, code signing, S/MIME signing and
encryption, document sealing and timestamp-signing certificates. It issues the
credentials; it does not itself serve TLS, sign documents or run a timestamp service.

[MIT license](LICENSE.txt) · © 2025–2026 Bruno Goirand

## Capabilities and scope

- RSA, named-curve EC, Ed25519 and Ed448 keys; profiles selected against the actual key.
- DNS, IP, email and URI SANs, with explicit validation and deterministic defaults.
- Intermediate kinds `web`, `auth`, `code`, `smime` and `archive`, plus custom authorities.
- Exact CN selection, duplicate-active-CN protection and retained issuer generations.
- Chain verification, strict optional CRL coverage, single/bulk revocation and CRL generation.
- Intermediate rollover/rollback, inventory export and policy-preserving batch reissuance.
- Shared workspace locking, interrupted-operation reporting and resumable CRL publication.

This is an administrator-operated filesystem toolkit. It has no enrollment server,
ACME service, renewal scheduler, OCSP responder, trust-store installer or HSM interface.
Private keys are unencrypted files with restrictive permissions. There is no
atomic multi-file transaction or arbitrary crash repair. A durable command fence
and checked persistence barriers protect local operations: an abrupt interruption
blocks further operations until verified resumption or explicit review. Actual
hardware power-cut behavior remains unqualified. Verified installation plans can
be resumed without signing again; see the [recovery guide](specifications/guides/recovery-en.md).

## Requirements

Run commands from the project root with Bash, Make, OpenSSL and ordinary Unix
utilities (`awk`, `sed`, `grep`, `mktemp`, `install`, `date`, `od`, `tr`, `iconv`, `sort`, and file tools).
The backend gate accepts OpenSSL 1.1.1 or 3.x and rejects LibreSSL. Select another
executable with `OPENSSL=/absolute/path/to/openssl`.

The qualified environment is macOS, Bash 3.2.57, GNU Make 3.81 and OpenSSL 3.6.4.
Other accepted versions/platforms are not thereby qualified. Python 3.8+ is required
at runtime for persistence barriers as well as for tests; the recorded environment
uses Python 3.14.7. The durability helper supports macOS and Linux, fails closed
on unsupported barriers, and requires a single local filesystem. External writers,
including synchronization agents modifying live PKI files, are prohibited.

## Quick start

Use a fresh workspace for this example. It creates a root and Web intermediate,
issues a server certificate and verifies it, first without and then with CRLs:

```sh
make root CN="Certnify Root CA"
make int-web CN="Certnify Web Issuing CA"
make server CN="app.example.test" SAN_DNS="app.example.test"
make verify KIND=web CN="app.example.test"
make crl-root
make crl KIND=web
make verify KIND=web CN="app.example.test" VERIFY_CRL=1
```

The server certificate, key and fullchain are under `intm-web-ca/`:

- `certs/app.example.test.cert.pem`
- `private/app.example.test.key.pem`
- `certs/app.example.test.fullchain.cert.pem` — leaf then intermediate, without root

The trust anchor is `root/certs/ca.cert.pem`. Deploy the appropriate certificate/key
and configure client trust separately; generation does not install trust or configure
an application. Repeating root creation with a different CN fails. Repeating leaf
issuance for an active CN also fails by default.

## Authorities, profiles and issuance

Root validity defaults to 7300 days; intermediates default to 3650 days. Create the
required intermediate before issuing leaves. Shortcuts are `int-web`, `int-auth`,
`int-code`, `int-smime` and `int-archive`; `intermediate` accepts an explicit destination.

| Target | Default authority | Leaf days | Default profile |
| --- | --- | ---: | --- |
| `server` | `intm-web-ca` | 397 | RSA: `server_cert`; EC/EdDSA: `server_ec` |
| `user` | `intm-auth-ca` | 825 | RSA: `client_cert`; EC/EdDSA: `client_ec` |
| `dev`, `code` | `intm-code-ca` | 730 | `code_sign` |
| `email` | `intm-smime-ca` | 730 | `smime` (combined signing/encryption) |
| `doc`, `archive` | `intm-archive-ca` | 3600 | `archive` |
| `generic` | `intm-generic-ca` | 397 | Required: `PROFILE` or `EXT_SECTION` |

Examples below are independent issuance choices, requiring their corresponding authorities:

```sh
make server CN="api.example.test" KEY_ALG=EC KEY_CURVE=secp384r1 \
  SAN_DNS="api.example.test" SAN_URI="spiffe://certnify/api"
make user CN="alice@example.test" KEY_ALG=Ed25519
make code CN="Release Signing Key" KEY_ALG=Ed25519
make email CN="signer@example.test" SMIME_MODE=sign KEY_ALG=EC
make email CN="encrypt@example.test" SMIME_MODE=encrypt KEY_ALG=RSA
make archive CN="Document Seal" ARCHIVE_MODE=seal DAYS=3600
make archive CN="Timestamp Signer" ARCHIVE_MODE=timestamp DAYS=3600
```

`SMIME_MODE=combined` (or `legacy`) selects `smime`; `sign` selects `smime_sign`;
`encrypt` selects `smime_encrypt`. Encryption and combined S/MIME require RSA.
`ARCHIVE_MODE=legacy` selects `archive`, `seal` selects `archive_seal`, and
`timestamp`/`timestamping` selects `timestamping`. These work with either target alias.
Explicit incompatible key/profile combinations fail.

For explicit-profile issuance from a generic authority, after creating the root:

```sh
make int-generic CN="Generic Issuing CA"
make generic CN="Signing Key" PROFILE=code_sign KEY_ALG=Ed25519 DAYS=730
make generic CN="app.example.test" PROFILE=server_ec KEY_ALG=EC SAN_DNS=app.example.test
```

The direct script is `CN="Signing Key" PROFILE=code_sign bin/gen-generic.sh`.
CN and PROFILE or EXT_SECTION are required; EXT_SECTION takes precedence.
The default authority is intm-generic-ca and the default lifetime is 397 days.
INT_DIR can select another authority recorded as generic. Normal key, DN, SAN and
lifetime controls apply; no CN-based SAN is added implicitly. The selected profile
defines the certificate usage. This command rejects specialized authorities even
when the requested profile would otherwise match them.

The authority's recorded category also restricts issuance: `web` → `serverAuth`,
`auth` → `clientAuth`, `code` → `codeSigning`, `smime` → `emailProtection`.
`archive` allows timestamping or the seal profiles without EKU. Checks use compiled
extensions, including custom profiles; PROFILE, EXT_SECTION and routing flags
cannot disable them. For a new intentionally multipurpose authority, explicitly use
`make intermediate KIND=generic INT_DIR=pki-data/general CN="General Issuing CA"`.
Environment overrides cannot reclassify an existing authority. Old custom paths
without recorded KIND require offline review/restoration; canonical names remain
recognized. These rules cover toolkit issuance and built-in reissuance. They do not
change existing certificates or constrain direct private-key use outside Certnify.
See [issuance categories](specifications/04-cryptography-and-profiles.md#authority-issuance-categories).

| Input | Meaning/default |
| --- | --- |
| `CN`, `C`, `O`, `OU` | Subject fields; country/organization/unit optional |
| `KEY_ALG` | RSA (default), EC, EdDSA, Ed25519 or Ed448 |
| `KEY_SIZE` | RSA bits, default 4096, minimum 2048 |
| `KEY_CURVE` | prime256v1 (default), secp384r1 or secp521r1 |
| `KEY_EDDSA` | Ed25519 (default) or Ed448 for generic EdDSA |
| `DAYS` | Requested validity; refused if it exceeds the remaining chain validity |
| `INT_DIR`, `KIND` | Explicit directory takes precedence over kind, then action defaults |
| `PROFILE`, `EXT_SECTION` | Explicit installed profile; EXT_SECTION takes precedence |
| `SAN_DNS`, `SAN_IP`, `SAN_EMAIL`, `SAN_URI` | Comma-separated typed lists |
| `SAN` | Combined list such as `DNS:app.example.test,IP:127.0.0.1` |
| `FORCE_NEW_KEY` | 0: reuse leaf key; 1: back up/replace; rotate: preserve canonical artifacts |
| `ROOT_PATHLEN` | 1 by default; explicitly empty omits the constraint in a new config; 0 prevents intermediate and leaf issuance |
| `QUIET_OPENSSL` | 1 suppresses selected backend chatter; toolkit logs remain |

`FORCE_NEW_KEY=1` retains a serial-named key/CSR/certificate/fullchain set and,
after verification, replaces all four conventional paths with matching artifacts.
An existing key is backed up; interruptions still require journal review.
Archive leaves default to 3600 days, leaving a margin below a newly created
3650-day intermediate. Explicit DAYS values are never silently reduced.

Reused keys keep their actual algorithm despite a different requested KEY_ALG.
Key rotation does not bypass duplicate-CN protection: `ALLOW_DUPLICATE_CN=1` is a
separate explicit override. `FORCE_REISSUE`, `ROTATE_KEY` and `FORCE_REUSE_KEY`
control intermediate renewal/rekeying; see the [issuance contract](specifications/05-issuance.md).

Any explicit nonempty SAN list suppresses the implicit CN SAN. Without one,
servers get DNS:CN; user/email actions get email:CN when CN contains `@`.
Malformed entries fail rather than being discarded. A profile SAN conflicting
with the request is rejected before signing; the issued SAN set is checked before
installation. Subject fields use validated UTF-8. Quote values in your shell.

Fragments in `profiles/` compose **new** authority configurations. Editing those
fragments does not update an existing `openssl.cnf`: retain and review the installed
configuration before an explicit policy edit. Issued leaves retain policy snapshots.
Exact extensions and validation rules are in the [cryptographic specification](specifications/04-cryptography-and-profiles.md).

## Verification, revocation and CRLs

Verification and revocation require `KIND` or `INT_DIR`, even with FILE. FILE can be
authority-relative, matching workspace-relative, or an absolute contained path:

```sh
make verify KIND=web FILE="certs/app.example.test.cert.pem"
make verify KIND=web FILE="intm-web-ca/certs/app.example.test.cert.pem"
make revoke KIND=web CN="app.example.test" REASON=keyCompromise DRY_RUN=1
make revoke KIND=web CN="app.example.test" REASON=keyCompromise
```

CN lookup requires one exact active match, or one unambiguous historical match.
Use FILE when ambiguous; revocation also accepts SERIAL. A nonempty CHAIN override
is rejected. Verification uses the certificate's bound issuer generation and workspace
root. Add one of `VERIFY_DNS`, `VERIFY_IP`, `VERIFY_EMAIL`, `VERIFY_URI`, or `VERIFY_SUBJECT` for an expected
identity, and `VERIFY_PURPOSE` for the application purpose.

`VERIFY_URI` compares the complete URI SAN exactly (case-sensitive, no URI
normalization). `VERIFY_SUBJECT` compares the complete subject exactly as printed
by `openssl x509 -in cert.pem -noout -subject -nameopt RFC2253`, without `subject=`.
It supports certificates without SANs; it does not uniquely pin a certificate.
`VERIFY_ATTIME` selects nonnegative Unix seconds (UTC, through year 9999).
Certificate and CRL validity use that same reference time. Supply retained CRLs
covering that time; this does not reconstruct historical trust or prove signing time.
URI/subject mismatch is a preflight failure in every mode.

`VERIFY_CRL=1` requires valid root **and** issuer CRLs, including the historical
issuer CRL when applicable. Missing, stale or invalid required CRLs fail.

| VERIFY_MODE | Valid | Revoked | Other completed verification error |
| --- | --- | --- | --- |
| normal | Success | Failure | Failure |
| strict | Success | Failure | Failure |
| tolerate_revoked | Success | Success | Failure |
| info | Success | Success | Success, report only |

Preflight errors fail in every mode. In info mode, read `VERIFY STATUS`; exit zero
is not proof of validity. Default verification does not check revocation.

The `VERIFY CHECKS` report lists requested checks: chain, revocation, identity type
and purpose. `not-requested` means the check was not requested, not that it passed.
`VERIFY STATUS: OK` applies only to requested checks; incomplete successful
verification explicitly says so. `VERIFY_PURPOSE=any` does not require a specific
purpose. `CN` selects the certificate and `KIND` the authority; neither supplies
an expected identity or purpose, which must come from the application's needs.
Existing commands and exit codes remain unchanged.


For automation, `VERIFY_MODE=strict` requires one expected identity (SAN or explicit subject) and a
specific purpose, enforces strict X.509 validation and full-chain CRL coverage,
and returns nonzero on any failure. `VERIFY_CRL=0` cannot disable strict coverage.
For example, after renewing the required CRLs:

```sh
make crl KIND=web CRL_HISTORY=1
make verify KIND=web CN=app.example.test VERIFY_MODE=strict \
  VERIFY_DNS=app.example.test VERIFY_PURPOSE=sslserver
make verify KIND=smime CN=user@example.test \
  VERIFY_EMAIL=user@example.test VERIFY_PURPOSE=smimesign
```

Purpose names are OpenSSL names, such as sslserver, sslclient, smimesign,
smimeencrypt and timestampsign. Backend-specific purposes (such as codesign)
fail if unsupported by the selected OpenSSL version.

```sh
make crl-root
make crl KIND=web CRL_DAYS=7
make crl-show KIND=web
make crl-all
make revoke-intermediate KIND=web DRY_RUN=1
make revoke-intm-and-leafs KIND=web LEAF_STATUSES=V,E DRY_RUN=1
```

Remove DRY_RUN only to apply the intended revocation. Intermediate-only revocation
disables issuance but leaves leaf rows unchanged. Bulk revocation selects stored
statuses (V by default, which can include expired certificates not yet updated).
Required item failures produce a nonzero aggregate result; committed revocations
are retained. Make revocation targets default CRL_UPDATE to 1; use 0 to omit refresh.
Repeating revocation preserves its original date/reason and can retry CRL refresh.
Supported reasons and mappings are in the [revocation contract](specifications/06-verification-and-revocation.md).
Release only a `certificateHold` suspension with the existing targets:

```sh
make revoke KIND=web SERIAL=1000 REASON=removeFromCRL DRY_RUN=1
make revoke KIND=web SERIAL=1000 REASON=removeFromCRL
make revoke-intermediate KIND=web REASON=removeFromCRL
```

Release requires `CRL_UPDATE=1` and publishes a new complete CRL without that
entry; it never emits `removeFromCRL` in a complete CRL. Permanent revocations
cannot be undone. Distribute the new CRL: clients may retain the previous one
until refresh. An expired certificate stays expired. Bulk release is rejected;
release each intended certificate explicitly. Independent `.disabled` markers
are retained; only a marker created for this intermediate's hold is removed.

`crl-root` uses configured CRL validity, normally seven days; CRL_DAYS controls
intermediate generation. `crl-all` includes matching legacy directories and excludes
root by default. `make crl-all CRL_HISTORY=1 CRL_DAYS=7` explicitly renews root,
canonical intermediate and retained generation CRLs, including legacy directories.
`make crl KIND=web CRL_HISTORY=1` limits intermediate discovery to that authority
and also renews root. Custom authority paths must be selected explicitly.
The whole set is preflighted, but installation is per file: a later failure can
leave earlier CRLs renewed and counters advanced. No CRL URLs are fetched or automatically added to certificate extensions.
`verify-intermediate-revoked` fails for a revoked intermediate; it does not invert
verification success. Inspection helpers include `show-intermediate-serial` and
`crl-root-revoked` with an explicit authority selector.

## Lifecycle, batches and publication

These are separate operational choices, not one sequence to run indiscriminately:

```sh
make rollover-web INT_CN="Web CA v2"
make list-leafs-web
make reissue-leafs-web DRY_RUN=1
make rollback-web
```

Inventory exports accept `OUT=out/<name>.tsv` (directly under `out/`) or `OUT=-`
for stdout. Other paths, symbolic links and hard links are refused. `out/` is
reserved for exports and cannot contain an authority. Existing TSV exports are
replaced atomically after complete validation.


Rollover preserves the previous authority directory and creates a new active one;
it does not revoke or migrate old certificates. Rollback preserves the current
active directory before restoring a legacy one; it does not undo revocation.
Inventory and batch commands accept explicit source/input/destination selectors.
Batch reissuance defaults to **preserve**: original certificates and archived
profile records in `LEGACY_DIR` supply the full subject, SANs, effective profile
and key parameters. Fresh keys are generated with the same algorithm, RSA size
or EC curve; old private keys are not needed. Every row is checked before issuing,
including in `DRY_RUN=1`. Missing evidence or incompatible profiles fail closed.
Issuer, serial number, SKI/AKI and validity are renewed; `DAYS` still selects the
new lifetime within the chain limits. This mode requires OpenSSL 3.x.
For reviewed lossy reissuance from a TSV alone, use `REISSUE_MODE=cn-only`.
Custom `ISSUE_CMD` commands have no preservation guarantee.
Per-item receipts block blind retries after uncertain results. See the
[lifecycle specification](specifications/07-lifecycle-and-migration.md).

Final CRL preparation/publication is a direct script operation:

```sh
KIND=web DRY_RUN=1 bin/intm-publish-final-crl.sh
```

Without DRY_RUN it generates PEM, DER and digest sidecars, plus latest aliases.
By default it refuses unrevoked, unexpired indexed leaves. “Final” is advisory;
it does not retire the authority. Remote publication occurs only with an explicitly
configured PUBLISH_CMD. All six artifacts must succeed. FINAL_CRL selects a retained
valid versioned PEM to retry without consuming another CRL number. Its local
`.resume-state` must match the PEM, revoked index entries and next CRL counter.
A subsequent revocation or CRL generation attempt invalidates that retry; generate
a fresh final CRL. Older final CRLs without this state must also be regenerated.
Routine refresh replaces latest aliases without changing versioned archives;
if a current DER exists, it is refreshed alongside the PEM. See the
[publication and recovery guide](specifications/guides/recovery-en.md).

## Storage and interrupted operations

The root uses `root/`; intermediate shortcuts use `intm-<kind>-ca/`. Each contains
configuration, index, counters, private keys, certificates and CRLs. Intermediates
also have CSRs, issuer-generation archives, bindings, policy snapshots and name maps.
The root layout does **not** create a CSR directory. `ca.chain.cert.pem` contains
intermediate then root; `chain.cert.pem` is its compatibility alias.

Ordinary safe CNs retain their names, including spaces/@. Unsafe or reserved names
use a digest stem and exact CN map; subsequent certificates can use serial-based
names. See the [storage specification](specifications/03-persistence-and-artifacts.md).
Custom data locations should use `pki-data/` or an explicit local Git exclusion.
After moving an intact, inactive workspace, preview and apply configuration
rebinding from its new location:

```sh
RECOVERY_ACTION=relocate bin/recovery.sh
RECOVERY_ACTION=relocate RELOCATE_APPLY=1 bin/recovery.sh
```

This discovers root, nested and historical authorities, preserves custom policy,
updates internal absolute aliases and retains all keys, indexes and counters.
Resolve pending operations before relocation. External aliases, missing state,
unsupported paths and configuration includes are refused; concurrent use of the
old workspace is outside this operation's scope.

An existing authority with missing database/counters is refused without recreating
state. Restore and reconcile its retained files explicitly; never reset counters.
RSA generation/reuse requires at least 2048 bits, and chain verification enforces
authentication level 2. Older weak keys/certificates require an explicit migration;
these checks do not replace or revoke existing material.

Toolkit transactions share `.locks/root-ca.lock`. An interrupted issuance or move
can leave `.recovery/pending`, which blocks further locked operations until reviewed:

```sh
bin/recovery.sh
```

This report is read-only. A fully prepared installation can be completed with
`RECOVERY_ACTION=resume bin/recovery.sh`, or automatically before the next locked
command by setting `AUTO_RECOVER=1`. This covers validated leaf installation,
hold-release publication and workspace rebinding. Every saved source, destination,
state guard and validity deadline is rechecked; recovery never signs a certificate
or resets a counter. Completed private journals are retained as receipts and may
contain private key copies with restrictive permissions.

An uncertain signing result, an incomplete plan, an interrupted authority rollover,
a stale lock, or changed evidence still requires explicit reconciliation and
acknowledgment. There is no automatic rollback or lock stealing.
A failed CRL refresh/publication does not undo a local revocation or generated CRL.
The [reliability contract](specifications/08-architecture-and-reliability.md) describes
commit boundaries, stale locks and manual recovery.

## Tests, inspection and cleanup

```sh
make help
make tree
make ls-web
make test-stage0 test-stage1 test-stage2 test-stage3 test-stage4 test-stage5 test-stage6 test-stage7 test-stage8 test-stage9 test-stage10
make test-smoke
```

Tests create disposable workspaces from an explicit source manifest and use generated
fixture keys. The suites cover parsing, policies, concurrency, revocation and injected
failures; publication uses local stubs. See [test/README.md](test/README.md) for execution
and [acceptance coverage](specifications/10-acceptance-and-traceability.md) for limits.

`make clean` now previews only, without a workspace mutation. After checking the
listed paths and taking any required backup, `make clean CLEAN_APPLY=1` deletes
root, recognized top-level intm-* authorities and out, including keys and history.
The entire plan is revalidated under lock. Symlink candidates and incomplete
recognized authorities are refused; unrelated intm-* directories are preserved.
Custom authority paths and recovery journals are outside this cleanup scope.
Cleanup validates local authority state without interpreting OpenSSL configuration
paths or policies, so stale paths after a workspace move do not block it.
CLEAN_APPLY=1 with DRY_RUN=1 is rejected.

Compatibility: issuance now refuses an invalid issuer or DAYS exceeding the
shortest chain lifetime, reporting the limiting expiry and maximum whole days.
For example, use `make archive CN="Records Seal" DAYS=3600` when the archive CA
has enough remaining validity; a 3650-day CA cannot issue a 3650-day leaf later.
No duration is silently capped. Existing certificates and keys are not migrated.

## Documentation

- [Functional and technical specifications](specifications/README.md)
- [Script reference](specifications/guides/shell-en.md)
- [Profile selection guide](specifications/guides/profiles-en.md)
- [Recovery procedures](specifications/guides/recovery-en.md)
- [Compatibility and supported limits](specifications/09-compatibility-and-limitations.md)
