# 02 — Commands and configuration

## Public operations

Run Make from the project root. The default target is `help`. Variables are strings supplied through Make assignments or the environment; recipes and wrappers apply additional defaults. Empty strings frequently mean “use the default,” except where explicitly noted.

| Make target | Operation / implementation |
| --- | --- |
| `help` | Print the primary command summary |
| `root` | `gen-root.sh`: initialize or validate the root |
| `intermediate` | `gen-intm.sh`: generic intermediate; Make defaults kind to `web`, CN to `Web Issuing CA` |
| `int-web`, `int-auth`, `int-code`, `int-smime`, `int-archive` | Same intermediate generator, with kind-specific CN defaults |
| `server` | `gen-server.sh` → `gen-leaf.sh`, action `server` |
| `user` | `gen-user.sh` → `gen-leaf.sh`, action `user` |
| `dev`, `code` | `gen-code.sh` → `gen-leaf.sh`, action `dev` |
| `email` | `gen-email.sh` → `gen-leaf.sh`, action `email` |
| `doc`, `archive` | `gen-archive.sh` → `gen-leaf.sh`, action `doc` |
| `verify` | `verify.sh`: leaf chain/optional CRL evaluation |
| `revoke` | `revoke-leaf.sh`: one leaf revocation |
| `revoke-intermediate` | `revoke-intm.sh`: root database revocation and issuance disablement |
| `revoke-intm-and-leafs` | Revoke the intermediate and selected issuance rows |
| `crl-root` | Generate root CRL using configured validity |
| `crl`, `crl-show` | Generate or inspect a selected intermediate CRL |
| `crl-all` | Generate CRLs for every `intm-*` entry containing `openssl.cnf`, including legacy directories |
| `verify-intermediate-revoked` | Run OpenSSL verification with root CRL; a revoked certificate fails verification |
| `show-intermediate-serial` | Print intermediate serial as hexadecimal and colon-separated byte pairs |
| `crl-root-revoked` | Display revoked entries from root CRL, highlighting selected intermediate serial |
| `rollover-<kind>` | `intm-rollover.sh`: preserve active directory and create replacement |
| `rollback-<kind>` | `intm-rollback-to-legacy.sh`: restore selected/latest legacy directory |
| `list-leafs-<kind>` | `list-leafs-by-issuer.sh`: export inventory |
| `reissue-leafs-<kind>` | `intm-reissue-leafs.sh`: consume inventory |
| `ls-web`, `ls-auth`, `ls-code`, `ls-smime`, `ls-archive` | List certificate directory; listing failure is ignored |
| `tree` | Display directories to depth three |
| `test-smoke`, `test-stage0` … `test-stage8` | Run disposable integration/regression fixtures |
| `clean` | Preview controlled root/intm-*/out cleanup; CLEAN_APPLY=1 explicitly applies |

`bin/intm-publish-final-crl.sh` and `bin/recovery.sh` are direct script operations without Make targets. `bin/gen-leaf.sh` also permits direct use. See [the guides](guides/README.md) for examples.

## Default routing and validity

| Action | Kind | Leaf days | Default profile | Intermediate shortcut CN |
| --- | --- | ---: | --- | --- |
| server | web | 397 | RSA: `server_cert`; EC/EdDSA: `server_ec` | Web Issuing CA |
| user | auth | 825 | RSA: `client_cert`; EC/EdDSA: `client_ec` | Auth Issuing CA |
| dev | code | 730 | `code_sign` | Code Signing Issuing CA |
| email | smime | 730 | `smime` | S/MIME Issuing CA |
| doc | archive | 3650 | `archive` | Archive Issuing CA |

Root defaults: CN `Root CA`, 7300 days. Intermediate defaults: 3650 days. Direct `gen-intm.sh` defaults CN to `Example Intermediate CA` and, without a selector, directory to `intermediate`. Direct `gen-leaf.sh` defaults CN to `example.com`; without an action it uses 397 days and the effective-key server profile; an intermediate selector remains required.

## Intermediate selection

For action-aware issuance, precedence is INT_DIR, then KIND, then the action
mapping. REQUIRE_STRICT_KIND=1 rejects an inferable conflict with that mapping;
default 0 permits cross-kind routing. ALLOW_KIND_FROM_DIR=1 permits kind inference
from a conventional directory. Custom directories need not encode a kind.
Ordinary CRL selection uses CRL_INT_DIR > INT_DIR > KIND. Lifecycle shortcuts
operate on canonical `intm-<kind>-ca` directory names.

Authority selectors accept a kind, workspace-relative directory, absolute path
inside the workspace, or an internal symlink alias. Nested authorities are
supported. `.` selects the original calling directory. Resolution uses physical
paths, and data artifacts must stay inside the selected authority. Outside
symlinks, parent traversal, control characters, and configuration-interpolating
path characters are rejected. The root trust anchor is always the workspace's
`root/certs/ca.cert.pem`, independent of intermediate nesting.

Before use, generated CA configurations must bind `CA_default.dir` and all CA
storage paths to the selected authority. Includes and unsupported path overrides
are rejected rather than evaluated. Operator extension/policy settings are not
reconstructed from templates. Rollover and rollback validate the old binding,
stage the path rewrite, then validate the new binding. A relocated workspace with
stale absolute bindings is rejected; automatic whole-workspace migration is not
implemented. Do not repoint an old legacy configuration at a live active CA.

## FILE and CHAIN

Verification and leaf revocation always require `KIND` or `INT_DIR`. `FILE` accepts:

- authority-relative `certs/example.cert.pem` or `newcerts/1000.pem`;
- workspace-relative `intm-web-ca/certs/example.cert.pem`, including an internal
  authority alias, only when its resolved authority matches the selector;
- an absolute path contained in the selected authority.

Other simple relative paths remain authority-relative. A relative path with an
intermediate prefix before `/certs/` or `/newcerts/` is treated as workspace-relative;
a mismatched prefix fails, rather than guessing a different issuer. Containment
and symlink checks apply to all forms. Examples:

```sh
make verify KIND=web FILE=certs/example.cert.pem
make revoke KIND=web FILE=intm-web-ca/certs/example.cert.pem REASON=superseded
```

A nonempty `CHAIN` now fails explicitly. There is no chain-override interface:
verification uses the bound issuer generation and the workspace root trust anchor.
Make continues forwarding CHAIN solely so unsupported existing use receives the
same diagnostic instead of being silently ignored.

## Parameter transport and validation

Public Make parameters are frozen as literal values and exported. Recipe code
reads shell variables; neither Make functions inside these values nor shell
metacharacters are evaluated. Pattern target names are transported the same way.
Make options, makefiles and the explicit ISSUE_CMD/PUBLISH_CMD hooks remain trusted
operator code, not an untrusted-input API.

Shared validation runs before lock/layout mutations. Nonempty boolean controls
accept 0/1; FORCE_NEW_KEY also accepts rotate. DAYS, KEY_SIZE, DN_MAXLEN and CRL
durations are positive decimal integers (at most nine digits); lock timeout,
renewal threshold and nonempty ROOT_PATHLEN also allow zero. Empty values retain
the documented defaults, including the special empty ROOT_PATHLEN behavior.

## Shared inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `CN`, `C`, `O`, `OU` | operation CN; others empty | Subject fields |
| `DN_MAXLEN` | 128 | Maximum bytes per CN/O/OU field |
| `KEY_ALG` | RSA | RSA, EC, EdDSA, Ed25519, Ed448; normalized case/whitespace |
| `KEY_SIZE` | 4096 | RSA modulus size; at least 2048 bits for generation and reuse |
| `KEY_CURVE` | prime256v1 | EC curve; also secp384r1 or secp521r1 |
| `KEY_EDDSA` | Ed25519 | Variant when generic EdDSA is selected |
| `DAYS` | operation-dependent | Requested certificate lifetime |
| `ROOT_PATHLEN` | 1 | Root constraint; explicitly empty omits it |
| `ROOT_CNF` | root/openssl.cnf | Root generator configuration path only |
| `OPENSSL` | openssl | Backend executable passed literally through the environment |
| `CERTNIFY_PROFILES_DIR` | workspace/profiles | Fragment source directory |
| `QUIET_OPENSSL` | 1 in public issuance/revocation | Suppress selected backend output; toolkit logs remain |
| `DEBUG` | 0 | Additional tracing in scripts that implement it |
| `LOCK_TIMEOUT` | 30 seconds | Wait for the shared workspace lock |

`ROOT_DIR` is assigned by the shared library from the physical parent of `bin`; it is not a configurable data directory despite some comments.

## Issuance controls

| Input | Default / behavior |
| --- | --- |
| `ACTION`, `TYPE` | `ACTION` wins; `TYPE` is a legacy action alias |
| `EXT_SECTION`, `PROFILE` | Wrapper precedence: nonempty `EXT_SECTION` > `PROFILE` > computed profile; core accepts both with the same explicit-override precedence |
| `SAN_DNS`, `SAN_IP`, `SAN_EMAIL`, `SAN_URI` | Empty comma-separated lists |
| `SAN` | Combined syntax; defaults apply only when no SAN list is supplied (chapter 04) |
| `SMIME_MODE` | `combined`; `legacy` also selects smime; `sign` / `encrypt` select specialized profiles |
| `ARCHIVE_MODE` | `legacy`; `seal`, `timestamp` / `timestamping` supported |
| `FORCE_NEW_KEY` | `0`; `1` backs up/replaces a leaf key; `rotate` preserves canonical artifacts |
| `ALLOW_DUPLICATE_CN` | 0; `1` bypasses active-CN refusal |
| `ALLOW_SIGN_WITH_REVOKED_INT` | 0; `1` bypasses both revoked-parent and disabled-marker checks |
| `AUTO_UPDATEDB` | 1; refresh expiry statuses before duplicate check |
| `REFRESH_CRL_BEFORE_ISSUE` | 0; optionally generate intermediate CRL |
| `CRL_DAYS` | 7 for ordinary CRL generation |
| `REKEY_ON_ALG_CHANGE`, `REKEY_ON_REVOKE` | 1 for intermediate generation |
| `FORCE_REUSE_KEY`, `ROTATE_KEY`, `INTM_REVOKED`, `FORCE_REISSUE` | 0; intermediate controls |
| `REISSUE_IF_EXPIRES_BEFORE` | 2592000 seconds; intermediate renewal threshold |

S/MIME and archive modes are trimmed and lowercased; invalid modes fail even when a profile override is supplied. Direct rollover defaults to EC/secp384r1; Make supplies its global RSA/prime256v1 defaults instead.

## Verification, revocation, and lifecycle inputs

Verification uses `FILE` or `CN`, `VERIFY_CRL=0`, and `VERIFY_MODE=normal|tolerate_revoked|info|strict`. A nonempty `CHAIN` is rejected; issuer binding and the workspace root determine trust.

Revocation uses `FILE`, `SERIAL`, or `CN`, `REASON=cessationOfOperation`, `MAP_PRIV_WITHDRAWN_TO=cessationOfOperation`, and `CRL_DAYS=7`. Leaf revocation defaults `CRL_UPDATE=1`; direct intermediate/bulk scripts default it to `0`, while Make defaults all three to `1`. Bulk selection uses `LEAF_STATUSES=V`; `V,E` includes expired rows. `DRY_RUN=1` is read-only for leaf/intermediate/bulk revocation, batch reissuance and final CRL preparation. Other operations do not gain dry-run semantics from this flag.

Lifecycle uses `INT_CN` for rollover (Make default `<UPPERCASE KIND> CA v2`), `LEGACY_DIR`, `ACTIVE_DIR`, `INPUT`, `OUT`, `INCLUDE_REVOKED=0`, `INCLUDE_EXPIRED=0`, `ISSUE_CMD`, `COL_SERIAL=1`, `COL_EXPIRES=2`, and `COL_CN=3`. Final CRL publication adds `CRL_DAYS=90`, optional `CRL_HOURS`, `OUT_DIR=crl`, `FINAL_MODE=1`, `ALLOW_REMAINING_LEAFS=0`, optional `PUBLISH_CMD`, `DRY_RUN=0`, and `FINAL_CRL` for resuming an existing versioned CRL. Recovery reporting uses `RECOVERY_ACTION=report` by default; acknowledgment requires `RECOVERY_ACTION=acknowledge`, the exact `RECOVERY_ID` and nonempty `RECOVERY_NOTE` (chapter 08).

Most switches activate only for the literal string `1`. A replacement should validate typed options rather than silently accepting arbitrary values. Uniform validation of every option is not guaranteed by the shell interface.

## Routine-operation options (step 2)

- CLEAN_APPLY=0 (default): clean is a read-only preview. CLEAN_APPLY=1 revalidates
  all candidates under the workspace lock, then deletes only listed directories.
  Root and recognized top-level intm-* authorities must pass configuration/state
  checks; out is the fixed generated-output directory. Symlink or non-directory
  candidates fail; intm-* directories without openssl.cnf are preserved. Custom
  authority paths are not discovered. DRY_RUN=1 conflicts with CLEAN_APPLY=1.
  Deletion is sequential, not transactional: a filesystem error after an earlier
  deletion cannot restore that directory. Backups remain an operator operation.
- VERIFY_DNS, VERIFY_IP or VERIFY_EMAIL: at most one literal expected identity,
  independently of the CN used to select a certificate. VERIFY_PURPOSE selects
  sslclient, sslserver, nssslserver, smimesign, smimeencrypt, crlsign, any,
  ocsphelper, timestampsign or codesign (backend support required).
- VERIFY_MODE=strict requires an identity and a purpose other than any. It enables
  full-chain CRL coverage regardless of VERIFY_CRL, requires the identity type in
  SAN, and adds X.509 strict validation and root self-signature validation.
- CRL_HISTORY=1 with crl-all includes root and all discovered current/retained
  issuers, including legacy directories. With crl, it includes root and the
  selected authority's generations. ISSUER_ID cannot be combined with this option.
  CRL_DAYS (default 7) applies to the entire historical renewal set, including root.

These new Make values use the same literal environment transport as other public
inputs. CLEAN_APPLY and CRL_HISTORY accept only 0/1. The existing ordinary CRL and
verification modes retain their default scope. See chapters 05–06 for validity
refusals, strict verification and historical renewal failure boundaries.
