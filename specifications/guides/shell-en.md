# Shell Scripts

This document summarizes the scripts in the `bin/` directory, their main purpose, and their most visible dependencies.

See also `profiles-en.md` for the reference of the OpenSSL profiles used by these scripts.

## Overview

| Script | Description | Main dependencies |
| --- | --- | --- |
| `bin/pki-env.sh` | Shared shell library for the project: logging helpers, validation, locks, `INT_DIR`/`KIND` resolution, OpenSSL checks, metadata generation, and common utility functions. | `openssl`, `awk`, `sed`, `grep`, `mktemp`, `install`, `date`, `tr`, `wc`, `iconv`, Bash shell |
| `bin/gen-root.sh` | Creates or validates the root certificate authority, its directory structure, private key, certificate, and metadata. | `bin/pki-env.sh`, `openssl`, `awk`, `sed`, `mktemp`, `date` |
| `bin/gen-intm.sh` | Generates or reissues an intermediate CA (`intm-<kind>-ca`), with key rotation handling, chain generation, metadata writing, and reissue safeguards. | `bin/pki-env.sh`, `openssl`, `awk`, `sed`, `mktemp`, `install`, `cp`, `mv`, `rm`, `date` |
| `bin/gen-leaf.sh` | Core script for issuing end-entity certificates (`server`, `user`, `dev`, `email`, `doc`) with SAN support, OpenSSL profiles, key rotation, and intermediate state checks. | `bin/pki-env.sh`, `openssl`, `awk`, `sed`, `grep`, `mktemp`, `install`, `cp`, `mv`, `rm`, `date` |
| `bin/gen-server.sh` | Wrapper used to issue a server certificate by delegating to `gen-leaf.sh` with `ACTION=server`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-user.sh` | Wrapper used to issue a user/client certificate by delegating to `gen-leaf.sh` with `ACTION=user`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-code.sh` | Wrapper used to issue a code-signing certificate by delegating to `gen-leaf.sh` with `ACTION=dev`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-email.sh` | Wrapper used to issue an S/MIME certificate by delegating to `gen-leaf.sh` with `ACTION=email`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-archive.sh` | Wrapper used to issue an archive/document certificate by delegating to `gen-leaf.sh` with `ACTION=doc`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/verify.sh` | Verifies a leaf certificate against the root and an intermediate, with optional CRL checking and different exit modes. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `sed` |
| `bin/revoke-leaf.sh` | Revokes a single end-entity certificate from a `FILE`, `SERIAL`, or `CN`, then rebuilds the intermediate CRL if requested. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `sed`, `mktemp`, `install`, `rm` |
| `bin/revoke-intm.sh` | Revokes an intermediate CA in the root database, creates a `.disabled` flag, and can republish the root CRL. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `mktemp`, `install`, `rm` |
| `bin/revoke-intm-and-leafs.sh` | Revokes an intermediate CA and then batch-revokes the selected end-entity certificates in its history, with optional root and intermediate CRL updates. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `mktemp`, `install`, `rm` |
| `bin/intm-rollover.sh` | Performs an intermediate rollover without symlinks: archives the current active directory, creates a new active intermediate, and generates its chain. | `bin/pki-env.sh`, `openssl`, `mv`, `cat`, `date` |
| `bin/intm-rollback-to-legacy.sh` | Restores a `legacy` intermediate as the active one and saves the current active directory before rollback. | `bin/pki-env.sh`, `mv`, `cat`, `sort`, `head`, `sed`, `date` |
| `bin/list-leafs-by-issuer.sh` | Extracts from `index.txt` the list of leaf certificates issued by an active or `legacy` intermediate and produces a TSV file that can be used for batch reissuance. | `bin/pki-env.sh`, `awk`, `sort`, `head`, `sed`, `grep`, `mkdir` |
| `bin/intm-reissue-leafs.sh` | Batch-reissues the leaf certificates listed in a TSV file, automatically calling the appropriate `gen-*` wrappers based on `KIND`. | `bin/pki-env.sh`, `bash`, `sort`, `head`, `gen-*` wrappers |
| `bin/recovery.sh` | Report pending operations; acknowledge completed manual review. | Bash, filesystem tools |
| `bin/crl.sh` | Locked current/root/historical CRL operations. | OpenSSL, shared helpers |
| `bin/intm-publish-final-crl.sh` | Generates a final intermediate CRL, produces PEM/DER/SHA256 artifacts, and can publish them through an external command. | `bin/pki-env.sh`, `openssl`, `sed`, `awk`, `date`, `ln`, `bash` |

## Audit hardening helpers

`pki-input.sh` validates scalar controls before mutations. `pki-state.sh` opens
established state without recreating missing databases/counters. `pki-policy.sh`
enforces generated/reused key strength and compares preflighted and issued SAN
sets using `pki-san-output.awk`. Subject validation additionally requires `iconv`;
SAN set comparison uses `sort`. Internal SAN compilation uses only disposable
CSRs and a temporary key, never an authority key.

## Notes

- The `gen-server.sh`, `gen-user.sh`, `gen-code.sh`, `gen-email.sh`, and `gen-archive.sh` scripts are lightweight wrappers around `gen-leaf.sh`.
- Almost every script relies on `bin/pki-env.sh`, which acts as the shared foundation of the toolkit.
- The project's main external dependency is `OpenSSL` (1.1.1 or 3.x, with LibreSSL explicitly rejected by `pki-env.sh`).
- The dependencies listed here are the main ones visible in the scripts; they are not intended to be a fully exhaustive command-by-command matrix.

See [commands and defaults](../02-commands-and-configuration.md) and [recovery](recovery-en.md).

## Routine operations

- `make clean` previews the bounded cleanup. Use `CLEAN_APPLY=1` only after reviewing
  the paths and backup needs; keys and historical state are included. Symlink
  candidates or incomplete recognized authorities abort the entire plan.
- Issuance refuses invalid issuers or a DAYS value beyond the chain's remaining
  lifetime. Use the reported maximum to choose DAYS; existing certificates are
  unchanged. `pki-validity.sh` and `pki-time.awk` implement this preflight.
- `make verify KIND=web CN=app.example.test VERIFY_MODE=strict
  VERIFY_DNS=app.example.test VERIFY_PURPOSE=sslserver` checks the expected SAN,
  application usage and complete local CRL coverage. Supply these options on one
  command line. Missing or invalid coverage fails; strict mode cannot tolerate
  revocation. VERIFY_IP and VERIFY_EMAIL select other identity types.
- `make crl-all CRL_HISTORY=1` renews root plus discovered current and historical
  issuer CRLs. For a custom authority use `make crl INT_DIR=pki-data/custom
  CRL_HISTORY=1` on one line. Keys must be retained for every selected generation;
  the operation does not recover missing keys or publish remotely.
- Built-in batch reissuance still warns that it is CN-only. Person names without
  @ no longer receive an invented email SAN.

`pki-clean.sh` implements cleanup; `pki-crl-history.sh` preflights the renewal set.
Historical CRL renewal is per-file, so a later error can leave earlier renewals
committed. Full behavioral contracts and examples are in chapters 02, 05 and 06.
