# 11 — Toolkit versioning and source releases

## Version contract

`VERSION` is the sole toolkit version: three nonnegative decimal integers without
leading zeroes, separated by dots and terminated by exactly one LF newline.
The initial baseline is `1.0.0`; this does not assert a published release or tag.
OpenSSL versions, certificate serials, issuer generations and storage format
versions are independent. Changing VERSION neither migrates nor touches PKI state.

Run from the source root with Python 3.8+ and Make:

```sh
make version
make version-bump LEVEL=patch
# Alternatives: LEVEL=minor or LEVEL=major
```

`make version` prints only the version and newline. Direct equivalents are
`python3 -B tools/version.py show` and
`LEVEL=patch python3 -B tools/version.py bump`.
Both work without Git, OpenSSL or an initialized authority.

Choose patch for compatible fixes, minor for compatible functionality, and major
for incompatible public command, policy or storage-contract changes. Document
migration requirements explicitly; a major bump is not a migration mechanism.
Patch increments PATCH; minor increments MINOR and resets PATCH; major increments
MAJOR and resets MINOR and PATCH. Every successful invocation increments again.
Missing, empty or unknown LEVEL fails without changing VERSION. Malformed,
missing, symlinked or nonregular VERSION files are rejected, never initialized.

A bump replaces only VERSION, preserving its permission bits, using a temporary
file in the same directory and atomic replacement. A separate exclusive
`.version-bump.lock/` serializes cooperating bumps; an existing lock causes failure.
It does not acquire the operational PKI lock or invoke PKI bootstrap. Ordinary
errors clean up owned temporary files and the lock. Abrupt termination may retain
source-maintenance evidence; inspect it and confirm no bump is running before
manual cleanup. This is not a power-loss durability guarantee. Do not edit or
package sources concurrently with a bump.

## Changelog and manual release procedure

Maintain `CHANGELOG.md` manually: collect user-visible changes under Unreleased,
including compatibility breaks, migration steps and exact validation scope.
Before a release, choose the increment, run it once, and move the relevant notes
into a section bearing that VERSION and the release date. Retain Unreleased for
future work. Review the diff and run the relevant acceptance gates. Historical
qualification records do not automatically qualify new versions.

There is no automatic hook, `release-prepare` command, Git mutation, tagging or
publication in version maintenance. Any later commit, `vMAJOR.MINOR.PATCH` tag or
publication is a separate deliberate maintainer action after review.

## Source archives

Use the explicit source distribution manifest, including runtime, profiles,
tests, documentation, VERSION and changelog:

```sh
python3 -B test/workspace.py archive . /tmp/certnify-1.0.0.tar.gz
```

Choose a fresh output filename matching the inspected VERSION. The command does
not infer or validate the filename version. Members are exactly the files listed
in `test/source-manifest.txt`, under `certnify/`; no recursive directory or Git
tracked-file enumeration is used. The complete manifest is validated first:
missing files, duplicate/unsafe paths, symlinks and nonregular files fail before
output creation. The destination is exclusive: existing files and links are never
overwritten. An I/O failure after creation removes the incomplete archive.

Review manifest additions as source packaging changes. Never list operational
state, private keys, recovery journals or local planning/configuration. Unlisted
files are excluded even inside source directories. The manifest is a reviewed
allowlist, not a secret-content scanner. Archive only a quiescent trusted source
tree; concurrent external edits are unsupported. Archives preserve source modes
and timestamps and are not promised byte-for-byte reproducible.

Validate the archive's member list and test a separately extracted source tree
before distributing it. Extraction and subsequent tests must use disposable
locations, never an operational PKI. See [test guidance](../test/README.md) and
[the French guide](guides/versioning-fr.md).
