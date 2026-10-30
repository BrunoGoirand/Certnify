# Changelog

Each release records user-visible changes, compatibility breaks, migrations and
validation scope. Toolkit versions are independent of OpenSSL and PKI data formats.

## Unreleased

### Added

- Unified toolkit version in `VERSION`, `make version`, and explicit
  `make version-bump LEVEL=patch|minor|major` maintenance.
- Manifest-only source archive generation and documented English/French manual
  release procedure.
- Disposable source-maintenance regression gate: `make test-versioning`, covering
  version validation/increments, literal inputs, locks and archive safety.

## 1.0.0 — Initial versioning baseline

The existing toolkit contract is the initial numbered baseline. This entry does
not assert that a Git tag or published release already exists. Earlier acceptance
records remain dated evidence, not a new qualification of this baseline.
