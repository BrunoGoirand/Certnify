# Named PKI workspaces

[Français](guides/named-pki-fr.md)

Sources and profiles belong to CERTNIFY_SOURCE_DIR, computed from the installed
scripts. ROOT_DIR is the selected operational workspace, never a caller override.
The public PKI=certnify-<slug> selector chooses a sibling of the source base when
its physical directory name is `.certnify`, and a direct child otherwise.
For example, `PKI/.certnify` uses `PKI/certnify-main-holding` for new state.
Existing nested workspaces remain accessible without moving them. If the selected
name exists both inside and beside `.certnify`, resolution refuses the ambiguity,
including files and dangling symlinks. No automatic migration is performed.
Without PKI, named directories in either location prevent legacy fallback.
The engine validates names (ASCII lowercase alphanumeric groups separated by
hyphens, at most 80 characters including the prefix), rejects symlink/non-directory
workspaces and confines authority paths to that selected workspace.

Use `make pki-name CN="Personal Root"` to obtain the identifier
`certnify-personal-root`. Naming belongs to the engine: Unicode NFKD, combining
mark removal, ASCII lowercase and hyphen-separated non-alphanumeric runs. The CN
itself is preserved. Empty/overlong derived identifiers are refused. An explicit
valid identifier may be chosen for names without an ASCII representation.

Only root creation may create a missing workspace. Subsequent operations require
it to exist. Existing root creation retains the existing identity/idempotency
contract; the skill's first-root workflow additionally refuses name collisions.
No implicit workspace selection or migration is provided. Without PKI, legacy
state in the source base remains supported only if no named workspace is present.

All PKI state, including counters, index, keys, CRLs, issuer bindings, exports,
locks, recovery journals and durability fences, is inside the selected workspace.
Shared source/profile lookup never follows ROOT_DIR. Relative authority paths
are relative to the selected workspace. A peer's absolute paths are refused.
Commands continue to run from the source base, with the same explicit PKI value:

```sh
make root PKI=certnify-personal-root CN="Personal Root"
make int-web PKI=certnify-personal-root CN="Personal Web"
make server PKI=certnify-personal-root CN=app.test SAN_DNS=app.test
```

Catalogued capability `named-pki-v1` is declared by capabilities.json, which is
included in source-manifest archives. Old releases must not be assumed to support
it. Source archive creation never includes named PKI data. Upgrades and migration
are separate workflows. Concurrency is serialized within each PKI, not globally;
source updates must not run concurrently with PKI operations.

Validation: test/named-pki.py uses manifest-only disposable workspaces. It covers
two independent hierarchies, verification/revocation, independent guards, rejected
selectors and peer paths, and naming. This does not establish storage power-loss
or assistant behavioral qualification.

## Read-only resolver and mixed layouts

`make pki-info PKI=certnify-personal-root` returns schema-versioned JSON with
source_base, selector, workspace, exists, layout and guard presence. It performs
no bootstrap, lock acquisition or mutation. The shared resolver also controls
engine bootstrap and transaction admission; clients must use its returned paths.
Named mode refuses legacy state in the source base (root, intermediate, intm-*,
pki-data, out, .locks or .recovery). This prevents silently stranding an existing
legacy installation. Migration remains a separate operation.
