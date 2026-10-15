# Certnify — Production Quickstart

[Français](QUICKSTART-fr.md)

This guide explains how to install Certnify in an **isolated production
workspace**, without a Git repository, so that confidential PKI data cannot
accidentally be synchronized to GitHub.

## Principle

Certnify has two distinct parts:

- **Source code** (`bin/`, `profiles/`, `Makefile`) — versioned in Git,
  contains no sensitive data.
- **PKI workspace** (`root/`, `intm-*/`, private keys, certificates) —
  confidential data that must never end up in a Git repository.

The safest approach is to install the source code into a dedicated production
directory **without initializing a Git repository**. PKI data lives in that
directory and can neither be committed nor pushed.

## Initial installation

### 1. Create the production directory

```sh
mkdir -p ~/PKI/my-organisation
```

### 2. Export the source code without the Git history

```sh
git -C ~/Dev/Certnify archive --format=tar HEAD | \
  tar -x -C ~/PKI/my-organisation/
```

`git archive` exports only the source files tracked by Git. PKI data, the Git
history and the `.git/` directory are not included.

### 3. Verify that there is no Git repository

```sh
ls -la ~/PKI/my-organisation/
# → bin/, profiles/, Makefile, README*.md … but NO .git/
```

The production workspace has no GitHub remote. It cannot be accidentally
synchronized there.

## Normal use

Work from the production workspace exactly as described in the
[README](README.md):

```sh
cd ~/PKI/my-organisation

make root       CN="My Root CA"
make int-web    CN="Web Issuing CA"
make server     CN="app.example.com"  SAN_DNS="app.example.com"
make verify     KIND=web CN="app.example.com"
make crl-root
make crl        KIND=web
```

Authorities, private keys and certificates are generated in this directory.
See the [README](README.md) for the full command reference.

## Updating the source code

When a new Certnify release is available, update only the source files
**without touching the existing PKI data**:

```sh
# Update the source repository
cd ~/Dev/Certnify
git pull

# Export only the source files into the production workspace
git archive --format=tar HEAD bin profiles Makefile | \
  tar -x -C ~/PKI/my-organisation/
```

`tar -x` replaces the source files (`bin/`, `profiles/`, `Makefile`) but does
not touch the PKI directories (`root/`, `intm-*/`) because Git does not know
about them — they are not included in the exported archive.

## Backup

The production workspace contains the authority private keys. It must be backed
up regularly. A cloud sync agent (iCloud, Dropbox, etc.) must **not** write to
the active PKI workspace: concurrent writes are explicitly refused by the
toolkit.

Use an offline encrypted backup (Time Machine, `rsync` to an encrypted volume,
etc.).

## Moving the workspace

Generated configurations contain absolute paths. After moving the production
directory, rebind the configurations with:

```sh
cd /new/path/my-organisation
RECOVERY_ACTION=relocate bin/recovery.sh                       # preview
RECOVERY_ACTION=relocate RELOCATE_APPLY=1 bin/recovery.sh     # apply
```

Resolve any pending operation before moving the workspace.
See the [recovery guide](specifications/guides/recovery-en.md).
