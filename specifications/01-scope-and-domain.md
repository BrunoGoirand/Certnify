# 01 — Scope and domain

## Purpose

Certnify creates and operates a private PKI with a self-signed root, root-signed intermediate authorities, and intermediate-signed end-entity certificates. Its operator is a local administrator or an automation process with filesystem access to CA keys and state. Authorization is inherited from that filesystem access; there are no application accounts or roles.

The toolkit supports TLS servers, client authentication, code signing, S/MIME signing/encryption, document sealing, and certificates suitable for timestamp signing. It issues credentials for those uses; it does not itself sign software or documents, encrypt mail, serve TLS, or implement a timestamp service.

## Domain entities

| Entity | Identity and responsibilities |
| --- | --- |
| Workspace | One physical project root; contains one root authority and zero or more intermediate directories |
| Authority | Key pair, CA certificate, configuration, issuance database, next certificate serial, next CRL number |
| Intermediate kind | Routing label: `web`, `auth`, `code`, `smime`, `archive`; custom kinds are possible |
| Authority generation | A specific CA certificate and key, distinct from the active directory name |
| Certificate | Issuer-scoped serial, subject, public key, validity interval, extensions, signature |
| Request | Subject, public key and requested extensions in a PKCS#10 CSR |
| Issuance record | Status, expiry, revocation data, serial, certificate locator, subject |
| Profile | Named extension policy applied at signing |
| CRL | Signed revocation list belonging to one issuing authority, with update times and CRL number |
| Inventory | TSV selection of issuance records used as batch input |
| Pending operation | Recovery journal recording an uncertain or unfinished issuance/directory transition |
| Disabled marker | Local policy switch preventing ordinary issuance from an intermediate |

A CN is a subject attribute, not a globally unique certificate identity or a general-purpose filename. New artifact names follow the mapping in chapter 03. Serial numbers are unique within an issuer database, not across the workspace. Two intermediates can issue serial `1000` independently. A kind is a routing convention, not a cryptographic restriction: all standard leaf profiles are present in every generated intermediate configuration.

## State model

An authority is absent, initialized incompletely, active, locally disabled, or represented by a legacy directory. Separately, its CA certificate can be valid, expired, or revoked by its parent. These dimensions must not be collapsed into one status.

An OpenSSL issuance row uses `V` (valid record), `R` (revoked), or `E` (expired record). A row still marked `V` may already be past its validity time until database maintenance runs. Revocation remains a property of a particular certificate even after a new certificate with the same subject is issued.

Root creation is idempotent for a matching subject and key. Intermediate generation may skip, renew, or rekey. Leaf generation normally rejects an already active CN instead of returning the prior certificate. Rollover preserves an entire directory and creates a new active authority; in-place intermediate renewal preserves the same leaf database. Rollback changes directory roles and does not undo revocation.

## Operational boundaries

### Exclusive ownership of operational PKI state

All writes to operational PKI state MUST go through supported Certnify operations,
including the OpenSSL subprocesses they control. This covers keys, certificates,
installed authority configuration, indexes, counters, CRLs, metadata, history,
aliases, locks and recovery journals. Direct OpenSSL administration, manual file
edits and third-party scripts writing that state are unsupported, even when no
toolkit command is running. Editing source templates for future authorities is
distinct from modifying installed authority state.

Deployment MUST exclude external writers: other accounts and applications must
not have write access, and synchronization agents must not restore, merge or
replace files in the live PKI. Publication hooks may read/export final artifacts
but MUST NOT modify local PKI state. Backups must use a consistent offline copy
or a qualified snapshot; restoration and exceptional repair require a separately
documented offline maintenance procedure before toolkit use resumes. Such
maintenance is not a supported alternative write interface.

This is a required operating contract, not a protection currently enforced against
all processes. The shell toolkit inherits the invoking account's privileges;
its lock cannot exclude another process with the same filesystem permissions.
Enforcement requires OS access isolation, typically a dedicated account and a
controlled command entry point without arbitrary write or shell access. A missing
supported maintenance command requires an explicit toolkit extension, not routine
manual editing. See chapter 08 for reliability and chapter 09 for residual limits.

No automatic renewal scheduler, ACME enrollment, external CSR enrollment command, OCSP responder, trust-store installation, public CA integration, HSM interface, encrypted-key password workflow, PKCS#12 export, certificate-transparency integration, remote repository, or backup service is implemented. There is no runtime package installation or implicit network access in ordinary CA operations.

Publication exists only as an explicit administrator-supplied shell command for final CRL artifacts. Root rollover is not implemented. The hierarchy is normally root → intermediate → leaf; intermediate profiles prohibit subordinate CAs through `pathlen:0`.

The current implementation requires Bash, Make for its public facade, OpenSSL accepted by the shared version check, Python 3.8+ for durability barriers, and ordinary Unix text/file tools. Durability primitives support macOS and Linux on a single local filesystem; storage qualification remains separate. Bash 3.2 portability is an implementation goal visible in the code, not a claim that every command has been tested on every platform.
