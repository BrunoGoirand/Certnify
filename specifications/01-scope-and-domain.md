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

No automatic renewal scheduler, ACME enrollment, external CSR enrollment command, OCSP responder, trust-store installation, public CA integration, HSM interface, encrypted-key password workflow, PKCS#12 export, certificate-transparency integration, remote repository, or backup service is implemented. There is no runtime package installation or implicit network access in ordinary CA operations.

Publication exists only as an explicit administrator-supplied shell command for final CRL artifacts. Root rollover is not implemented. The hierarchy is normally root → intermediate → leaf; intermediate profiles prohibit subordinate CAs through `pathlen:0`.

The current shell implementation requires Bash, Make for its public facade, OpenSSL accepted by the shared version check, and ordinary Unix text/file tools. Bash 3.2 portability is an implementation goal visible in the code, not a claim that every command has been tested on every platform.
