# 04 — Cryptography and profiles

## Backend and keys

The shared library accepts version strings matching OpenSSL 1.1.1 (including letter suffixes) or OpenSSL 3.x and rejects LibreSSL. This specifies the existing executable gate, not a claim about vendor support lifetimes.

RSA uses `genpkey -algorithm RSA` and a configurable bit count, default 4096 and minimum 2048 bits. The minimum also applies to reused keys. Issuance and ordinary chain verification explicitly use OpenSSL authentication level 2. EC uses named parameters with prime256v1, secp384r1, or secp521r1 only. EdDSA uses Ed25519 or Ed448; an explicit variant in `KEY_ALG` overrides `KEY_EDDSA`. No passphrase is requested and no key encryption is configured.

SHA-256 is the configured digest for RSA/EC requests and signatures. The root generator omits its explicit digest switch when the actual reused/generated key is EdDSA. Other paths still pass SHA-256 options; algorithm/backend combinations need explicit interoperability tests. The signature algorithm is determined by the signing authority's key, not the leaf public-key type.

A replacement must use a maintained cryptographic library or backend for key generation, randomness, ASN.1, signatures, and validation. It must not implement cryptographic primitives from these workflow descriptions.

## Subjects

CN is mandatory after defaults; C, O, and OU are optional. Trim surrounding whitespace; reject control characters and consecutive ASCII spaces in CN/O/OU; enforce `DN_MAXLEN` bytes, default 128, per field. C must be exactly two uppercase ASCII letters when present; there is no membership lookup against an actual country list.

The generated request DN section is ordered C, O, OU, CN, omitting empty optional entries. Subject bytes must be valid UTF-8 (checked with iconv). Requests explicitly use -utf8 as well as UTF-8-only string masking. Canonical comparison renders CN, OU, O, C in RFC2253 order with escaping for backslash, comma, plus, quote, angle brackets, semicolon, leading hash, and boundary spaces. Equals signs remain literal inside values. Comparisons use RFC2253 with UTF-8 output and without high-byte escaping on both sides. No Unicode normalization or case folding is applied.

The root's `policy_strict` and intermediate's `policy_loose` both require commonName and treat country, state, locality, organization, and organizational unit as optional. The root policy name does not imply that organization/country must match the issuer.

## Exact extension matrix

All leaf profiles have critical `basicConstraints = CA:false`, noncritical `subjectKeyIdentifier = hash`, and noncritical `authorityKeyIdentifier = keyid,issuer`. Their key usage is critical. EKU is noncritical unless noted. “Absent” means omit the extension, not an empty extension.

| Profile | Key usage | Extended key usage | Additional extensions |
| --- | --- | --- | --- |
| server_cert / server_rsa | digitalSignature, keyEncipherment | serverAuth | nsCertType=server; nsComment="OpenSSL Generated Server Certificate" |
| server_ec | digitalSignature | serverAuth | None |
| client_cert / client_rsa / usr_cert | digitalSignature, keyEncipherment | clientAuth | None |
| client_ec | digitalSignature | clientAuth | None |
| code_sign | digitalSignature | codeSigning | None |
| smime | digitalSignature, keyEncipherment | emailProtection | None |
| smime_sign | digitalSignature | emailProtection | None |
| smime_encrypt | keyEncipherment | emailProtection | None |
| archive / archive_seal | digitalSignature | Absent | None |
| timestamping | digitalSignature, nonRepudiation | **critical**, timeStamping only | None |

Root `v3_ca`: SKI hash; AKI `keyid:always,issuer`; critical CA=true basic constraints with configurable path length; critical keyCertSign+cRLSign usage. Intermediate `v3_intermediate_ca`: same identifiers/usages, critical CA=true and pathlen=0. Neither CA profile defines EKU.

The OpenSSL `hash` SKI behavior and AKI key identifier/issuer conditional behavior should be matched through decoded extensions in cross-backend tests. SHA-256 SPKI pins used by toolkit integrity checks are separate from SKI generation.

No supplied profile defines AIA, CRL distribution points, certificate policies, name constraints, or OCSP URLs. Local CRL production does not cause remote clients to discover those CRLs automatically.

## Leaf profile compatibility

Server/client defaults depend on the key actually reused or generated. RSA uses
server_cert/client_cert; EC and both EdDSA variants use server_ec/client_ec.
Wrappers and direct gen-leaf invocation share this decision. Direct invocation
without ACTION defaults to the server profile and 397 days; it still requires
an explicit authority selector. PROFILE and EXT_SECTION are explicit overrides,
with EXT_SECTION taking precedence.

Requested profiles must describe a leaf (CA:false without CA signing usage).
keyEncipherment/dataEncipherment require RSA in the supported key set; RSA cannot
perform keyAgreement, and EdDSA cannot perform encryption or key agreement.
Therefore smime_encrypt and the legacy combined smime profile reject EC/EdDSA
keys; use a signing profile for a signing-only key. A reused EC key remains EC
when KEY_ALG=RSA is requested without forcing a new key. The profile is selected
accordingly; an explicitly incompatible profile fails before signing.

## SAN contract

An explicit nonempty SAN or SAN_* list is authoritative: no default CN SAN is
appended. When no SAN is supplied, server defaults to DNS:CN; user/email defaults
to email:CN when CN contains @. Other actions have no new default SAN.

SAN accepts comma-separated DNS:, IP:, email: and URI: entries; a bare value means
DNS. Type matching is case-insensitive. SAN and SAN_* contributions are combined
and deduplicated in order. Unknown types, empty entries, control characters and
malformed values fail rather than being silently dropped. URI values retain
colons; IPv6 is supplied unbracketed as an IP value. SAN values are quoted when
rendered into OpenSSL configuration.

The supported subset is deliberately bounded: ASCII DNS labels (punycode for
international names), optional trailing dot, and a complete leftmost wildcard;
IPv4 octets and IPv6 groups including compressed/mapped forms; a simple unquoted
email local part with a DNS domain; and an ASCII URI scheme followed by a nonempty
value without whitespace, quotes or backslashes. Commas delimit entries and must
be encoded inside URI values. This does not claim complete RFC mailbox/URI
validation or hostname authorization. Certificate extension semantics remain
subject to the selected installed profile.

## Complete and versioned configurations

New configurations are assembled in a temporary file next to their destination,
validated, then renamed into place. A missing required fragment or invalid native
basicConstraints/keyUsage cannot leave an installed partial openssl.cnf. Temporary
files are removed on normal failure. Validation checks the required sections,
CA/req policy references, path bindings, required CA defaults, and native extension
constraints. Identical repeated legacy definitions are accepted; conflicting
values are rejected. Existing configurations missing required policy sections
are rejected rather than treated as valid because a file exists.

Generated files have `CERTNIFY_POLICY_SCHEMA=1` and
`CERTNIFY_INITIAL_POLICY_SHA256` comments. The initial digest covers the assembled
bytes before these comments are appended. Existing complete unversioned native
configurations remain usable. Unknown or indirect native keyUsage declarations
require explicit migration rather than an implicit policy guess.

Changing source profile fragments affects **new configurations only**. Existing
operator configuration is retained byte-for-byte by ordinary generation. Policy
updates are an explicit operator edit: retain the previous configuration, review
the changed sections and intended extension semantics, then edit the installed
configuration. The toolkit validates it at the next operation and does not
silently replace customizations from new templates. Structural validation is not
a policy approval or exhaustive validation of arbitrary OpenSSL extension syntax;
OpenSSL still validates the actual requested CSR/certificate operation.

Each new leaf archives the exact installed configuration as
`policies/<sha256>.cnf` (0444). A conflicting existing archive fails closed.
`issuers/<serial>.policy` (0444) records SCHEMA=1, POLICY_SHA256, EXT_SECTION and
the effective ALG. These are additional files; the original two-line issuer
binding remains unchanged. Historical snapshots retain their original paths and
are evidence, not configurations to execute after a directory move. Old leaves
are not assigned invented historical policy versions. Policy/name receipts can
remain after a later failure; chapter 08 defines the recovery boundary.

## Request and validity behavior

DN/SAN values are quoted as OpenSSL configuration data. SAN extension entries
are emitted in DNS, IP, email, URI order with increasing indices. The intermediate
uses copy_extensions=copy. Before CA maintenance or key replacement, the request
and any selected profile SAN declaration are compiled into temporary CSRs with a
disposable EC key (never an authority key). Conflicting nonempty sets are rejected.
A profile-only SAN becomes the effective set when the request contains none.
Matching sets are allowed, including indirect profile SAN sections. Malformed
backend SAN syntax fails at this preflight stage.

Decoded DNS/IP/email/URI sets are compared independently of order and duplicates;
DNS case is folded and IP spellings are normalized by OpenSSL. URI and email
values retain case. Unsupported profile SAN types fail closed. Internal sections
certnify_request_san, certnify_request_names and certnify_san_check are reserved;
operator alt_names/req_ext sections cannot add names to an explicit request.
After signing, the decoded certificate SAN set must equal the effective set before
installing the certificate or a replacement key. A mismatch retains the pending
journal and committed index/history for review; it never resets the serial.
There is no domain-control proof, IDNA conversion or application authorization.
Requested lifetime is refused if it exceeds the shortest remaining lifetime in
the issuer chain. Current issuer validity and signing constraints are checked
before mutation; explicit signing dates keep the emitted notAfter within that
limit. No silent lifetime reduction is applied (chapter 05).
See chapter 10 for semantic tests rather than byte-for-byte signature comparison.
