# 03 — Persistence and artifacts

## Workspace layout

```text
workspace/
  profiles/                       profile templates, including root/base.cnf
  .locks/root-ca.lock/pid         workspace lock ownership hint
  .recovery/power-loss            durable in-flight command fence (JSON)
  .recovery/power-loss-error      persistence-error latch, when writable
  .recovery/power-loss-reviewed-<id>  explicit review receipt
  .recovery/pending/              interrupted-operation journal
  .recovery/reviewed-<id>/         acknowledged recovery record
  .recovery/completed-<id>/        verified installation receipt (private artifacts)
  root/
    openssl.cnf
    ca.meta
    index.txt
    index.txt.attr                 managed by OpenSSL when applicable
    serial
    crlnumber
    private/ca.key.pem
    certs/ca.cert.pem
    newcerts/<SERIAL>.pem          root-issued intermediates
    crl/ca.crl.pem
  intm-<kind>-ca/
    openssl.cnf
    ca.meta                       effective artifact metadata
    serial.last                   current intermediate certificate serial
    index.txt
    serial                        next leaf serial
    crlnumber
    .disabled                     optional local issuance guard
    private/ca.key.pem
    csr/ca.csr.pem
    certs/ca.cert.pem
    certs/ca.chain.cert.pem
    certs/chain.cert.pem           symlink to ca.chain.cert.pem
    private/<basename>.key.pem
    csr/<basename>.csr.pem
    certs/<basename>.cert.pem
    certs/<basename>.fullchain.cert.pem
    newcerts/<SERIAL>.pem
    crl/ca.crl.pem
    generations/<id>/ca.cert.pem
    generations/<id>/ca.key.pem
    generations/<id>/ca.crl.pem    when historical CRL generated
    issuers/<serial>              leaf-to-issuer binding
    issuers/<serial>.policy       effective leaf policy reference
    policies/<sha256>.cnf         exact issuance configuration snapshot
    names/<stem>.cn               exact normalized CN
    reissues/<id>                 batch receipt
  intm-<kind>-ca-legacy-<timestamp>/
  intm-<kind>-ca-pre-rollback-<timestamp>/
  out/<kind>-leafs[-<timestamp>].tsv
```

The root layout helper does not create a CSR directory. OpenSSL may create backup files such as `index.txt.old`, `serial.old`, or attribute files; these are backend state, not substitute authoritative records.

## Encoding, ordering and permissions

Keys are unencrypted PEM private keys; requests are PEM PKCS#10; certificates are
PEM X.509. Consumers parse certificates rather than compare PEM text bytes.
Intermediate chains contain intermediate then root; the relative compatibility
alias `certs/chain.cert.pem` points to `ca.chain.cert.pem`. Leaf fullchains contain
leaf then issuer intermediate, without the root. Keys and CSRs are separate files.

The implementation uses umask 077. Root and leaf keys normally have mode 0600,
intermediate/generation keys 0400, and installed certificates, chains, metadata,
CRLs, policy snapshots and name/binding records 0444. Leaf key backups use 0600.
Existing permissions are not comprehensively repaired; read-only modes are not
immutability. Replacement and interruption behavior is specified in chapter 08.

## CN identity versus artifact filename

CN is certificate identity, not shell/configuration source. Make exports identity
and SAN values as data instead of interpolating them into recipe shell source;
DN rendering quotes and escapes OpenSSL configuration metacharacters. Callers must
still quote arguments in their own shell.

Common ASCII names beginning with a letter/digit and containing letters, digits,
spaces, dot, underscore, @, + or - retain their filenames, except reserved names.
Other CNs use `cn-<SHA256 of normalized UTF-8 CN>` as their artifact stem. Reserved
patterns are ca, ca.*, ca-*, chain, chain.*, cn-*, srl-* and rot-*, plus names
ending in .fullchain; they use the hashed form too (case-insensitive matching). This prevents CNs such
as ca or chain from replacing authority artifacts, and avoids lossy replacement
collisions such as A/B versus A_B.

`names/<stem>.cn` contains the exact normalized CN and is read-only after creation.
A conflicting mapping is rejected, including aliases of the same filename on a
case-insensitive filesystem. Existing named certificates are checked against
index identity before first claiming their name. An existing key without a
certificate has no embedded CN; reuse remains an operator-supplied association.

A later certificate for an occupied stem uses `srl-<serial>-<stem>`. Forced rotate
uses a temporary rot- namespace and ends with that same serial namespace. Existing
serial destinations are not overwritten. FORCE_NEW_KEY=1 also retains a complete
serial-named key/CSR/certificate/fullchain set, then replaces the conventional
paths after verification; an existing private key is backed up. Key/CSR/certificate suffix conventions
otherwise remain unchanged. No existing artifact is renamed just by lookup.

Verification by CN now uses exact index selection (one active match, otherwise
one unambiguous historical match), as revocation already did. Archived serial
certificates support legacy raw names, including names that cannot safely appear
in new filenames. Ambiguous names require explicit SERIAL/FILE targeting as
applicable. FILE containment rules remain unchanged. Spaces and @ in ordinary
legacy filenames are preserved, not converted to underscores.

Intermediate serial archives use `certs/ca-<SERIAL>.cert.pem` and
`certs/ca-<SERIAL>.chain.cert.pem`. Replacement key backups use
`private/ca.key.<YYYYMMDD-HHMMSS>.<pid>.bak`; leaf forced-key backups use
`private/<stem>.key.<YYYYMMDDHHMMSS>.<pid>.bak.pem`. Generation-ID archives provide
the durable logical issuer association; backup basenames alone do not bind leaves.
Metadata is refreshed, not an immutable per-generation audit record.

## OpenSSL database contract

`index.txt` is a tab-delimited file without a header. Preserve empty fields.

| Position | Field | Meaning |
| --- | --- | --- |
| 1 | status | V, R, or E |
| 2 | expiry | OpenSSL ASN.1 time text, ordinarily YYMMDDHHMMSSZ |
| 3 | revocation | Empty until revoked; backend timestamp with optional comma-separated reason data |
| 4 | serial | Hexadecimal issuer-scoped serial |
| 5 | filename | Relative certificate path or literal `unknown` |
| 6 | subject | OpenSSL slash-form DN |

For example, the following notation represents one valid row (the empty revocation field is significant):

```text
V<TAB>270919120000Z<TAB><TAB>1000<TAB>newcerts/1000.pem<TAB>/CN=app.example.test
```

Root rows track intermediate certificates; intermediate rows track leaves. After issuance, helpers replace `unknown` with `newcerts/<SERIAL>.pem` for the new `V` row. After revocation, helpers set the filename of the `R` row to `unknown`; the archived PEM remains available under `newcerts`.

`serial` and `crlnumber` start with the text `1000`, interpreted as hexadecimal (4096), only if absent. `serial` is the next issuance number, whereas `serial.last` is the active intermediate certificate's root-issued serial. These must never be confused. Root self-signing does not consume a normal `openssl ca` issuance row.

## Index validation

An index row has exactly six tab-separated fields, including the empty revocation
field of V/E rows. Empty lines and lines beginning with `#` are ignored. CRLF is
accepted. Other control characters, malformed fields, unknown statuses, invalid
dates, duplicate numeric serials, empty certificate locators, and subjects without
exactly one nonempty CN are rejected. Validation is completed before emitting any
selected records. Diagnostics identify the input and line.

Subjects use OpenSSL's slash-form representation. Escaped slash, plus, equals,
backslash, and `\xHH` bytes are decoded; commas within slash-form values are
literal. UTF-8 bytes are retained without Unicode normalization or case folding.
Multiple CN attributes, malformed/trailing escapes, and decoded control bytes
are rejected instead of guessing a subject. RFC2253/comma-form names are not an
alternative index input format.

Expiry and revocation timestamps accept UTCTime (`YYMMDDHHMMSSZ`, 00–49 means
2000–2049 and 50–99 means 1950–1999) and GeneralizedTime (`YYYYMMDDHHMMSSZ`).
Calendar validation includes leap years and time ranges. Exported expiry is
`YYYY-MM-DDTHH:MM:SSZ`. Active means status V **and** expiry strictly after now.

## Serial repair

The toolkit's checked serial range is unsigned 64-bit hexadecimal, consistent
with the existing leaf issuance limit. Arithmetic compares strings and propagates
hexadecimal carries, so values above signed 64-bit or floating-point precision
boundaries remain exact. Larger numeric values and exhausted history fail before
updating the counter. No truncation or removal of non-hexadecimal characters is
performed. Leading zeros and letter case do not change serial identity.

Missing index.txt, serial or crlnumber on an existing authority fails without
recreating state. Only an absent or empty authority directory initializes counters
to 1000. A missing policy on an authority with key/certificate material requires
explicit restoration. Numeric serial collisions with retained newcerts, issuer
bindings/policy receipts or serial-named leaf certificates fail before issuance,
including differences in hexadecimal case or leading zero padding. A valid existing
counter above the index maximum is retained, including its spelling. Otherwise
the counter advances to maximum+1, with an even number of hexadecimal digits for
OpenSSL. The replacement is staged beside the counter. Validation failures leave
the index and counter unchanged. Existing history and certificates are never
rewritten, and an abnormally high counter is never lowered automatically.

Intermediate generation validates both issuer and local histories/counters before
rekeying, and repairs the root counter before signing. Leaf issuance validates
before expiry maintenance/key generation and repairs its counter before signing.
The workspace lock serializes counter validation and signing (chapter 08).

## CN and serial selection

Duplicate detection compares the decoded CN literally, within one authority,
using the active definition above. Regex metacharacters are data: `a.b` and `axb`
are different identities. ALLOW_DUPLICATE_CN retains its explicit bypass.

Revocation precedence remains FILE > SERIAL > CN. SERIAL compares hexadecimal
values, then uses the original indexed spelling to locate the archived PEM.
An explicit unresolved SERIAL fails; it never falls through to CN.

For CN selection, choose exactly one active exact match. Multiple active matches
fail and list candidate serials. If none is active, select only when exactly one
historical exact match exists; this allows a single expired certificate or an
already-revoked no-op. Multiple historical matches fail with serial guidance.
There is no fallback to an unchecked canonical CN filename. Missing indexed
artifacts fail with guidance to select FILE explicitly.

Use explicit FILE or SERIAL, where supported, to select among ambiguous
certificate generations. Verification accepts FILE or CN; revocation also accepts
SERIAL. Missing history is not permission to select a different issuer.

## Generation identity and historical leaves

A generation ID is the lowercase SHA-256 digest of its CA certificate DER.
`generations/<id>/ca.cert.pem` and `ca.key.pem` retain the matching public
certificate and private key, with modes 0444 and 0400. Treat generation backups
as private CA material. Archive creation verifies key/certificate correspondence.

`issuers/<leaf-serial>` contains two newline-terminated values: the issuer
generation ID and the SHA-256 digest of the leaf DER. New issuance records this
binding. Before renewal/rekey or lifecycle moves, existing index records must
have archived leaf certificates; unbound leaves are matched cryptographically
against known issuer certificates. Exactly one distinct certificate must qualify.
Missing or ambiguous history is rejected, including same-key renewals whose
unbound leaves cannot distinguish issuer certificates. Existing bindings are
validated, not silently reassigned.

Verification uses the retained issuer certificate and the workspace root.
Revocation uses that generation's matching key with the authority's preserved
index and monotonically advancing serial/CRL counters. Historical CRLs are stored
at `generations/<id>/ca.crl.pem`; the current generation retains `crl/ca.crl.pem`.
`ISSUER_ID=<id> bin/crl.sh generate` with INT_DIR selects a historical CRL signer.
Missing historical certificates prevent verification; missing historical keys
prevent revocation/CRL signing. Restoring a directory does not undo root revocation
or remove an existing disable marker. Strict CRL coverage and outcome classification are defined in chapter 06.

## CA metadata

`ca.meta` is UTF-8 KEY=value text. Split at the first equals sign; never source
or execute it. It describes observed artifacts; certificates and keys remain
authoritative. Root issuer fields equal its own identity. Metadata is refreshed
on successful generation/no-op and may change independently of certificate bytes.

| Field | Meaning |
| --- | --- |
| CREATED_AT | Metadata write time, UTC YYYY-MM-DDTHH:MM:SSZ |
| OPENSSL_VERSION | Configured backend version |
| DN, ISSUER_DN | RFC2253 certificate subject/issuer |
| ALG | Actual inspected key algorithm |
| KEY_SIZE, KEY_CURVE, KEY_EDDSA | Applicable actual key parameters |
| REQUESTED_DAYS | Requested lifetime; not measured certificate lifetime |
| notBefore, notAfter | Actual certificate validity, OpenSSL date text |
| PATHLEN | Actual certificate basicConstraints limit; absent if unconstrained |
| SERIAL, ISSUER_SERIAL | Uppercase hexadecimal certificate serials |
| SPKI_SHA256 | Base64 SHA-256 of DER SubjectPublicKeyInfo |
| POLICY_SHA256 | Hash of installed authority configuration at metadata write time |
| INT_DIR, KIND | Optional intermediate directory/routing values |

POLICY_SHA256 does not establish the historical policy that signed a reused CA
certificate. Legacy metadata with DAYS or incomplete fields can be imported as
informational data; recover effective values from the key/certificate. Old `meta`
and regular chain layouts are accepted during normalization; the old metadata
file is retained. Lifecycle moves update directory metadata and current policy
hash after validated rebinding.

## Inventory compatibility

The export remains four columns without a header: serial, ISO UTC expiry, CN,
and index certificate locator. It validates the complete index before replacing
an output file. With OUT=-, stdout contains TSV only; diagnostic logs use stderr.
Successful empty or explicit-directory listings return zero.

Batch import requires exactly four columns. COL_SERIAL, COL_EXPIRES, and COL_CN
must be distinct positions from 1 through 4. The selected fields must contain a
valid serial, ISO UTC timestamp, and nonempty CN. Other fields may be empty and
remain in their original positions. Blank lines are ignored; malformed nonblank
rows fail the whole input **before any batch command executes**. The validated
selection is retained in a temporary snapshot for iteration, including a final
line without a newline. No escaping/version change is introduced into the TSV;
tabs/newlines/control bytes within fields are unsupported and rejected.

The locator column retains the indexed spelling, including `unknown`.
Four columns do not encode full subject/SAN/profile/key policy; batch migration
semantics and receipts are defined in chapter 07.

## Generated configuration contract

Both configurations define `[ca] default_ca=CA_default` and a CA_default section pointing to the authority's certs, crl, database, newcerts, certificate, serial, crlnumber, private key, and private/.rand. Defaults include SHA-256, seven CRL days, the creation-time DAYS value, `preserve=no`, `unique_subject=no`, and backend name/certificate display options `ca_default`. The intermediate adds `copy_extensions=copy`; the root does not.

Request settings use default_bits=4096, string_mask=utf8only, default_md=sha256, prompt=no, and a request DN section with replaceable C/O/OU/CN placeholders. x509_extensions points to v3_ca for the root and v3_intermediate_ca for intermediates. The policy sections require CN and permit optional country/state/locality/organization/organizational unit. The current DN injection drops empty C/O/OU lines; it does not expose state/locality inputs.

The root composer appends root/base.cnf and substitutes its root basic-constraints placeholder. The intermediate composer appends its CA fragment, server RSA/EC, client RSA/EC, code signing, S/MIME legacy/sign/encrypt, archive legacy/seal, and timestamping fragments, adding the aliases specified in document 04. A fully imported configuration can contain custom sections; PROFILE/EXT_SECTION selects a section by name and the backend ultimately validates it.

## Final CRL resume state

Each newly generated final PEM has a local `<version>.crl.pem.resume-state` file,
installed with mode 0444. It contains LF-terminated `SCHEMA=1`, `PEM_SHA256`,
`REVOKED_SHA256` and `NEXT_CRL_NUMBER` fields. The first digest hashes the PEM
bytes; the second hashes index R rows, in index order, with only tab-separated
status, expiry, revocation data and serial fields followed by LF. The counter is
read after generation. This local retry guard is distinct from the public DER
hash sidecars and is not among the six remotely published artifacts. It is not
tamper-proof against an administrator with write access. Missing or mismatched
state requires fresh CRL generation; never reconstruct it to authorize an old CRL.
