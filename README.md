# Certnify

![Certnify logo](image/Certnify.png)

An `OpenSSL`-based PKI toolkit for creating a root CA, specialized intermediate CAs, and then issuing, verifying, revoking, and evolving certificates for several real-world use cases.

Licensed under the MIT License.  
© 2025 Bruno Goirand

## Why Certnify?

Certnify helps you build a local PKI that stays readable, scriptable, and repeatable, without having to handcraft the same OpenSSL operations again and again.

The project covers:

- a root certificate authority (`root`)
- specialized intermediate CAs: `web`, `auth`, `code`, `smime`, `archive`
- end-entity certificate issuance for servers, users, code signing, S/MIME, archiving, and timestamping
- chain and revocation verification
- CRL generation and publication
- revocation of a leaf certificate or an intermediate CA
- rollover, rollback, and batch re-issuance workflows
- versioned OpenSSL profiles under `profiles/`

OpenSSL configuration fragments are stored in `profiles/` and automatically assembled into the generated `openssl.cnf` files for the root and intermediate authorities.

## Highlights

- Simple `make`-based interface
- Consistent and reproducible PKI layout
- Support for `RSA`, `EC`, `Ed25519`, and `Ed448`
- Clean SAN handling with `SAN_DNS`, `SAN_IP`, `SAN_EMAIL`, and `SAN_URI`
- Safety checks that block issuance from revoked or disabled intermediates
- Duplicate active certificates for the same `CN` are refused by default unless explicitly overridden
- Dedicated modes for S/MIME and archival use cases
- End-to-end smoke test included

## Requirements

- `bash`
- `make`
- `openssl` 1.1.1 or 3.x
- Common Unix tools: `awk`, `sed`, `grep`, `mktemp`, `install`, `date`

`LibreSSL` is not supported.

## Quick Start

The flow below creates a minimal but complete chain: one root CA, one Web intermediate CA, and one server certificate ready to use.

### 1. Create the root CA

```bash
make root CN="Certnify Root CA"
```

Main files:

- `root/certs/ca.cert.pem`
- `root/private/ca.key.pem`
- `root/openssl.cnf`

### 2. Create a Web intermediate CA

```bash
make int-web CN="Certnify Web Issuing CA"
```

Main files:

- `intm-web-ca/certs/ca.cert.pem`
- `intm-web-ca/private/ca.key.pem`
- `intm-web-ca/certs/chain.cert.pem`

### 3. Issue a server certificate

```bash
make server CN="app.example.com" SAN_DNS="app.example.com"
```

Generated artifacts:

- `intm-web-ca/certs/app.example.com.cert.pem`
- `intm-web-ca/certs/app.example.com.fullchain.cert.pem`
- `intm-web-ca/private/app.example.com.key.pem`

### 4. Verify the certificate

```bash
make verify KIND=web CN="app.example.com"
```

With CRL checking:

```bash
make crl-root
make crl KIND=web
make verify KIND=web CN="app.example.com" VERIFY_CRL=1
```

### 5. Revoke it if needed

```bash
make revoke KIND=web CN="app.example.com" REASON="keyCompromise"
```

In practice, a first working cycle often looks like this:

```bash
make root CN="Demo Root CA"
make int-web CN="Demo Web CA"
make server CN="app.example.test" SAN_DNS="app.example.test"
make verify KIND=web CN="app.example.test"
```

## Generated Layout

Each CA uses a classic OpenSSL-style directory structure.

```text
root/
  certs/
  crl/
  csr/
  newcerts/
  private/

intm-web-ca/
  certs/
  crl/
  csr/
  newcerts/
  private/
```

Default conventions:

- `root/` for the root CA
- `intm-<kind>-ca/` for intermediate CAs
- `certs/<CN>.cert.pem` for certificates
- `private/<CN>.key.pem` for private keys

## Command Reference

### Help and inspection

```bash
make help
make tree
make ls-web
make ls-auth
make ls-code
make ls-smime
make ls-archive
```

### Create certificate authorities

Root CA:

```bash
make root CN="Root CA" [DAYS=7300]
```

Generic intermediate:

```bash
make intermediate KIND=web CN="Web Issuing CA" [DAYS=3650]
```

Shortcuts:

```bash
make int-web
make int-auth
make int-code
make int-smime
make int-archive
```

### Issue end-entity certificates

Automatic target mapping:

- `server` -> `KIND=web` -> `intm-web-ca`
- `user` -> `KIND=auth` -> `intm-auth-ca`
- `dev` -> `KIND=code` -> `intm-code-ca`
- `email` -> `KIND=smime` -> `intm-smime-ca`
- `doc` -> `KIND=archive` -> `intm-archive-ca`

Canonical commands:

```bash
make server  CN="app.example.com"     [SAN_DNS="app.example.com"] [DAYS=397]
make user    CN="john@example.com"    [SAN_EMAIL="john@example.com"] [DAYS=825]
make dev     CN="CI Signing Key"      [DAYS=730]
make email   CN="john@example.com"    [SAN_EMAIL="john@example.com"] [DAYS=730]
make doc     CN="Records Seal"        [DAYS=3650]
```

Compatibility aliases:

```bash
make code CN="Build Signing Key"
make archive CN="Archive Seal"
```

Possible overrides:

```bash
make server KIND=web CN="api.example.com"
make user INT_DIR="intm-customers-ca" CN="alice@example.com"
```

### Verification

By file:

```bash
make verify FILE="intm-web-ca/certs/app.example.com.cert.pem"
```

By `CN`:

```bash
make verify KIND=web CN="app.example.com"
make verify INT_DIR="intm-smime-ca" CN="john@example.com"
```

Useful options:

- `VERIFY_CRL=1` enables CRL verification
- `VERIFY_MODE=normal|tolerate_revoked|info` controls the exit code behavior

### Revoke a leaf certificate

By `CN`:

```bash
make revoke KIND=web CN="app.example.com" REASON="keyCompromise"
```

By file:

```bash
make revoke FILE="intm-web-ca/certs/app.example.com.cert.pem" REASON="superseded"
```

By serial number:

```bash
make revoke INT_DIR="intm-web-ca" SERIAL="1002" REASON="cessationOfOperation"
```

Supported reasons:

- `unspecified`
- `keyCompromise`
- `CACompromise`
- `affiliationChanged`
- `superseded`
- `cessationOfOperation`
- `certificateHold`
- `removeFromCRL`
- `AACompromise`

### Manage CRLs

```bash
make crl-root
make crl KIND=web
make crl-show KIND=web
make crl-all
```

Useful variables:

- `CRL_DAYS=7`
- `CRL_INT_DIR=...`
- `INT_DIR=...`
- `KIND=...`

### Revoke an intermediate CA

Revoke only the intermediate in the root CA database:

```bash
make revoke-intermediate KIND=web REASON="keyCompromise"
```

Revoke the intermediate and all still-valid leaf certificates it issued:

```bash
make revoke-intm-and-leafs KIND=web REASON="cessationOfOperation"
```

Check its status from the root CRL:

```bash
make verify-intermediate-revoked KIND=web
make show-intermediate-serial KIND=web
make crl-root-revoked KIND=web
```

### Rollover, rollback, and re-issuance

Create a new active intermediate while preserving the previous one as `legacy`:

```bash
make rollover-web INT_CN="Web CA v2"
```

List certificates issued by an intermediate:

```bash
make list-leafs-web
```

Batch re-issue from the generated TSV:

```bash
make reissue-leafs-web
```

Switch back to a legacy intermediate:

```bash
make rollback-web
```

### Quality and cleanup

```bash
make test-smoke
make clean
```

`make clean` removes `root`, all `intm-*` directories, and `out`, so it should be used carefully.

## Important Variables

DN variables:

- `CN`
- `C`
- `O`
- `OU`

Crypto variables:

- `KEY_ALG=RSA|EC|EdDSA|Ed25519|Ed448`
- `KEY_SIZE=4096` for RSA
- `KEY_CURVE=prime256v1|secp384r1` for EC
- `KEY_EDDSA=Ed25519|Ed448`

SAN variables:

- `SAN_DNS`
- `SAN_IP`
- `SAN_EMAIL`
- `SAN_URI`

Other useful variables:

- `DAYS`
- `INT_DIR`
- `KIND`
- `PROFILE`
- `ROOT_PATHLEN`
- `ROOT_CNF`
- `OPENSSL`
- `FORCE_NEW_KEY=0|1|rotate`
- `QUIET_OPENSSL=0|1`

## Supported Profiles

### CA profiles

- `v3_ca` for the root CA
- `v3_intermediate_ca` for intermediate CAs

### Server certificates

- `server_cert`: legacy RSA profile
- `server_ec`: recommended profile for EC / EdDSA

### Client certificates

- `client_cert`: legacy RSA profile
- `client_ec`: recommended profile for EC / EdDSA
- `usr_cert`: legacy alias

### Code signing

- `code_sign`

### S/MIME

- `smime`: combined legacy profile
- `smime_sign`: signing
- `smime_encrypt`: encryption

Selection:

```bash
make email CN="john@example.com"
make email CN="john@example.com" SMIME_MODE=sign
make email CN="john@example.com" SMIME_MODE=encrypt
```

### Archival and timestamping

- `archive`: legacy profile
- `archive_seal`: document sealing
- `timestamping`: timestamping

Selection:

```bash
make doc CN="Records Seal"
make doc CN="Records Seal" ARCHIVE_MODE=seal
make doc CN="Time Stamp Authority" ARCHIVE_MODE=timestamp
```

## Practical Examples

### EC TLS server certificate

```bash
make server \
  CN="api.example.com" \
  KEY_ALG="EC" \
  KEY_CURVE="secp384r1" \
  SAN_DNS="api.example.com" \
  SAN_URI="spiffe://certnify/api"
```

### User certificate

```bash
make user \
  CN="john@example.com" \
  SAN_EMAIL="john@example.com"
```

### Code-signing certificate

```bash
make dev \
  CN="Release Signing Key" \
  KEY_ALG="Ed25519"
```

### Timestamping

```bash
make doc \
  CN="Internal TSA" \
  ARCHIVE_MODE=timestamp
```

## Useful Behavior to Know

- Leaf issuance is blocked if the targeted intermediate is revoked or marked as disabled.
- By default, the toolkit refuses to issue a second active certificate for the same `CN`.
- SANs are injected into the CSR and copied into the final certificate.
- File names follow the `CN`, with automatic sanitization when needed.
- `INT_DIR` takes priority over `KIND` when both are provided.

## Related Documentation

- [doc/shell-en.md](doc/shell-en.md)
- [doc/profiles-en.md](doc/profiles-en.md)

## Quick Toolkit Test

The project includes an end-to-end smoke test:

```bash
make test-smoke
```

It notably covers:

- root and intermediate creation
- certificate issuance across multiple profiles
- verification
- revocation
- `timestamp`, `encrypt`, `EC`, and `Ed25519` modes

---
