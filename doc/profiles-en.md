# OpenSSL Profiles

This document describes the OpenSSL fragments stored under `profiles/`, their intended purpose, the main X.509 extensions they define, and how to select them from the `make` commands.

## Overview

The toolkit scripts still generate a final `openssl.cnf` per authority (`root/openssl.cnf`, `intm-*/openssl.cnf`), but the extension sections are no longer hardcoded inside the shell scripts. They now come from versioned fragments stored under `profiles/`.

Composition happens in `bin/pki-env.sh`:

- `profiles/root/base.cnf` for the root CA
- `profiles/intermediate/base.cnf` for intermediate CAs
- `profiles/leaf/*.cnf` for end-entity certificates

This separation makes it possible to:

- review profiles without digging through Bash logic;
- evolve certificate policy independently from CA layout code;
- keep legacy aliases while introducing clearer profiles.

## CA Profiles

### `v3_ca`

Source: `profiles/root/base.cnf`

Usage:

- self-signed root certificate;
- base CA extensions for the trust anchor.

Main extensions:

- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid:always,issuer`
- `basicConstraints = critical, CA:true[, pathlen:N]`
- `keyUsage = critical, keyCertSign, cRLSign`

Note:

- the exact `basicConstraints` value is injected dynamically by the scripts according to `ROOT_PATHLEN`.

### `v3_intermediate_ca`

Sources:

- `profiles/root/base.cnf`
- `profiles/intermediate/base.cnf`

Usage:

- intermediate CA certificate signed by the root.

Main extensions:

- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid:always,issuer`
- `basicConstraints = critical, CA:true, pathlen:0`
- `keyUsage = critical, keyCertSign, cRLSign`

## Leaf Profiles

### TLS Server

#### `server_cert`

Source: `profiles/leaf/server-rsa.cnf`

Usage:

- historical TLS server profile;
- primarily designed for RSA keys.

Main extensions:

- `basicConstraints = critical, CA:false`
- `nsCertType = server`
- `nsComment = "OpenSSL Generated Server Certificate"`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = serverAuth`

#### `server_rsa`

Logical source:

- alias automatically reconstructed from `server_cert`.

Usage:

- clearer name for the RSA TLS server profile;
- same content as `server_cert`.

#### `server_ec`

Source: `profiles/leaf/server-ec.cnf`

Usage:

- TLS server with EC or EdDSA key.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = serverAuth`

Selection:

- `make server` automatically selects `server_ec` when `KEY_ALG=EC|EdDSA|Ed25519|Ed448`;
- otherwise the legacy flow stays on `server_cert`.

### Client / User Authentication

#### `client_cert`

Source: `profiles/leaf/client-rsa.cnf`

Usage:

- historical client authentication profile;
- primarily designed for RSA keys.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = clientAuth`

#### `client_rsa`

Logical source:

- alias automatically reconstructed from `client_cert`.

Usage:

- explicit RSA client profile variant.

#### `usr_cert`

Logical source:

- legacy alias automatically reconstructed from `client_cert`.

Usage:

- compatibility with older OpenSSL conventions and legacy scripts.

#### `client_ec`

Source: `profiles/leaf/client-ec.cnf`

Usage:

- client authentication with EC or EdDSA key.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = clientAuth`

Selection:

- `make user` automatically selects `client_ec` when `KEY_ALG=EC|EdDSA|Ed25519|Ed448`;
- otherwise the legacy flow stays on `client_cert`.

### Code Signing

#### `code_sign`

Source: `profiles/leaf/code-sign.cnf`

Usage:

- code signing, binaries, build artifacts.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = codeSigning`

### S/MIME

#### `smime`

Source: `profiles/leaf/smime-legacy.cnf`

Usage:

- combined legacy profile;
- covers both signing and encryption in the historical toolkit behavior.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = emailProtection`

#### `smime_sign`

Source: `profiles/leaf/smime-sign.cnf`

Usage:

- dedicated S/MIME signing profile.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = emailProtection`

#### `smime_encrypt`

Source: `profiles/leaf/smime-encrypt.cnf`

Usage:

- dedicated S/MIME encryption profile.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, keyEncipherment`
- `extendedKeyUsage = emailProtection`

Selection:

- `make email`: legacy `smime` profile
- `make email SMIME_MODE=sign`: `smime_sign` profile
- `make email SMIME_MODE=encrypt`: `smime_encrypt` profile

### Archive / Document / Sealing

#### `archive`

Source: `profiles/leaf/archive-legacy.cnf`

Usage:

- historical legacy profile for document / archive certificates.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`

#### `archive_seal`

Source: `profiles/leaf/archive-seal.cnf`

Usage:

- clearer profile for document or archive sealing.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`

#### `timestamping`

Source: `profiles/leaf/timestamping.cnf`

Usage:

- timestamp token or TSA-like authority;
- more specialized than the `archive` profile.

Main extensions:

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, nonRepudiation`
- `extendedKeyUsage = critical, timeStamping`

Selection:

- `make doc`: legacy `archive` profile
- `make doc ARCHIVE_MODE=seal`: `archive_seal` profile
- `make doc ARCHIVE_MODE=timestamp`: `timestamping` profile

## SANs and Issuance Behavior

`bin/gen-leaf.sh` builds a transient `[ req_ext ]` section whenever SAN values are provided.

Supported SAN types:

- `SAN_DNS`
- `SAN_IP`
- `SAN_EMAIL`
- `SAN_URI`

The intermediate profile enables `copy_extensions = copy`, allowing SANs from the CSR to be copied into the issued certificate.

## Compatibility and Aliases

The toolkit keeps several historical aliases to avoid breaking existing calls:

- `server_cert`
- `client_cert`
- `usr_cert`
- `smime`
- `archive`

Some aliases are now reconstructed automatically while generating the final `openssl.cnf`, in order to avoid storing the same extension block multiple times.

## Practical Recommendations

- Use `server_ec` / `client_ec` whenever issuing certificates with EC or EdDSA keys.
- Keep `smime` and `archive` only when you want to preserve legacy behavior.
- Prefer `smime_sign`, `smime_encrypt`, `archive_seal`, and `timestamping` for more explicit business-oriented use cases.
- Treat the `profiles/` directory as the source of truth for the project's X.509 policy.
