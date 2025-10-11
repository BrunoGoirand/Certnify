# Certnify - PKI Toolkit

![CertnifyLogo](image/Certnify.png)

Licensed under the MIT License.
© 2025 Bruno Goirand — PKI Toolkit.

## Overview

PKI toolkit for generating a root CA, specialized intermediates (web, auth, code, smime, archive), and issuing/verifying/revoking certificates.

## 🚀 Quick Start — PKI Toolkit

Follow these simple steps to generate a complete certificate chain using PKI Toolkit.
Each command below automatically handles directory structure, OpenSSL configuration, and file naming.

### 🏗️ 1. Create the Root Certificate Authority

The **Root CA** is the trust anchor for your PKI.
It signs intermediate certificates but never issues end-entity certificates directly.

```bash
# root certificate creation
make root CN="Root CA"
```

📁 The Root CA will be created in the `root/` directory:

- Certificate: `root/certs/ca.cert.pem`
- Private key: `root/private/ca.key.pem`

**Tip:** The root key should always remain offline and secured.

### 🪜 2. Create the Intermediate Certificate (Web CA)

The Intermediate CA signs all certificates for web servers.
This separation ensures better security and revocation control.

```bash
# intermediate certificate creation
make int-web CN="Web Issuing CA"
```

📁 The intermediate will be stored in:

```text
intm-web-ca/
├── certs/
├── crl/
├── csr/
├── newcerts/
└── private/
```

- Certificate: `intm-web-ca/certs/ca.cert.pem`
- Private key: `intm-web-ca/private/ca.key.pem`
- Chain file (Root + Intermediate): `intm-web-ca/certs/chain.cert.pem`

**Tip:** You can create other intermediates for different purposes (e.g. int-auth, int-code, int-smime, int-archive).

### 🌐 3. Issue a Server Certificate

Generate a server certificate signed by your web intermediate CA:

```bash
# server certificate creation
make server CN="app.example.com"
```

📁 The resulting files are stored in `intm-web-ca/certs/`:

| File | Description |
| :- | :- |
| app.example.com.cert.pem | Server certificate |
| app.example.com.fullchain.cert.pem | Certificate + chain (recommended for web servers) |
| intm-web-ca/private/app.example.com.key.pem | Private key (keep secret) |

**Example use:**
In Nginx or Apache, configure your HTTPS server with:

```nginx
ssl_certificate     app.example.com.fullchain.cert.pem;
ssl_certificate_key intm-web-ca/private/app.example.com.key.pem;
```

DONE !

## 🧭 Next Steps

Once your basic PKI is operational, you can extend and maintain it using the following features of PKI Toolkit.

### 🏷️ 1. Create Additional Intermediate CAs

You can easily generate other specialized intermediate authorities for different usages — keeping your trust chain modular and secure.

```bash
# Examples of additional intermediate CAs
make int-auth    CN="Auth Issuing CA"      # For user/client authentication
make int-code    CN="Code Signing CA"      # For code or software signing
make int-smime   CN="S/MIME Issuing CA"    # For email encryption/signing
make int-archive CN="Archive CA"           # For long-term archival certificates
```

Each intermediate follows the same structure as `intm-web-ca/`.

### 👤 2. Issue User or Client Certificates

For authentication or S/MIME, issue end-entity certificates from the appropriate intermediate:

```bash
# Example: user/client certificate
make user CN="john@example.com"
```

📁 Files will be generated under `intm-auth-ca/certs/`:

- `john@example.com.cert.pem`
- `john@example.com.fullchain.cert.pem`
- Private key in `intm-auth-ca/private/`

### 🚫 3. Revoke Certificates and Update CRLs

To maintain certificate integrity, revoke compromised or obsolete certificates and update the Certificate Revocation Lists (CRL).

```bash
# Revoke a certificate by its name
make revoke KIND="auth" CN="john@example.com" REASON="keyCompromise"

# Regenerate CRLs (root + intermediate)
make crl-all
```

📁 The CRL files are located in:

`root/crl/ca.crl.pem`
`intm-web-ca/crl/ca.crl.pem`

**Tip:** Always publish your CRL or OCSP endpoint to allow clients to verify revocation status.

### 🏁 You’re all set

Your PKI is now ready for real-world usage — from HTTPS servers to identity-based authentication.
Use make help anytime to explore all available commands and advanced options.

---
