# Certnify

![Certnify logo](image/Certnify.png)

Toolkit PKI basé sur `OpenSSL` pour créer une autorité racine, des AC intermédiaires spécialisées, puis émettre, vérifier, révoquer et faire évoluer des certificats pour plusieurs usages métier.

Licensed under the MIT License.  
© 2025 Bruno Goirand

## Pourquoi Certnify ?

Certnify sert à monter une PKI locale, lisible et scriptable, sans devoir recoder à la main les mêmes opérations OpenSSL à chaque fois.

Le projet prend en charge :

- une autorité racine (`root`)
- des intermédiaires spécialisés : `web`, `auth`, `code`, `smime`, `archive`
- l'émission de certificats finaux : serveur, utilisateur, signature de code, S/MIME, archivage, horodatage
- la vérification de chaîne et de révocation
- la génération et la publication de CRL
- la révocation d'un certificat leaf ou d'un intermédiaire
- le rollover, le rollback et la réémission en lot de certificats
- des profils OpenSSL versionnés sous `profiles/`

Les fragments de configuration OpenSSL sont stockés dans `profiles/` et assemblés automatiquement dans les `openssl.cnf` générés pour la racine et les intermédiaires.

## Points forts

- Interface simple via `make`
- Layout PKI homogène et reproductible
- Support de `RSA`, `EC`, `Ed25519` et `Ed448`
- SAN gérés proprement (`SAN_DNS`, `SAN_IP`, `SAN_EMAIL`, `SAN_URI`)
- Garde-fous contre l'émission sur intermédiaire révoqué ou désactivé
- Refus des doublons actifs par `CN` sauf override explicite
- Modes dédiés pour S/MIME et archivage
- Smoke test de bout en bout inclus

## Prérequis

- `bash`
- `make`
- `openssl` 1.1.1 ou 3.x
- Outils Unix usuels : `awk`, `sed`, `grep`, `mktemp`, `install`, `date`

`LibreSSL` n'est pas supporté.

## Quick Start

Le scénario ci-dessous crée une chaîne complète minimale : une racine, un intermédiaire Web, puis un certificat serveur exploitable immédiatement.

### 1. Créer la racine

```bash
make root CN="Certnify Root CA"
```

Fichiers principaux :

- `root/certs/ca.cert.pem`
- `root/private/ca.key.pem`
- `root/openssl.cnf`

### 2. Créer un intermédiaire Web

```bash
make int-web CN="Certnify Web Issuing CA"
```

Fichiers principaux :

- `intm-web-ca/certs/ca.cert.pem`
- `intm-web-ca/private/ca.key.pem`
- `intm-web-ca/certs/chain.cert.pem`

### 3. Émettre un certificat serveur

```bash
make server CN="app.example.com" SAN_DNS="app.example.com"
```

Artefacts générés :

- `intm-web-ca/certs/app.example.com.cert.pem`
- `intm-web-ca/certs/app.example.com.fullchain.cert.pem`
- `intm-web-ca/private/app.example.com.key.pem`

### 4. Vérifier le certificat

```bash
make verify KIND=web CN="app.example.com"
```

Avec contrôle CRL :

```bash
make crl-root
make crl KIND=web
make verify KIND=web CN="app.example.com" VERIFY_CRL=1
```

### 5. Révoquer si nécessaire

```bash
make revoke KIND=web CN="app.example.com" REASON="keyCompromise"
```

En pratique, un premier cycle de travail ressemble souvent à ceci :

```bash
make root CN="Demo Root CA"
make int-web CN="Demo Web CA"
make server CN="app.example.test" SAN_DNS="app.example.test"
make verify KIND=web CN="app.example.test"
```

## Architecture générée

Chaque AC utilise une arborescence OpenSSL classique.

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

Convention par défaut :

- `root/` pour la racine
- `intm-<kind>-ca/` pour les intermédiaires
- `certs/<CN>.cert.pem` pour les certificats
- `private/<CN>.key.pem` pour les clés privées

## Référence rapide des commandes

### Aide et inspection

```bash
make help
make tree
make ls-web
make ls-auth
make ls-code
make ls-smime
make ls-archive
```

### Création des autorités

Racine :

```bash
make root CN="Root CA" [DAYS=7300]
```

Intermédiaire générique :

```bash
make intermediate KIND=web CN="Web Issuing CA" [DAYS=3650]
```

Raccourcis :

```bash
make int-web
make int-auth
make int-code
make int-smime
make int-archive
```

### Émission de certificats finaux

Mapping automatique par cible :

- `server` -> `KIND=web` -> `intm-web-ca`
- `user` -> `KIND=auth` -> `intm-auth-ca`
- `dev` -> `KIND=code` -> `intm-code-ca`
- `email` -> `KIND=smime` -> `intm-smime-ca`
- `doc` -> `KIND=archive` -> `intm-archive-ca`

Commandes canoniques :

```bash
make server  CN="app.example.com"     [SAN_DNS="app.example.com"] [DAYS=397]
make user    CN="john@example.com"    [SAN_EMAIL="john@example.com"] [DAYS=825]
make dev     CN="CI Signing Key"      [DAYS=730]
make email   CN="john@example.com"    [SAN_EMAIL="john@example.com"] [DAYS=730]
make doc     CN="Records Seal"        [DAYS=3650]
```

Alias de compatibilité :

```bash
make code CN="Build Signing Key"
make archive CN="Archive Seal"
```

Overrides possibles :

```bash
make server KIND=web CN="api.example.com"
make user INT_DIR="intm-customers-ca" CN="alice@example.com"
```

### Vérification

Par fichier :

```bash
make verify FILE="intm-web-ca/certs/app.example.com.cert.pem"
```

Par `CN` :

```bash
make verify KIND=web CN="app.example.com"
make verify INT_DIR="intm-smime-ca" CN="john@example.com"
```

Options utiles :

- `VERIFY_CRL=1` active la vérification CRL
- `VERIFY_MODE=normal|tolerate_revoked|info` ajuste le code de sortie

### Révocation d'un certificat leaf

Par `CN` :

```bash
make revoke KIND=web CN="app.example.com" REASON="keyCompromise"
```

Par fichier :

```bash
make revoke FILE="intm-web-ca/certs/app.example.com.cert.pem" REASON="superseded"
```

Par numéro de série :

```bash
make revoke INT_DIR="intm-web-ca" SERIAL="1002" REASON="cessationOfOperation"
```

Raisons supportées :

- `unspecified`
- `keyCompromise`
- `CACompromise`
- `affiliationChanged`
- `superseded`
- `cessationOfOperation`
- `certificateHold`
- `removeFromCRL`
- `AACompromise`

### Gestion des CRL

```bash
make crl-root
make crl KIND=web
make crl-show KIND=web
make crl-all
```

Variables utiles :

- `CRL_DAYS=7`
- `CRL_INT_DIR=...`
- `INT_DIR=...`
- `KIND=...`

### Révocation d'un intermédiaire

Révoquer uniquement l'intermédiaire dans la base de la racine :

```bash
make revoke-intermediate KIND=web REASON="keyCompromise"
```

Révoquer l'intermédiaire et tous les leafs encore valides :

```bash
make revoke-intm-and-leafs KIND=web REASON="cessationOfOperation"
```

Contrôler l'état depuis la CRL racine :

```bash
make verify-intermediate-revoked KIND=web
make show-intermediate-serial KIND=web
make crl-root-revoked KIND=web
```

### Rollover, rollback et réémission

Créer un nouvel intermédiaire actif en préservant l'ancien en `legacy` :

```bash
make rollover-web INT_CN="Web CA v2"
```

Lister les certificats émis par un intermédiaire :

```bash
make list-leafs-web
```

Réémettre en lot à partir du TSV généré :

```bash
make reissue-leafs-web
```

Revenir vers un intermédiaire legacy :

```bash
make rollback-web
```

### Qualité et nettoyage

```bash
make test-smoke
make clean
```

`make clean` supprime `root`, tous les `intm-*` et `out` : à utiliser avec prudence.

## Variables importantes

Variables DN :

- `CN`
- `C`
- `O`
- `OU`

Variables crypto :

- `KEY_ALG=RSA|EC|EdDSA|Ed25519|Ed448`
- `KEY_SIZE=4096` pour RSA
- `KEY_CURVE=prime256v1|secp384r1` pour EC
- `KEY_EDDSA=Ed25519|Ed448`

Variables SAN :

- `SAN_DNS`
- `SAN_IP`
- `SAN_EMAIL`
- `SAN_URI`

Autres variables utiles :

- `DAYS`
- `INT_DIR`
- `KIND`
- `PROFILE`
- `ROOT_PATHLEN`
- `ROOT_CNF`
- `OPENSSL`
- `FORCE_NEW_KEY=0|1|rotate`
- `QUIET_OPENSSL=0|1`

## Profils supportés

### CA

- `v3_ca` pour la racine
- `v3_intermediate_ca` pour les intermédiaires

### Certificats serveur

- `server_cert` : profil historique RSA
- `server_ec` : profil recommandé pour EC / EdDSA

### Certificats client

- `client_cert` : profil historique RSA
- `client_ec` : profil recommandé pour EC / EdDSA
- `usr_cert` : alias legacy

### Signature de code

- `code_sign`

### S/MIME

- `smime` : profil legacy combiné
- `smime_sign` : signature
- `smime_encrypt` : chiffrement

Sélection :

```bash
make email CN="john@example.com"
make email CN="john@example.com" SMIME_MODE=sign
make email CN="john@example.com" SMIME_MODE=encrypt
```

### Archivage et horodatage

- `archive` : profil legacy
- `archive_seal` : scellement documentaire
- `timestamping` : horodatage

Sélection :

```bash
make doc CN="Records Seal"
make doc CN="Records Seal" ARCHIVE_MODE=seal
make doc CN="Time Stamp Authority" ARCHIVE_MODE=timestamp
```

## Exemples concrets

### Certificat serveur TLS en EC

```bash
make server \
  CN="api.example.com" \
  KEY_ALG="EC" \
  KEY_CURVE="secp384r1" \
  SAN_DNS="api.example.com" \
  SAN_URI="spiffe://certnify/api"
```

### Certificat utilisateur

```bash
make user \
  CN="john@example.com" \
  SAN_EMAIL="john@example.com"
```

### Certificat de signature de code

```bash
make dev \
  CN="Release Signing Key" \
  KEY_ALG="Ed25519"
```

### Horodatage

```bash
make doc \
  CN="Internal TSA" \
  ARCHIVE_MODE=timestamp
```

## Comportements utiles à connaître

- L'émission des leafs est bloquée si l'intermédiaire ciblé est révoqué ou marqué désactivé.
- Le toolkit refuse par défaut d'émettre un second certificat actif pour le même `CN`.
- Les SAN sont injectés dans la CSR puis recopiés à la signature.
- Les noms de fichiers suivent le `CN`, avec sanitation automatique quand nécessaire.
- `INT_DIR` est prioritaire sur `KIND` lorsqu'ils sont tous les deux fournis.

## Documentation associée

- [doc/shell-fr.md](doc/shell-fr.md)
- [doc/profiles-fr.md](doc/profiles-fr.md)

## Test rapide du toolkit

Le projet embarque un smoke test de bout en bout :

```bash
make test-smoke
```

Il couvre notamment :

- la création racine et intermédiaires
- l'émission de certificats avec plusieurs profils
- la vérification
- la révocation
- les modes `timestamp`, `encrypt`, `EC` et `Ed25519`

---
