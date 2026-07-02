# Profils OpenSSL

Ce document décrit les fragments OpenSSL stockés dans `profiles/`, leur intention métier, les principales extensions X.509 qu'ils posent, et la manière de les sélectionner depuis les commandes `make`.

## Vue d'ensemble

Les scripts du toolkit génèrent toujours un `openssl.cnf` final par autorité (`root/openssl.cnf`, `intm-*/openssl.cnf`), mais les sections d'extensions ne sont plus codées en dur dans le shell. Elles proviennent maintenant de fragments versionnés sous `profiles/`.

La composition se fait dans `bin/pki-env.sh` :

- `profiles/root/base.cnf` pour la racine
- `profiles/intermediate/base.cnf` pour les AC intermédiaires
- `profiles/leaf/*.cnf` pour les certificats finaux

Cette séparation permet :

- de relire les profils sans parcourir la logique Bash ;
- de faire évoluer les usages métier indépendamment du layout CA ;
- de garder les alias historiques tout en introduisant des profils plus explicites.

## Profils CA

### `v3_ca`

Source : `profiles/root/base.cnf`

Usage :

- certificat de racine auto-signé ;
- extensions CA de base pour l'ancre de confiance.

Extensions principales :

- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid:always,issuer`
- `basicConstraints = critical, CA:true[, pathlen:N]`
- `keyUsage = critical, keyCertSign, cRLSign`

Note :

- la valeur exacte de `basicConstraints` est injectée dynamiquement par les scripts selon `ROOT_PATHLEN`.

### `v3_intermediate_ca`

Sources :

- `profiles/root/base.cnf`
- `profiles/intermediate/base.cnf`

Usage :

- certificat d'AC intermédiaire signé par la racine.

Extensions principales :

- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid:always,issuer`
- `basicConstraints = critical, CA:true, pathlen:0`
- `keyUsage = critical, keyCertSign, cRLSign`

## Profils leaf

### Serveur TLS

#### `server_cert`

Source : `profiles/leaf/server-rsa.cnf`

Usage :

- profil historique pour serveur TLS ;
- pensée principalement pour des clés RSA.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `nsCertType = server`
- `nsComment = "OpenSSL Generated Server Certificate"`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = serverAuth`

#### `server_rsa`

Source logique :

- alias reconstruit automatiquement à partir de `server_cert`.

Usage :

- nom plus explicite pour serveur TLS RSA ;
- même contenu que `server_cert`.

#### `server_ec`

Source : `profiles/leaf/server-ec.cnf`

Usage :

- serveur TLS avec clé EC ou EdDSA.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = serverAuth`

Sélection :

- `make server` choisit automatiquement `server_ec` si `KEY_ALG=EC|EdDSA|Ed25519|Ed448` ;
- sinon, le flux legacy reste sur `server_cert`.

### Client / authentification utilisateur

#### `client_cert`

Source : `profiles/leaf/client-rsa.cnf`

Usage :

- profil historique pour authentification client ;
- pensé principalement pour des clés RSA.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = clientAuth`

#### `client_rsa`

Source logique :

- alias reconstruit automatiquement à partir de `client_cert`.

Usage :

- variante explicite du profil client RSA.

#### `usr_cert`

Source logique :

- alias legacy reconstruit automatiquement à partir de `client_cert`.

Usage :

- compatibilité avec certains anciens appels OpenSSL / scripts.

#### `client_ec`

Source : `profiles/leaf/client-ec.cnf`

Usage :

- authentification client avec clé EC ou EdDSA.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = clientAuth`

Sélection :

- `make user` choisit automatiquement `client_ec` si `KEY_ALG=EC|EdDSA|Ed25519|Ed448` ;
- sinon, le flux legacy reste sur `client_cert`.

### Signature de code

#### `code_sign`

Source : `profiles/leaf/code-sign.cnf`

Usage :

- signature de code, binaires, artefacts de build.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = codeSigning`

### S/MIME

#### `smime`

Source : `profiles/leaf/smime-legacy.cnf`

Usage :

- profil legacy combiné ;
- couvre à la fois signature et chiffrement au sens historique du toolkit.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, keyEncipherment`
- `extendedKeyUsage = emailProtection`

#### `smime_sign`

Source : `profiles/leaf/smime-sign.cnf`

Usage :

- signature S/MIME dédiée.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`
- `extendedKeyUsage = emailProtection`

#### `smime_encrypt`

Source : `profiles/leaf/smime-encrypt.cnf`

Usage :

- chiffrement S/MIME dédié.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, keyEncipherment`
- `extendedKeyUsage = emailProtection`

Sélection :

- `make email` : profil legacy `smime`
- `make email SMIME_MODE=sign` : profil `smime_sign`
- `make email SMIME_MODE=encrypt` : profil `smime_encrypt`

### Archivage / document / scellement

#### `archive`

Source : `profiles/leaf/archive-legacy.cnf`

Usage :

- profil legacy historique pour document / archive.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`

#### `archive_seal`

Source : `profiles/leaf/archive-seal.cnf`

Usage :

- profil plus explicite pour un scellement documentaire ou d'archive.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature`

#### `timestamping`

Source : `profiles/leaf/timestamping.cnf`

Usage :

- jeton ou autorité d'horodatage (TSA-like) ;
- plus spécialisé que le profil `archive`.

Extensions principales :

- `basicConstraints = critical, CA:false`
- `subjectKeyIdentifier = hash`
- `authorityKeyIdentifier = keyid,issuer`
- `keyUsage = critical, digitalSignature, nonRepudiation`
- `extendedKeyUsage = critical, timeStamping`

Sélection :

- `make doc` : profil legacy `archive`
- `make archive` : profil legacy `archive`
- `make doc ARCHIVE_MODE=seal` : profil `archive_seal`
- `make archive ARCHIVE_MODE=seal` : profil `archive_seal`
- `make doc ARCHIVE_MODE=timestamp` : profil `timestamping`
- `make archive ARCHIVE_MODE=timestamp` : profil `timestamping`

## SAN et comportement d'émission

Le script `bin/gen-leaf.sh` construit à la volée une section `[ req_ext ]` quand des SAN sont fournis.

Types supportés :

- `SAN_DNS`
- `SAN_IP`
- `SAN_EMAIL`
- `SAN_URI`

Le profil intermédiaire active `copy_extensions = copy`, ce qui permet de recopier les SAN de la CSR dans le certificat final.

## Compatibilité et alias

Le toolkit conserve plusieurs alias historiques pour ne pas casser les appels existants :

- `server_cert`
- `client_cert`
- `usr_cert`
- `smime`
- `archive`

Certains alias sont désormais reconstruits automatiquement lors de la génération du `openssl.cnf` final, afin d'éviter de dupliquer plusieurs fois le même bloc d'extensions.

## Recommandations pratiques

- Utiliser `server_ec` / `client_ec` dès qu'on émet avec des clés EC ou EdDSA.
- Garder `smime` et `archive` uniquement si l'on veut préserver un comportement legacy.
- Préférer `smime_sign`, `smime_encrypt`, `archive_seal` et `timestamping` pour les usages métier plus précis.
- Considérer ce répertoire `profiles/` comme la source de vérité pour la politique X.509 du projet.
