# Scripts Shell

Ce document récapitule les scripts du répertoire `bin/`, leur rôle principal et leurs dépendances les plus visibles.

## Vue d'ensemble

| Script | Description | Dépendances principales |
| --- | --- | --- |
| `bin/pki-env.sh` | Bibliothèque shell partagée du projet : helpers de log, validation, verrous, résolution `INT_DIR`/`KIND`, contrôles OpenSSL, génération de métadonnées et fonctions utilitaires communes. | `openssl`, `awk`, `sed`, `grep`, `mktemp`, `install`, `date`, `tr`, `wc`, shell Bash |
| `bin/gen-root.sh` | Génère ou régénère l'autorité racine, son arborescence, sa clé privée, son certificat et ses métadonnées. | `bin/pki-env.sh`, `openssl`, `awk`, `sed`, `mktemp`, `date` |
| `bin/gen-intm.sh` | Génère ou réémet une AC intermédiaire (`intm-<kind>-ca`), avec gestion de rotation de clé, chaîne, métadonnées et garde-fous de réémission. | `bin/pki-env.sh`, `openssl`, `awk`, `sed`, `mktemp`, `install`, `cp`, `mv`, `rm`, `date` |
| `bin/gen-leaf.sh` | Script cœur pour émettre les certificats finaux (`server`, `user`, `dev`, `email`, `doc`) avec SAN, profils OpenSSL, rotation de clé et contrôles d'état de l'intermédiaire. | `bin/pki-env.sh`, `openssl`, `awk`, `sed`, `grep`, `mktemp`, `install`, `cp`, `mv`, `rm`, `date` |
| `bin/gen-server.sh` | Wrapper pour émettre un certificat serveur en déléguant à `gen-leaf.sh` avec `ACTION=server`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-user.sh` | Wrapper pour émettre un certificat utilisateur/client en déléguant à `gen-leaf.sh` avec `ACTION=user`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-code.sh` | Wrapper pour émettre un certificat de signature de code en déléguant à `gen-leaf.sh` avec `ACTION=dev`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-email.sh` | Wrapper pour émettre un certificat S/MIME en déléguant à `gen-leaf.sh` avec `ACTION=email`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/gen-archive.sh` | Wrapper pour émettre un certificat d'archivage/document en déléguant à `gen-leaf.sh` avec `ACTION=doc`. | `bin/pki-env.sh`, `bin/gen-leaf.sh` |
| `bin/verify.sh` | Vérifie un certificat leaf contre la racine et un intermédiaire, avec option de contrôle CRL et différents modes de sortie. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `sed` |
| `bin/revoke-leaf.sh` | Révoque un certificat final unique à partir d'un `FILE`, d'un `SERIAL` ou d'un `CN`, puis regénère la CRL intermédiaire si demandé. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `sed`, `mktemp`, `install`, `rm` |
| `bin/revoke-intm.sh` | Révoque une AC intermédiaire dans la base de la racine, pose un flag `.disabled` et peut republier la CRL racine. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `mktemp`, `install`, `rm` |
| `bin/revoke-intm-and-leafs.sh` | Révoque une AC intermédiaire puis révoque en lot tous les certificats finaux qu'elle a émis, avec mise à jour optionnelle des CRL racine et intermédiaire. | `bin/pki-env.sh`, `openssl`, `awk`, `grep`, `mktemp`, `install`, `rm` |
| `bin/intm-rollover.sh` | Effectue un rollover d'intermédiaire sans symlink : archive l'ancien dossier actif, recrée un nouvel intermédiaire actif et génère sa chaîne. | `bin/pki-env.sh`, `openssl`, `mv`, `cat`, `date` |
| `bin/intm-rollback-to-legacy.sh` | Restaure un intermédiaire `legacy` comme intermédiaire actif et sauvegarde au passage l'actif courant avant rollback. | `bin/pki-env.sh`, `mv`, `cat`, `sort`, `head`, `sed`, `date` |
| `bin/list-leafs-by-issuer.sh` | Extrait depuis `index.txt` la liste des leafs émis par un intermédiaire actif ou `legacy`, et produit un TSV exploitable pour une réémission batch. | `bin/pki-env.sh`, `awk`, `sort`, `head`, `sed`, `grep`, `mkdir` |
| `bin/intm-reissue-leafs.sh` | Réémet en lot les leafs listés dans un fichier TSV, en appelant automatiquement les wrappers adaptés selon le `KIND`. | `bin/pki-env.sh`, `bash`, `sort`, `head`, wrappers `gen-*` |
| `bin/intm-publish-final-crl.sh` | Génère une CRL finale d'intermédiaire, produit PEM/DER/empreintes SHA256 et peut publier les artefacts via une commande externe. | `bin/pki-env.sh`, `openssl`, `sed`, `awk`, `date`, `ln`, `bash` |

## Notes

- Les scripts `gen-server.sh`, `gen-user.sh`, `gen-code.sh`, `gen-email.sh` et `gen-archive.sh` sont des wrappers légers autour de `gen-leaf.sh`.
- Presque tous les scripts s'appuient sur `bin/pki-env.sh`, qui joue le rôle de socle commun du toolkit.
- La dépendance externe structurante du projet est `OpenSSL` (1.1.1 ou 3.x, LibreSSL refusé par `pki-env.sh`).
- Les dépendances listées ici sont les principales dépendances visibles dans les scripts ; elles ne prétendent pas être une matrice exhaustive commande par commande.
