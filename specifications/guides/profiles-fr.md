# Choisir un profil de certificat

La [spécification cryptographique](../04-cryptography-and-profiles.md), en anglais,
définit les extensions exactes, les alias, la compatibilité des clés et les SAN.
Ce guide décrit leur utilisation, sans dupliquer la politique normative.

Créer d’abord la racine et les intermédiaires nécessaires, puis par exemple :

```sh
make server CN=app.example.test KEY_ALG=EC SAN_DNS=app.example.test,api.example.test
make user CN=user@example.test KEY_ALG=Ed25519
make code CN="Signing Key" KEY_ALG=EC
make email CN=user@example.test SMIME_MODE=sign KEY_ALG=EC
make email CN=encrypt@example.test SMIME_MODE=encrypt KEY_ALG=RSA
make archive CN="Document Seal" ARCHIVE_MODE=seal KEY_ALG=EC
make archive CN="Timestamp Signer" ARCHIVE_MODE=timestamp KEY_ALG=EC
```

Les profils serveur/client suivent la clé réellement utilisée, y compris une clé
réutilisée. Le chiffrement et le profil S/MIME combiné exigent RSA. `code`/`dev`
et `archive`/`doc` sont des alias. PROFILE choisit une section installée explicite ;
EXT_SECTION est prioritaire. Une combinaison incompatible est refusée. Une liste
SAN ou SAN_* explicite supprime l’ajout implicite du CN. Protéger les arguments
dans le shell : le CN reste une donnée, pas du code à évaluer.

Les fragments de `profiles/` servent uniquement aux nouvelles configurations.
Pour modifier une autorité existante, conserver sa configuration, examiner les
extensions souhaitées puis modifier explicitement son openssl.cnf installé.
Ne pas remplacer les personnalisations par un nouveau modèle sans examen.
La validation structurelle suivante ne constitue pas une approbation de politique.
Les instantanés par certificat conservent la configuration réellement utilisée.
