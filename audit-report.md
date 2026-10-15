# Rapport d'audit — Certnify PKI Toolkit

**Date :** 14.10.2026  
**Périmètre :** Sécurité · Qualité de code · Architecture · Couverture de tests  
**Base analysée :** `bin/`, `profiles/`, `test/`, `Makefile`, `specifications/`  
**Plate-forme qualifiée :** macOS, Bash 3.2.57, GNU Make 3.81, OpenSSL 3.x  

---

## Résumé exécutif

Certnify est un outillage PKI Bash/Make destiné à la gestion d'autorités racine, d'intermédiaires et de feuilles. L'audit couvre l'ensemble des scripts shell, des helpers AWK/Python, des profils OpenSSL et des tests de régression.

**Conclusion générale :** La base de code est de qualité professionnelle. Aucune vulnérabilité critique n'est identifiée. Les pratiques de sécurité (protection des clés, validation des entrées, atomicité des verrous, fencing durable) sont correctement implémentées.

| Domaine | Note |
|---|---|
| Sécurité | ✅ Solide |
| Qualité de code | ✅ Solide |
| Architecture | ✅ Solide |
| Couverture de tests | ✅ Solide |

---

## 1. Sécurité

### 1.1 Validation des entrées utilisateur

✅ **Solide.** Toutes les entrées passées par l'environnement sont validées avant toute utilisation.

- `bin/pki-env.sh` lignes 343–406 : `validate_component_utf8()` rejette les caractères de contrôle, les espaces consécutifs, les dépassements de longueur (DN_MAXLEN, défaut 128), et les séquences UTF-8 invalides.
- `bin/pki-env.sh` lignes 373–383 : `validate_country_iso()` impose deux lettres ASCII uniquement.
- `bin/pki-input.sh` lignes 2–34 : toutes les entrées numériques (DAYS, KEY_SIZE, LOCK_TIMEOUT, etc.) sont validées comme entiers décimaux avec bornes.
- `bin/pki-state.sh` lignes 20–48 : `workspace_path()` rejette `$`, `"`, `#`, `\`, les caractères de contrôle et les séquences `..` dans tous les chemins.
- `bin/pki-state.sh` lignes 52–66 : `data_path()` bloque les espaces de noms réservés (`bin`, `test`, `profiles`, `.git`, `.locks`, `.recovery`, `out`).
- `bin/pki-san.awk` : validation exhaustive des formats DNS, IPv4/IPv6, email et URI (labels DNS ≤ 63 cars, longueur totale ≤ 253, pas de caractères de contrôle ni de backslash).

### 1.2 Protection des clés privées

✅ **Excellente.** Plusieurs couches de protection indépendantes.

- `bin/pki-env.sh` ligne 23 : `umask 077` positionné globalement dès le bootstrap — tous les fichiers créés héritent des permissions 600/700 sans action supplémentaire.
- `bin/pki-env.sh` lignes 500–504 : `chmod 400` appliqué explicitement après génération de clé (défense en profondeur).
- `bin/gen-leaf.sh` ligne 484 : les sauvegardes de clés sont installées en mode 600 via `staged_install`.
- `bin/pki-durable.py` lignes 39–52 : fichiers temporaires créés avec `O_CREAT | O_EXCL | 0o600` (pas de TOCTOU).
- Les noms de fichiers temporaires utilisent `mktemp` avec suffixe `XXXXXX` — pas de noms statiques prédictibles.
- `.gitignore` exclut `private/`, `*.key.pem`, `*.key.*.pem`, `*.key.*.bak` à plusieurs niveaux.

### 1.3 Injection de commandes

✅ **Sûre.** Aucun `eval`, aucune commande construite par concaténation non contrôlée.

- `bin/gen-leaf.sh` lignes 519–534 et 593–606 : toutes les variables sont entre guillemets dans les appels `openssl req` et `openssl ca`.
- `bin/pki-records.awk` et `bin/pki-san.awk` : les paramètres passent par `ENVIRON` (jamais via `awk -v`) pour éviter l'injection d'échappements shell.
- `bin/pki-publish.py` ligne 38 : les commandes hook passent par `shlex.quote()` avant exécution.
- `bin/pki-durable.py` lignes 109–118 : les appels subprocess utilisent des listes d'arguments directs, jamais des chaînes shell.
- Aucun sourçage dynamique de contenu non contrôlé n'a été trouvé.

**Point notable :** Le Makefile gèle toutes ses variables avec `override VAR := $(value VAR); export VAR` avant les recettes, ce qui empêche toute interpolation de variables Make dans le code shell des recettes.

### 1.4 Symlinks et résolution de chemins

✅ **Excellente.**

- `bin/pki-env.sh` lignes 123–158 : `canonicalize_path_allow_missing()` suit les symlinks avec détection de cycle (limite 40 sauts, ligne 130).
- `bin/pki-env.sh` ligne 53 : les chemins de lock eux-mêmes sont vérifiés contre les symlinks (`[[ ! -L "$lock_root" && ! -L "$lock_dir" ]]`) pour éviter qu'un attaquant local ne redirige le lock.
- `bin/pki-state.sh` lignes 20–48 : tout chemin dont la résolution sort de `ROOT_DIR` est refusé.
- `bin/pki-durable.py` ligne 112 : validation Python supplémentaire — les chemins de sortie ne peuvent pas pointer vers le répertoire `out/` via un lien symbolique.

### 1.5 Porte de garde des hooks administrateur

✅ **Solide.** La porte est vérifiée à plusieurs points indépendants.

- `bin/pki-env.sh` lignes 32–36 : la présence de `ISSUE_CMD`, `PUBLISH_CMD` ou `PUBLISH_FETCH_CMD` provoque un `die` immédiat si `ALLOW_ADMIN_HOOKS` n'est pas exactement `1`. La vérification se fait avant tout appel backend, au bootstrap de l'environnement.
- `bin/pki-publish.py` lignes 81–82 : le script Python re-vérifie `ALLOW_ADMIN_HOOKS=1` de façon indépendante.
- `bin/pki-publish.py` lignes 34–75 : les hooks sont lancés dans une nouvelle session (`start_new_session=True`) avec nettoyage `killpg` pour éviter les processus en arrière-plan en cas d'échec.

### 1.6 Sécurité Python (pki-durable.py, pki-publish.py)

✅ **Correcte.**

- `bin/pki-durable.py` lignes 39–52 : I/O POSIX strict (`O_WRONLY | O_CREAT | O_EXCL` pour la création ; `O_RDONLY | O_NOFOLLOW` pour la lecture).
- `bin/pki-durable.py` lignes 88–192 : parsing JSON strict avec validation de schéma (version = 1), regex sur les IDs, validation du hash de préparation.
- `bin/pki-publish.py` lignes 43–60 : intégrité vérifiée par comparaison SHA-256 octet à octet après publication.
- `bin/pki-publish.py` lignes 92–94 : les noms d'artefacts sont validés comme `basename` uniquement (pas de séparateur de chemin).
- macOS : appel `fcntl(fd, F_FULLFSYNC)` pour la garantie de flush au niveau du périphérique (ligne 50).

---

## 2. Qualité de code

### 2.1 Gestion des erreurs

✅ **Cohérente.**

- Convention unifiée : `die()` pour toute erreur fatale (écrit `[ERR]` sur stderr, exit non nul), `warn()` pour les avertissements, `info()` pour les confirmations. Définis dans `bin/pki-env.sh` ligne 26 et utilisés dans tous les scripts.
- Tous les scripts commencent par `set -euo pipefail` — les commandes qui échouent font sortir le script sans code supplémentaire.
- Les traps sont correctement positionés : `bin/gen-leaf.sh` ligne 115 (`trap 'rc=$?; cleanup; pki_exit "$rc"' EXIT`) et `bin/pki-state.sh` ligne 8 (`trap 'pki_exit "$?"' EXIT`).
- Les sous-scripts délégués (`bin/gen-server.sh`, etc.) passent par `exec env ... gen-leaf.sh` — les erreurs remontent directement.

### 2.2 Déclaration des variables locales

✅ **Excellente.** 153 déclarations `local` recensées dans les scripts shell. Toutes les fonctions de `bin/pki-env.sh`, `bin/pki-state.sh`, `bin/gen-leaf.sh` et `bin/pki-recovery.sh` déclarent leurs variables en local.

### 2.3 Absence de duplication de code

✅ **Architecture propre.** Les cinq wrappers (`gen-server.sh`, `gen-user.sh`, `gen-code.sh`, `gen-email.sh`, `gen-archive.sh`) délèguent tous à `gen-leaf.sh` via `env ACTION="..." bin/gen-leaf.sh`. Aucune logique métier n'est dupliquée. Les valeurs par défaut spécifiques à chaque action sont injectées dans les wrappers, puis surchargées si l'appelant les a précisées.

Exemple dans `bin/gen-server.sh` :
```bash
env ACTION="server" CN="${CN}" \
  DAYS="${DAYS:-397}" PROFILE="${PROFILE:-}" \
  "${SCRIPT_DIR}/gen-leaf.sh"
```

### 2.4 Scripts AWK

✅ **Correct avec une attention particulière sur les cas limites.**

**pki-records.awk :**
- Arithmétique hexadécimale 64 bits entièrement textuelle (fonctions `hex`, `greater`, `increment`) — pas de conversion en entier ou en flottant, ce qui évite les débordements de type shell.
- Validation ASN.1 YYMMDDHHmmssZ / YYYYMMDDHHmmssZ avec gestion des années sur 2 et 4 chiffres.
- Décodage des séquences `\xHH` dans les CN (norme OpenSSL), avec test de bout en bout.
- Le débordement du domaine des sériaux (> 16 chiffres hex) est détecté et fatal.

**pki-san.awk :**
- Validation DNS : labels de 63 caractères max, total 253 max, uniquement alphanumérique/tiret, wildcard autorisé en première position uniquement.
- Validation IPv6 : notation compressée `::`, IPv4-dans-IPv6, colonnes en tête/fin.
- Déduplication des valeurs séparées par virgule (ordre préservé).

### 2.5 Portabilité Bash 3.2

✅ **Respectée.** La plate-forme qualifiée est macOS / Bash 3.2.57. Le code évite les constructions Bash 4+ (tableaux associatifs, `mapfile`, `|&`, `${var,,}`). Les extractions de sous-chaîne utilisent `sed` plutôt que les captures de groupe des regex Bash (ex. `kind_from_int_dir` dans `bin/pki-env.sh` ligne 215).

---

## 3. Architecture

### 3.1 Modèle de verrou unique

✅ **Correct et intentionnel.**

Le verrou est implémenté via `mkdir` (atomique POSIX) dans `bin/pki-state.sh` lignes 42–79 :

```
.locks/root-ca.lock/   ← directory = lock acquis
.locks/root-ca.lock/pid  ← PID du processus détenteur
```

- Un seul verrou physique (`root-ca`) sérialise toutes les opérations PKI sur le workspace. Ce choix de conception garantit la cohérence de la base de données OpenSSL (`index.txt`, `serial`) sans conflit d'écriture concurrent.
- Le timeout est configurable (`LOCK_TIMEOUT`, défaut 30 s) et la granularité est de 1 s.
- Les chemins de lock sont protégés contre les symlinks (§1.4).
- Le verrou est libéré dans le sens inverse de l'acquisition (LIFO), ce qui est correct pour les acquisitions imbriquées potentielles.

**Implication opérationnelle :** deux `make server` simultanés sur des intermédiaires différents ne s'exécutent pas en parallèle — ils se mettent en file. C'est documenté dans les specs (chapitre 08).

### 3.2 Fencing durable (pki-durable.sh / pki-durable.py)

✅ **Rigoureux.** Le protocole de fencing garantit la détectabilité d'une interruption entre intention et complétion.

Séquence de base :
1. **Intention** (`durability_begin`) : création de `.recovery/power-loss` avec schéma=1, id aléatoire, `ready=null`. Fsync du fichier + du répertoire.
2. **Préparation** : le script appelant construit le plan d'installation dans `.recovery/pending/ready`.
3. **Scellement** (`durability_seal`) : mise à jour de `ready` avec SHA-256(plan). Rename atomique + fsync.
4. **Complétion** (`durability_finish`) : rename de la clôture en `.durable-<uuid>`, fsync du répertoire, suppression de la quittance.

Si un processus meurt entre l'étape 1 et l'étape 4, `.recovery/power-loss` persiste et bloque toute nouvelle opération via `recovery_guard()` jusqu'à examen manuel. Il n'y a pas de réparation automatique — c'est documenté et intentionnel.

### 3.3 Flux de récupération (pki-recovery.sh)

✅ **Traçable.** Le cycle de vie d'une opération est journalisé à chaque phase.

- `recovery_start()` crée `.recovery/pending/` avec l'ID d'opération.
- `recovery_phase()` met à jour la phase en cours (ex. `signing-outcome-uncertain`).
- `recovery_signing()` enregistre l'émetteur et la sortie avant l'appel backend.
- `staged_install()` utilise `cat > tmp ; chmod ; mv -f tmp dest` — le rename est atomique sur un même système de fichiers.
- À la reprise (`bin/pki-resume.sh`), les hachages des fichiers sources sont recalculés avant toute installation, et comparés au digest du manifeste.

### 3.4 Rollover et rollback d'intermédiaire

✅ **Préservation d'état correcte.**

**Rollover** (`bin/intm-rollover.sh`) :
1. Archive la génération courante sous `generations/<sha256>/`.
2. Renomme l'intermédiaire actif en `intm-web-ca-legacy-<timestamp>-N`.
3. Met à jour les chemins dans l'`openssl.cnf` de la version legacy.
4. Génère un nouvel intermédiaire.

**Rollback** (`bin/intm-rollback-to-legacy.sh`) :
1. Sélectionne le legacy le plus récent.
2. Archive la génération courante, déplace l'actif en `intm-web-ca-pre-rollback-<timestamp>`.
3. Restaure le legacy comme actif.

Données préservées : `index.txt`, flag `.disabled`, liaisons d'émetteur (`issuers/`). Les statuts de révocation restent cohérents après un rollback.

### 3.5 Migration (pki-migration.sh)

✅ **Solide.** La migration réutilise le sujet, les SANs et le profil d'extensions d'un certificat source en le réémettant sous un nouvel intermédiaire.

Gardes de sécurité :
- Comparaison du digest du sujet (§ DN identity).
- Comparaison du digest des extensions.
- Validation SHA-256 de la politique.
- Détection de dérive d'algorithme (KEY_ALG / KEY_SIZE).

La migration `cn-only` efface les variables SAN (comportement intentionnel et documenté). Un `warn()` explicite est émis si des variables SAN sont définies par l'appelant, rendant la perte de données visible dans les logs.

---

## 4. Couverture de tests

### 4.1 Vue d'ensemble des stages

| Stage | Périmètre | Méthodes (aprox.) |
|---|---|---|
| 0 | Packaging source, génération racine, règles Git | ~8 |
| 1 | Parser `pki-records.awk`, monotonie des sériaux | ~12 |
| 2 | Isolation des autorités, transactions, chemins réservés | ~10 |
| 3 | Hooks admin, batch partiel, concurrence, retry | ~9 |
| 4 | Vérification stricte, CRL, horodatage, idempotence | ~10 |
| 5 | Politique et SAN, noms CN sûrs, staging config | ~10 |
| 6 | Injection d'échecs, recovery, publication, tuerie d'émetteur | ~14 |
| 7 | Audit : orphelins, clés faibles, conflits de profil | ~9 |
| 8 | Opérations courantes, nettoyage, durée, stricte CRL | ~12 |
| 9 | Migration batch UTF-8, rotation de clé, dérive de profil | ~10 |
| 10 | Hold/release, révocation irréversible, relocation workspace | ~11 |
| 11 | Fencing durable, barrières, admission de checkpoint | ~13 |
| 12 | Catégories d'autorité, refus de reclassification | ~9 |
| 13 | Hooks admin, FIFO, publication, couverture de persistance | ~8 |
| **14** | **`list-leafs-by-issuer.sh` : listing, filtres, legacy, stdout** | **9** |
| **smoke** | Intégration de bout en bout, toutes les catégories de feuilles | ~20 cas |

**Total :** 124+ méthodes distinctes.

### 4.2 Isolation des tests

✅ **Excellente.** Chaque test :
- Copie uniquement les fichiers listés dans `test/source-manifest.txt` vers un répertoire temporaire.
- Exécute les commandes avec un environnement épuré (uniquement `PATH`, `TMPDIR`, `OPENSSL`, `LC_ALL`).
- Nettoie le répertoire temporaire à la fin (`TemporaryDirectory.cleanup`).

Aucun test ne touche le workspace opérationnel courant.

### 4.3 Limites de couverture (documentées et intentionnelles)

Les limites suivantes sont explicitement documentées dans `test/README.md` et dans la spec chapitre 10 :
- Publication distante (seuls des stubs locaux sont utilisés).
- Perte d'alimentation réelle / comportement du cache disque.
- Stockage réseau.
- Plates-formes Linux et Windows.
- Versions OpenSSL antérieures à 1.1.1.

---

## 5. Profils OpenSSL

### 5.1 Profil intermédiaire

✅ **Correct** (`profiles/intermediate/base.cnf`) :
- `basicConstraints = critical, CA:true, pathlen:0` — intermédiaire ne peut émettre que des feuilles, pas de sous-intermédiaires.
- `keyUsage = critical, keyCertSign, cRLSign` — nécessaire et suffisant pour signer des feuilles et émettre des CRL.
- Conforme à la hiérarchie à 3 niveaux (Racine → Intermédiaire → Feuille).

### 5.2 Profils feuilles

✅ **Conformes RFC 5280 et RFC 5280/5652.** Sélection analysée :

| Profil | basicConstraints | keyUsage | extendedKeyUsage |
|---|---|---|---|
| `server-rsa.cnf` | critical, CA:false | critical, digitalSignature, keyEncipherment | serverAuth |
| `client-rsa.cnf` | critical, CA:false | critical, digitalSignature, keyEncipherment | clientAuth |
| `code-sign.cnf` | critical, CA:false | critical, digitalSignature | codeSigning |
| `smime-sign.cnf` | critical, CA:false | critical, digitalSignature | emailProtection |
| `timestamping.cnf` | critical, CA:false | critical, digitalSignature | timeStamping |

Tous les profils :
- Posent `CA:false` sur les feuilles.
- Limitent `keyUsage` au strict nécessaire pour chaque usage.
- N'incluent pas d'EKU `anyExtendedKeyUsage`.

---

## Annexe — Matrice de couverture sécurité

| Vecteur d'attaque | Mitigé | Mécanisme |
|---|---|---|
| Injection de commande via CN/SAN | ✅ | `validate_component_utf8`, guillemets systématiques |
| Path traversal via INT_DIR / FILE | ✅ | `workspace_path` + `canonicalize_path_allow_missing` |
| Symlink race sur les verrous | ✅ | Vérification `! -L` avant `mkdir` |
| Fuite de clé privée | ✅ | `umask 077` + `chmod 400` + exclusions `.gitignore` |
| Hook malveillant sans consentement | ✅ | `ALLOW_ADMIN_HOOKS=1` requis, vérifié en deux points |
| Sérialisation corrompue (OpenSSL index) | ✅ | Verrou unique + `set -euo pipefail` + staged rename |
| Interruption de processus (power loss) | ✅ | Fencing durable + `recovery_guard` au redémarrage |
| LibreSSL silencieusement accepté | ✅ | Gate explicite dans `require_openssl` |
| Débordement de série | ✅ | `pki-records.awk` — détection à 16 chiffres hex |
| Cross-category cert issuance | ✅ | `assert_certificate_issuance_kind` post-signature |

---
