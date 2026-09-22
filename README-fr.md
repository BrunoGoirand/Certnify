<a href="https://certnify.org/"><img alt="Logo Certnify" src="image/Certnify.png" width="300"></a>

# Certnify

[English](README.md)

Certnify est un outil de gestion de PKI privée locale, écrit en Bash, avec une
interface Make et un moteur OpenSSL. Il gère une racine autosignée, des autorités
intermédiaires et l’émission, la vérification, la révocation et le remplacement
des certificats.

Il couvre l’authentification TLS serveur/client, la signature de code, la signature
et le chiffrement S/MIME, le scellement documentaire et les certificats de signature
d’horodatage. Il émet les certificats ; il ne fournit pas lui-même de serveur TLS,
de signature documentaire ou de service d’horodatage.

[Licence MIT](LICENSE.txt) · © 2025–2026 Bruno Goirand

## Fonctionnalités et périmètre

- Clés RSA, EC sur courbes nommées, Ed25519 et Ed448 ; profils adaptés à la clé réelle.
- SAN DNS, IP, email et URI, avec validation explicite et valeurs par défaut définies.
- Intermédiaires `web`, `auth`, `code`, `smime` et `archive`, et autorités personnalisées.
- Sélection exacte par CN, protection contre les doublons actifs et conservation des générations d’émetteur.
- Vérification de chaîne, contrôle CRL strict facultatif, révocation unitaire/en lot et génération de CRL.
- Rollover/rollback d’intermédiaires, export d’inventaire et réémission en lot conservant l’identité et le profil.
- Verrou partagé du workspace, signalement des interruptions et publication de CRL reprenable.

L’outil est exploité par un administrateur sur le système de fichiers. Il ne fournit
ni serveur d’enrôlement, ni ACME, ni renouvellement planifié, ni répondeur OCSP,
ni installation de confiance, ni interface HSM. Les clés privées sont des fichiers
non chiffrés aux permissions restrictives. Un marqueur durable et des barrières de
persistance protègent les opérations locales : après une interruption brutale,
les nouvelles opérations sont bloquées jusqu’à une reprise vérifiée ou une revue
explicite. Cela ne fournit ni transaction multifichier atomique ni réparation d’un
incident arbitraire. Les coupures matérielles réelles restent à qualifier. Voir le
[guide de reprise](specifications/guides/recovery-fr.md).

## Prérequis

Exécuter les commandes depuis la racine du projet avec Bash, Make, OpenSSL et les
utilitaires Unix usuels (`awk`, `sed`, `grep`, `mktemp`, `install`, `date`, `od`, `tr`,
`iconv`, `sort` et outils de fichiers). Le contrôle de version accepte OpenSSL 1.1.1 ou 3.x et refuse
LibreSSL. Choisir un autre exécutable avec `OPENSSL=/chemin/absolu/vers/openssl`.

L’environnement qualifié est macOS, Bash 3.2.57, GNU Make 3.81 et OpenSSL 3.6.4.
L’acceptation d’autres versions ne constitue pas leur qualification. Python 3.8+
est requis à l’exécution pour les barrières de persistance, ainsi que pour les tests ;
l’environnement consigné utilise Python 3.14.7. Le composant de persistance prend
en charge macOS et Linux sur un seul système de fichiers local et refuse les
barrières non prises en charge. Les écritures externes, notamment celles d’un
agent de synchronisation sur l’état PKI actif, sont interdites.

## Démarrage rapide

Utiliser un workspace neuf pour cet exemple. Il crée une racine et un intermédiaire
Web, émet un certificat serveur et le vérifie, sans puis avec les CRL :

```sh
make root CN="Certnify Root CA"
make int-web CN="Certnify Web Issuing CA"
make server CN="app.example.test" SAN_DNS="app.example.test"
make verify KIND=web CN="app.example.test"
make crl-root
make crl KIND=web
make verify KIND=web CN="app.example.test" VERIFY_CRL=1
```

Le certificat serveur, sa clé et sa chaîne sont dans `intm-web-ca/` :

- `certs/app.example.test.cert.pem`
- `private/app.example.test.key.pem`
- `certs/app.example.test.fullchain.cert.pem` — certificat final puis intermédiaire, sans racine

L’ancre de confiance est `root/certs/ca.cert.pem`. Déployer le certificat et la clé
appropriés et configurer séparément la confiance des clients : la génération
n’installe pas la confiance et ne configure pas l’application. Recréer la racine
avec un autre CN échoue. Réémettre un certificat final pour un CN actif échoue
également par défaut.

## Autorités, profils et émission

La validité par défaut est de 7300 jours pour la racine et de 3650 jours pour les
intermédiaires. Créer l’intermédiaire nécessaire avant les certificats finaux.
Les raccourcis sont `int-web`, `int-auth`, `int-code`, `int-smime` et `int-archive` ;
`intermediate` accepte une destination explicite.

| Cible | Autorité par défaut | Durée en jours | Profil par défaut |
| --- | --- | ---: | --- |
| `server` | `intm-web-ca` | 397 | RSA : `server_cert` ; EC/EdDSA : `server_ec` |
| `user` | `intm-auth-ca` | 825 | RSA : `client_cert` ; EC/EdDSA : `client_ec` |
| `dev`, `code` | `intm-code-ca` | 730 | `code_sign` |
| `email` | `intm-smime-ca` | 730 | `smime` (signature et chiffrement combinés) |
| `doc`, `archive` | `intm-archive-ca` | 3600 | `archive` |

Ces exemples sont des choix d’émission indépendants ; chacun exige son autorité :

```sh
make server CN="api.example.test" KEY_ALG=EC KEY_CURVE=secp384r1 \
  SAN_DNS="api.example.test" SAN_URI="spiffe://certnify/api"
make user CN="alice@example.test" KEY_ALG=Ed25519
make code CN="Release Signing Key" KEY_ALG=Ed25519
make email CN="signer@example.test" SMIME_MODE=sign KEY_ALG=EC
make email CN="encrypt@example.test" SMIME_MODE=encrypt KEY_ALG=RSA
make archive CN="Document Seal" ARCHIVE_MODE=seal DAYS=3600
make archive CN="Timestamp Signer" ARCHIVE_MODE=timestamp DAYS=3600
```

`SMIME_MODE=combined` (ou `legacy`) sélectionne `smime` ; `sign` sélectionne
`smime_sign` ; `encrypt` sélectionne `smime_encrypt`. Le chiffrement et le mode
S/MIME combiné exigent RSA. `ARCHIVE_MODE=legacy` sélectionne `archive`, `seal`
sélectionne `archive_seal`, et `timestamp`/`timestamping` sélectionne `timestamping`.
Ces modes fonctionnent avec les deux alias de cible. Les combinaisons explicites
de clé et de profil incompatibles sont refusées.

| Paramètre | Signification / valeur par défaut |
| --- | --- |
| `CN`, `C`, `O`, `OU` | Identité ; pays, organisation et unité facultatifs |
| `KEY_ALG` | RSA (défaut), EC, EdDSA, Ed25519 ou Ed448 |
| `KEY_SIZE` | Taille RSA en bits, 4096 par défaut, minimum 2048 |
| `KEY_CURVE` | prime256v1 (défaut), secp384r1 ou secp521r1 |
| `KEY_EDDSA` | Ed25519 (défaut) ou Ed448 pour EdDSA générique |
| `DAYS` | Validité demandée ; refus si elle dépasse la validité restante de la chaîne |
| `INT_DIR`, `KIND` | Répertoire explicite prioritaire sur le type, puis sur les valeurs de l’action |
| `PROFILE`, `EXT_SECTION` | Profil installé explicite ; EXT_SECTION est prioritaire |
| `SAN_DNS`, `SAN_IP`, `SAN_EMAIL`, `SAN_URI` | Listes typées séparées par des virgules |
| `SAN` | Liste combinée, par exemple `DNS:app.example.test,IP:127.0.0.1` |
| `FORCE_NEW_KEY` | 0 : réutiliser ; 1 : sauvegarder/remplacer ; rotate : conserver les fichiers canoniques |
| `ROOT_PATHLEN` | 1 par défaut ; une valeur explicitement vide omet la contrainte dans une nouvelle configuration |
| `QUIET_OPENSSL` | 1 masque certaines sorties du moteur ; les messages de l’outil restent visibles |

`FORCE_NEW_KEY=1` conserve un ensemble clé/CSR/certificat/chaîne suffixé par le
numéro de série puis, après vérification, remplace les quatre chemins habituels
par des fichiers concordants. Une clé existante est sauvegardée ; une interruption
nécessite toujours l’examen du journal. Les feuilles d’archive durent 3600 jours
par défaut, avec une marge sous les 3650 jours d’un nouvel intermédiaire.
Une valeur DAYS explicite n’est jamais réduite silencieusement.

Une clé réutilisée conserve son algorithme réel malgré un autre KEY_ALG demandé.
La rotation de clé ne contourne pas la protection contre les doublons de CN :
`ALLOW_DUPLICATE_CN=1` est une dérogation explicite distincte. `FORCE_REISSUE`,
`ROTATE_KEY` et `FORCE_REUSE_KEY` contrôlent le renouvellement et le changement de
clé d’un intermédiaire ; voir le [contrat d’émission](specifications/05-issuance.md).

Toute liste SAN explicite non vide supprime le SAN implicite issu du CN. Sans liste,
les serveurs reçoivent DNS:CN ; les actions user/email reçoivent email:CN si le CN
contient `@`. Les entrées incorrectes sont refusées, pas ignorées. Protéger les
valeurs avec les guillemets appropriés dans le shell. Un SAN de profil en conflit
avec la demande est refusé avant signature ; les SAN émis sont comparés à la
demande effective avant installation. Les champs du sujet utilisent un UTF-8 validé.

Les fragments de `profiles/` composent les **nouvelles** configurations d’autorité.
Leur modification ne met pas à jour un `openssl.cnf` existant : conserver et examiner
la configuration installée avant une modification explicite de politique. Chaque
nouveau certificat final conserve un instantané de sa politique. Les extensions
exactes et règles de validation figurent dans la [spécification cryptographique](specifications/04-cryptography-and-profiles.md).

## Vérification, révocation et CRL

La vérification et la révocation exigent `KIND` ou `INT_DIR`, même avec FILE. FILE
accepte un chemin relatif à l’autorité, relatif au workspace pour la même autorité,
ou absolu contenu dans cette autorité :

```sh
make verify KIND=web FILE="certs/app.example.test.cert.pem"
make verify KIND=web FILE="intm-web-ca/certs/app.example.test.cert.pem"
make revoke KIND=web CN="app.example.test" REASON=keyCompromise DRY_RUN=1
make revoke KIND=web CN="app.example.test" REASON=keyCompromise
```

La recherche par CN exige une correspondance active exacte unique, ou une seule
correspondance historique non ambiguë. Utiliser FILE en cas d’ambiguïté ; la
révocation accepte aussi SERIAL. Une valeur CHAIN non vide est refusée. La
vérification utilise la génération d’émetteur liée au certificat et la racine du
workspace. Ajouter `VERIFY_DNS`, `VERIFY_IP`, `VERIFY_EMAIL`, `VERIFY_URI` ou `VERIFY_SUBJECT` pour une identité
attendue, et `VERIFY_PURPOSE` pour l’usage applicatif.

`VERIFY_URI` compare exactement le SAN URI (sensible à la casse, sans normalisation).
`VERIFY_SUBJECT` compare le sujet complet au format RFC2253, tel que produit par
`openssl x509 -in cert.pem -noout -subject -nameopt RFC2253`, sans `subject=`.
Cela permet le mode strict sans SAN, sans identifier un certificat de façon unique.
`VERIFY_ATTIME` fixe la date en secondes Unix positives ou nulles (UTC, jusqu’à 9999).
La même date s’applique aux certificats et aux CRL : il faut conserver des CRL
couvrant cette époque. Cela ne reconstitue pas la confiance passée et ne prouve
pas la date d’une signature. Une identité URI/sujet incorrecte échoue dans tous les modes.

`VERIFY_CRL=1` exige les CRL valides de la racine **et** de l’émetteur, y compris
la CRL historique appropriée. Une CRL requise absente, périmée ou invalide fait échouer
la commande.

| VERIFY_MODE | Valide | Révoqué | Autre erreur de vérification terminée |
| --- | --- | --- | --- |
| normal | Succès | Échec | Échec |
| strict | Succès | Échec | Échec |
| tolerate_revoked | Succès | Succès | Échec |
| info | Succès | Succès | Succès, rapport uniquement |

Les erreurs préalables échouent dans tous les modes. En mode info, lire
`VERIFY STATUS` : un code de sortie nul ne prouve pas la validité. Par défaut,
la vérification ne contrôle pas la révocation.

Pour les automatisations, `VERIFY_MODE=strict` exige une identité attendue (SAN ou sujet explicite) et
un usage précis, impose les contrôles X.509 stricts et les CRL de toute la chaîne,
et échoue pour toute erreur. `VERIFY_CRL=0` ne désactive pas ces contrôles stricts.
Exemples, après renouvellement des CRL nécessaires :

```sh
make crl KIND=web CRL_HISTORY=1
make verify KIND=web CN=app.example.test VERIFY_MODE=strict \
  VERIFY_DNS=app.example.test VERIFY_PURPOSE=sslserver
make verify KIND=smime CN=user@example.test \
  VERIFY_EMAIL=user@example.test VERIFY_PURPOSE=smimesign
```

Les usages sont ceux d’OpenSSL : sslserver, sslclient, smimesign, smimeencrypt,
timestampsign, etc. Un usage propre à une version (comme codesign) échoue si le
backend choisi ne le prend pas en charge.

```sh
make crl-root
make crl KIND=web CRL_DAYS=7
make crl-show KIND=web
make crl-all
make revoke-intermediate KIND=web DRY_RUN=1
make revoke-intm-and-leafs KIND=web LEAF_STATUSES=V,E DRY_RUN=1
```

Retirer DRY_RUN uniquement pour appliquer la révocation souhaitée. La révocation
de l’intermédiaire seul désactive l’émission mais ne change pas les lignes des
certificats finaux. La révocation en lot sélectionne les statuts enregistrés
(V par défaut, pouvant inclure des certificats expirés non encore actualisés).
Les échecs requis produisent un résultat global non nul ; les révocations déjà
enregistrées restent acquises. Les cibles Make de révocation utilisent CRL_UPDATE=1
par défaut ; 0 omet l’actualisation. Répéter la révocation préserve sa date et sa
raison initiales et permet de retenter l’actualisation de CRL. Les raisons et
correspondances acceptées sont dans le [contrat de révocation](specifications/06-verification-and-revocation.md).
La levée d’une suspension `certificateHold` est disponible via les commandes existantes :

```sh
make revoke KIND=web SERIAL=1000 REASON=removeFromCRL DRY_RUN=1
make revoke KIND=web SERIAL=1000 REASON=removeFromCRL
make revoke-intermediate KIND=web REASON=removeFromCRL
```

Elle exige `CRL_UPDATE=1` et publie une nouvelle CRL complète sans le certificat
suspendu. Les révocations définitives ne peuvent pas être annulées. Distribuer
la nouvelle CRL aux clients ; leurs caches peuvent conserver l’ancienne jusqu’au
rafraîchissement. Un certificat expiré reste expiré. La levée par lot est refusée.
Un marqueur `.disabled` indépendant est conservé ; seul celui créé pour cette
suspension de l’intermédiaire est retiré.

`crl-root` utilise la durée configurée, normalement sept jours ; CRL_DAYS contrôle
la génération intermédiaire. `crl-all` inclut les répertoires legacy correspondants
et exclut la racine par défaut. `make crl-all CRL_HISTORY=1 CRL_DAYS=7` renouvelle
explicitement les CRL de la racine, des intermédiaires courants et des générations
conservées, y compris dans les répertoires legacy. `make crl KIND=web CRL_HISTORY=1`
limite la recherche à cet intermédiaire et renouvelle également la racine.
Les chemins personnalisés doivent être sélectionnés explicitement. Toute la liste
est contrôlée avant émission, mais les installations sont individuelles : un échec
tardif peut laisser des CRL déjà renouvelées et des compteurs avancés.
Aucune URL de CRL n’est téléchargée ou ajoutée automatiquement
aux extensions. `verify-intermediate-revoked` échoue pour un intermédiaire révoqué ;
il n’inverse pas le succès de vérification. Les commandes `show-intermediate-serial`
et `crl-root-revoked` permettent l’inspection avec un sélecteur d’autorité explicite.

## Cycle de vie, lots et publication

Ces commandes sont des choix opérationnels distincts, pas une séquence à exécuter
sans discernement :

```sh
make rollover-web INT_CN="Web CA v2"
make list-leafs-web
make reissue-leafs-web DRY_RUN=1
make rollback-web
```

Le rollover conserve le répertoire de l’autorité précédente et crée une nouvelle
autorité active ; il ne révoque ni ne migre les anciens certificats. Le rollback
conserve l’autorité active avant de restaurer une ancienne ; il n’annule pas les
révocations. L’inventaire et les lots acceptent des sélecteurs explicites de source,
d’entrée et de destination. La réémission utilise par défaut `REISSUE_MODE=preserve` :
elle retrouve les certificats et profils archivés dans `LEGACY_DIR` (automatique
après rollover), conserve le sujet complet, les SAN, les extensions et leur
criticité, puis génère de nouvelles clés avec le même algorithme, la même taille
RSA ou la même courbe EC. Les anciennes clés privées ne sont pas nécessaires.
Tout le lot est vérifié avant émission, y compris avec `DRY_RUN=1` ; une preuve
manquante ou un profil incompatible provoque un refus. Le numéro de série,
l’émetteur, les identifiants SKI/AKI et la validité sont renouvelés (`DAYS` reste
applicable dans les limites de la chaîne). Ce mode nécessite OpenSSL 3.x.
L’ancien comportement reste accessible explicitement avec `REISSUE_MODE=cn-only`.
Une commande personnalisée `ISSUE_CMD` ne bénéficie pas de cette garantie.
Les reçus par élément bloquent les reprises aveugles après un résultat incertain. Voir la
[spécification du cycle de vie](specifications/07-lifecycle-and-migration.md).

La préparation/publication d’une CRL finale utilise directement un script :

```sh
KIND=web DRY_RUN=1 bin/intm-publish-final-crl.sh
```

Sans DRY_RUN, il génère PEM, DER et empreintes, ainsi que les alias les plus récents.
Par défaut, il refuse les certificats indexés non révoqués et non expirés. « Finale »
reste indicatif : l’autorité n’est pas retirée du service. La publication distante
exige un PUBLISH_CMD explicitement configuré. Les six artefacts doivent réussir.
FINAL_CRL sélectionne un PEM versionné valide conservé pour retenter sans consommer
un autre numéro de CRL. Son fichier local `.resume-state` doit correspondre au
PEM, aux entrées révoquées et au prochain compteur de CRL. Une révocation ou une
tentative ultérieure de génération de CRL rend cette reprise impossible : générer
une nouvelle CRL finale. Les anciennes CRL sans cet état doivent aussi être
régénérées. Le rafraîchissement courant remplace les alias sans modifier leurs
archives ; si un DER courant existe, il est actualisé avec le PEM. Voir le [guide de publication et reprise](specifications/guides/recovery-fr.md).

## Stockage et interruptions

La racine utilise `root/` ; les raccourcis intermédiaires utilisent `intm-<kind>-ca/`.
Chaque autorité contient configuration, index, compteurs, clés privées, certificats
et CRL. Les intermédiaires conservent aussi CSR, générations d’émetteur, liaisons,
instantanés de politique et correspondances de noms. L’arborescence racine ne crée
**pas** de répertoire CSR. `ca.chain.cert.pem` contient l’intermédiaire puis la racine ;
`chain.cert.pem` est son alias de compatibilité.

Les CN ordinaires sûrs conservent leur nom, espaces/@ compris. Les noms dangereux
ou réservés utilisent une empreinte et une correspondance exacte ; les certificats
suivants peuvent recevoir des noms basés sur le numéro de série. Voir la
[spécification du stockage](specifications/03-persistence-and-artifacts.md).
Utiliser `pki-data/` ou une exclusion Git locale explicite pour les données
personnalisées. Les configurations contiennent des chemins absolus : déplacer un
workspace exige leur rattachement via le mode `RECOVERY_ACTION=relocate` décrit ci-dessous.

Une autorité existante dont la base ou les compteurs manquent est refusée sans
recréation d’état. Restaurer et réconcilier explicitement les fichiers conservés ;
ne jamais réinitialiser les compteurs. La génération et la réutilisation de RSA
exigent au moins 2048 bits ; la vérification de chaîne impose le niveau de sécurité
2 d’OpenSSL. Les anciennes clés ou certificats trop faibles demandent une migration
explicite : ces contrôles ne remplacent ni ne révoquent les données existantes.

Les transactions partagent `.locks/root-ca.lock`. Une émission ou un déplacement
interrompu peut laisser `.recovery/pending`, qui bloque les opérations sous verrou
jusqu’à examen :

```sh
bin/recovery.sh
```

Ce rapport est en lecture seule. Les plans d’installation complets disposent
d’une reprise vérifiée (voir ci-dessous). Les autres cas demandent une réconciliation
et un acquittement explicites par l’opérateur. Ne jamais réduire
les compteurs consommés ou répéter aveuglément la signature. Un échec d’actualisation
ou de publication CRL n’annule pas une révocation locale ou une CRL générée.
Le [contrat de fiabilité](specifications/08-architecture-and-reliability.md) décrit
les limites de persistance, les verrous abandonnés et les procédures manuelles.

## Tests, inspection et nettoyage

```sh
make help
make tree
make ls-web
make test-stage0 test-stage1 test-stage2 test-stage3 test-stage4 test-stage5 test-stage6 test-stage7 test-stage8 test-stage9 test-stage10
make test-smoke
```

Les tests créent des workspaces jetables depuis un manifeste de sources explicite
et génèrent leurs propres clés. Ils couvrent analyse des entrées, politiques,
concurrence, révocation et pannes injectées ; la publication utilise des simulations
locales. Voir [test/README.md](test/README.md) pour l’exécution et les
[critères d’acceptation](specifications/10-acceptance-and-traceability.md) pour les limites.

`make clean` affiche désormais un aperçu sans modifier le workspace. Après examen
des chemins et sauvegarde si nécessaire, `make clean CLEAN_APPLY=1` supprime root,
les autorités intm-* reconnues à la racine du workspace et out, clés et historiques
compris. Le plan complet est revérifié sous verrou. Les candidats symboliques et
les autorités reconnues incomplètes sont refusés ; les répertoires intm-* sans
configuration sont conservés. Les chemins personnalisés et journaux de reprise
restent hors périmètre. CLEAN_APPLY=1 avec DRY_RUN=1 est refusé.
Le nettoyage valide l’état local des autorités sans interpréter les chemins ni
les politiques OpenSSL : un ancien chemin après déplacement ne le bloque pas.

Compatibilité : l’émission refuse désormais un émetteur invalide ou une durée DAYS
supérieure à la validité restante de la chaîne. Le message indique l’expiration
limitante et le maximum en jours entiers. Exemple :
`make archive CN="Records Seal" DAYS=3600` si l’émetteur le permet ; une autorité de
3650 jours ne peut pas émettre plus tard une feuille de 3650 jours. Aucune durée
n’est plafonnée silencieusement ; les certificats existants ne sont pas migrés.

## Documentation

Les spécifications de référence sont en anglais ; les guides existent dans les deux langues.

- [Spécifications fonctionnelles et techniques](specifications/README.md)
- [Référence des scripts](specifications/guides/shell-fr.md)
- [Choix des profils](specifications/guides/profiles-fr.md)
- [Procédures de reprise](specifications/guides/recovery-fr.md)
- [Compatibilité et limites](specifications/09-compatibility-and-limitations.md)

## Reprise vérifiée et déplacement du workspace

Une fois le workspace complet déplacé, sans opérations en cours, ces commandes
prévisualisent puis appliquent le rattachement au nouvel emplacement :

```sh
RECOVERY_ACTION=relocate bin/recovery.sh
RECOVERY_ACTION=relocate RELOCATE_APPLY=1 bin/recovery.sh
```

Les configurations des autorités racine, imbriquées et historiques et les liens
absolus internes sont ajustés ; clés, index et compteurs restent conservés.
Les liens externes, chemins non pris en charge, états incomplets et inclusions de
configuration sont refusés. Résoudre toute opération en attente avant le déplacement.

Après une interruption de l’installation d’un certificat terminal déjà validé,
d’une levée de suspension ou d’un rattachement du workspace :

```sh
RECOVERY_ACTION=resume bin/recovery.sh
# Ou reprise automatique avant la prochaine commande verrouillée :
make verify KIND=web CN=app.example.com AUTO_RECOVER=1
```

La reprise contrôle les empreintes des sources, destinations et états conservés,
ainsi que les échéances de validité, avant d’installer les fichiers. Elle ne signe
aucun nouveau certificat. Les journaux terminés restent dans `.recovery/completed-*` ;
ils peuvent conserver des copies de clés privées, protégées par des permissions
restrictives. Un résultat de signature incertain, un plan incomplet, un déplacement
d’autorité interrompu, un verrou périmé ou des données modifiées nécessitent encore
un examen manuel. Aucun compteur n’est réinitialisé et aucun verrou n’est volé.
