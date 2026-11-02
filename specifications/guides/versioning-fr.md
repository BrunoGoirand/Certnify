# Versionnement et archives sources

Le fichier `VERSION` porte l’unique version du toolkit au format
`MAJOR.MINOR.PATCH`, sans zéros initiaux, avec exactement un saut de ligne LF final.
La base initiale `1.0.0` n’affirme pas l’existence d’un tag ou d’une publication.
Cette version est indépendante d’OpenSSL, des numéros de série, des générations
d’autorités et des formats de données PKI.

Depuis la racine des sources, avec Python 3.8+ et Make :

```sh
make version
make version-bump LEVEL=patch
# Autres choix : LEVEL=minor ou LEVEL=major
```

`make version` affiche uniquement la version et un saut de ligne. Les équivalents
directs sont `python3 -B tools/version.py show` et
`LEVEL=patch python3 -B tools/version.py bump`. Git, OpenSSL et une autorité
initialisée ne sont pas nécessaires.

Choisir patch pour une correction compatible, minor pour une fonctionnalité
compatible, major pour une rupture du contrat public (commandes, politique ou
stockage). Minor remet PATCH à zéro ; major remet MINOR et PATCH à zéro.
Chaque invocation réussie incrémente de nouveau. Un LEVEL absent, vide ou inconnu,
un VERSION absent, mal formé, non régulier ou symbolique provoque un refus.

Seul VERSION est remplacé atomiquement, avec conservation de ses permissions.
Le verrou exclusif `.version-bump.lock/` est indépendant du verrou PKI ; un verrou
existant provoque un refus. Les erreurs ordinaires nettoient les fichiers
temporaires et le verrou détenus. Après une interruption brutale, inspecter les
traces et confirmer qu’aucun incrément n’est actif avant un nettoyage manuel.
Ce mécanisme ne garantit pas la résistance aux coupures électriques. Ne pas
modifier ou archiver les sources pendant un incrément. Aucune donnée PKI n’est
modifiée et aucune migration n’est déclenchée.

## Préparation manuelle

Tenir `CHANGELOG.md` à jour sous Unreleased : changements visibles, ruptures,
migrations et périmètre exact des validations. Avant une version, choisir et
exécuter une seule fois l’incrément, déplacer les notes concernées dans une section
portant la version et la date de sortie, puis conserver Unreleased pour la suite.
Relire le diff et exécuter les tests pertinents. Les qualifications historiques ne
qualifient pas automatiquement une nouvelle version.

L’utilitaire de version n’a aucun hook automatique ni effet Git. La publication
Git reste une action explicite du mainteneur, manuelle ou réalisée par la commande
de release groupée ci-dessous.

### Créer et publier un tag Git

Depuis la racine du dépôt `certnify`, commiter d’abord les changements de version
relus, notamment VERSION et CHANGELOG.md. Vérifier que HEAD est le commit à
publier et que `origin` désigne le dépôt GitHub souhaité :

```sh
git status --short
git log -1 --oneline
git remote -v
git show HEAD:VERSION
```

Remplacer `vX.Y.Z` ci-dessous par `v` suivi du VERSION commité. Exécuter chaque
commande séparément et s’arrêter en cas d’échec :

```sh
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

La première commande crée un tag annoté sur HEAD. La seconde publie ce tag précis
sur GitHub. Vérifier sa présence distante avec :

```sh
git ls-remote --exit-code --tags origin refs/tags/vX.Y.Z
```

Une GitHub Release avec notes de version et pièces jointes constitue une étape
de publication distincte ; pousser un tag ne la crée pas à lui seul.

## Archive sur manifeste explicite

```sh
python3 -B test/workspace.py archive . /tmp/certnify-1.0.0.tar.gz
```

Choisir un nouveau nom correspondant au VERSION inspecté ; cette correspondance
n’est pas vérifiée par la commande. L’archive contient exactement les fichiers de
`test/source-manifest.txt`, sous `certnify/`, sans copie récursive ni inventaire
Git. Tout fichier absent, lien symbolique, fichier non régulier ou chemin dangereux
ou dupliqué provoque un refus avant création. Une destination existante, y compris
un lien, n’est jamais écrasée. Une erreur d’écriture supprime l’archive incomplète.

Relire chaque ajout au manifeste : aucune clé privée, donnée d’autorité, journal
de reprise ou configuration locale ne doit y figurer. Les fichiers non listés sont
exclus même dans les répertoires sources. Ce manifeste est une liste contrôlée,
pas un détecteur de secrets. Archiver un arbre source fiable et sans modification
concurrente. Les modes et dates sources sont conservés ; la reproductibilité
binaire n’est pas garantie.

Inspecter les membres et tester une extraction dans un emplacement jetable avant
distribution, jamais dans une PKI opérationnelle. Voir le
[contrat anglais](../11-versioning-and-releases.md) et les
[instructions de test](../../test/README.md).

## Commande de release groupée

Après revue, tests et commit des changements et du changelog, utiliser :

```sh
python3 -B tools/release.py patch
# Aperçu facultatif uniquement :
python3 -B tools/release.py patch --dry-run
# Autres choix : minor ou major
```

L’option facultative `--dry-run` affiche la prochaine version, le tag annoté et la
destination de push d’origin (accès réseau en lecture nécessaire), sans modifier
VERSION, les commits ni les tags. Sans cette option, la commande incrémente VERSION
via l’utilitaire existant, commite uniquement VERSION sous `Release vX.Y.Z`, crée
le tag annoté et pousse uniquement ce tag vers l’unique destination de push
d’origin. L’objet tag distant est vérifié. Aucune branche n’est poussée ; aucune
GitHub Release ni pièce jointe n’est créée. Le commit est accessible via le tag ;
la branche peut être poussée séparément. L’authentification Git et l’identité
auteur/commiteur doivent être disponibles. La commande ne lance pas les tests
d’acceptation et ne modifie pas le changelog : préparer les notes pour la version
visée dans le commit précédent.

Un dépôt propre sur une branche, VERSION commité et un tag absent localement et
à distance sont exigés. `.release.lock/` sérialise ces commandes ; aucune édition,
incrémentation, création de commit ou publication concurrente. S’arrêter sur toute
erreur : conserver version, commit et tag déjà créés et inspecter l’état local et
distant avant toute nouvelle tentative. Aucun rollback, push forcé, remplacement
de tag ni nouvelle tentative automatique. Un push refusé peut laisser une release
locale ; une vérification distante échouée peut suivre une publication réussie.
Une interruption peut conserver le verrou ; inspecter avant nettoyage manuel.
Les hooks Git existants restent actifs. Aucune PKI ni skill installé n’est modifié.

`python3 -B test/release.py -v` valide l’aperçu, les trois incréments, les tags
annotés, les pushes limités aux tags, les refus de dépôt modifié/doublons et l’état
conservé après un push refusé, avec des sources copiées par manifeste et des dépôts
bare locaux ; cela ne constitue pas une publication GitHub.
