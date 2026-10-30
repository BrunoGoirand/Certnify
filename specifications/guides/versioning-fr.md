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

Aucun hook automatique ni commande `release-prepare` n’est installé. Les commandes
ne créent ni commit, ni tag, ni publication. Ces actions éventuelles, dont un tag
`vMAJOR.MINOR.PATCH`, restent des décisions distinctes du mainteneur après revue.

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
