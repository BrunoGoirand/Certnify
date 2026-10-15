# Certnify — Démarrage en production

[English](QUICKSTART.md)

Ce guide explique comment installer Certnify dans un **workspace de production
isolé**, sans dépôt Git, de façon à ce que les données PKI confidentielles ne
puissent pas être synchronisées accidentellement avec GitHub.

## Principe

Certnify est constitué de deux éléments distincts :

- **Le code source** (`bin/`, `profiles/`, `Makefile`) — versionné dans Git, sans
  données sensibles.
- **Le workspace PKI** (`root/`, `intm-*/`, clés privées, certificats) — données
  confidentielles qui ne doivent jamais se trouver dans un dépôt Git.

L'option la plus sûre consiste à installer le code source dans un répertoire
dédié à la production, **sans initialiser de dépôt Git**. Les données PKI
vivent alors dans ce répertoire et ne peuvent être ni commitées ni poussées.

## Installation initiale

### 1. Créer le répertoire de production

```sh
mkdir -p ~/PKI/mon-organisation
```

### 2. Exporter le code source sans l'historique Git

```sh
git -C ~/Dev/Certnify archive --format=tar HEAD | \
  tar -x -C ~/PKI/mon-organisation/
```

`git archive` exporte uniquement les fichiers sources listés dans Git. Les
données PKI, l'historique Git et le répertoire `.git/` ne sont pas inclus.

### 3. Vérifier l'absence de dépôt Git

```sh
ls -la ~/PKI/mon-organisation/
# → bin/, profiles/, Makefile, README*.md … mais PAS .git/
```

Le workspace de production ne contient aucun remote GitHub. Il est impossible
de l'y synchroniser accidentellement.

## Utilisation normale

Travailler depuis le workspace de production exactement comme décrit dans le
[README](README-fr.md) :

```sh
cd ~/PKI/mon-organisation

make root       CN="Ma Racine CA"
make int-web    CN="Web Issuing CA"
make server     CN="app.mondomaine.fr"  SAN_DNS="app.mondomaine.fr"
make verify     KIND=web CN="app.mondomaine.fr"
make crl-root
make crl        KIND=web
```

Les autorités, clés privées et certificats sont générés dans ce répertoire.
Voir le [README](README-fr.md) pour la référence complète des commandes.

## Mise à jour du code

Lors d'une nouvelle version de Certnify, mettre à jour uniquement les fichiers
source **sans toucher aux données PKI existantes** :

```sh
# Mettre à jour le dépôt source
cd ~/Dev/Certnify
git pull

# Exporter uniquement les fichiers source vers le workspace de production
git archive --format=tar HEAD bin profiles Makefile | \
  tar -x -C ~/PKI/mon-organisation/
```

`tar -x` remplace les fichiers source (`bin/`, `profiles/`, `Makefile`) mais
ne touche pas aux répertoires PKI (`root/`, `intm-*/`) car Git ne les connaît
pas — ils ne sont pas dans l'archive exportée.

## Sauvegarde

Le workspace de production contient les clés privées des autorités. Il doit être
sauvegardé régulièrement. Un agent de synchronisation cloud (iCloud, Dropbox,
etc.) ne doit **pas** écrire dans le workspace PKI actif : les écritures
concurrentes sont explicitement interdites par le toolkit.

Utiliser une sauvegarde chiffrée hors ligne (Time Machine, `rsync` vers un
volume chiffré, etc.).

## Déplacement du workspace

Les configurations générées contiennent des chemins absolus. Après un déplacement
du répertoire de production, rebinder les configurations avec :

```sh
cd /nouveau/chemin/mon-organisation
RECOVERY_ACTION=relocate bin/recovery.sh          # prévisualisation
RECOVERY_ACTION=relocate RELOCATE_APPLY=1 bin/recovery.sh  # application
```

Résoudre toute opération en attente avant de déplacer le workspace.
Voir le [guide de reprise](specifications/guides/recovery-fr.md).
