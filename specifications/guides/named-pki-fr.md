# Espaces PKI nommés

[English](../12-named-pki.md)

Les sources et profils appartiennent à CERTNIFY_SOURCE_DIR, calculé depuis les
scripts installés. ROOT_DIR désigne l’espace opérationnel sélectionné et ne peut
pas être imposé par l’appelant. Le paramètre public PKI=certnify-<slug> sélectionne
un enfant direct de la base. Le moteur valide le nom (groupes alphanumériques
ASCII minuscules séparés par des tirets, 80 caractères maximum préfixe compris),
refuse liens symboliques et fichiers, et confine les chemins à cet espace.

`make pki-name CN="Racine Personnelle"` retourne `certnify-racine-personnelle`.
La normalisation appartient au moteur : Unicode NFKD, retrait des marques
combinatoires, minuscules ASCII et tirets entre les groupes alphanumériques.
Le CN original est conservé. Les noms dérivés vides ou trop longs sont refusés.
Un identifiant explicite valide est possible pour un nom sans représentation ASCII.

Seule la création racine peut créer un espace absent. Les opérations suivantes
exigent son existence. Le moteur conserve son contrat d’identité/idempotence pour
une racine existante ; le parcours première racine du skill refuse en plus toute
collision de nom. Aucune sélection implicite ni migration. Sans PKI, le mode
historique reste disponible uniquement si aucune PKI nommée n’est présente.

Tout l’état de la PKI (clés, certificats, index, compteurs, CRL, liaisons émetteurs,
exports, verrous, récupération et barrières de durabilité) réside dans cet enfant.
Les sources/profils partagés ne suivent jamais ROOT_DIR. Les chemins relatifs
partent de l’espace sélectionné ; les chemins absolus d’une voisine sont refusés.
Exécuter les commandes depuis la base des sources avec le même PKI explicite :

```sh
make root PKI=certnify-racine-personnelle CN="Racine Personnelle"
make int-web PKI=certnify-racine-personnelle CN="Web Personnel"
make server PKI=certnify-racine-personnelle CN=app.test SAN_DNS=app.test
```

La capacité named-pki-v1 figure dans capabilities.json, inclus dans les archives
sources. Ne pas l’attribuer aux anciennes releases. Les archives sources excluent
les données PKI. Mises à jour et migrations sont des parcours distincts. Les
opérations sont sérialisées par PKI ; aucune mise à jour des sources ne doit être
concurrente avec une opération PKI.

Validation : test/named-pki.py utilise des instances jetables copiées par manifeste
pour tester deux hiérarchies, vérification/révocation, verrous indépendants,
sélecteurs et chemins voisins interdits, et normalisation. Cela ne qualifie ni les
coupures de courant ni le comportement d’un assistant.

## Résolution en lecture seule et modes mixtes

`make pki-info PKI=certnify-racine-personnelle` renvoie un JSON versionné avec
source_base, selector, workspace, exists, layout et la présence des gardes.
Aucun bootstrap, verrou ni mutation. Le même résolveur contrôle le démarrage du
moteur et l’admission des transactions ; les clients utilisent ses chemins.
Le mode nommé refuse un état historique à la base (root, intermediate, intm-*,
pki-data, out, .locks ou .recovery), pour ne pas rendre une installation existante
inaccessible. La migration reste une opération distincte.
