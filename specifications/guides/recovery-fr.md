# Reprise après interruption

## Après une coupure ou une erreur de persistance

Python 3.8+ est désormais requis à l’exécution. Avant toute modification de la
PKI, le toolkit rend durable un marqueur `.recovery/power-loss`. Il le retire
seulement après synchronisation des fichiers et répertoires, complétée sur macOS
par une barrière du cache matériel. Une interruption brutale conserve ce blocage,
y compris pendant une révocation, une génération de CRL ou l’initialisation.
Une erreur de synchronisation fait échouer la commande et peut laisser aussi
`.recovery/power-loss-error`. Les messages de progression ne suffisent pas :
la fin normale exige un code zéro et `Local state durably synchronized`.
Les coupures matérielles réelles restent à qualifier.

Exécuter `bin/recovery.sh` pour consulter l’état sans le modifier. Avant de retirer
un verrou obsolète, établir que le processus indiqué et ses enfants OpenSSL sont
arrêtés. Ne jamais supprimer le marqueur de coupure pour débloquer un nouvel essai.
Si un plan vérifié possède un point de reprise durable, utiliser
`RECOVERY_ACTION=resume`. La seule présence de `ready` ne suffit pas : son empreinte
doit correspondre au point de reprise enregistré durablement.

Sinon, arrêter les opérations, conserver les preuves et suivre la revue hors ligne
ci-dessous. Un index ou compteur OpenSSL interrompu exige une réconciliation ;
l’absence de succès n’autorise ni nouvelle signature ni retour arrière du compteur.
Après cette revue, utiliser `RECOVERY_ACTION=acknowledge` avec le `RECOVERY_ID`
rapporté et une `RECOVERY_NOTE` explicative. Si un journal d’installation est aussi
présent, utiliser son identifiant d’opération. L’acquittement conserve un reçu privé
et synchronise l’état réconcilié avant de lever le blocage ; il ne répare ni ne
valide cet état de manière indépendante. Un marqueur illisible ou incomplet doit
être conservé pour expertise hors ligne, sans inventer d’identifiant.

La PKI active doit rester sur un seul système de fichiers local, sans écrivain
externe. Stockage réseau ou synchronisé, caches matériels ne respectant pas les
barrières et destruction du support ne sont pas couverts.

Le [contrat de fiabilité](../08-architecture-and-reliability.md) précise les limites
de validation et de persistance. La [publication](../07-lifecycle-and-migration.md)
définit séparément les reprises de CRL.

## Reprise automatique d’une installation vérifiée

Pour une installation de certificat terminal déjà validé, une levée de suspension
ou un rattachement du workspace dont le plan est complet :

```sh
RECOVERY_ACTION=resume bin/recovery.sh
```

`AUTO_RECOVER=1` active la même reprise avant la prochaine commande verrouillée.
Le rapport et les modes `DRY_RUN=1` restent en lecture seule. La reprise vérifie
l’intégralité des sources, des destinations et des états conservés avant la première
écriture ; elle accepte une destination déjà installée, refuse toute divergence et
revérifie les échéances des certificats/CRL. Aucun certificat n’est signé, aucune
CRL n’est régénérée et aucun compteur n’est diminué. Une reprise interrompue reste
reprenable. Son journal terminé est conservé dans `.recovery/completed-<ID>`.

Les journaux peuvent contenir des copies privées de clés (fichiers 400, répertoires
privés), en plus des preuves de publication. Les protéger et les conserver hors
Git, archives publiques et sauvegardes non protégées. Leur rétention est manuelle.
Un plan incomplet, une signature incertaine, une émission racine/intermédiaire ou
un mouvement d’autorité sans plan pris en charge reste soumis à l’examen ci-dessous.
Un verrou abandonné n’est jamais retiré automatiquement.

## Déplacement du workspace complet

Arrêter les opérations et résoudre les journaux en attente avant de déplacer le
dossier complet. Depuis le nouvel emplacement :

```sh
RECOVERY_ACTION=relocate bin/recovery.sh
RECOVERY_ACTION=relocate RELOCATE_APPLY=1 bin/recovery.sh
```

Le premier appel ne modifie aucun fichier du workspace. Le second verrouille,
valide les autorités racine, imbriquées et historiques, puis rattache leurs
configurations et liens absolus internes. Les clés, index et compteurs sont
conservés. Les politiques personnalisées sont préservées et les empreintes de
configuration dans `ca.meta`/`meta` sont actualisées. Aucune donnée de l’ancien
emplacement n’est modifiée. Les écritures concurrentes dans une ancienne copie
restent interdites. Les liens externes, états incomplets, chemins non pris en
charge et inclusions de configuration sont refusés. Une interruption après
préparation complète se termine avec `RECOVERY_ACTION=resume`.

## Émission ou déplacement interrompu

`bin/recovery.sh` affiche un rapport sans modifier la PKI ni créer de verrou.
Un journal en attente bloque les nouvelles mutations. Un verrou laissé par un
processus tué ne doit être retiré qu’après avoir établi que son propriétaire ne
travaille plus. Aucun vol automatique de verrou n’est effectué.

1. Arrêter les écritures externes et sauvegarder les éléments avant intervention.
   Examiner index.txt, serial, newcerts, fichiers temporaires, clés archivées et
   chemins du journal. Ne jamais restaurer un compteur inférieur pour réessayer.
2. Si le certificat a été émis, vérifier son archive et sa clé puis compléter les
   fichiers manquants avec ces mêmes artefacts. Ne pas signer un nouveau certificat
   uniquement parce que le message final de succès a été perdu.
3. Après un déplacement, localiser l’autorité active et les dossiers conservés.
   Restaurer le chemin lié à la configuration ou terminer explicitement le
   déplacement et le rattachement des chemins. Vérifier les paires, historiques,
   compteurs et liaisons d’émetteur. Aucun rollback automatique n’est fourni.
4. Après réconciliation, enregistrer l’examen avec l’identifiant exact du rapport :

```sh
RECOVERY_ACTION=acknowledge RECOVERY_ID=20260919T120000Z-1234 \
  RECOVERY_NOTE='Décrire les vérifications et la réconciliation effectuées' \
  bin/recovery.sh
```

Cette commande déplace le journal vers `.recovery/reviewed-<ID>` sous verrou.
Elle ne répare ni ne valide la PKI. Si l’identifiant n’a pas pu être écrit avant
l’interruption, conserver et déplacer manuellement le journal après le même examen.
Les reçus d’un lot de réémission peuvent nécessiter un examen distinct.

## Reprendre une publication de CRL

Réutiliser le PEM versionné indiqué par l’erreur, avec le même OUT_DIR et la
commande de publication prévue :

```sh
INT_DIR=intm-web-ca FINAL_CRL=crl/ca-<version>.crl.pem \
  PUBLISH_CMD='your-publisher %FILE%' bin/intm-publish-final-crl.sh
```

Aucun nouveau numéro de CRL n’est consommé. Les six artefacts sont retentés ; la
commande doit accepter les copies répétées. Examiner les reçus `.publication`.
Une CRL expirée exige une nouvelle génération. « Finale » reste indicatif : cela
n’interdit pas l’émission et ne met pas fin au service de révocation.

La reprise exige aussi le fichier original `.crl.pem.resume-state` et des octets
PEM, entrées révoquées et compteur de prochaine CRL inchangés. Une révocation
ultérieure ou l’avancement du compteur, même après un échec de génération, bloque
la reprise avant publication. Si cet état manque, notamment pour les CRL produites
par une ancienne version, relancer la commande initiale **sans FINAL_CRL**, avec
les mêmes OUT_DIR et PUBLISH_CMD, en respectant le contrôle des feuilles restantes.
Ne pas abaisser le compteur ni fabriquer un état de reprise. Un rafraîchissement
courant préserve les archives et remplace les alias PEM/DER ; leurs deux
remplacements restent des renommages distincts.
