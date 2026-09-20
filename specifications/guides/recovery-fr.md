# Reprise après interruption

Le [contrat de fiabilité](../08-architecture-and-reliability.md) précise les limites
de validation et de persistance. La [publication](../07-lifecycle-and-migration.md)
définit séparément les reprises de CRL.

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
