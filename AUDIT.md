> Mise à jour du 21 septembre 2026 : les quatre défauts ci-dessous sont corrigés.
> Les CRL obsolètes ne peuvent plus être reprises ; les archives restent intactes
> et les PEM/DER courants concordent ; le remplacement forcé publie un ensemble
> clé/CSR/certificat/chaîne cohérent ; les archives durent 3600 jours par défaut.
> Dix tests ciblés ont réussi, ainsi que la syntaxe Bash et le contrôle du diff.
> La suite complète n’a pas été relancée. Les anciennes CRL finales sans état de
> reprise doivent être régénérées. Voir la [validation détaillée](specifications/10-acceptance-and-traceability.md).
>
> Le texte qui suit conserve les constats et la validation de l’audit initial ;
> ses défauts et références de lignes décrivent l’état antérieur aux corrections.

Certnify est un outil local de gestion d’une **PKI privée** : création des autorités, émission, vérification, révocation et renouvellement des certificats via Bash/Make et OpenSSL.

**Verdict : le périmètre est clairement délimité, mais la solution n’est ni exhaustive ni entièrement correcte. Quatre défauts ont été reproduits, dont un permettant de déclarer valide un certificat révoqué.** Aucun fichier du projet n’a été modifié.

Les problèmes à corriger, par priorité :

| Priorité | Constat reproduit | Correction nécessaire |
|---|---|---|
| **Élevée — sécurité** | Reprendre la publication d’une ancienne CRL avec `FINAL_CRL` rétablit une liste antérieure aux dernières révocations. Un certificat passe de `REVOKED` à `OK`, même avec `VERIFY_CRL=1`. | Refuser toute régression de CRL et vérifier sa cohérence avec les révocations actuelles avant de remplacer les liens ou republier. [Code](/Users/geebe/Personal/Projects/Dev/Certnify/bin/intm-publish-final-crl.sh:22) |
| **Élevée — intégrité** | Après publication finale, une révocation peut suivre le lien `ca.crl.pem` et **écraser la CRL versionnée**. Son DER et ses empreintes restent ceux de l’ancienne version. | Séparer les archives des sorties courantes ; remplacer le lien sans modifier sa cible ; maintenir la cohérence PEM/DER/empreintes. [Code](/Users/geebe/Personal/Projects/Dev/Certnify/bin/revoke-leaf.sh:137) |
| **Moyenne — fonctionnement** | Avec `FORCE_NEW_KEY=1`, le nouveau certificat reçoit un nom suffixé, mais la nouvelle clé remplace la clé habituelle. Les chemins usuels du certificat et de la clé deviennent incompatibles, malgré un succès annoncé. | Versionner ensemble clé, certificat et chaîne, puis fournir une référence cohérente vers le nouvel ensemble. [Code](/Users/geebe/Personal/Projects/Dev/Certnify/bin/gen-leaf.sh:569) |
| **Moyenne — paramètres par défaut** | L’intermédiaire d’archive et ses certificats ont tous deux une durée par défaut de 3 650 jours. Dès que du temps s’écoule, l’émission est refusée car le certificat dépasserait l’expiration de l’intermédiaire. | Choisir des durées par défaut compatibles, en conservant le contrôle de validité. [Code](/Users/geebe/Personal/Projects/Dev/Certnify/bin/gen-archive.sh:35) |

La solution ne couvre pas une exploitation PKI complète. Les sujets absents sont :

- Enrôlement distant, ACME, traitement de CSR externes et validation de l’identité ou de la propriété des domaines.
- Renouvellement planifié, supervision, alertes d’expiration, déploiement des certificats et installation de la confiance.
- Serveur OCSP, distribution automatique des CRL et configuration standard des points AIA/CDP.
- HSM, clés chiffrées, gestion des secrets, rôles applicatifs et séparation des responsabilités.
- Sauvegarde/restauration intégrée, haute disponibilité, transactions durables et coordination entre plusieurs machines.
- Rotation de la racine, intégration aux autorités publiques, Certificate Transparency et export PKCS#12.
- Signature effective des logiciels/documents, chiffrement des messages et service d’horodatage : seuls les certificats correspondants sont produits.

Même dans son périmètre, certains cas restent non couverts :

- Migration conservant intégralement sujet, SAN, profil et politique de clés : la réémission par lot est limitée au CN.
- Levée d’une suspension `certificateHold`, récupération automatique après incident et déplacement arbitraire du workspace.
- Vérification d’identité URI, vérification à une date historique et mode strict adapté aux certificats sans identité DNS/IP/email.
- Ensemble des syntaxes internationales DN/SAN, hiérarchies avec plusieurs niveaux d’intermédiaires et qualification de toutes les plateformes/OpenSSL acceptés.

Au-delà des bogues, plusieurs limites de sécurité doivent être prises en compte :

- Les clés privées non chiffrées reposent entièrement sur la protection du poste et du système de fichiers.
- La vérification par défaut contrôle la chaîne, sans imposer révocation, identité attendue et usage. Ces contrôles doivent être explicitement exigés selon l’application. [Référence OpenSSL](https://docs.openssl.org/3.3/man1/openssl-verification-options/)
- Les catégories `web`, `code`, etc. ne constituent pas un cloisonnement cryptographique : prévoir des contraintes d’émission si cette séparation est recherchée.
- Le verrouillage et les journaux protègent les opérations du toolkit, sans garantir l’intégrité face aux écritures externes, à une coupure électrique ou à une altération volontaire.

L’implémentation possède néanmoins de bonnes protections : contrôle des clés, validation des entrées, verrouillage commun, conservation des émetteurs historiques et blocage après émission incertaine.

Validation réalisée : **13 tests des suites 0 et 1 réussis et quatre reproductions ciblées** sous OpenSSL 3.6.4. La campagne générale a été interrompue pendant la suite 2 ; elle n’est donc pas déclarée validée. Cet audit ne constitue pas une preuve d’absence d’autres défauts.