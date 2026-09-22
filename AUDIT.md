> Complément du 22 septembre 2026 — émission générique : `make int-generic`
> crée l’autorité et `make generic` / `bin/gen-generic.sh` émettent avec un profil
> explicite obligatoire. La commande exige une autorité `generic`, conserve les
> contrôles communs et n’ajoute aucun SAN implicite. Deux nouveaux tests ciblés
> de la suite 12 réussissent sur PKI temporaires sous OpenSSL 3.6.4 ; aide Make,
> syntaxe, manifeste et diff vérifiés. Aucune PKI réelle modifiée ; campagne
> complète et smoke non relancés pour cet ajout.

> Complément du 22 septembre 2026 — contraintes d’émission : la catégorie de
> l’autorité contrôle désormais les usages des profils compilés et des certificats
> signés, y compris les réémissions intégrées. Les changements de catégorie par
> renouvellement, rollover ou rollback sont refusés. `generic` reste polyvalent ;
> les profils de sceau sans EKU et l’utilisation directe des clés hors Certnify
> ne constituent pas des domaines de confiance isolés. Aucun certificat de CA
> existant n’a été modifié. Validation : **29 tests distincts réussis**, par suites
> et relances ciblées, sur PKI temporaires sous OpenSSL 3.6.4. Syntaxe Bash/Python,
> manifeste, cibles des liens relatifs et diff vérifiés. Le smoke et la campagne
> complète n’ont pas été relancés ; aucune PKI réelle n’a été modifiée. Voir la
> [validation des contraintes d’émission](specifications/10-acceptance-and-traceability.md#issuance-category-validation-2026-09-22).

> Complément du 22 septembre 2026 — portée de la vérification : `VERIFY CHECKS`
> indique les contrôles demandés ; un résultat `OK` incomplet rappelle explicitement
> sa portée. Les valeurs par défaut et codes de sortie sont conservés. Les contrôles
> applicatifs restent disponibles individuellement ou imposés par le mode strict.
> Validation actuelle : trois tests ciblés de la suite 8 réussis sur PKI temporaires
> (identités DNS/IP/courriel/URI/sujet, usage, CRL, révocation, date de référence),
> sous OpenSSL 3.6.4 ; syntaxe Bash et contrôle du diff réussis. La suite complète
> et le smoke n’ont pas été relancés ; aucune PKI réelle n’a été modifiée.

> Complément du 21 septembre 2026 — résistance aux coupures : le protocole logiciel
> est implémenté. Un marqueur durable précède les modifications ; les barrières de
> persistance couvrent l’état local, y compris les index et compteurs OpenSSL.
> Après interruption, seules les installations disposant d’un point de reprise
> durable et vérifié peuvent reprendre ; les autres cas restent bloqués pour revue.
> Python 3.8+ devient une dépendance d’exécution. Validation : **115 tests distincts
> réussis** dans les suites 0 à 11, dont les 13 tests de durabilité, avec relances
> ciblées après les derniers ajustements. Le smoke a également réussi avant ces
> derniers ajustements, couverts par les tests ciblés. Syntaxe, manifeste, liens
> locaux et diff vérifiés. Les coupures matérielles réelles et Linux restent à qualifier.
> Voir la [validation de durabilité](specifications/10-acceptance-and-traceability.md#durability-validation-2026-09-21)
> et le [guide de reprise](specifications/guides/recovery-fr.md).

> Complément du 21 septembre 2026 — maintenance : la levée individuelle de
> `certificateHold`, la reprise des installations vérifiées (`AUTO_RECOVER=1` ou
> `RECOVERY_ACTION=resume`) et le rattachement d’un workspace déplacé hors ligne
> (`RECOVERY_ACTION=relocate`, prévisualisation puis `RELOCATE_APPLY=1`) sont implémentés.
> Les signatures incertaines, plans incomplets, verrous abandonnés et opérations
> sans plan de reprise pris en charge exigent encore un examen manuel.
> Les journaux terminés peuvent conserver des copies privées de clés ; ils restent
> protégés par permissions et exclus de Git. Voir le [guide de reprise](specifications/guides/recovery-fr.md).
> Validation actuelle : **101 cas de test distincts réussis** dans les suites 0 à 10,
> avec relances ciblées après ajustements. Contrôles de syntaxe Bash/Python,
> manifeste des sources, liens documentaires relatifs et diff réussis. Le smoke
> n’a pas été relancé ; aucune PKI réelle, coupure électrique ni plateforme distante
> n’a été testée. Voir la [traçabilité](specifications/10-acceptance-and-traceability.md#maintenance-validation-2026-09-21).

> Complément du 21 septembre 2026 — migration : la réémission par lot conserve
> désormais le sujet complet, les SAN, le profil effectif et les paramètres des
> clés à partir de sources vérifiées. Elle génère de nouvelles clés et refuse
> les métadonnées manquantes ou les profils incompatibles avant émission.
> Le comportement limité au CN exige `REISSUE_MODE=cn-only`.
> Validation actuelle : 40 scénarios distincts réussis sur des PKI temporaires,
> syntaxe Bash/Python et contrôle du diff réussis. La suite exhaustive et le smoke
> n’ont pas été relancés. Voir la [trace de validation](specifications/10-acceptance-and-traceability.md#preserving-migration-validation-2026-09-21).

> Mise à jour du 21 septembre 2026 : les quatre défauts ci-dessous sont corrigés.
> Les CRL obsolètes ne peuvent plus être reprises ; les archives restent intactes
> et les PEM/DER courants concordent ; le remplacement forcé publie un ensemble
> clé/CSR/certificat/chaîne cohérent ; les archives durent 3600 jours par défaut.
> Dix tests ciblés ont réussi, ainsi que la syntaxe Bash et le contrôle du diff.
> La suite complète n’a pas été relancée. Les anciennes CRL finales sans état de
> reprise doivent être régénérées. Voir la [validation détaillée](specifications/10-acceptance-and-traceability.md).
>
> Hors complément migration ci-dessus, le texte conserve les constats de l’audit initial ;
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
- Sauvegarde/restauration intégrée, haute disponibilité, transactions multifichiers atomiques et coordination entre plusieurs machines.
- Rotation de la racine, intégration aux autorités publiques, Certificate Transparency et export PKCS#12.
- Signature effective des logiciels/documents, chiffrement des messages et service d’horodatage : seuls les certificats correspondants sont produits.

Même dans son périmètre, certains cas restent non couverts :

- Migration de certificats sans certificat source ou sans profil archivé : le mode conservateur refuse ces cas. La réémission conserve désormais le sujet, les SAN, le profil effectif et les paramètres cryptographiques pour les sources vérifiables ; le mode limité au CN reste une option explicite. Les politiques externes de stockage des clés (HSM, chiffrement) restent hors périmètre.
- Récupération d’un résultat de signature incertain, des opérations sans plan complet et des verrous abandonnés ; déplacement du workspace en cours d’utilisation. La levée individuelle de `certificateHold`, la reprise des installations vérifiées et le rattachement explicite d’un workspace déplacé hors ligne sont désormais implémentés.
- Reconstitution automatique de la confiance et des preuves de révocation historiques. La vérification URI exacte, la date de référence explicite (`VERIFY_ATTIME`) et le mode strict avec sujet RFC2253 attendu (`VERIFY_SUBJECT`) sont désormais disponibles ; les CRL couvrant la date choisie doivent être conservées.
- Ensemble des syntaxes internationales DN/SAN, hiérarchies avec plusieurs niveaux d’intermédiaires et qualification de toutes les plateformes/OpenSSL acceptés.

Au-delà des bogues, plusieurs limites de sécurité doivent être prises en compte :

- Les clés privées non chiffrées reposent entièrement sur la protection du poste et du système de fichiers.
- La vérification par défaut conserve un contrôle de chaîne sans imposer de paramètres supplémentaires. Le rapport `VERIFY CHECKS` explicite les contrôles demandés et un succès incomplet rappelle sa portée limitée. Révocation, identité attendue et usage sont disponibles explicitement ; `VERIFY_MODE=strict` les rend obligatoires. L’identité et l’usage doivent être fournis selon le besoin réel de l’application, sans être déduits du certificat présenté. [Référence OpenSSL](https://docs.openssl.org/3.3/man1/openssl-verification-options/)
- Les catégories `web`, `auth`, `code`, `smime` et `archive` imposent désormais des contraintes d’émission dans Certnify, contrôlées sur les extensions compilées et lors des réémissions intégrées. `generic` reste volontairement polyvalent ; les sceaux `archive` sans EKU ne garantissent pas une séparation des usages côté client. Les certificats de CA restent sans contraintes d’usage propres à la catégorie : l’emploi direct des clés hors de l’outil n’est pas cloisonné, et aucun certificat existant n’est modifié. Voir le chapitre 04.
- Toute écriture de l’état PKI doit passer par le toolkit : les écritures externes sont interdites par le contrat d’exploitation (spécifications, chapitre 01). Leur exclusion exige un cloisonnement des accès système ; le verrouillage actuel ne l’impose pas à un processus disposant des mêmes droits. Le protocole logiciel de résistance aux coupures est implémenté : marqueur durable avant modification, barrières de persistance et reprise limitée aux plans durablement préparés. Une interruption incertaine bloque les nouvelles opérations. Il ne fournit ni réparation automatique des index OpenSSL, ni protection contre une altération volontaire ; les coupures matérielles réelles restent à qualifier (chapitre 08).

L’implémentation possède néanmoins de bonnes protections : contrôle des clés, validation des entrées, verrouillage commun, conservation des émetteurs historiques et blocage après émission incertaine.

Validation réalisée : **13 tests des suites 0 et 1 réussis et quatre reproductions ciblées** sous OpenSSL 3.6.4. La campagne générale a été interrompue pendant la suite 2 ; elle n’est donc pas déclarée validée. Cet audit ne constitue pas une preuve d’absence d’autres défauts.
