# Audit de Certnify — état après les étapes 1 et 2

Date et heure de mise à jour de l’audit : **20 septembre 2026 à 21:48:26 CEST (UTC+02:00, Europe/Paris)**.

Périmètre examiné : **état de travail local**, comprenant les corrections non commitées et les nouveaux fichiers, sur la base Git `2c944a83c6bb965dd0b2ab3856359405232d2be1`. Cette révision Git seule ne contient donc pas les corrections décrites ici.

Audit initial : 20 septembre 2026 à 20:20:01 CEST. Dernière validation fonctionnelle terminée à **21:42:56 CEST**. Cette mise à jour documentaire s’appuie sur une relecture ciblée du code et sur les validations réalisées pendant les deux étapes ; elle ne constitue pas une nouvelle campagne exhaustive de tests. Les autorités opérationnelles n’ont pas été modifiées.

## 1. Ce que fait la solution

Certnify est un outillage local Bash/Make utilisant OpenSSL pour administrer une PKI privée : racine, intermédiaires, émission, vérification, révocation, CRL et remplacement des intermédiaires. Il produit les certificats destinés aux applications ; il n’exécute pas ces applications.

## 2. Réponse à la problématique et exhaustivité

**La solution couvre largement une PKI privée administrée manuellement. Les six défauts reproduits lors de l’audit initial sont corrigés dans les scénarios vérifiés ; les cinq renforcements d’opérations courantes ont également été réalisés. Elle ne constitue toujours pas une gestion complète de PKI.**

L’évaluation porte sur le périmètre annoncé par le dépôt, sans cahier des charges externe. Les fonctionnalités suivantes restent absentes ou hors périmètre :

- Enrôlement distant, contrôle de possession d’une identité, signature administrée de CSR externes, ACME/EST/SCEP, API et interface utilisateur.
- Renouvellement planifié, alertes d’expiration, déploiement des certificats, installation de la confiance et configuration des applications.
- OCSP, téléchargement des CRL, ajout automatique des points de distribution/AIA, Certificate Transparency et intégration à une autorité publique.
- HSM/PKCS#11, workflow de clés chiffrées, racine hors ligne avec transfert administré, séparation des rôles et approbation multiple.
- Export PKCS#12, signature effective de logiciels/documents, chiffrement du courrier et service d’horodatage.
- Rotation de racine, hiérarchies arbitraires de sous-autorités, migration fidèle des certificats et restitution depuis `certificateHold`.
- Sauvegarde/restauration administrée, haute disponibilité, réplication, transaction atomique multifichier, durabilité après coupure électrique et reprise automatique.
- Journal inviolable, gestion multiutilisateur, conformité réglementaire ou certification de sécurité.

Ces exclusions ne sont pas toutes des bogues : plusieurs correspondent au modèle d’outil local retenu. Sources : [périmètre](specifications/01-scope-and-domain.md), [limitations](specifications/09-compatibility-and-limitations.md).

## 3. Exactitude des fonctionnalités et état des corrections

### Défauts de l’audit initial

Les identifiants A01–A06 sont conservés pour la traçabilité. Leurs anciennes priorités P1/P2 concernaient le code avant correction ; ils ne constituent plus la liste des problèmes ouverts.

| ID | Défaut initial | État actuel et contrôle réalisé |
| --- | --- | --- |
| A01 | Recréation d’un état perdu et réutilisation d’un numéro de série | **Corrigé dans les cas testés.** Initialisation séparée de l’ouverture ; refus d’état/configuration manquant et de collision numérique avec les certificats, liaisons et archives conservés avant signature. Comparaison des états avant/après refus. |
| A02 | Injection de commandes par des paramètres Make | **Corrigé pour le passage des paramètres PKI publics testé.** Valeurs transmises littéralement par environnement ; validation des scalaires. Tests de substitutions Make, backticks, guillemets, espaces et nouvelles options de l’étape 2. Makefiles, options de Make et hooks explicites restent du code administrateur. |
| A03 | RSA faible accepté avec vérification positive | **Corrigé.** Minimum RSA 2048 bits pour génération/réutilisation, contrôle des paramètres effectifs et vérification explicite au niveau de sécurité 2. Tests de clés faibles nouvelles, réutilisées et de certificats importés ; refus du rollover faible avant déplacement. |
| A04 | SAN demandé remplacé silencieusement par le profil | **Corrigé pour la conformité SAN.** Compilation préalable, refus des conflits, puis comparaison des ensembles typés après signature avant installation. Un écart tardif conserve l’émission dans l’historique et le journal de reprise. La conformité exhaustive de toutes les extensions d’un profil personnalisé n’est pas démontrée. |
| A05 | DN UTF-8 corrompu et idempotence rompue | **Corrigé.** Validation UTF-8, requêtes explicites `-utf8`, comparaisons RFC2253 cohérentes. Cas accentués, non latins, caractères spéciaux, relance, sélection et révocation testés. Pas de normalisation Unicode générale. |
| A06 | Échec après émission de l’intermédiaire sans KIND | **Corrigé.** Initialisation de KIND et tests de création puis relance par appel direct sans sélecteur. |

Sources : [état et numéros de série](bin/pki-state.sh), [Makefile](Makefile), [validation des entrées](bin/pki-input.sh), [politique cryptographique et SAN](bin/pki-policy.sh), [bibliothèque commune](bin/pki-env.sh), [émission des feuilles](bin/gen-leaf.sh), [émission des intermédiaires](bin/gen-intm.sh), [tests A01–A06](test/stage7.py).

### Opérations courantes renforcées

| Sujet | État actuel | Limite conservée |
| --- | --- | --- |
| `clean` | Aperçu sans modification par défaut ; `CLEAN_APPLY=1` applique après validation du plan sous verrou. Candidats bornés à root, out et autorités intm-* reconnues à la racine du workspace. Liens symboliques et autorités reconnues incomplètes refusés. | Suppression des clés et historiques comprise ; sauvegarde manuelle. Suppression séquentielle sans restauration automatique en cas d’échec partiel. Chemins personnalisés hors périmètre. |
| Validité | Contrôle de la chaîne émettrice actuelle, signature racine et contraintes CA/signature ; refus de DAYS au-delà de l’expiration la plus proche, avec date et maximum en jours entiers. Dates de signature fixées lors du contrôle préalable. | Aucun plafonnement silencieux ni renouvellement automatique de l’émetteur ; une demande auparavant acceptée peut désormais échouer. |
| Vérification applicative | Identité attendue par `VERIFY_DNS`, `VERIFY_IP` ou `VERIFY_EMAIL`, usage par `VERIFY_PURPOSE`. `VERIFY_MODE=strict` exige identité SAN et usage précis, contrôles X.509 stricts et CRL valides de toute la chaîne. | Vérification ordinaire sans révocation par défaut ; `info` reste informatif. Usages disponibles dépendants du backend, sans téléchargement de CRL ni validation de possession de l’identité. |
| Batch | SAN email implicite ajouté uniquement aux CN contenant @ ; les noms de personnes sans adresse ne reçoivent plus un SAN email invalide. Avertissement CN-only conservé. | Réémission toujours limitée au CN, sans restitution du sujet complet, de tous les SAN ou de la politique d’origine. |
| CRL historiques | `CRL_HISTORY=1` renouvelle explicitement la racine et les émetteurs courants/historiques sélectionnés. Prévalidation des configurations, index, clés, empreintes, liaisons et destinations. | Découverte globale limitée aux autorités intm-* configurées, y compris legacy ; autres chemins à sélectionner explicitement. Remplacements individuels, sans garantie de publication distante. |

Sources : [nettoyage](bin/pki-clean.sh), [validité](bin/pki-validity.sh), [conversion UTC](bin/pki-time.awk), [vérification](bin/verify.sh), [batch](bin/intm-reissue-leafs.sh), [CRL historiques](bin/pki-crl-history.sh), [tests des opérations courantes](test/stage8.py).

## 4. Faiblesses de sécurité et cas restant à traiter

Les points suivants sont des limites actuelles, des risques d’exploitation ou des besoins de déploiement. Ils ne sont pas présentés comme de nouvelles vulnérabilités reproduites pendant cette mise à jour.

| Sujet | Limite ou risque actuel | Action restante |
| --- | --- | --- |
| Protection des secrets | Clés non chiffrées, racine et intermédiaires dans le même espace, anciennes clés conservées. Les permissions Unix ne protègent pas d’un processus compromis sous le même compte. | Séparer la racine selon le déploiement ; prévoir chiffrement/HSM, sauvegardes protégées, accès distincts et politique de conservation/destruction. |
| Modes de vérification | `normal` ne contrôle pas automatiquement nom, usage et révocation ; `info` peut retourner zéro pour une chaîne invalide. | Employer le mode strict avec attentes explicites dans les automatisations ; adapter les consommateurs qui interprètent `info` comme une validation. |
| Cloisonnement des usages | Les catégories web/auth/etc. sont des conventions ; tous les profils sont disponibles dans chaque intermédiaire. Pas de contraintes de noms ni de contrôle de possession des identités. | Restreindre les profils, imposer les contraintes et valider les identités si ces catégories doivent former des frontières de sécurité. |
| Conformité complète d’émission | La comparaison SAN, les contrôles de clés, de profils et de chaîne ne constituent pas une comparaison exhaustive du sujet et de toutes les extensions du certificat avec une politique attendue indépendante. | Étendre les assertions après émission au sujet, aux usages et aux contraintes personnalisées selon le niveau d’assurance recherché. |
| Anciens certificats et clés | Les corrections ne réparent pas les certificats déjà émis avec identité, SAN, durée ou force cryptographique inadéquats. | Inventorier ces données, définir les remplacements/révocations et exécuter une migration explicitement autorisée. |
| Commandes privilégiées | `ISSUE_CMD`, `PUBLISH_CMD`, les configurations et l’invocation de Make restent sous contrôle de l’administrateur. | Ne pas exposer ces mécanismes à des entrées non fiables ; isoler et limiter les droits d’un éventuel service enveloppant l’outil. |
| Nettoyage et sauvegardes | L’application explicite de clean reste destructive et peut être partielle ; aucune sauvegarde/restauration administrée n’est fournie. | Prévoir et tester des sauvegardes avant suppression ; organiser la restauration et la réconciliation des autorités incomplètes. |
| CRL et publication | Renouvellement historique explicite mais non planifié ; clés historiques nécessaires ; CRL « finale » sans retraite permanente. Livraison distante jugée sur le code retour du hook. | Orchestrer toutes les autorités nécessaires, surveiller les échéances, définir le retrait et contrôler effectivement la livraison distante. |
| Traçabilité | Fichiers et journaux modifiables par leur propriétaire, sans preuve d’intégrité externe. | Ajouter un journal externe et une politique d’accès si une traçabilité opposable est requise. |

Sources : [vérification/révocation](specifications/06-verification-and-revocation.md), [cycle de vie](specifications/07-lifecycle-and-migration.md), [fiabilité](specifications/08-architecture-and-reliability.md), [limites](specifications/09-compatibility-and-limitations.md).

## 5. Faiblesses algorithmiques, robustesse et limites fonctionnelles

**Les défauts algorithmiques reproduits A01, A04, A05 et A06 ont des corrections et des tests de régression. Cela ne démontre pas l’absence d’autres bogues ni la couverture de toutes les combinaisons de paramètres.** Les limites suivantes subsistent :

| Sujet | Cas non couvert ou garantie absente | Travail à prévoir |
| --- | --- | --- |
| Reconstruction d’état | Refus des fichiers manquants et des collisions détectées, sans réconciliation exhaustive d’un index/historique tronqué mais encore syntaxiquement valide. | Procédure explicite de comparaison index/certificats/liaisons/révocations, sans remise à zéro des compteurs. |
| Persistance et reprise | Pas de transaction multifichier ni de `fsync` ; une signature, révocation, suppression ou génération de CRL peut être acquise avant un échec ultérieur. | Étendre les garanties de persistance selon les besoins ; tester disque plein, restauration et coupure. Ne pas assimiler un échec à un rollback. |
| Concurrence et charge | Verrou global au workspace ; index relus et nombreux processus OpenSSL. Pas de verrou distribué ni de protection contre un écrivain externe. Aucune mesure de charge. | Réserver les écritures aux outils coordonnés, mesurer les volumes cibles et adapter stockage/verrouillage si nécessaire. |
| Migration | Réémission CN-only ; sujet complet, SAN supplémentaires, extensions, dates et politique d’origine non conservés. | Concevoir une migration depuis les champs décodés, avec plan explicite et validation préalable de toutes les lignes. |
| Formats d’entrée | DN bornés à CN/C/O/OU ; SAN DNS/IP/email/URI avec listes séparées par virgules. Pas d’IDNA automatique, de normalisation Unicode, d’otherName ou de syntaxe complète mailbox/URI. | Élargir les formats seulement selon un contrat défini, avec refus explicite des cas non pris en charge. |
| Numéros de série et imports | Séries limitées à 64 bits ; imports ambigus ou sans CN unique refusés. Pas d’import général ni de déplacement arbitraire automatique du workspace. | Prévoir des procédures d’import/migration contrôlées si ces cas sont requis. |
| Découverte des autorités | clean et crl-all n’effectuent pas un inventaire récursif de toutes les autorités possibles ; les chemins personnalisés exigent un traitement explicite. | Tenir un inventaire de déploiement et orchestrer chaque autorité nécessaire. |
| Portabilité | Parsing des sorties OpenSSL et comportements Bash/AWK qualifiés seulement sur l’environnement testé. Le contrôle de version accepté ne vaut pas qualification. | Exécuter les suites sur chaque couple OS/backend ciblé et suivre les versions effectivement supportées. |

Les protections déjà en place restent utiles : verrou commun, contrôle des chemins/configurations, comparaison textuelle des séries, sélection exacte des CN, liaisons aux générations d’émetteurs, installations préparées, journaux de reprise et reçus de batch. Elles limitent les risques sans remplacer les garanties absentes ci-dessus.

## 6. Vérifications réalisées et portée de la conclusion

Dernière campagne fonctionnelle terminée le **20 septembre 2026 à 21:42:56 CEST**, sur macOS, Bash 3.2.57, GNU Make 3.81, OpenSSL 3.6.4 et Python 3.14.7 pour les tests.

| Validation | Résultat disponible |
| --- | --- |
| Suites `test-stage0` à `test-stage6` | 55 tests réussis : respectivement 4, 9, 6, 8, 9, 8 et 11 |
| Suite `test-stage7` | 13 tests réussis, couvrant notamment A01–A06 et le transport des nouvelles options |
| Suite `test-stage8` | 11 scénarios validés ; sept au premier passage, trois après correction et relance ciblée, puis un cas supplémentaire d’autorité personnalisée |
| Total | **79 scénarios validés** |
| `make test-smoke` | **Réussi**, dont rekey, révocation et réémission d’intermédiaire |
| Syntaxe et différences | 29 scripts Bash et les deux suites Python modifiées vérifiés ; `git diff --check` sans erreur lors de la clôture des corrections |

Les scénarios vérifient notamment les refus sans mutation, les clés faibles, les SAN avant/après signature, l’UTF-8, les durées limitées par la chaîne, le mode strict, les CRL historiques, les erreurs de backend, les interruptions et les commandes sur chemins personnalisés. Ils utilisent des copies temporaires depuis un manifeste de sources et des clés générées pour les essais. Aucun matériel opérationnel n’a servi de fixture ni été migré.

**Non validés :** clients/services réels TLS, S/MIME, signature ou horodatage ; publication réseau réelle ; HSM ; autres versions de backend/OS ; charge ; système de fichiers réseau ; coupure électrique. Il ne s’agit ni d’une certification de sécurité ni d’un audit exhaustif de l’historique Git ou des données opérationnelles.

La présente mise à jour a relu les contrôles concernés et les journaux de validation disponibles. Elle ne prétend pas avoir relancé les 79 scénarios. Source des commandes et de la couverture : [tests](test/README.md), [acceptation et traçabilité](specifications/10-acceptance-and-traceability.md).

## 7. Traçabilité — première étape

Clôture : **20 septembre 2026 à 21:06:55 CEST**. Corrections A01–A06 et ajout de la suite `test-stage7`. Bilan de cette étape : 68 tests et smoke réussis. Une erreur de tableau vide sous Bash 3.2 sur le chemin sans SAN a été corrigée et couverte par un test supplémentaire.

Les constats initiaux portaient sur l’état antérieur aux corrections. Leurs preuves de reproduction ne décrivent plus le comportement courant ; leur statut actualisé figure en section 3. Les anciennes références de lignes ont été remplacées par des liens vers les sources actuelles.

## 8. Traçabilité — deuxième étape et suites recommandées

Clôture : **20 septembre 2026 à 21:42:56 CEST**. Renforcement de clean, de la validité, de la vérification applicative, du batch et des CRL historiques ; ajout de `test-stage8`. Bilan cumulé : **79 scénarios validés et smoke réussi**.

Changements de compatibilité à retenir : application explicite de clean, refus des durées excessives, mode strict exigeant identité/usage/CRL, renouvellement historique sur option, batch toujours CN-only. Les README et spécifications donnent les exemples ; aucune ancienne clé ou ancien certificat n’a été remplacé automatiquement.

Les prochains travaux doivent être choisis selon le déploiement :

1. **Protection et exploitation :** secrets, sauvegardes/restauration, inventaire des autorités, emploi du mode strict, surveillance et livraison des CRL.
2. **Identité et politique :** cloisonnement des usages, validation de possession, conformité complète d’émission et migration fidèle.
3. **Garanties opérationnelles :** réconciliation d’état, durabilité, qualification multi-plateforme, charge et traçabilité externe.

A01–A06 ne sont plus à présenter comme des corrections encore à réaliser. Les risques et exclusions ouverts sont ceux des sections 2, 4 et 5, à distinguer des protections déjà implémentées et vérifiées.
