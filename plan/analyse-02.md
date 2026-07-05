# Analyse

Voici une analyse fraîche du projet, en repartant de zéro et en me basant sur l’état actuel du dépôt.

## Vue d’ensemble

Le projet est maintenant un vrai toolkit PKI Bash/OpenSSL assez bien structuré, avec 4 couches nettes :

- API utilisateur via [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:1)
- logique commune et génération de config dans [`bin/pki-env.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:1)
- workflows opérationnels dans `bin/gen-*.sh`, `verify.sh`, `revoke-*.sh`
- profils X.509 versionnés dans [`profiles/`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/profiles)

La grosse amélioration par rapport à un toolkit shell classique, c’est que les extensions OpenSSL ne sont plus enterrées dans les scripts: elles sont externalisées dans `profiles/root`, `profiles/intermediate` et `profiles/leaf`, puis assemblées dans les `openssl.cnf` générés par [`create_root_openssl_cnf_if_missing`]( /Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:768) et [`create_intermediate_openssl_cnf_if_missing`]( /Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:828). C’est le bon découpage pour faire évoluer les usages métier sans casser toute la plomberie CA.

## Ce qui est solide

L’interface publique est aujourd’hui lisible et cohérente: `server/user/dev/email/doc`, avec alias `code/archive`, plus des opérations de révocation, CRL, rollover et reissue exposées dans le [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:255). La résolution `ACTION -> KIND -> INT_DIR` et la validation des chemins sont bien centralisées dans [`bin/pki-env.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:159), avec des garde-fous utiles contre les chemins hors workspace.

La logique d’émission leaf dans [`bin/gen-leaf.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-leaf.sh:115) est assez mature: choix automatique de profils EC, déduplication des SAN, verrouillage léger, protection contre doublons CN, refus de signer avec un intermédiaire révoqué, vérification post-émission, fullchain, et modes spécialisés via wrappers (`SMIME_MODE`, `ARCHIVE_MODE`).

Côté qualité, la suite [`test/smoke.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/test/smoke.sh:1) est devenue un vrai filet de sécurité. Je l’ai relancée sur l’état actuel du dépôt, et `make test-smoke` passe entièrement. Elle couvre génération complète, profils RSA/EC, SAN URI/email, révocation, CRL, roots EdDSA, `ROOT_PATHLEN`, rekey d’intermédiaire, et validation des chemins.

## Points d’attention

Le point le plus subtil que je vois encore est autour de l’alias `archive`: dans le `Makefile`, il force `PROFILE=archive` par défaut ([`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:249), [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:319)), alors que [`bin/gen-archive.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-archive.sh:15) choisit normalement `archive_seal` ou `timestamping` selon `ARCHIVE_MODE`. En pratique, `make doc ARCHIVE_MODE=timestamp` fonctionne, mais `make archive ARCHIVE_MODE=timestamp` risque de rester collé au profil `archive`. Ce n’est pas bloquant pour le cœur du projet, mais c’est une incohérence réelle de surface.

L’autre point important est opérationnel: les `openssl.cnf` générés ne sont reconstruits que s’ils n’existent pas déjà ([`bin/pki-env.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:771), [`bin/pki-env.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:830)). Donc une modification dans `profiles/` n’impacte pas rétroactivement les PKI déjà générées. C’est défendable, mais il faut le considérer comme une règle d’exploitation: changement de profil = regeneration, rollover ou reissue, pas simple “mise à jour à chaud”.

## Conclusion

Le projet est aujourd’hui nettement plus propre qu’au premier passage: architecture claire, profils externalisés, vraie doc (`README`, `doc/`), et smoke tests crédibles. Je le classerais comme un toolkit shell PKI sérieux et exploitable, avec une seule incohérence fonctionnelle subtile encore visible autour de l’alias `archive`, et une contrainte opérationnelle à bien documenter sur la non-régénération automatique des `openssl.cnf` existants.

Si tu veux, je peux faire la suite logique: soit un audit “release readiness” plus strict, soit corriger directement le cas `make archive ARCHIVE_MODE=...`.

---
