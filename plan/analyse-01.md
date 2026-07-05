# Analyse

## Vue d’ensemble

Le projet est un toolkit PKI en Bash/OpenSSL, piloté principalement par [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:1). L’architecture est simple et saine: `make` sert d’API utilisateur, `bin/pki-env.sh` centralise les helpers et la génération des configs OpenSSL, puis les scripts `gen-root.sh`, `gen-intm.sh`, `gen-leaf.sh`, `verify.sh`, `revoke-*.sh` implémentent le cycle de vie des certificats.

Le dépôt source est propre: les artefacts sensibles/générés (`root/`, `intm-*`, `draft/`) sont ignorés par [`.gitignore`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/.gitignore:1), et `git status` est vide. Les dossiers `root/` et `intm-web-ca/` présents localement ressemblent bien à des sorties de génération, pas à du code versionné.

## Points d’attention

- Interface incohérente entre doc et implémentation: la doc et `make help` annoncent `make code` et `make archive`, mais les vraies cibles sont `make dev` et `make doc` dans le `Makefile`. `make -n code` échoue bien avec “No rule to make target `code`”. Voir [`README.md`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/README.md:61), [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:96), [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:204).

- Probable bug fonctionnel sur les profils non serveur: `gen-leaf.sh` attend `code_sign`, `smime` et `archive` pour `dev/email/doc`, mais les configs générées dans [`bin/pki-env.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:667) ne définissent que `[ server_cert ]` et `[ client_cert ]`. Donc l’émission de certificats code signing, S/MIME ou archive risque d’échouer ou de dépendre d’une config non documentée. Voir [`bin/gen-leaf.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-leaf.sh:112) et [`bin/pki-env.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/pki-env.sh:667).

- Les wrappers `gen-user.sh`, `gen-code.sh`, `gen-email.sh`, `gen-archive.sh` ont des fallbacks de `PROFILE` incohérents: ils injectent tous `server_cert` par défaut, même quand l’action est `user`, `dev`, `email` ou `doc`. `gen-leaf.sh` corrige souvent ça ensuite, mais appelé différemment, ce comportement peut produire de mauvaises extensions. Voir [`bin/gen-user.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-user.sh:14), [`bin/gen-code.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-code.sh:14), [`bin/gen-email.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-email.sh:14), [`bin/gen-archive.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/gen-archive.sh:14).

- Le `Makefile` annonce une commande `verify-intermediate-revoked`, mais je n’ai trouvé aucune cible correspondante. Voir [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:54).

- La cible `rollback-%` est incomplète et finie sur un `LEGACY` nu, donc inutilisable en l’état. `make -n rollback-web` révèle directement cette recette tronquée. Voir [`Makefile`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/Makefile:512).

- Petite dette d’interface: `make verify` transmet `CHAIN=...`, mais [`bin/verify.sh`](/Users/glendale/Library/CloudStorage/SynologyDrive-Projects/Dev/Certnify/bin/verify.sh:73) ne l’utilise pas du tout. Ça ressemble à une option morte.

## Conclusion

Le socle du projet est bon: structure claire, scripts factorisés, garde-fous utiles dans `gen-leaf.sh` et `pki-env.sh`, et un vrai effort pour couvrir émission, vérification, révocation, CRL et rollover. En revanche, l’interface publique n’est pas totalement alignée avec le code, et il y a au moins 2 sujets à corriger vite: les noms de cibles documentés, et les profils OpenSSL manquants pour `dev/email/doc`.

---
