# Selecting certificate profiles

The [cryptographic specification](../04-cryptography-and-profiles.md) defines
exact extension values, aliases, key compatibility and SAN validation. This guide
shows the command interface; it does not define a second extension policy.

Generate the required root and intermediate first. Typical issuance commands:

```sh
make server CN=app.example.test KEY_ALG=EC SAN_DNS=app.example.test,api.example.test
make user CN=user@example.test KEY_ALG=Ed25519
make code CN="Signing Key" KEY_ALG=EC
make email CN=user@example.test SMIME_MODE=sign KEY_ALG=EC
make email CN=encrypt@example.test SMIME_MODE=encrypt KEY_ALG=RSA
make archive CN="Document Seal" ARCHIVE_MODE=seal KEY_ALG=EC DAYS=3600
make archive CN="Timestamp Signer" ARCHIVE_MODE=timestamp KEY_ALG=EC DAYS=3600
```

Server/client defaults follow the actual key, including reused keys. Encryption
and legacy combined S/MIME require RSA. `code`/`dev` and `archive`/`doc` are aliases.
PROFILE selects an explicit installed section; EXT_SECTION takes precedence.
Incompatible key/profile combinations fail rather than silently changing usage.
An explicit SAN or SAN_* list suppresses the default CN SAN. Quote shell arguments;
quotes in CN are data, not a safe substitute for shell quoting.

The profile must also match the authority's recorded category. Changing PROFILE,
EXT_SECTION or caller KIND cannot make a web authority issue codeSigning leaves.
Custom sections are checked using compiled extensions. Create an intentionally
multipurpose authority with KIND=generic; this does not isolate usage trust domains.

Profile fragments under `profiles/` compose new configurations only. To change an
existing authority, retain its current configuration, review intended extension
changes, then explicitly edit the installed openssl.cnf. Do not overwrite operator
customizations by copying a new template indiscriminately. The next operation
validates configuration structure; that validation is not approval of your policy.
Per-leaf configuration snapshots retain the actual emission policy for inspection.
