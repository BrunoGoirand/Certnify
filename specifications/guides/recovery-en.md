# Recovery procedures

The [reliability contract](../08-architecture-and-reliability.md) defines commit
boundaries; [publication](../07-lifecycle-and-migration.md) defines CRL retries.

## Explicit review and recovery

`bin/recovery.sh` defaults to a read-only report: no lock creation and no PKI
mutation. It can be used even when a stale lock remains. Read-only dry-run plans
are still advisory snapshots, including while recovery is pending.

1. Stop concurrent external writers and inspect the reported paths, current
   issuer index, `serial`, `newcerts`, pending temporary files and archived keys.
   Preserve a backup before manual reconciliation. Treat any OpenSSL `.new` or
   `.old` database files as evidence, never as automatic rollback instructions.
2. If the serial was issued, validate the archived certificate and matching key.
   Finish its missing named artifact, issuer binding, policy record, chain or
   metadata using those exact artifacts; do not sign another certificate merely
   to replace a lost success response. If signing did not commit, retain the
   current counter and preserve any prepared key before a reviewed retry.
3. After a move, locate both active and legacy/backup directories. Restore the
   old directory to its original configuration-bound path, or manually complete
   the intended move and rebind configuration paths. Validate key/certificate
   pairs, generation bindings and counters. An incomplete active directory must
   never be blindly rolled over again. No automated lifecycle rollback is offered.
4. Record the completed review using the exact ID printed by the report:

   ```sh
   RECOVERY_ACTION=acknowledge RECOVERY_ID=20260919T120000Z-1234 \
     RECOVERY_NOTE='Describe the artifacts inspected and reconciliation performed' \
     bin/recovery.sh
   ```

Acknowledgment takes the workspace lock and moves the journal to
`.recovery/reviewed-<ID>`. It **does not validate or repair** CA state. It is an
explicit administrator assertion that reconciliation is complete, not a retry
flag. A missing/mismatched ID or empty note fails. Preserve reviewed journals;
they may contain certificate identities and paths but never private key bytes.
They are Git-ignored and excluded from source packages. If interruption occurred
before an operation ID was written, retain and manually relocate the incomplete
journal after the same review; acknowledgment cannot invent a missing ID.

## Resume CRL publication

After a conversion, alias or publisher failure, use the retained versioned PEM
reported in the error, with the same OUT_DIR and intended PUBLISH_CMD:

```sh
INT_DIR=intm-web-ca FINAL_CRL=crl/ca-<version>.crl.pem \
  PUBLISH_CMD='your-publisher %FILE%' bin/intm-publish-final-crl.sh
```

This reuses the existing valid CRL without consuming another CRL number. All six
artifacts are attempted again; the publisher must tolerate repeated copies.
Review `.publication` receipts. An expired CRL needs fresh generation. A final
CRL never freezes issuance or ends the operator's revocation-service responsibility.

A retry additionally requires the original `.crl.pem.resume-state` and unchanged
PEM bytes, revoked index entries and next CRL counter. Later revocations or CRL
counter advancement (even from a failed generation) block replay before publication.
Missing state, including final CRLs from older releases, requires fresh generation:
repeat the original command **without FINAL_CRL**, retaining OUT_DIR and PUBLISH_CMD
and satisfying the normal remaining-leaf guard. Do not reset counters or fabricate
resume state. A routine CRL refresh preserves versioned archives and replaces
current PEM/DER aliases; paired output updates remain separate renames.
