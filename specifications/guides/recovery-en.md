# Recovery procedures

The [reliability contract](../08-architecture-and-reliability.md) defines commit
boundaries; [publication](../07-lifecycle-and-migration.md) defines CRL retries.

## After power loss or a persistence error

Python 3.8+ is required at runtime. Mutating commands persist a
`.recovery/power-loss` fence before changing PKI state and retire it only after
checked file/directory synchronization (plus a full device barrier on macOS).
An abrupt stop leaves the fence, including for revocation, CRL generation and
initialization. A barrier error fails the command; it may also leave
`.recovery/power-loss-error`. Earlier progress messages do not mean the operation
completed: require exit zero and the final `Local state durably synchronized`
message. No hardware power-cut qualification is claimed.

Run `bin/recovery.sh` to inspect the state without modifying it. Establish that
the recorded process and its backend children are no longer running before
removing a stale lock; never remove the power-loss fence as a retry shortcut.
If a durable verified plan exists, use `RECOVERY_ACTION=resume` below. A `ready`
file alone does not authorize recovery: its persisted checkpoint must match.
Otherwise stop operations, retain evidence and reconcile through the offline
review procedure. This includes interrupted OpenSSL database/counter updates.
Missing success does not authorize reissuance or counter rollback.

After reconciliation, use the reported `RECOVERY_ID` and a meaningful
`RECOVERY_NOTE` with `RECOVERY_ACTION=acknowledge`. If an installation journal is
also reported, use its operation ID. This records a private review receipt and
synchronizes the reconciled state before lifting the fence; it does not repair
or independently verify that state. If the fence itself is unreadable/incomplete,
preserve it and perform offline expert review; do not invent a replacement ID.
Keep the live PKI on one local filesystem with external writers excluded.
Network/synced storage, lying device caches and destroyed media are not covered.

## Resume a verified installation

For a validated leaf installation, hold release or workspace rebinding with a
complete saved plan:

```sh
RECOVERY_ACTION=resume bin/recovery.sh
```

`AUTO_RECOVER=1` enables the same recovery before the next locked command. Report
and `DRY_RUN=1` remain read-only. Every saved source, destination and state guard
is checked before the first write. Already installed entries are accepted;
changed evidence and expired certificate/CRL validity are rejected. Recovery never
signs a certificate, regenerates a CRL or reduces counters. An interrupted resume
can be resumed again. Completed plans are kept in `.recovery/completed-<ID>`.

Journals can include private key copies (mode 400 in private directories). Protect
them like authority private storage and exclude them from Git, public archives and
unprotected backups. Retention is operator-managed. An incomplete plan, uncertain
signing result, root/intermediate issuance or authority directory move without a
supported plan still needs the manual review below. Stale locks are never stolen.

## Move an intact workspace

Stop operations and resolve pending journals before moving the entire directory.
From the new location, preview, then apply:

```sh
RECOVERY_ACTION=relocate bin/recovery.sh
RECOVERY_ACTION=relocate RELOCATE_APPLY=1 bin/recovery.sh
```

Preview does not modify the workspace. Apply locks and validates root, nested and
historical authorities before rebinding configurations and internal absolute
aliases. Keys, indexes and counters are retained. Custom policies are preserved;
configuration fingerprints in `ca.meta`/`meta` are refreshed. No data at the old
location is modified. Concurrent use of another workspace copy is unsupported.
External links, missing state, unsupported paths and configuration includes are
rejected. If installation is interrupted after plan completion, use
`RECOVERY_ACTION=resume`.

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
they may contain private key copies as well as certificate identities and paths.
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
