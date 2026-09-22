# 05 — Issuance workflows

All issuance uses the physical-workspace lock and recovery guard in chapter 08.
Subject, SAN, profile and storage rules are defined in chapters 03–04. Successful
completion includes required validation; a nonzero result after signing does not
imply rollback. No serial or committed issuance record is reset after failure.

## Issuer validity and duration admission

Before intermediate initialization/rekey or leaf maintenance/key replacement,
validate the issuer chain at the current time, root self-signature, cryptographic
strength and CA/signing constraints. Check the root for an intermediate and both
root and intermediate for a leaf. Rollover performs the root check before moving
its active directory. Existing disabled/revoked-issuer controls remain in force.

DAYS must fit within the earliest notAfter among those certificates. A refusal
names the limiting certificate, its UTC expiry and maximum whole-day DAYS value.
The command does not cap the request. The start and end UTC instants are fixed
at preflight and passed explicitly to OpenSSL, avoiding an overrun caused by
key generation or signing delay. Date conversion is portable AWK, with Gregorian
leap-year handling; no Python runtime or platform-specific date parsing is used.

Archive leaves default to 3600 days in wrappers, direct ACTION=doc issuance and
built-in batch reissuance; intermediates retain their 3650-day default. This margin
does not guarantee admission under an older or shorter-lived issuer.

This intentionally changes admission for existing workflows: a 3650-day leaf
requested after creation of a 3650-day intermediate is too long. Select a smaller
DAYS value or renew the issuer with appropriate validity. Even a repeated
intermediate request must pass this admission before the no-op/rekey decision.
Root self-signing has no parent lifetime to constrain it. No existing certificate
is shortened or rewritten by these checks.

## Root

1. Resolve defaults, validate the UTF-8 subject and effective key policy. Initialize
   layout/counters only in an absent or empty authority directory; an existing
   authority must retain its database, counters and required directories. Create
   or validate the selected root configuration; missing established policy fails.
2. If a certificate exists, require a readable certificate with the requested
   RFC2253 DN and its original matching private key. A missing key fails instead
   of generating a replacement for the existing certificate.
3. Without a certificate, start a recovery journal. Reuse an existing key regardless
   of requested algorithm parameters, or generate a key through a staged file.
   Inspect the actual key, render a temporary request and self-sign v3_ca.
4. Check the staged key/certificate pair and self-verification, then install the
   certificate through a staged rename. Root self-signing consumes no CA index row.
5. Write effective metadata even on a successful no-op, verify the root using
   itself as trust anchor and complete the journal, if one was started.

Repeating the same DN does not renew validity or change path length. Explicitly
empty ROOT_PATHLEN omits the constraint when composing a new configuration;
existing installed configuration is never silently rebuilt from a new request.

## Intermediate

1. Resolve and validate the destination, subject and configurations. Validate both
   root and local index/counter histories before rekeying. Inspect any canonical
   certificate, its root signature and root-index revocation status.
2. Archive the current matching issuer pair and backfill unambiguous leaf bindings.
   Missing or ambiguous certificate history fails before replacement.
3. Compare normalized requested algorithm/size/curve/EdDSA variant with the actual
   key. REKEY_ON_ALG_CHANGE and REKEY_ON_REVOKE default to 1. ROTATE_KEY=1 forces
   rekey; INTM_REVOKED=1 supplies an explicit revocation signal. FORCE_REUSE_KEY=1
   prevents key replacement but does not erase the rekey-needed decision.
4. Skip issuance only when key and certificate exist, FORCE_REISSUE and ROTATE_KEY
   are not 1, the requested DN matches, remaining validity exceeds the renewal
   threshold, neither revocation signal is set and no rekey is needed. Check the
   pair and current root chain, normalize companion chain/alias/serial.last and
   refresh actual metadata before reporting success.
5. Otherwise journal the operation. For rekey, retain the old canonical pair and
   archived key while generating a staged replacement. Render the CSR, raise the
   root counter if needed, record the expected serial and uncertain signing phase,
   and sign v3_intermediate_ca through the root database.
6. Read the actual serial, normalize the root row locator, record committed state,
   and verify the new pair/root chain. Preserve the previous serial-named certificate
   and chain, then install replacement key/certificate and intermediate+root chain.
7. Retain serial-named copies, preserve/repair the local leaf serial upward, write
   metadata and serial.last, remove an existing .disabled marker, verify the new
   intermediate and normalize/archive its generation before completion.

In-place renewal retains the local database and counters. It does not revoke the
previous intermediate, reissue old leaves or automatically refresh their CRLs.
Historical leaves retain their original cryptographic issuer binding.

## Leaf

1. Resolve action/defaults, authority, normalized subject, typed/combined SANs and
   safe artifact stem. Validate authority configuration and issuer pair. Unless
   ALLOW_SIGN_WITH_REVOKED_INT=1, refuse disabled or root-revoked intermediates.
   Batch issuance also checks its pinned expected issuer identity.
2. Inspect a reused key before selecting its compatible default/explicit profile.
   Validate name-map compatibility, complete authority state and retained serial
   collisions before key replacement. Compile the effective SAN request and reject
   conflicting profile SANs before CA maintenance. RSA must have at least 2048 bits;
   reused keys are subject to the same policy.
3. Run requested expiry maintenance and optional CRL refresh; either failure aborts.
   Unless ALLOW_DUPLICATE_CN=1, refuse exact CN matches that are V and unexpired,
   reporting their serials and locators. Key rotation does not bypass this rule.
4. Start the pending journal and claim the name mapping. FORCE_NEW_KEY=0 reuses
   an existing key. With 1, back up any existing key and stage the new key and CSR,
   retaining canonical artifacts until the replacement has passed verification. With rotate, prepare new
   rot- namespace artifacts without replacing the canonical artifacts.
5. Inspect the actual key again, validate its profile, retain the exact policy
   snapshot and create the CSR from the preflighted UTF-8 DN/SAN configuration.
6. Raise the next serial to avoid history collisions and require 1–16 hex digits.
   Journal the expected serial and temporary output, then sign through the
   intermediate database. Read the returned certificate serial and normalize its
   newcerts locator. A backend failure here leaves an uncertain recovery outcome.
7. Compare the decoded issued SAN set with the preflighted effective set; a
   mismatch leaves committed history and a pending journal, without installation.
   Persist issuer binding and policy reference. Select a free canonical or
   `srl-<serial>-<stem>` certificate destination; never overwrite an occupied serial
   destination. Check the issued pair, equality with retained newcerts evidence,
   and the chain against the workspace root before publishing deployment files.
8. Build the leaf+intermediate fullchain and a sealed installation plan. For rotate
   or FORCE_NEW_KEY=1, retain the key, CSR and certificate in the serial namespace.
   For FORCE_NEW_KEY=1, also replace all four conventional paths from the same
   verified bytes, including on first issuance. Remove temporary key/CSR files only
   after their replacements are installed. The plan records source/destination
   hashes, issuer/index/serial guards and the certificate validity deadline.
   Completed plans are retained as private receipts. A fully prepared interrupted
   installation can be resumed explicitly or via AUTO_RECOVER=1, without signing
   again. An interruption before sealing still needs manual review. Individual
   replacements are not a multi-file transaction and never undo issuance commits.

## Results for another implementation

The shell interface returns exit status plus human-readable paths/statuses.
A native implementation should return operation, authority/generation, serial,
key reuse/replacement, artifact paths, commit certainty and verification result.
Distinguish preflight rejection, issued-and-verified, uncertain backend outcome,
and committed issuance awaiting artifact reconciliation. Never blindly reissue
because a previous invocation failed to return its final success message.
