#!/usr/bin/env bash
# Read-only by default; acknowledgment records an operator's completed review.
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"
cd "$ROOT_DIR"
case "${RECOVERY_ACTION:-report}" in
  report) recovery_report ;;
  acknowledge)
    acquire_lock root-ca
    trap release_locks EXIT
    recovery_report
    : "${RECOVERY_ID:?Set RECOVERY_ID to the reported id after reconciliation}"
    : "${RECOVERY_NOTE:?Describe the completed manual reconciliation}"
    [[ "$RECOVERY_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || die "Invalid recovery ID"
    [[ "$(sed -n '1p' .recovery/pending/operation)" == "id=$RECOVERY_ID" ]] || die "Recovery ID mismatch"
    [[ ! -e ".recovery/reviewed-$RECOVERY_ID" && ! -L ".recovery/reviewed-$RECOVERY_ID" ]] || die "Review destination exists"
    [[ ! -L .recovery/pending/review ]] || die "Unsafe review path"
    printf '%s\n' "$RECOVERY_NOTE" > .recovery/pending/review
    mv .recovery/pending ".recovery/reviewed-$RECOVERY_ID"
    info "Review recorded. No PKI artifacts, counters, or database records were repaired by this command."
    ;;
  *) die "RECOVERY_ACTION must be report or acknowledge" ;;
esac
