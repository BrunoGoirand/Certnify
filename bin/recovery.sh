#!/usr/bin/env bash
# Read-only by default; verified resume/rebinding or explicit manual acknowledgment.
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"
cd "$ROOT_DIR"
case "${RECOVERY_ACTION:-report}" in
  report) recovery_report ;;
  resume)
    [[ "${DRY_RUN:-0}" != 1 ]] || die "Use RECOVERY_ACTION=report for read-only inspection"
    acquire_lock root-ca
    trap 'pki_exit "$?"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ -e .recovery/pending ]]; then recovery_resume; else recovery_report; durability_guard; fi
    ;;
  relocate)
    source "$ROOT_DIR/bin/pki-relocate.sh"
    relocate_workspace
    ;;
  acknowledge)
    acquire_lock root-ca
    trap release_locks EXIT
    recovery_report
    : "${RECOVERY_ID:?Set RECOVERY_ID to the reported id after reconciliation}"
    : "${RECOVERY_NOTE:?Describe the completed manual reconciliation}"
    [[ "$RECOVERY_ID" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || die "Invalid recovery ID"
    [[ "$RECOVERY_NOTE" == *[![:space:]]* ]] || die "Nonempty recovery note required"
    if [[ -e .recovery/pending ]]; then
      [[ "$(sed -n '1p' .recovery/pending/operation)" == "id=$RECOVERY_ID" ]] || die "Recovery ID mismatch"
      [[ ! -e ".recovery/reviewed-$RECOVERY_ID" && ! -L ".recovery/reviewed-$RECOVERY_ID" ]] || die "Review destination exists"
      [[ ! -L .recovery/pending/review ]] || die "Unsafe review path"
    else
      [[ -e .recovery/power-loss ]] || die "No pending operation to acknowledge"
    fi
    # Even an ordinary/legacy journal needs a fence: offline reconciliation may
    # have changed state since the previous command's durability barrier.
    if [[ ! -e .recovery/power-loss ]]; then
      durability_begin || die "Cannot persist manual-review intent"
    fi
    if [[ -e .recovery/pending ]]; then
      printf '%s\n' "$RECOVERY_NOTE" > .recovery/pending/review
    fi
    python3 -B "$ROOT_DIR/bin/pki-durable.py" acknowledge "$ROOT_DIR" "$RECOVERY_ID" "$RECOVERY_NOTE"
    PKI_DURABLE_OWNED=""
    if [[ ! -e .recovery/pending ]]; then
      info "Power-loss review recorded; no PKI repair or reissuance performed."
      info "Local state durably synchronized" >&2
      exit 0
    fi
    mv .recovery/pending ".recovery/reviewed-$RECOVERY_ID"
    durability_flush || die "Cannot persist manual review"
    info "Review recorded. No PKI artifacts, counters, or database records were repaired by this command."
    info "Local state durably synchronized" >&2
    ;;
  *) die "RECOVERY_ACTION must be report, resume, relocate or acknowledge" ;;
esac
