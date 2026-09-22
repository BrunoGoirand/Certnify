# Durable command fence. Ownership is process-local, never trusted from env (MIT).
PKI_DURABLE_OWNED=""
PKI_DURABLE_KEEP=0
PKI_DURABLE_COMPLETED=0
durability() { python3 -B "$ROOT_DIR/bin/pki-durable.py" "$@" "$ROOT_DIR"; }
durability_flush() { durability flush || return 1; }
durability_begin() {
  [[ -z "$PKI_DURABLE_OWNED" ]] || return 0
  PKI_DURABLE_COMPLETED=0
  PKI_DURABLE_OWNED="$(python3 -B "$ROOT_DIR/bin/pki-durable.py" begin "$ROOT_DIR" "$$")" || return 1
}
durability_guard() {
  [[ -z "$PKI_DURABLE_OWNED" ]] || return 0
  if [[ -e "$ROOT_DIR/.recovery/power-loss" || -L "$ROOT_DIR/.recovery/power-loss" || -e "$ROOT_DIR/.recovery/power-loss-error" || -L "$ROOT_DIR/.recovery/power-loss-error" ]]; then
    durability report >&2 || return 1
    die "Unresolved power-loss operation; inspect bin/recovery.sh before any further operation"
  fi
}
durability_resume_admit() {
  [[ -z "$PKI_DURABLE_OWNED" ]] || return 0
  if [[ -e "$ROOT_DIR/.recovery/power-loss" || -L "$ROOT_DIR/.recovery/power-loss" ]]; then
    PKI_DURABLE_OWNED="$(durability admit)" || return 1
  else
    durability_guard
    durability_begin || return 1
    # Ordinary failures retire their command fence while retaining the plan.
    # Persist a fresh checkpoint so an interrupted resume can itself be resumed.
    durability seal || return 1
  fi
}
durability_finish() {
  [[ -n "$PKI_DURABLE_OWNED" ]] || return 0
  [[ "$PKI_DURABLE_KEEP" == 0 ]] || return 0
  durability finish || return 1
  PKI_DURABLE_OWNED=""
  PKI_DURABLE_COMPLETED=1
}
