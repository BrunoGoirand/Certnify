# Recoverable boundaries, not a database transaction or power-loss guarantee (MIT).
# Process-local ownership must never be inherited from the caller environment.
PKI_RECOVERY_OWNED=""
PKI_OPERATION_COMPLETE=0
recovery_guard() {
  [[ -z "${PKI_RECOVERY_OWNED:-}" ]] || return 0
  [[ ! -L "$ROOT_DIR/.recovery" && ! -L "$ROOT_DIR/.recovery/pending" ]] || die "Unsafe recovery journal path"
  if [[ -e "$ROOT_DIR/.recovery/pending" ]]; then
    recovery_report >&2
    die "Unresolved operation; inspect with bin/recovery.sh before retrying. No automatic rollback or serial reset."
  fi
}

recovery_report() {
  local journal="$ROOT_DIR/.recovery/pending" file
  [[ ! -L "$ROOT_DIR/.recovery" && ! -L "$journal" ]] || die "Unsafe recovery journal path"
  if [[ ! -d "$journal" ]]; then info "No pending operation"; return 0; fi
  warn "Recovery required: $journal"
  for file in operation phase events; do
    [[ ! -L "$journal/$file" ]] || die "Unsafe recovery journal entry"
    [[ ! -f "$journal/$file" ]] || cat "$journal/$file"
  done
  warn "Inspect current index.txt, serial, newcerts and the named artifacts; a backend error does not prove absence of a commit. Retain all counters and certificate history."
}

recovery_start() {
  [[ -z "${PKI_RECOVERY_OWNED:-}" ]] || { recovery_note "nested=$*"; return 0; }
  recovery_guard
  mkdir -p "$ROOT_DIR/.recovery"
  mkdir "$ROOT_DIR/.recovery/pending"
  PKI_RECOVERY_OWNED=1
  PKI_OPERATION_COMPLETE=0
  printf 'id=%s-%s\noperation=%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" "$*" > "$ROOT_DIR/.recovery/pending/operation"
  recovery_phase preparing
}
recovery_note() {
  [[ -n "${PKI_RECOVERY_OWNED:-}" ]] || return 0
  printf '%s\n' "$*" >> "$ROOT_DIR/.recovery/pending/events"
}
recovery_phase() {
  [[ -n "${PKI_RECOVERY_OWNED:-}" ]] || return 0
  local file="$ROOT_DIR/.recovery/pending/phase"
  printf 'phase=%s\n' "$*" > "$file.new"
  mv -f "$file.new" "$file"
  recovery_note "phase=$*"
}
recovery_signing() {
  local base="$1" output="$2"
  recovery_note "issuer=$base output=$output next_serial=$(cat "$base/serial")"
  recovery_phase signing-outcome-uncertain
}
recovery_complete() { PKI_OPERATION_COMPLETE=1; }
pki_exit() {
  local rc="$1"
  if [[ -n "${PKI_RECOVERY_OWNED:-}" ]]; then
    if [[ "$rc" == 0 && "${PKI_OPERATION_COMPLETE:-0}" == 1 ]]; then
      rm -rf "$ROOT_DIR/.recovery/pending" || rc=1
    else
      recovery_report >&2 || true
      [[ "$rc" != 0 ]] || rc=1
    fi
  fi
  release_locks
  trap - EXIT
  exit "$rc"
}

# Same-directory staged replacement: individual rename, not a multi-file commit.
staged_install() (
  set -e
  source_file="$1"; destination="$2"; mode="${3:-444}"
  [[ ! -d "$destination" && ! -L "$destination" ]] || die "Unsafe installation destination: $destination"
  temporary="$(mktemp "$(dirname "$destination")/.install.XXXXXX")"
  trap 'rm -f "$temporary"' EXIT
  cat "$source_file" > "$temporary"
  chmod "$mode" "$temporary"
  mv -f "$temporary" "$destination"
)
# Replace the directory entry itself, including an existing symlink.
staged_link() (
  set -e
  target="$1"; destination="$2"
  [[ ! -d "$destination" ]] || die "Alias destination is a directory: $destination"
  temporary_dir="$(mktemp -d "$(dirname "$destination")/.alias.XXXXXX")"
  trap 'rm -rf "$temporary_dir"' EXIT
  ln -s "$target" "$temporary_dir/link"
  mv -f "$temporary_dir/link" "$destination"
)
