# Explicit, bounded workspace cleanup. Sourced only by crl.sh clean (MIT).
clean_plan() {
  local path resolved
  CLEAN_TARGETS=()
  for path in root out intm-*; do
    [[ -e "$path" || -L "$path" ]] || continue
    [[ ! -L "$path" ]] || die "Cleanup refuses a symlink candidate: $path"
    [[ -d "$path" ]] || die "Cleanup refuses a non-directory candidate: $path"
    if [[ "$path" == intm-* && ! -f "$path/openssl.cnf" ]]; then
      warn "Cleanup preserves unrecognized directory: $path"
      continue
    fi
    resolved="$(workspace_path "$path")"
    [[ "$resolved" == "$ROOT_DIR/$path" ]] || die "Unsafe cleanup target: $path"
    if [[ "$path" != out ]]; then
      # Cleanup uses local paths only, never paths or policies from openssl.cnf.
      # Retain structural checks even when the workspace has been relocated.
      open_authority_state "$resolved"
      [[ "$path" == root || -d "$resolved/csr" ]] || die "Incomplete authority: missing $resolved/csr"
      [[ -f "$resolved/openssl.cnf" ]] || die "Missing configuration: $resolved/openssl.cnf"
    fi
    CLEAN_TARGETS+=("$resolved")
  done
}

clean_workspace() {
  local path i
  cd "$ROOT_DIR"
  if [[ "${CLEAN_APPLY:-0}" == 1 ]]; then
    [[ "${DRY_RUN:-0}" != 1 ]] || die "CLEAN_APPLY=1 conflicts with DRY_RUN=1"
    pki_begin
  fi
  # Fully validate the plan before the first deletion, under lock when applying.
  clean_plan
  for ((i=0; i<${#CLEAN_TARGETS[@]}; i++)); do
    printf '[CLEAN] %s\n' "${CLEAN_TARGETS[$i]}"
  done
  if [[ "${CLEAN_APPLY:-0}" != 1 ]]; then
    info "Preview only; CLEAN_APPLY=1 deletes exactly these directories, including keys and history. Back up first."
    return 0
  fi
  for ((i=0; i<${#CLEAN_TARGETS[@]}; i++)); do
    path="${CLEAN_TARGETS[$i]}"
    [[ ! -L "$path" && -d "$path" ]] || die "Cleanup target changed: $path"
    rm -rf -- "$path"
  done
  info "Cleanup applied (${#CLEAN_TARGETS[@]} directories)"
}
