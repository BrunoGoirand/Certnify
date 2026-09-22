# Rebind an intact, offline-moved workspace. Preview by default (MIT).
relocate_workspace() (
  set -e
  local old stage config base relative file target mapped i count=0 counter rebind
  local -a configs=() links=() targets=()
  [[ ! -L "$ROOT_DIR/.recovery" ]] || die "Unsafe recovery journal path"
  [[ ! -e "$ROOT_DIR/.recovery/pending" && ! -L "$ROOT_DIR/.recovery/pending" ]] || die "Resolve the pending operation before workspace relocation"
  if [[ "${RELOCATE_APPLY:-0}" == 1 ]]; then
    [[ "${DRY_RUN:-0}" != 1 ]] || die "RELOCATE_APPLY=1 conflicts with DRY_RUN=1"
    pki_begin
  fi
  [[ -f "$ROOT_DIR/root/openssl.cnf" && ! -L "$ROOT_DIR/root/openssl.cnf" ]] || die "Missing regular root configuration"
  old="$(awk '
    /^[ \t]*\[/ {section=$0; gsub(/[ \t\[\]]/,"",section)}
    section=="CA_default" && /^[ \t]*dir[ \t]*=/ {sub(/^[^=]*=[ \t]*/,""); sub(/[ \t]+$/,""); print}
  ' "$ROOT_DIR/root/openssl.cnf")"
  [[ "$old" == /*/root ]] || die "Cannot identify the old workspace from root/openssl.cnf"
  old="${old%/root}"
  ! has_control_chars "$old" || die "Invalid old workspace binding"
  stage="$(mktemp -d "${TMPDIR:-/tmp}/certnify-relocate.XXXXXX")"
  trap 'rc=$?; rm -rf "$stage"; pki_exit "$rc"' EXIT
  # Do not follow aliases or include retained recovery copies in discovery.
  find "$ROOT_DIR" \( -name .git -o -name .recovery -o -name .locks \) -prune -o -name openssl.cnf -print0 > "$stage/configs"
  while IFS= read -r -d '' config; do
    base="${config%/openssl.cnf}"
    [[ -e "$base/index.txt" ]] || die "Incomplete authority beside configuration: $config"
    [[ ! -L "$config" ]] || die "Symlinked authority configuration: $config"
    relative="${base#"$ROOT_DIR/"}"
    recovery_relative "$config" >/dev/null
    for file in index.txt serial crlnumber private/ca.key.pem certs/ca.cert.pem; do
      [[ -f "$base/$file" && ! -L "$base/$file" ]] || die "Missing or symlinked authority state: $base/$file"
    done
    for file in ca.meta meta; do
      [[ ! -L "$base/$file" ]] || die "Symlinked authority metadata: $base/$file"
    done
    for file in private certs newcerts crl; do
      [[ -d "$base/$file" && ! -L "$base/$file" ]] || die "Missing or aliased authority directory: $base/$file"
    done
    [[ "$relative" == root || ( -d "$base/csr" && ! -L "$base/csr" ) ]] || die "Missing authority CSR directory: $base"
    counter="$(cat "$base/serial")"
    PKI_RECORD_COUNTER="$counter" pki_records serial "$base/index.txt" >/dev/null
    counter="$(cat "$base/crlnumber")"
    [[ "$counter" =~ ^[0-9A-Fa-f]+$ && ${#counter} -le 16 ]] || die "Invalid CRL counter: $base"
    check_pair "$base/certs/ca.cert.pem" "$base/private/ca.key.pem"
    "$OPENSSL" verify -auth_level 2 -no_check_time -check_ss_sig \
      -CAfile "$ROOT_DIR/root/certs/ca.cert.pem" "$base/certs/ca.cert.pem" >/dev/null
    count=$((count+1))
    PKI_CONFIG_BASE="$old/$relative" PKI_CONFIG_NEW="$base" LC_ALL=C \
      awk -f "$ROOT_DIR/bin/pki-config.awk" "$config" > "$stage/$count.cnf"
    PKI_CONFIG_BASE="$base" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-config.awk" "$stage/$count.cnf" >/dev/null
    validate_policy_config "$stage/$count.cnf" "$base"
    configs+=("$config")
    printf '[RELOCATE] %s -> %s\n' "$old/$relative" "$base"
  done < "$stage/configs"
  # Relative links must still be internal. Internal absolute aliases are rebound;
  # external links and missing targets require explicit repair before applying.
  find "$ROOT_DIR" \( -name .git -o -name .recovery -o -name .locks \) -prune -o -type l -print0 > "$stage/links"
  while IFS= read -r -d '' file; do
    target="$(readlink "$file")"
    rebind=0
    case "$target" in
      "$old"/*) mapped="$ROOT_DIR/${target#"$old/"}"; rebind=1 ;;
      /*) mapped="$target" ;;
      *) mapped="$(dirname "$file")/$target" ;;
    esac
    # Canonicalization allows normal relative '..' aliases but never an escape.
    mapped="$(canonicalize_path_allow_missing "$mapped")"
    # macOS aliases such as /var -> /private/var may occur in stored absolute links.
    if [[ "$old" != "$ROOT_DIR" && "$mapped" == "$old/"* ]]; then
      mapped="$(canonicalize_path_allow_missing "$ROOT_DIR/${mapped#"$old/"}")"
      rebind=1
    fi
    case "$mapped" in "$ROOT_DIR"/*) ;; *) die "External symlink prevents relocation: $file" ;; esac
    [[ -e "$mapped" ]] || die "Missing relocation symlink target: $file -> $mapped"
    if [[ "$rebind" == 1 ]]; then
      recovery_relative "$file" L >/dev/null
      links+=("$file"); targets+=("$mapped")
      printf '[RELOCATE] alias %s -> %s\n' "$file" "$mapped"
    fi
  done < "$stage/links"
  [[ "$old" != "$ROOT_DIR" ]] || { info "Workspace bindings already use $ROOT_DIR"; exit 0; }
  if [[ "${RELOCATE_APPLY:-0}" != 1 ]]; then
    info "Preview only; RELOCATE_APPLY=1 rebinds these configurations and internal aliases"
    exit 0
  fi
  recovery_start "workspace-relocation from=$old to=$ROOT_DIR"
  recovery_plan_begin
  for ((i=0; i<${#configs[@]}; i++)); do
    config="${configs[$i]}"; base="${config%/openssl.cnf}"
    recovery_plan_add "$stage/$((i+1)).cnf" "$config" 600
    for file in index.txt serial crlnumber private/ca.key.pem certs/ca.cert.pem; do recovery_plan_guard "$base/$file"; done
    for file in ca.meta meta; do
      [[ -f "$base/$file" ]] || continue
      [[ ! -L "$base/$file" ]] || die "Symlinked authority metadata: $base/$file"
      PKI_REBOUND_HASH="$(recovery_digest "$stage/$((i+1)).cnf")" awk '
        /^POLICY_SHA256=/ {print "POLICY_SHA256=" ENVIRON["PKI_REBOUND_HASH"]; next} {print}
      ' "$base/$file" > "$stage/meta"
      recovery_plan_add "$stage/meta" "$base/$file"
    done
  done
  for ((i=0; i<${#links[@]}; i++)); do recovery_plan_add "${targets[$i]}" "${links[$i]}" 444 L; done
  recovery_plan_seal
  recovery_resume
  for ((i=0; i<${#configs[@]}; i++)); do check_config "${configs[$i]%/openssl.cnf}"; done
  info "Workspace relocation applied; keys, certificate history and counters preserved"
)
