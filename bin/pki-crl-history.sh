# Explicit CRL coverage for canonical and retained issuer generations (MIT).
crl_plan_add() {
  local base="$1" cert="$2" key="$3" output="$4"
  authority_path "$base" "$cert" >/dev/null
  authority_path "$base" "$key" >/dev/null
  authority_path "$base" "$output" >/dev/null
  [[ ! -d "$output" && -d "${output%/*}" ]] || die "Invalid CRL destination: $output"
  check_pair "$cert" "$key"
  CRL_BASES+=("$base"); CRL_CERTS+=("$cert"); CRL_KEYS+=("$key"); CRL_OUTPUTS+=("$output")
}

crl_plan_authority() {
  local base="$1" current path id entry i
  base="$(workspace_path "$base")"
  for ((i=0; i<${#CRL_BASES[@]}; i++)); do
    [[ "${CRL_BASES[$i]}" != "$base" ]] || return 0
  done
  check_config "$base"
  pki_records validate "$base/index.txt" >/dev/null
  current="$(certificate_id "$base/certs/ca.cert.pem")"
  crl_plan_add "$base" "$base/certs/ca.cert.pem" "$base/private/ca.key.pem" "$base/crl/ca.crl.pem"
  for path in "$base"/generations/*; do
    [[ -e "$path" || -L "$path" ]] || continue
    id="${path##*/}"
    [[ "$id" =~ ^[0-9a-f]{64}$ && -d "$path" && ! -L "$path" ]] || die "Invalid retained generation: $path"
    authority_path "$base" "$path/ca.cert.pem" >/dev/null
    [[ "$(certificate_id "$path/ca.cert.pem")" == "$id" ]] || die "Generation fingerprint mismatch: $path"
    [[ "$id" != "$current" ]] || continue
    crl_plan_add "$base" "$path/ca.cert.pem" "$path/ca.key.pem" "$path/ca.crl.pem"
  done
  # A missing generation must not silently remove coverage for a bound leaf.
  for entry in "$base"/issuers/*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    id="${entry##*/}"
    [[ "$id" =~ ^[0-9A-Fa-f]+$ ]] || continue
    authority_path "$base" "$entry" >/dev/null
    LC_ALL=C awk 'length($0)!=64 || $0!~/^[0-9a-f]+$/ {bad=1} END {exit(bad || NR!=2)}' "$entry" || die "Invalid issuer binding: $entry"
    IFS= read -r id < "$entry"
    [[ -f "$base/generations/$id/ca.cert.pem" ]] || die "Missing bound issuer generation: $entry -> $id"
  done
}

renew_historical_crls() {
  local base raw i
  [[ -z "${ISSUER_ID:-}" ]] || die "CRL_HISTORY=1 cannot be combined with ISSUER_ID"
  CRL_BASES=(); CRL_CERTS=(); CRL_KEYS=(); CRL_OUTPUTS=()
  crl_plan_authority root
  if [[ "$operation" == all ]]; then
    for base in intm-*; do
      [[ -e "$base" || -L "$base" ]] || continue
      [[ ! -L "$base" ]] || die "Historical CRL discovery refuses symlink: $base; select its authority explicitly"
      if [[ -d "$base" && -f "$base/openssl.cnf" ]]; then crl_plan_authority "$base"; fi
    done
  else
    raw="${CRL_INT_DIR:-${INT_DIR:-}}"
    [[ -n "$raw" ]] || raw="intm-${KIND:?INT_DIR or KIND required}-ca"
    crl_plan_authority "$(resolve_authority "$raw")"
  fi
  # All paths/keys/bindings have been checked before any CRL counter advances.
  for ((i=0; i<${#CRL_BASES[@]}; i++)); do
    info "CRL coverage: ${CRL_OUTPUTS[$i]}"
  done
  for ((i=0; i<${#CRL_BASES[@]}; i++)); do
    publish_crl "${CRL_BASES[$i]}" "${CRL_CERTS[$i]}" "${CRL_KEYS[$i]}" "${CRL_OUTPUTS[$i]}" -crldays "${CRL_DAYS:-7}" || return 1
    info "CRL renewed: ${CRL_OUTPUTS[$i]}"
  done
}
