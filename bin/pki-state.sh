# Certnify state/path/generation helpers. Sourced by pki-env.sh (MIT).
# One physical-workspace lock intentionally serializes every PKI transaction.
pki_begin() {
  local access="${1:-write}"
  case "$access" in read|write) ;; *) die "Invalid transaction access mode: $access" ;; esac
  cd "$ROOT_DIR"
  acquire_lock root-ca
  trap 'pki_exit "$?"' EXIT
  recovery_guard
  durability_guard
  # Readers need admission checks, but no new write transaction. Inventory
  # export and batch receipt creation do mutate the workspace and are fenced.
  if [[ "$access" == write ]]; then
    durability_begin || die "Cannot establish durable operation intent"
  fi
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

workspace_path() {
  local raw="$1" resolved
  while [[ "$raw" == *'//'* ]]; do raw="${raw//\/\//\/}"; done
  while [[ "$raw" == *'/./'* ]]; do raw="${raw//\/.\//\/}"; done
  [[ "$raw" == / ]] || raw="${raw%/}"
  [[ -n "$raw" && "$raw" != *'$'* && "$raw" != *'"'* && "$raw" != *'#'* && "$raw" != *'\'* ]] || die "Unsafe workspace path: $raw"
  ! has_control_chars "$raw" || die "Control character in path"
  case "/$raw/" in */../*) die "Path must stay within the workspace (no '..'): $raw" ;; esac
  [[ "$raw" == /* ]] || raw="$ROOT_DIR/$raw"
  resolved="$(canonicalize_path_allow_missing "$raw")" || return 1
  case "$resolved" in "$ROOT_DIR"/*) ;; *) die "Path resolves outside workspace: $raw -> $resolved" ;; esac
  # These paths are excluded from persistence scans and must never hold CA data.
  case "${resolved#"$ROOT_DIR/"}" in
    .git|.git/*|.locks|.locks/*) die "Reserved non-PKI path: $resolved" ;;
  esac
  if grep -Fxq -- "${resolved#"$ROOT_DIR/"}" "$ROOT_DIR/test/source-manifest.txt"; then
    die "Distribution source cannot be used as operational PKI state: $resolved"
  fi
  printf '%s\n' "$resolved"
}

resolve_authority() {
  local raw="$1" absolute
  [[ -n "$raw" ]] || die "Missing authority selector"
  if [[ "$raw" == '.' ]]; then raw="$PKI_CALL_DIR"; fi
  case "$raw" in
    /*|*/*|intm-*|intermediate) ;;
    *) [[ -e "$ROOT_DIR/$raw" ]] || raw="intm-${raw}-ca" ;;
  esac
  absolute="$(workspace_path "$raw")" || return 1
  [[ "$absolute" != "$ROOT_DIR/root" ]] || die "Root is not an intermediate authority"
  printf '%s\n' "${absolute#"$ROOT_DIR/"}"
}

# Resolve a data artifact without allowing it to escape the selected authority.
authority_path() {
  local base="$1" item="$2" absolute
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  [[ "$item" == /* ]] || item="$base/$item"
  absolute="$(workspace_path "$item")" || return 1
  case "$absolute" in "$base"/*) printf '%s\n' "$absolute" ;; *) die "Artifact escapes authority $base: $item" ;; esac
}

check_authority_paths() {
  local base="$1" item
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  base="$(workspace_path "$base")" || return 1
  for item in openssl.cnf index.txt index.txt.tmp index.txt.old index.txt.new index.txt.attr index.txt.attr.old index.txt.attr.new serial serial.old serial.new crlnumber crlnumber.old crlnumber.new serial.last ca.meta meta .disabled private certs csr newcerts crl generations issuers; do
    authority_path "$base" "$item" >/dev/null
  done
  for item in private/ca.key.pem private/.rand csr/ca.csr.pem certs/ca.cert.pem certs/ca.chain.cert.pem certs/chain.cert.pem crl/ca.crl.pem; do
    authority_path "$base" "$item" >/dev/null
  done
}

check_config() {
  local base="$1" cnf="${2:-$1/openssl.cnf}"
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  check_authority_paths "$base"
  open_authority_state "$base"
  [[ "$base" == "$ROOT_DIR/root" || -d "$base/csr" ]] || die "Incomplete authority: missing $base/csr"
  [[ -f "$cnf" ]] || die "Missing configuration: $cnf"
  PKI_CONFIG_BASE="$base" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-config.awk" "$cnf" >/dev/null
  validate_policy_config "$cnf" "$base"
}

# Opening an existing authority never reconstructs missing issuer state.
open_authority_state() {
  local base="$1" item counter
  check_authority_paths "$base"
  for item in index.txt serial crlnumber; do
    [[ -f "$base/$item" ]] || die "Incomplete authority: missing $base/$item; reconcile retained state explicitly"
  done
  for item in certs crl newcerts private; do
    [[ -d "$base/$item" ]] || die "Incomplete authority: missing directory $base/$item"
  done
  counter="$(cat "$base/serial")"
  PKI_RECORD_COUNTER="$counter" pki_records serial "$base/index.txt" >/dev/null
  counter="$(cat "$base/crlnumber")"
  [[ "$counter" =~ ^[0-9A-Fa-f]+$ && ${#counter} -le 16 ]] || die "Invalid CRL counter: $base/crlnumber"
}

initialize_authority_layout() {
  local base="$1" kind="$2" entry occupied=0
  check_authority_paths "$base"
  for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
    if [[ -e "$entry" || -L "$entry" ]]; then occupied=1; break; fi
  done
  if [[ "$occupied" == 1 ]]; then
    open_authority_state "$base"
    [[ "$kind" == root || -d "$base/csr" ]] || die "Incomplete authority: missing $base/csr"
    return 0
  fi
  mkdir -p "$base"/{certs,crl,newcerts,private}
  [[ "$kind" == root ]] || mkdir -p "$base/csr"
  : > "$base/index.txt"
  printf '1000\n' > "$base/serial"
  printf '1000\n' > "$base/crlnumber"
}

# Check retained numeric serial identities before maintenance, keys or signing.
check_next_serial() {
  local base="$1" current path name serial
  [[ -f "$base/index.txt" && -s "$base/serial" ]] || die "Missing issuer state: $base/index.txt or $base/serial"
  current="$(cat "$base/serial")"
  PKI_NEXT_SERIAL="$(PKI_RECORD_COUNTER="$current" pki_records serial "$base/index.txt")" || return 1
  # One parser for the whole directory inventory, not one process per artifact.
  for path in "$base"/newcerts/*.pem "$base"/issuers/* "$base"/certs/srl-*.cert.pem; do
    [[ -e "$path" || -L "$path" ]] || continue
    name="${path##*/}"
    case "${path%/*}" in
      "$base/newcerts") serial="${name%.pem}" ;;
      "$base/issuers") serial="${name%.policy}" ;;
      "$base/certs") serial="${name#srl-}"; serial="${serial%%-*}" ;;
    esac
    [[ "$serial" =~ ^[0-9A-Fa-f]+$ ]] || continue
    printf '%s\t%s\n' "$serial" "$path"
  done | PKI_NEXT_SERIAL_VALUE="$PKI_NEXT_SERIAL" LC_ALL=C awk '
    function canonical(v) {v=toupper(v); sub(/^0+/,"",v); return "s" (v=="" ? "0" : v)}
    BEGIN {FS="\t"; wanted=canonical(ENVIRON["PKI_NEXT_SERIAL_VALUE"])}
    canonical($1)==wanted {print "[ERR] Serial collision with retained history: " $2 > "/dev/stderr"; bad=1}
    END {exit bad}
  ' || die "Serial $PKI_NEXT_SERIAL is not available; reconcile before signing"
  authority_path "$base" "newcerts/$PKI_NEXT_SERIAL.pem" >/dev/null
}

rebind_config() {
  local base="$1" old="$2" tmp
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  check_authority_paths "$base"
  tmp="$(mktemp "$base/openssl.cnf.rebind.XXXXXX")"
  if ! PKI_CONFIG_BASE="$old" PKI_CONFIG_NEW="$base" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-config.awk" "$base/openssl.cnf" > "$tmp"; then
    rm -f "$tmp"; die "Cannot rebind configuration: $base"
  fi
  mv "$tmp" "$base/openssl.cnf"
  check_config "$base"
}

certificate_id() {
  "$OPENSSL" x509 -in "$1" -outform DER | "$OPENSSL" dgst -sha256 | awk '{print $NF}'
}

check_pair() {
  local cert="$1" key="$2" a b
  [[ -s "$cert" && -s "$key" ]] || die "Missing authority certificate/key: $cert / $key"
  a="$(pubkey_sha256_b64 "$cert" cert)"; b="$(pubkey_sha256_b64 "$key" key)"
  [[ -n "$a" && "$a" == "$b" ]] || die "Authority certificate/key mismatch: $cert / $key"
}

# Snapshot the key before rotation. Certificate DER fingerprint is generation ID.
archive_generation() {
  local base="$1" id dest staging
  check_pair "$base/certs/ca.cert.pem" "$base/private/ca.key.pem"
  id="$(certificate_id "$base/certs/ca.cert.pem")"
  dest="$(authority_path "$base" "generations/$id")"
  authority_path "$base" "$dest/ca.cert.pem" >/dev/null
  authority_path "$base" "$dest/ca.key.pem" >/dev/null
  if [[ -d "$dest" ]]; then
    [[ "$(certificate_id "$dest/ca.cert.pem")" == "$id" ]] || die "Generation fingerprint mismatch: $dest"
    check_pair "$dest/ca.cert.pem" "$dest/ca.key.pem"
  else
    mkdir -p "$base/generations"
    staging="$(mktemp -d "$base/generations/.generation.XXXXXX")"
    install -m 444 "$base/certs/ca.cert.pem" "$staging/ca.cert.pem"
    install -m 400 "$base/private/ca.key.pem" "$staging/ca.key.pem"
    check_pair "$staging/ca.cert.pem" "$staging/ca.key.pem"
    mv "$staging" "$dest"
  fi
}

# Resolve from a persisted binding; unbound imports must have exactly one signer.
# Populates ISSUER_CERT/ISSUER_KEY/ISSUER_ID, never trusts subject-name equality.
resolve_leaf_issuer() {
  local base="$1" leaf="$2" serial binding id expected fingerprint candidate matches=0 seen='|' selected=''
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  serial="$(openssl_serial "$leaf")"
  [[ "$serial" =~ ^[0-9A-Fa-f]+$ ]] || die "Invalid leaf serial: $leaf"
  binding="$(authority_path "$base" "issuers/$serial")"
  fingerprint="$(certificate_id "$leaf")"
  if [[ -f "$binding" ]]; then
    { IFS= read -r id; IFS= read -r expected; } < "$binding"
    [[ "$id" =~ ^[0-9a-f]{64}$ && "$fingerprint" == "$expected" ]] || die "Leaf binding mismatch: $leaf"
    selected="$(authority_path "$base" "generations/$id/ca.cert.pem")"
    [[ -f "$selected" && "$(certificate_id "$selected")" == "$id" ]] || die "Missing/mismatched historical issuer: $selected"
  else
    for candidate in "$base/certs/ca.cert.pem" "$base"/generations/*/ca.cert.pem "$base"/certs/ca-*.cert.pem; do
      [[ -f "$candidate" ]] || continue
      candidate="$(authority_path "$base" "$candidate")"
      id="$(certificate_id "$candidate")"
      case "$seen" in *"|$id|"*) continue ;; esac
      seen="$seen$id|"
      if "$OPENSSL" verify -no_check_time -partial_chain -trusted "$candidate" "$leaf" >/dev/null 2>&1; then
        matches=$((matches+1)); selected="$candidate"
      fi
    done
    [[ "$matches" == 1 ]] || die "Unresolved/ambiguous issuer generation for $leaf ($matches candidates)"
  fi
  "$OPENSSL" verify -no_check_time -partial_chain -trusted "$selected" "$leaf" >/dev/null 2>&1 || die "Issuer signature mismatch: $leaf"
  ISSUER_CERT="$selected"; ISSUER_ID="$(certificate_id "$selected")"
  ISSUER_KEY="$(authority_path "$base" "generations/$ISSUER_ID/ca.key.pem")"
  if [[ ! -f "$ISSUER_KEY" && "$(certificate_id "$base/certs/ca.cert.pem")" == "$ISSUER_ID" ]]; then
    ISSUER_KEY="$base/private/ca.key.pem"
  fi
}

bind_leaf() {
  local base="$1" leaf="$2" id="$3" serial dest tmp
  serial="$(openssl_serial "$leaf")"
  dest="$(authority_path "$base" "issuers/$serial")"
  if [[ -f "$dest" ]]; then
    [[ "$(sed -n '1p' "$dest")" == "$id" && "$(sed -n '2p' "$dest")" == "$(certificate_id "$leaf")" ]] || die "Existing leaf binding conflicts: $dest"
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  tmp="$(mktemp "$base/issuers/.binding.XXXXXX")"
  printf '%s\n%s\n' "$id" "$(certificate_id "$leaf")" > "$tmp"
  staged_install "$tmp" "$dest"
  rm -f "$tmp"
}

backfill_bindings() {
  local base="$1" serial leaf
  pki_records validate "$base/index.txt" >/dev/null
  while IFS= read -r serial; do
    [[ -n "$serial" ]] || continue
    leaf="$(authority_path "$base" "newcerts/$serial.pem")"
    [[ -f "$leaf" ]] || die "Missing certificate history before renewal: $leaf"
    resolve_leaf_issuer "$base" "$leaf"
    bind_leaf "$base" "$leaf" "$ISSUER_ID"
  done < <(awk -F '\t' '$1~/^[VRE]$/{print $4}' "$base/index.txt")
}

normalize_ca_artifacts() {
  local base="$1" serial tmp
  check_authority_paths "$base"
  check_pair "$base/certs/ca.cert.pem" "$base/private/ca.key.pem"
  tmp="$(mktemp "$base/certs/chain.tmp.XXXXXX")"
  cat "$base/certs/ca.cert.pem" "$ROOT_DIR/root/certs/ca.cert.pem" > "$tmp"
  chmod 444 "$tmp"
  mv "$tmp" "$base/certs/ca.chain.cert.pem"
  staged_link ca.chain.cert.pem "$base/certs/chain.cert.pem"
  if [[ ! -f "$base/ca.meta" && -f "$base/meta" ]]; then install -m 444 "$base/meta" "$base/ca.meta"; fi
  if [[ -f "$base/ca.meta" ]]; then
    tmp="$(mktemp "$base/meta.tmp.XXXXXX")"
    PKI_META_DIR="${base#"$ROOT_DIR/"}" PKI_META_POLICY="$("$OPENSSL" dgst -sha256 "$base/openssl.cnf" | awk '{print $NF}')" awk '
      /^INT_DIR=/ {print "INT_DIR=" ENVIRON["PKI_META_DIR"]; seen=1; next}
      /^POLICY_SHA256=/ {print "POLICY_SHA256=" ENVIRON["PKI_META_POLICY"]; next}
      {print} END {if(!seen) print "INT_DIR=" ENVIRON["PKI_META_DIR"]}
    ' "$base/ca.meta" > "$tmp"
    chmod 444 "$tmp"; mv "$tmp" "$base/ca.meta"
  fi
  serial="$(openssl_serial "$base/certs/ca.cert.pem")"
  printf '%s\n' "$serial" > "$base/serial.last"
}

# Explicit authority selector is always required. Preserve authority-relative FILE,
# and accept the workspace-relative spelling only if it names this authority.
resolve_leaf_file() {
  local base="$1" raw="$2" prefix
  if [[ "$raw" == /* ]]; then
    authority_path "$base" "$raw"
  elif [[ "$raw" == certs/* || "$raw" == newcerts/* ]]; then
    authority_path "$base" "$raw"
  elif [[ "$raw" == */certs/* || "$raw" == */newcerts/* ]]; then
    prefix="${raw%%/certs/*}"
    [[ "$prefix" != "$raw" ]] || prefix="${raw%%/newcerts/*}"
    [[ "$(resolve_authority "$prefix")" == "$base" ]] || die "FILE belongs to a different authority: $raw"
    authority_path "$base" "$(workspace_path "$raw")"
  else
    authority_path "$base" "$raw"
  fi
}

# Planning has no lock creation or workspace writes; its snapshot is advisory.
pki_plan_or_begin() {
  if [[ "${DRY_RUN:-0}" == 1 ]]; then cd "$ROOT_DIR"; else pki_begin; fi
}
