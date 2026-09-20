#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
# Re-sourcing within a lifecycle transaction must retain its owned lock.
if declare -F pki_begin >/dev/null; then return 0; fi
PKI_CALL_DIR="$(pwd -P)"

# ============================================
#  Shared helpers for the PKI toolkit (root+int)
# ============================================

# ---- Repo root & OpenSSL ----
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export ROOT_DIR
export OPENSSL="${OPENSSL:-openssl}"
export CERTNIFY_PROFILES_DIR="${CERTNIFY_PROFILES_DIR:-$ROOT_DIR/profiles}"

# ---- Security: private keys must not be world-readable ----
umask 077

# ---- Log helpers ----
die(){ echo "[ERR] $*" >&2; exit 1; }
info(){ echo "[OK ] $*"; }
warn(){ echo "[!! ] $*" >&2; }

# ---- Portable lock helpers (mkdir-based, works on macOS/Bash 3.2) ----
LOCK_TIMEOUT="${LOCK_TIMEOUT:-30}"
declare -a __CERTNIFY_LOCK_DIRS=()

acquire_lock() {
  local lock_name="$1"
  local timeout="${2:-$LOCK_TIMEOUT}"
  local lock_root="$ROOT_DIR/.locks"
  local lock_dir="${lock_root}/${lock_name}.lock"
  local waited=0 held i
  for ((i=0; i<${#__CERTNIFY_LOCK_DIRS[@]}; i++)); do
    held="${__CERTNIFY_LOCK_DIRS[$i]}"
    [[ "$held" == "$lock_dir" ]] && return 0
  done
  [[ "$timeout" =~ ^[0-9]+$ ]] || die "Invalid LOCK_TIMEOUT: $timeout"
  [[ ! -L "$lock_root" && ! -L "$lock_dir" ]] || die "Symlinked lock path: $lock_dir"

  mkdir -p "$lock_root"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    (( waited >= timeout )) && die "Timeout waiting for $lock_dir; inspect pid/owner and confirm no process is active before manual recovery (locks are never stolen)"
    sleep 1
    waited=$((waited + 1))
  done

  printf '%s\n' "$$" > "${lock_dir}/pid"
  __CERTNIFY_LOCK_DIRS+=("$lock_dir")
}

release_locks() {
  local lock_dir
  local idx

  for (( idx=${#__CERTNIFY_LOCK_DIRS[@]}-1; idx>=0; idx-- )); do
    lock_dir="${__CERTNIFY_LOCK_DIRS[$idx]}"
    [[ -n "$lock_dir" && -d "$lock_dir" ]] && rm -rf "$lock_dir"
  done
  __CERTNIFY_LOCK_DIRS=()
}

ensure_safe_int_dir() {
  local raw="${1:-}"
  local abs=""
  local canonical=""

  [[ -n "$raw" ]] || die "INT_DIR must not be empty"
  [[ "$raw" != "/" ]] || die "INT_DIR '/' is forbidden"

  if [[ "$raw" == .* && "$raw" != "." && "$raw" != ./* ]]; then
    die "INT_DIR must stay within the workspace: '$raw'"
  fi

  if [[ "$raw" == /* ]]; then
    case "$raw" in
      "$ROOT_DIR"/*) ;;
      *) die "Absolute INT_DIR outside workspace is forbidden: '$raw'" ;;
    esac
  fi

  case "/$raw/" in
    */../*)
      die "INT_DIR must not contain '..': '$raw'"
      ;;
  esac

  if [[ "$raw" == /* ]]; then
    abs="$raw"
  elif [[ "$raw" == "." ]]; then
    abs="$ROOT_DIR"
  else
    abs="$ROOT_DIR/$raw"
  fi

  canonical="$(canonicalize_path_allow_missing "$abs")"
  case "$canonical" in
    "$ROOT_DIR"|"$ROOT_DIR"/*) ;;
    *)
      die "INT_DIR resolves outside workspace: '$raw' -> '$canonical'"
      ;;
  esac
}

canonicalize_path_allow_missing() {
  local target="${1:-}"
  local missing_suffix=""
  local probe=""
  local resolved=""
  local hops=0 link
  while [[ -L "$target" ]]; do
    hops=$((hops+1)); (( hops <= 40 )) || die "Symlink cycle: $target"
    link="$(readlink "$target")"
    if [[ "$link" == /* ]]; then target="$link"; else target="$(dirname "$target")/$link"; fi
  done

  [[ -n "$target" ]] || die "canonicalize_path_allow_missing: path is required"

  if [[ "$target" != /* ]]; then
    die "canonicalize_path_allow_missing: absolute path expected, got '$target'"
  fi

  probe="$target"
  while [[ ! -e "$probe" ]]; do
    local base
    base="$(basename "$probe")"
    missing_suffix="/${base}${missing_suffix}"
    probe="$(dirname "$probe")"
    [[ -n "$probe" && "$probe" != "." ]] || probe="/"
    [[ "$probe" != "/" || -d "/" ]] || die "Cannot resolve path ancestor for '$target'"
  done

  if [[ -d "$probe" ]]; then
    resolved="$(cd "$probe" && pwd -P)"
  else
    resolved="$(cd "$(dirname "$probe")" && pwd -P)/$(basename "$probe")"
  fi

  printf '%s%s\n' "$resolved" "$missing_suffix"
}

# ---- OpenSSL presence + version (refuse LibreSSL) ----
require_openssl(){
  command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not found in PATH"
  local vstr; vstr="$("$OPENSSL" version)"
  grep -q 'LibreSSL' <<<"$vstr" && die "LibreSSL non supporté"
  grep -Eq 'OpenSSL (1\.1\.1[a-z]*|3\.[0-9]+\.[0-9]+)' <<<"$vstr" \
    || die "OpenSSL 1.1.1 ou 3.x requis, trouvé: $vstr"
}

require_openssl

require_profile_file() {
  local rel_path="$1"
  local abs_path="${CERTNIFY_PROFILES_DIR}/${rel_path}"
  [[ -f "$abs_path" ]] || die "Missing OpenSSL profile fragment: ${abs_path}"
  printf '%s\n' "$abs_path"
}

append_profile_file() {
  local out_file="$1" rel_path="$2"
  local src
  src="$(require_profile_file "$rel_path")"
  printf '\n' >> "$out_file"
  cat "$src" >> "$out_file"
  printf '\n' >> "$out_file"
}

append_alias_section_from_existing() {
  local out_file="$1" alias_section="$2" source_section="$3"
  local body=""

  body="$(
    awk -v section="$source_section" '
      $0 == "[ " section " ]" { in_section=1; next }
      /^\[/ && in_section { exit }
      in_section { print }
    ' "$out_file"
  )"

  [[ -n "$body" ]] || die "Unable to build alias section '${alias_section}' from '${source_section}' in ${out_file}"
  printf '\n[ %s ]\n%s\n' "$alias_section" "$body" >> "$out_file"
}

# ============================================
#  Action/KIND/INT_DIR resolution & validation
# ============================================

# --- helpers ---------------------------------------------------------------

normalize_int_dir() { resolve_authority "$1"; }

# Extrait le kind depuis un INT_DIR de la forme intm-<kind>-ca ; sinon vide.
kind_from_int_dir() {
  local v="$1"
  # Compatible Bash 3.2 (pas de =~ avec groupes capteurs portables) → sed
  sed -n 's/^intm-\(.*\)-ca$/\1/p' <<<"$v"
}

# expected_kind_for_action <action>
# Mappe un "verbe" fonctionnel vers le KIND attendu.
# server -> web, user -> auth, dev -> code, email -> smime, doc -> archive
expected_kind_for_action() {
  local action="$1"
  case "$action" in
    server)  printf '%s' 'web' ;;
    user)    printf '%s' 'auth' ;;
    dev)     printf '%s' 'code' ;;
    email)   printf '%s' 'smime' ;;
    doc)     printf '%s' 'archive' ;;
    # pour d'autres actions, on peut étendre ; par défaut: rien
    *)
      die "Action inconnue: '${action}' (attendu: server|user|dev|email|doc)"
      ;;
  esac
}

# --- require_int_dir_for_action -------------------------------------------

# ENV flags (facultatifs) :
#   REQUIRE_STRICT_KIND=1  → impose que INT_DIR/KIND collent exactement au mapping d’ACTION
#   ALLOW_KIND_FROM_DIR=1  → si INT_DIR explicite, déduis KIND depuis INT_DIR (défaut: 1)
require_int_dir_for_action() {
  local action="${1:-}"
  [[ -n "$action" ]] || die "require_int_dir_for_action: action manquante"

  local expected_kind; expected_kind="$(expected_kind_for_action "$action")"
  [[ -n "$expected_kind" ]] || die "Action inconnue: '$action'"

  local strict="${REQUIRE_STRICT_KIND:-0}"
  local allow_kind_from_dir="${ALLOW_KIND_FROM_DIR:-1}"

  local dir="${INT_DIR:-}"
  local kind="${KIND:-}"

  # 1) Si INT_DIR est fourni → on normalise et on gère la cohérence
  if [[ -n "$dir" ]]; then
    dir="$(normalize_int_dir "$dir")"
    ensure_safe_int_dir "$dir"

    # Déduire un kind potentiel à partir d'INT_DIR si possible
    local dir_kind=""
    if [[ "$allow_kind_from_dir" == "1" ]]; then
      dir_kind="$(kind_from_int_dir "$dir")"
    fi

    # Mode strict : il faut que dir_kind (si détectable) et/ou KIND cadrent avec expected_kind
    if [[ "$strict" == "1" ]]; then
      local ok=1
      if [[ -n "$dir_kind" && "$dir_kind" != "$expected_kind" ]]; then
        ok=0
      fi
      if [[ -n "$kind" && "$kind" != "$expected_kind" ]]; then
        ok=0
      fi
      if [[ $ok -eq 0 ]]; then
        die "Pour l'action '${action}', INT_DIR/KIND doivent correspondre à '${expected_kind}' (INT_DIR='${dir}', KIND='${kind:-<vide>}')."
      fi
      kind="$expected_kind"
    else
      # Mode souple : si KIND est vide et qu’on a un dir_kind, on l’utilise ; sinon on garde KIND tel quel
      if [[ -z "$kind" && -n "$dir_kind" ]]; then
        kind="$dir_kind"
      fi
      # Si KIND reste vide, poser quand même le expected_kind (pratique pour les logs)
      if [[ -z "$kind" ]]; then
        kind="$expected_kind"
      fi
    fi

    INT_DIR="$dir"
    KIND="$kind"

  else
    # 2) Pas d'INT_DIR fourni → priorité à KIND si présent, sinon fallback mapping d’ACTION
    if [[ -n "$kind" ]]; then
      if [[ "$strict" == "1" && "$kind" != "$expected_kind" ]]; then
        die "Pour l'action '${action}', KIND doit être '${expected_kind}' (reçu: '${kind}')."
      fi
      INT_DIR="intm-${kind}-ca"
    else
      # Aucun des deux → déduire depuis l’action
      kind="$expected_kind"
      INT_DIR="intm-${kind}-ca"
    fi
    # Normalise au cas où
    INT_DIR="$(normalize_int_dir "$INT_DIR")"
    ensure_safe_int_dir "$INT_DIR"
    KIND="$kind"
  fi

  # 3) Sanity check (exige un openssl.cnf valide pour l’intermédiaire)
  if [[ ! -f "${INT_DIR}/openssl.cnf" ]]; then
    die "Intermediate openssl.cnf introuvable: '${INT_DIR}/openssl.cnf' (génère l’intermédiaire '${INT_DIR}' avant)"
  fi

  export KIND INT_DIR
  #info "Using intermediate directory: ${INT_DIR} (kind=${KIND}, expected=${expected_kind}, strict=${strict})"
}

# Optionnel : helper générique si tu veux juste valider un KIND ou un INT_DIR sans action
# require_int_dir_with_kind  (KIND=..., INT_DIR=... obligatoires et cohérents)
require_int_dir_with_kind() {
  [[ -n "${KIND:-}" ]] || die "KIND manquant"
  [[ -n "${INT_DIR:-}" ]] || die "INT_DIR manquant"
  ensure_safe_int_dir "$INT_DIR"
  local expected="intm-${KIND}-ca"
  [[ "$INT_DIR" == "$expected" ]] || die "Cohérence KIND/INT_DIR invalide: attendu '$expected', reçu '$INT_DIR'"
  [[ -f "${INT_DIR}/openssl.cnf" ]] || die "openssl.cnf introuvable: ${INT_DIR}/openssl.cnf"
  export KIND INT_DIR
}

# ============================================
#  DN & input validation
# ============================================
trim_spaces() { sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//' <<<"${1-}"; }
has_control_chars() {
  case "$1" in *$'\n'*|*$'\r'*) return 0 ;; esac
  LC_ALL=C grep -q '[[:cntrl:]]' <<<"$1"
}
no_double_space() { [[ "${1-}" != *"  "* ]]; }
esc_sed() { printf '%s' "${1-}" | sed -e 's/[\/&\\]/\\&/g'; }

validate_len() {
  local label="$1" val="$2" maxlen="$3"
  local bytes
  bytes="$(printf '%s' "$val" | LC_ALL=C wc -c | tr -d '[:space:]')"
  if (( bytes > maxlen )); then
    die "$label too long (${bytes} > ${maxlen} bytes): '$val'"
  fi
}

validate_component_utf8() {
  local label="$1" raw="${2-}" maxlen="$3"
  local v; v="$(trim_spaces "$raw")"
  if [[ "$label" == "CN" && -z "$v" ]]; then
    die "CN must not be empty"
  fi
  if [[ -z "$v" ]]; then
    printf '%s' ""; return 0
  fi
  if has_control_chars "$v"; then
    die "$label contains control characters (forbidden): '$raw'"
  fi
  if ! no_double_space "$v"; then
    die "$label contains consecutive spaces (forbidden): '$v'"
  fi
  command -v iconv >/dev/null 2>&1 || die "iconv is required for UTF-8 subject validation"
  printf '%s' "$v" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1 || die "$label is not valid UTF-8"
  validate_len "$label" "$v" "$maxlen"
  printf '%s' "$v"
}

validate_country_iso() {
  local raw="${1-}"
  local v; v="$(trim_spaces "$raw")"
  if [[ -z "$v" ]]; then
    printf '%s' ""; return 0
  fi
  if [[ ! "$v" =~ ^[A-Z]{2}$ ]]; then
    die "C must be two uppercase letters (ISO 3166-1 alpha-2), got: '$raw'"
  fi
  printf '%s' "$v"
}

rfc2253_escape_value() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//,/\\,}"
  s="${s//+/\\+}"
  s="${s//\"/\\\"}"
  s="${s//</\\<}"
  s="${s//>/\\>}"
  s="${s//;/\\;}"

  if [[ "$s" == \#* ]]; then
    s="\\$s"
  fi
  if [[ "$s" == " "* ]]; then
    s="\\${s}"
  fi
  if [[ "$s" == *" " ]]; then
    s="${s% }\\ "
  fi

  printf '%s' "$s"
}

# RFC2253-order DN builder to match `openssl -nameopt RFC2253,utf8,-esc_msb`
canonical_dn_rfc2253() {
  local parts=()
  [[ -n "${CN:-}"  ]] && parts+=("CN=$(rfc2253_escape_value "$CN")")
  [[ -n "${OU:-}"  ]] && parts+=("OU=$(rfc2253_escape_value "$OU")")
  [[ -n "${O:-}"   ]] && parts+=("O=$(rfc2253_escape_value "$O")")
  [[ -n "${C:-}"   ]] && parts+=("C=$(rfc2253_escape_value "$C")")
  (IFS=,; printf '%s' "${parts[*]}")
}

render_req_cnf_with_dn() {
  local in_cnf="$1" out_cnf="$2" c="$3" o="$4" ou="$5" cn="$6"
  PKI_C="$c" PKI_O="$o" PKI_OU="$ou" PKI_CN="$cn" awk '
    function quote(v, i,c,out) {
      out="\""; for(i=1;i<=length(v);i++) {c=substr(v,i,1); if(c=="\\" || c=="\"" || c=="$") out=out "\\"; out=out c}; return out "\""
    }
    /^[ \t]*\[/ {section=$0; gsub(/[ \t\[\]]/,"",section)}
    section=="req_distinguished_name" && /^[ \t]*(C|O|OU|CN)[ \t]*=/ {
      key=$0; sub(/=.*/,"",key); gsub(/[ \t]/,"",key)
      value=ENVIRON["PKI_" key]; if(value!="") print key " = " quote(value); next
    }
    {print}
  ' "$in_cnf" > "$out_cnf"

}

# ============================================
#  Key generation & SPKI pin helpers
# ============================================
# QUIET_OPENSSL=1 to reduce OpenSSL noise
gen_private_key() {
  #local alg; alg="$(echo "${1-}" | tr '[:upper:]' '[:lower:]')"
  local alg; alg="$(echo "${1-}" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  local rsa_bits="${2-}"
  local ec_curve="${3-}"
  local destination="$4"
  check_key_generation_policy "$alg" "$rsa_bits" "$ec_curve"
  local out; out="$(mktemp "$(dirname "$destination")/.key.XXXXXX")"
  local quiet="${QUIET_OPENSSL:-0}"

  # Helper to run OpenSSL quietly/verbosely
  _run() {
    if [[ "${quiet:-0}" == "1" ]]; then
      "$@" >/dev/null 2>&1
    else
      "$@"
    fi
  }

  case "$alg" in
    rsa)
      [[ -n "$rsa_bits" ]] || die "Missing RSA size (e.g., KEY_SIZE=4096)"
      info "Generating private key RSA ${rsa_bits} bits (genpkey)…"
      _run "$OPENSSL" genpkey -algorithm RSA \
        -pkeyopt "rsa_keygen_bits:${rsa_bits}" \
        -out "$out"
      ;;

    ec)
      case "$ec_curve" in
        prime256v1|secp384r1|secp521r1) ;;
        *) die "Unsupported EC curve: ${ec_curve} (expected: prime256v1, secp384r1, or secp521r1)";;
      esac
      info "Generating private key EC (${ec_curve}) via genpkey…"
      _run "$OPENSSL" genpkey -algorithm EC \
        -pkeyopt "ec_paramgen_curve:${ec_curve}" \
        -pkeyopt ec_param_enc:named_curve \
        -out "$out"
      ;;

    eddsa|ed25519|ed448)
      # Allow KEY_ALG=EdDSA (use KEY_EDDSA) or KEY_ALG=Ed25519/Ed448 directly
      local ed_alg="${KEY_EDDSA:-Ed25519}"
      # If user set Ed25519/Ed448 directly in KEY_ALG, prefer that
      case "$alg" in
        ed25519) ed_alg="Ed25519" ;;
        ed448)   ed_alg="Ed448"   ;;
        *)       ;;  # keep KEY_EDDSA
      esac
      case "$ed_alg" in
        Ed25519|Ed448) ;;
        ed25519|ed448) ed_alg="$(tr '[:lower:]' '[:upper:]' <<<"${ed_alg:0:1}")${ed_alg:1}" ;; # normalize
        *) die "KEY_EDDSA must be Ed25519 or Ed448 (got: $ed_alg)";;
      esac
      info "Generating private key ${ed_alg} (EdDSA) via genpkey…"
      _run "$OPENSSL" genpkey -algorithm "$ed_alg" -out "$out"
      ;;

    *)
      die "Invalid KEY_ALG: ${alg} (expected: RSA, EC, or EdDSA/Ed25519/Ed448)"
      ;;
  esac

  assert_private_key_policy "$out"
  chmod 400 "$out"
  mv -f "$out" "$destination"
}

# Public key SPKI pin (sha256/base64) for cert or key
pubkey_sha256_b64() {
  local path="$1" mode="$2"
  if [[ "$mode" == "cert" ]]; then
    "$OPENSSL" x509 -in "$path" -noout -pubkey \
      | "$OPENSSL" pkey -pubin -outform DER \
      | "$OPENSSL" sha256 -binary | "$OPENSSL" base64
  else
    "$OPENSSL" pkey -in "$path" -pubout \
      | "$OPENSSL" pkey -pubin -outform DER \
      | "$OPENSSL" sha256 -binary | "$OPENSSL" base64
  fi
}

inspect_private_key_metadata() {
  local key_path="$1"
  # Output variables intentionally set as globals for the caller.
  DETECTED_KEY_ALG=""
  DETECTED_KEY_SIZE=""
  DETECTED_KEY_CURVE=""
  DETECTED_KEY_EDDSA=""

  [[ -s "$key_path" ]] || die "Missing key: $key_path"

  local pkey_text=""
  pkey_text="$("$OPENSSL" pkey -in "$key_path" -text -noout 2>/dev/null || true)"
  [[ -n "$pkey_text" ]] || die "Cannot inspect key: $key_path"

  if grep -Eq 'ASN1 OID:|NIST CURVE:' <<<"$pkey_text"; then
    # shellcheck disable=SC2034
    DETECTED_KEY_ALG="EC"
    # shellcheck disable=SC2034
    DETECTED_KEY_CURVE="$(
      awk -F': *' '
        /ASN1 OID:/ {print $2; found=1; exit}
        /NIST CURVE:/ {print $2; found=1; exit}
      ' <<<"$pkey_text"
    )"
    return 0
  fi

  if grep -q 'ED25519' <<<"$pkey_text"; then
    # shellcheck disable=SC2034
    DETECTED_KEY_ALG="ED25519"
    # shellcheck disable=SC2034
    DETECTED_KEY_EDDSA="Ed25519"
    return 0
  fi

  if grep -q 'ED448' <<<"$pkey_text"; then
    # shellcheck disable=SC2034
    DETECTED_KEY_ALG="ED448"
    # shellcheck disable=SC2034
    DETECTED_KEY_EDDSA="Ed448"
    return 0
  fi
  if grep -q '^modulus:' <<<"$pkey_text"; then
    # shellcheck disable=SC2034
    DETECTED_KEY_ALG="RSA"
    # shellcheck disable=SC2034
    DETECTED_KEY_SIZE="$(awk -F'[() ]' '/Private-Key:/ {for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) {print $i; exit}}' <<<"$pkey_text")"
    return 0
  fi


  die "Unsupported or unreadable key: $key_path"
}

# Shared, fail-closed index/inventory parser. Preserve backslashes via environment.
pki_records() {
  local mode="$1" input="$2"
  PKI_RECORD_MODE="$mode" PKI_RECORD_CN="${CN:-}" \
    PKI_RECORD_NOW="$(date -u +%Y%m%d%H%M%SZ)" \
    LC_ALL=C awk -f "$ROOT_DIR/bin/pki-records.awk" "$input"
}

# Validate the full index and counter before any counter update. The caller owns
# the CA lock. Unsupported (>64-bit) values fail rather than truncate or wrap.
ensure_serial_monotonic() {
  local dir="$1" current next tmp
  check_next_serial "$dir"
  current="$(cat "$dir/serial")"; next="$PKI_NEXT_SERIAL"
  if [[ "$next" != "$current" ]]; then
    tmp="$(mktemp "$dir/serial.tmp.XXXXXX")"
    printf '%s\n' "$next" > "$tmp"
    mv "$tmp" "$dir/serial"
  fi
  authority_path "$dir" "newcerts/$next.pem" >/dev/null
}

# -------------------------------------------
# write_ca_meta
# Écrit le metadata en lecture seule d'une CA (root ou intermédiaire)
# Usage:
#   write_ca_meta \
#     "<CERT_PATH>" "<KEY_PATH>" "<OUT_FILE>" \
#     "<KEY_ALG>" "<KEY_SIZE>" "<KEY_CURVE>" "<KEY_EDDSA>" \
#     "<DAYS>" "<KIND>" "<CA_DIR>" "<PATHLEN_OVERRIDE>" "<ISSUER_CERT_PATH?>"
#
# Notes:
# - Si ISSUER_CERT_PATH est vide → on traite comme self-signed (root).
# - Legacy request arguments are accepted for compatibility; key fields and
#   PATHLEN come from the actual artifacts. Requested lifetime is labeled.
# - Calcule DN, ISSUER_DN, SERIAL, ISSUER_SERIAL, SPKI_SHA256.
# - Rend OUT_FILE en lecture seule (444).
# -------------------------------------------
write_ca_meta() {
  local CERT_PATH="$1"
  local KEY_PATH="$2"
  local OUT_FILE="$3"
  local KEY_ALG_IN="$4"
  local KEY_SIZE_IN="$5"
  local KEY_CURVE_IN="$6"
  local KEY_EDDSA_IN="$7"
  local DAYS_VAL="$8"
  local KIND_VAL="$9"
  local CA_DIR_VAL="${10}"
  local PATHLEN_OVERRIDE="${11:-}"
  local ISSUER_CERT_PATH="${12:-}"

  check_pair "$CERT_PATH" "$KEY_PATH"
  inspect_private_key_metadata "$KEY_PATH"
  local alg_raw="$DETECTED_KEY_ALG"
  local meta_key_size="$DETECTED_KEY_SIZE" meta_key_curve="$DETECTED_KEY_CURVE" meta_key_eddsa="$DETECTED_KEY_EDDSA"
  # --- DN / Issuer / Serials depuis le(s) cert(s) ---
  local dn_rfc2253 issuer_dn_rfc2253 serial_hex issuer_serial_hex

  dn_rfc2253="$("$OPENSSL" x509 -in "$CERT_PATH" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
  serial_hex="$("$OPENSSL" x509 -in "$CERT_PATH" -noout -serial  2>/dev/null | sed 's/^serial=//I' | tr '[:lower:]' '[:upper:]')"

  if [[ -n "$ISSUER_CERT_PATH" ]]; then
    issuer_dn_rfc2253="$("$OPENSSL" x509 -in "$CERT_PATH" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')"
    issuer_serial_hex="$("$OPENSSL" x509 -in "$ISSUER_CERT_PATH" -noout -serial 2>/dev/null | sed 's/^serial=//I' | tr '[:lower:]' '[:upper:]')"
  else
    # Self-signed (root)
    issuer_dn_rfc2253="$dn_rfc2253"
    issuer_serial_hex="$serial_hex"
  fi

  # --- SPKI SHA-256 ---
  local spki
  spki="$("$OPENSSL" x509 -in "$CERT_PATH" -noout -pubkey 2>/dev/null \
    | "$OPENSSL" pkey -pubin -outform der 2>/dev/null \
    | "$OPENSSL" dgst -sha256 -binary 2>/dev/null \
    | base64)"

  local pathlen
  pathlen="$("$OPENSSL" x509 -in "$CERT_PATH" -noout -text | sed -n 's/.*pathlen:\([0-9][0-9]*\).*/\1/p')"
  local policy_config="${CERT_PATH%/certs/*}/openssl.cnf"
  [[ -f "$policy_config" ]] || policy_config="${ROOT_CNF:-$policy_config}"

  # --- Écriture par renommage dans le même répertoire (sans garantie fsync) ---
  local _tmp; _tmp="$(mktemp "$(dirname "$OUT_FILE")/.meta.XXXXXX")"
  {
    echo "CREATED_AT=$(date -u +%FT%TZ)"
    echo "OPENSSL_VERSION=$("$OPENSSL" version)"
    echo "DN=$dn_rfc2253"
    echo "ISSUER_DN=$issuer_dn_rfc2253"
    echo "ALG=$alg_raw"
    [[ -n "$meta_key_eddsa" ]] && echo "KEY_EDDSA=$meta_key_eddsa"
    [[ -n "$meta_key_size"  ]] && echo "KEY_SIZE=$meta_key_size"
    [[ -n "$meta_key_curve" ]] && echo "KEY_CURVE=$meta_key_curve"
    echo "REQUESTED_DAYS=$DAYS_VAL"
    "$OPENSSL" x509 -in "$CERT_PATH" -noout -startdate -enddate
    echo "POLICY_SHA256=$("$OPENSSL" dgst -sha256 "$policy_config" | awk '{print $NF}')"
    [[ -n "$pathlen" ]] && echo "PATHLEN=$pathlen"
    [[ -n "$serial_hex"        ]] && echo "SERIAL=$serial_hex"
    [[ -n "$issuer_serial_hex" ]] && echo "ISSUER_SERIAL=$issuer_serial_hex"
    echo "SPKI_SHA256=$spki"
    [[ -n "$CA_DIR_VAL" ]] && echo "INT_DIR=$CA_DIR_VAL"
    [[ -n "$KIND_VAL"   ]] && echo "KIND=$KIND_VAL"
  } > "$_tmp"
  chmod 444 "$_tmp"
  mv -f "$_tmp" "$OUT_FILE"
}

# --- Utility: set filename=unknown for a revoked serial in index.txt ---
index_set_filename_for_revoked() {
  local index_file="$1" serial="$2"
  [[ -f "$index_file" ]] || return 1
  awk -F'\t' -v s="$serial" 'BEGIN{FS=OFS="\t"} {
    if ($1=="R" && $4==s && $5!="unknown") { $5="unknown" }
    print
  }' "$index_file" > "${index_file}.tmp" && mv "${index_file}.tmp" "$index_file"
}

# --- Utility: deduplicate comma-separated lists (order-preserving) ---
dedup_csv() {
  awk -v str="$1" 'BEGIN{
    n=split(str, a, ",");
    for (i=1; i<=n; i++) {
      gsub(/^[ \t]+|[ \t]+$/, "", a[i]);
      if (a[i] != "" && !seen[a[i]]++) {
        out = (out ? out "," a[i] : a[i]);
      }
    }
    print out;
  }'
}

# ============================================
#  Layouts & OpenSSL config templates
# ============================================
ensure_root_layout() {
  initialize_authority_layout "$1" root
}

ensure_intermediate_layout() {
  initialize_authority_layout "$1" intermediate
}

_build_root_cnf() {
  local cnf="$1" root_abs="$2" days="$3" pathlen="${4-}"
  local basic_constraints="critical, CA:true"
  if [[ -n "$pathlen" ]]; then
    basic_constraints="${basic_constraints}, pathlen:${pathlen}"
  fi
  cat > "$cnf" <<CONF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $root_abs
certs             = \$dir/certs
crl_dir           = \$dir/crl
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/certs/ca.cert.pem
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
private_key       = \$dir/private/ca.key.pem
RANDFILE          = \$dir/private/.rand
name_opt          = ca_default
cert_opt          = ca_default
default_days      = ${days}
default_crl_days  = 7
default_md        = sha256
preserve          = no
policy            = policy_strict
unique_subject    = no

[ policy_strict ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca
prompt              = no

[ req_distinguished_name ]
C  = __C__
O  = __O__
OU = __OU__
CN = __CN__
CONF
  append_profile_file "$cnf" "root/base.cnf"
  sed -i.bak "s|__ROOT_BASIC_CONSTRAINTS__|${basic_constraints}|g" "$cnf"
  rm -f "${cnf}.bak"
}

# Intermediate config creator
_build_intermediate_cnf() {
  local cnf="$1" int_abs="$2" days="$3"
  cat > "$cnf" <<CONF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $int_abs
certs             = \$dir/certs
crl_dir           = \$dir/crl
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/certs/ca.cert.pem
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
private_key       = \$dir/private/ca.key.pem
RANDFILE          = \$dir/private/.rand
name_opt          = ca_default
cert_opt          = ca_default
default_days      = ${days}
default_crl_days  = 7
default_md        = sha256
preserve          = no
policy            = policy_loose
unique_subject    = no
copy_extensions = copy

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_intermediate_ca
prompt              = no

[ req_distinguished_name ]
C  = __C__
O  = __O__
OU = __OU__
CN = __CN__
CONF
  append_profile_file "$cnf" "intermediate/base.cnf"
  append_profile_file "$cnf" "leaf/server-rsa.cnf"
  append_alias_section_from_existing "$cnf" "server_rsa" "server_cert"
  append_profile_file "$cnf" "leaf/server-ec.cnf"
  append_profile_file "$cnf" "leaf/client-rsa.cnf"
  append_alias_section_from_existing "$cnf" "client_rsa" "client_cert"
  append_alias_section_from_existing "$cnf" "usr_cert" "client_cert"
  append_profile_file "$cnf" "leaf/client-ec.cnf"
  append_profile_file "$cnf" "leaf/code-sign.cnf"
  append_profile_file "$cnf" "leaf/smime-legacy.cnf"
  append_profile_file "$cnf" "leaf/smime-sign.cnf"
  append_profile_file "$cnf" "leaf/smime-encrypt.cnf"
  append_profile_file "$cnf" "leaf/archive-legacy.cnf"
  append_profile_file "$cnf" "leaf/archive-seal.cnf"
  append_profile_file "$cnf" "leaf/timestamping.cnf"
}

# ------------------------------------------------------------------------------
# Utils PKI réutilisables
# ------------------------------------------------------------------------------

openssl_serial() {
  local cert="$1"
  "$OPENSSL" x509 -in "$cert" -noout -serial | sed 's/^serial=//'
}

# Met à jour index.txt : pour un serial au statut V, si filename=unknown -> filename=newcerts/<serial>.pem
index_set_filename_for_valid() {
  local index_file="$1" serial_hex="$2"
  awk -v s="$serial_hex" 'BEGIN{FS=OFS="\t"}
    { if ($1=="V" && $4==s && $5=="unknown") $5=sprintf("newcerts/%s.pem", s); print }
  ' "$index_file" > "$index_file.tmp" && mv "$index_file.tmp" "$index_file"
}

assert_intermediate_ready() {
  [[ -d "$ROOT_DIR/$CA_DIR" ]] || die "Intermediate dir not found: $CA_DIR"
  [[ -f "$ROOT_DIR/$CA_DIR/openssl.cnf" ]] || warn "Missing $CA_DIR/openssl.cnf (will be generated by scripts if needed)"
}

# Shared path, generation and transaction contracts.
source "$ROOT_DIR/bin/pki-state.sh"
source "$ROOT_DIR/bin/pki-crl.sh"

source "$ROOT_DIR/bin/pki-policy.sh"

source "$ROOT_DIR/bin/pki-recovery.sh"
source "$ROOT_DIR/bin/pki-validity.sh"

source "$ROOT_DIR/bin/pki-input.sh"
validate_public_inputs
