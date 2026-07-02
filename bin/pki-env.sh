#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail

# ============================================
#  Shared helpers for the PKI toolkit (root+int)
# ============================================

# ---- Repo root & OpenSSL ----
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ROOT_DIR
export OPENSSL="${OPENSSL:-openssl}"

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
  local waited=0

  mkdir -p "$lock_root"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    (( waited >= timeout )) && die "Timeout while waiting for lock: $lock_name"
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
    */../*|*/./../*|*/.././*|*/../../*)
      die "INT_DIR must not contain '..': '$raw'"
      ;;
  esac
}

# ---- OpenSSL presence + version (refuse LibreSSL) ----
require_openssl(){
  command -v "$OPENSSL" >/dev/null 2>&1 || die "openssl not found in PATH"
  local vstr; vstr="$($OPENSSL version)"
  grep -q 'LibreSSL' <<<"$vstr" && die "LibreSSL non supporté"
  grep -Eq 'OpenSSL (1\.1\.1[a-z]*|3\.[0-9]+\.[0-9]+)' <<<"$vstr" \
    || die "OpenSSL 1.1.1 ou 3.x requis, trouvé: $vstr"
}

require_openssl

# ============================================
#  Action/KIND/INT_DIR resolution & validation
# ============================================

# --- helpers ---------------------------------------------------------------

normalize_int_dir() {
  local v="$1"
  if [[ "$v" == "." ]]; then
    printf "."
  elif [[ "$v" == */* ]]; then
    printf "%s" "$v"
  elif [[ "$v" =~ ^intm-.*-ca$ ]]; then
    printf "%s" "$v"
  else
    printf "intm-%s-ca" "$v"
  fi
}

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
  local expected="intm-${KIND}-ca"
  [[ "$INT_DIR" == "$expected" ]] || die "Cohérence KIND/INT_DIR invalide: attendu '$expected', reçu '$INT_DIR'"
  [[ -f "${INT_DIR}/openssl.cnf" ]] || die "openssl.cnf introuvable: ${INT_DIR}/openssl.cnf"
  export KIND INT_DIR
}

# ============================================
#  DN & input validation
# ============================================
trim_spaces() { sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//' <<<"${1-}"; }
has_control_chars() { LC_ALL=C grep -q '[[:cntrl:]]' <<<"$1"; }
no_double_space() { [[ "${1-}" != *"  "* ]]; }
esc_sed() { printf '%s' "${1-}" | sed -e 's/[\/&\\]/\\&/g'; }

validate_len() {
  local label="$1" val="$2" maxlen="$3"
  if (( ${#val} > maxlen )); then
    die "$label too long (${#val} > ${maxlen} bytes): '$val'"
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
  s="${s//=/\\=}"

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

# RFC2253-order DN builder to match `openssl -nameopt RFC2253`
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
  local c_esc o_esc ou_esc cn_esc tmp_raw
  c_esc="$(esc_sed "$c")"
  o_esc="$(esc_sed "$o")"
  ou_esc="$(esc_sed "$ou")"
  cn_esc="$(esc_sed "$cn")"

  tmp_raw="$(mktemp)"
  sed -e "s/__C__/${c_esc}/" \
      -e "s/__O__/${o_esc}/" \
      -e "s/__OU__/${ou_esc}/" \
      -e "s/__CN__/${cn_esc}/" \
      "$in_cnf" > "$tmp_raw"

  # Drop empty DN lines inside [req_distinguished_name]
  awk '
    BEGIN { in_dn=0 }
    /^\[ *req_distinguished_name *\]$/ { in_dn=1; print; next }
    /^\[/ { if (in_dn) in_dn=0; print; next }
    {
      if (in_dn) {
        if ($0 ~ /^[[:space:]]*C[[:space:]]*=[[:space:]]*$/) next
        if ($0 ~ /^[[:space:]]*O[[:space:]]*=[[:space:]]*$/) next
        if ($0 ~ /^[[:space:]]*OU[[:space:]]*=[[:space:]]*$/) next
      }
      print
    }
  ' "$tmp_raw" > "$out_cnf"
  rm -f "$tmp_raw"
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
  local out="$4"
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

  chmod 400 "$out"
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
  DETECTED_KEY_ALG=""
  DETECTED_KEY_SIZE=""
  DETECTED_KEY_CURVE=""
  DETECTED_KEY_EDDSA=""

  [[ -s "$key_path" ]] || return 0

  local pkey_text=""
  pkey_text="$("$OPENSSL" pkey -in "$key_path" -text -noout 2>/dev/null || true)"
  [[ -n "$pkey_text" ]] || return 0

  if grep -q '^Private-Key: (' <<<"$pkey_text"; then
    DETECTED_KEY_ALG="RSA"
    DETECTED_KEY_SIZE="$(awk -F'[() ]' '/Private-Key:/ {for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) {print $i; exit}}' <<<"$pkey_text")"
    return 0
  fi

  if grep -Eq 'ASN1 OID:|NIST CURVE:' <<<"$pkey_text"; then
    DETECTED_KEY_ALG="EC"
    DETECTED_KEY_CURVE="$(
      awk -F': *' '
        /ASN1 OID:/ {print $2; found=1; exit}
        /NIST CURVE:/ {print $2; found=1; exit}
      ' <<<"$pkey_text"
    )"
    return 0
  fi

  if grep -q 'ED25519' <<<"$pkey_text"; then
    DETECTED_KEY_ALG="ED25519"
    DETECTED_KEY_EDDSA="Ed25519"
    return 0
  fi

  if grep -q 'ED448' <<<"$pkey_text"; then
    DETECTED_KEY_ALG="ED448"
    DETECTED_KEY_EDDSA="Ed448"
    return 0
  fi
}

# Assure que $INT_DIR/serial >= (max serial vu dans index.txt) + 1
ensure_serial_monotonic() {
  local dir="$1"
  local idx="$dir/index.txt"
  local serfile="$dir/serial"

  [[ -f "$serfile" ]] || echo 1000 > "$serfile"
  [[ -f "$idx"     ]] || : > "$idx"

  local max=0
  # BSD/macOS-safe: pur bash arithmétique base 16
  while IFS=$'\t' read -r status expiry rev serial rest; do
    [[ -z "$serial" ]] && continue
    # strip espaces/CR, garder hex
    serial="${serial//$'\r'/}"
    serial="${serial//[^0-9A-Fa-f]/}"
    [[ -z "$serial" ]] && continue
    # éviter erreurs si serial commence par zéro vide
    local v=$((16#$serial))
    (( v > max )) && max=$v
  done < "$idx"

  local cur_hex; cur_hex="$(tr -d '\r\n' < "$serfile")"
  cur_hex="${cur_hex//[^0-9A-Fa-f]/}"
  [[ -z "$cur_hex" ]] && cur_hex="0"
  local cur=$((16#$cur_hex))

  local need=$((max + 1))
  if (( cur < need )); then
    printf '%X\n' "$need" > "$serfile"
  fi
}

# -------------------------------------------
# write_ca_meta
# Écrit le metadata immuable d'une CA (root ou intermédiaire)
# Usage:
#   write_ca_meta \
#     "<CERT_PATH>" "<KEY_PATH>" "<OUT_FILE>" \
#     "<KEY_ALG>" "<KEY_SIZE>" "<KEY_CURVE>" "<KEY_EDDSA>" \
#     "<DAYS>" "<KIND>" "<CA_DIR>" "<PATHLEN_OVERRIDE>" "<ISSUER_CERT_PATH?>"
#
# Notes:
# - Si ISSUER_CERT_PATH est vide → on traite comme self-signed (root).
# - PATHLEN_OVERRIDE (ex: ROOT_PATHLEN) écrase la détection depuis le cert si non vide.
# - Renseigne ALG + KEY_SIZE/CURVE/EDDSA avec fallback par introspection de la clé.
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

  # --- helpers locaux ---
  trim() { local s="${1-}"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

  local alg_raw="$(trim "${KEY_ALG_IN:-}")"
  local alg_lc="$(echo "$alg_raw" | tr '[:upper:]' '[:lower:]')"
  local key_size_raw="$(trim "${KEY_SIZE_IN:-}")"
  local key_curve_raw="$(trim "${KEY_CURVE_IN:-}")"
  local key_eddsa_raw="$(trim "${KEY_EDDSA_IN:-}")"

  local meta_key_size=""
  local meta_key_curve=""
  local meta_key_eddsa=""

  case "$alg_lc" in
    rsa)     meta_key_size="$key_size_raw" ;;
    ec)      meta_key_curve="$key_curve_raw" ;;
    ed25519) meta_key_eddsa="Ed25519" ;;
    ed448)   meta_key_eddsa="Ed448" ;;
    eddsa)   meta_key_eddsa="${key_eddsa_raw:-Ed25519}" ;;
    *)       ;;
  esac

  # --- Fallback: introspection depuis la clé si besoin ---
  if [[ -s "$KEY_PATH" ]]; then
    if [[ "$alg_lc" == "rsa" && -z "$meta_key_size" ]]; then
      meta_key_size="$("$OPENSSL" pkey -in "$KEY_PATH" -text -noout 2>/dev/null \
        | awk -F'[() ]' '/Private-Key:/ {for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) {print $i; exit}}')"
    fi
    if [[ "$alg_lc" == "ec" && -z "$meta_key_curve" ]]; then
      meta_key_curve="$("$OPENSSL" pkey -in "$KEY_PATH" -text -noout 2>/dev/null \
        | awk -F': *' '/ASN1 OID:/ {print $2; exit}')"
    fi
    if [[ "$alg_lc" =~ ^(eddsa|ed25519|ed448)$ && -z "$meta_key_eddsa" ]]; then
      local ed_from_key
      ed_from_key="$("$OPENSSL" pkey -in "$KEY_PATH" -text -noout 2>/dev/null \
        | awk '/ED25519/ {print "Ed25519"; exit} /ED448/ {print "Ed448"; exit}')"
      [[ -n "$ed_from_key" ]] && meta_key_eddsa="$ed_from_key"
    fi
  fi

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

  # --- PathLen: override > cert ---
  local pathlen=""
  if [[ -n "$PATHLEN_OVERRIDE" ]]; then
    pathlen="$(trim "$PATHLEN_OVERRIDE")"
  else
    pathlen="$( "$OPENSSL" x509 -in "$CERT_PATH" -text -noout 2>/dev/null \
      | awk '/Path Length Constraint/ {print $4; exit}' )"
  fi

  # --- Écriture (atomique & safe sur 0444 existant) ---
  local _tmp; _tmp="$(mktemp -t cameta.XXXXXX || mktemp)"
  {
    echo "CREATED_AT=$(date -u +%FT%TZ)"
    echo "OPENSSL_VERSION=$($OPENSSL version)"
    echo "DN=$dn_rfc2253"
    echo "ISSUER_DN=$issuer_dn_rfc2253"
    echo "ALG=$alg_raw"
    [[ -n "$meta_key_eddsa" ]] && echo "KEY_EDDSA=$meta_key_eddsa"
    [[ -n "$meta_key_size"  ]] && echo "KEY_SIZE=$meta_key_size"
    [[ -n "$meta_key_curve" ]] && echo "KEY_CURVE=$meta_key_curve"
    echo "DAYS=$DAYS_VAL"
    [[ -n "$pathlen" ]] && echo "PATHLEN=$pathlen"
    [[ -n "$serial_hex"        ]] && echo "SERIAL=$serial_hex"
    [[ -n "$issuer_serial_hex" ]] && echo "ISSUER_SERIAL=$issuer_serial_hex"
    echo "SPKI_SHA256=$spki"
    [[ -n "$CA_DIR_VAL" ]] && echo "INT_DIR=$CA_DIR_VAL"
    [[ -n "$KIND_VAL"   ]] && echo "KIND=$KIND_VAL"
  } > "$_tmp"
  install -m 444 "$_tmp" "$OUT_FILE"
  rm -f "$_tmp"
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
  local base="$1"
  mkdir -p "$base"/{certs,crl,newcerts,private}
  [[ -f "$base/index.txt" ]] || : > "$base/index.txt"
  [[ -f "$base/serial"    ]] || echo 1000 > "$base/serial"
  [[ -f "$base/crlnumber" ]] || echo 1000 > "$base/crlnumber"
}

ensure_intermediate_layout() {
  local base="$1"
  mkdir -p "$base"/{certs,crl,csr,newcerts,private}
  [[ -f "$base/index.txt" ]] || : > "$base/index.txt"
  [[ -f "$base/serial"    ]] || echo 1000 > "$base/serial"
  [[ -f "$base/crlnumber" ]] || echo 1000 > "$base/crlnumber"
}

create_root_openssl_cnf_if_missing() {
  local cnf="$1" root_abs="$2" days="$3" pathlen="${4-}"
  local basic_constraints="critical, CA:true"
  [[ -f "$cnf" ]] && return 0
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

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = ${basic_constraints}
keyUsage               = critical, keyCertSign, cRLSign

# useful to sign intermediates
[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
CONF
}

# Intermediate config creator
create_intermediate_openssl_cnf_if_missing() {
  local cnf="$1" int_abs="$2" days="$3"
  [[ -f "$cnf" ]] && return 0
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

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign

# Typical server cert extension; override via EXT_SECTION if different
[ server_cert ]
basicConstraints       = critical, CA:false
nsCertType             = server
nsComment              = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth

# Typical client cert extension
[ client_cert ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth

# Compatibility alias kept for legacy callers.
[ usr_cert ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth

[ code_sign ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
extendedKeyUsage       = codeSigning

[ smime ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = emailProtection

[ archive ]
basicConstraints       = critical, CA:false
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, digitalSignature
CONF
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
