#!/usr/bin/env bash
# ===============================================================
#  Certnify — PKI Toolkit
#  Copyright (c) 2025 Bruno Goirand
#
#  This file is part of the Certnify PKI Toolkit.
#  Certnify simplifies the creation and management of private
#  certification authorities (root, intermediates, and leafs),
#  following modern PKI best practices.
#
#  License: SPDX-License-Identifier: MIT
#  Permission is hereby granted, free of charge, to any person
#  obtaining a copy of this software and associated documentation
#  files (the “Software”), to deal in the Software without restriction,
#  including without limitation the rights to use, copy, modify,
#  merge, publish, distribute, sublicense, and/or sell copies of
#  the Software, subject to the inclusion of this notice in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#  NONINFRINGEMENT.
#
#  Project: https://github.com/brunogoirand/certnify
# ===============================================================

# ===============================================================
#  Environment Options (for Certnify scripts)
# ===============================================================
# These environment variables control script behavior and defaults.
# All variables are optional unless specified otherwise.
#
# === Identification ===
# CN                    Common Name (ex: "GOIRAND (Web)")
# C                     Country code (2 letters, ex: "FR")
# O                     Organization (optional)
# OU                    Organizational Unit (optional)
# DAYS                  Certificate validity in days (default: 3650 for intermediates)
#
# === Key Parameters ===
# KEY_ALG               Key algorithm: RSA | EC | EDDSA   (default: RSA)
# KEY_SIZE              RSA key size in bits (default: 4096)
# KEY_CURVE             EC curve name (default: prime256v1)
# KEY_EDDSA             EdDSA type: Ed25519 | Ed448 (default: Ed25519)
#
# === Directories & Layout ===
# ROOT_DIR              Root CA directory (default: ./root)
# INT_DIR               Intermediate CA directory (has priority over KIND)
# KIND                  Shortcut for intermediate type ("web", "auth", "code", "smime", "archive")
#                       Expands automatically to "intm-${KIND}-ca" if INT_DIR is unset.
#
# === Behavior Controls ===
# QUIET_OPENSSL         1 to silence OpenSSL output (default: 1)
# DEBUG                 1 to enable verbose debug traces (default: 0)
#
# === Key Management ===
# REKEY_ON_ALG_CHANGE   1 = regenerate key if algorithm/size/curve changes (default: 1)
# REKEY_ON_REVOKE       1 = regenerate key if previous cert revoked (default: 1)
# FORCE_REUSE_KEY       1 = force reuse of existing private key even if rekey would trigger
# ROTATE_KEY            1 = rotate key and reissue certificate regardless of validity
#
# === Intermediate Issuance ===
# FORCE_REISSUE         1 = force regeneration of certificate even if still valid
# REISSUE_IF_EXPIRES_BEFORE  Seconds before expiry to trigger auto-reissue (default: 2592000 = 30d)
#
# === Revocation Awareness ===
# INTM_REVOKED          1 = manual override: treat previous intermediate as revoked
#
# === DN Validation ===
# DN_MAXLEN             Maximum length for DN components (default: 128)
#
# === Post-Generation Behavior ===
# CRL_UPDATE            1 = automatically rebuild CRLs after issuance or revocation
# CRL_DAYS              CRL validity in days when CRL_UPDATE=1 (default: 7)
#
# === File Naming ===
# FORCE_NEW_KEY         Alias of ROTATE_KEY (for backward compatibility)
#
# === Miscellaneous ===
# OPENSSL               Path to OpenSSL binary (default: openssl)
# ROOT_CNF              Root configuration file path (auto-resolved)
# INT_CNF               Intermediate configuration file path (auto-resolved)
#
# Notes:
# - INT_DIR always takes precedence over KIND.
# - Scripts are idempotent by design: if the target CA/cert already exists
#   and remains valid, no regeneration occurs unless forced.
# - To regenerate intentionally, use one of:
#       FORCE_REISSUE=1
#       ROTATE_KEY=1
#       REKEY_ON_ALG_CHANGE=1
# ===============================================================
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"

REQ_CNF=""
cleanup() {
  [[ -n "$REQ_CNF" ]] && rm -f "$REQ_CNF"
  release_locks
}
trap cleanup EXIT

# ---------------------------
# Debug
# ---------------------------
DEBUG="${DEBUG:-0}"
dbg(){ [[ "$DEBUG" == "1" ]] && echo "[DBG ] $*" >&2 || true; }
if [[ "$DEBUG" == "1" ]]; then
  set -o errtrace
  trap 'rc=$?; echo "[DBG ] ERR at ${BASH_SOURCE[0]}:${LINENO} → ${BASH_COMMAND} (rc=${rc})" >&2' ERR
fi

# ---------------------------
# Inputs / defaults
# ---------------------------
CN="${CN:-Example Intermediate CA}"
C="${C:-}"
O="${O:-}"
OU="${OU:-}"
DAYS="${DAYS:-3650}"                   # 10 years by default for an intermediate

#KEY_ALG="${KEY_ALG:-RSA}"
#KEY_SIZE="${KEY_SIZE:-4096}"
#KEY_CURVE="${KEY_CURVE:-prime256v1}"

# trim/normalize
# RSA | EC | EdDSA
KEY_ALG="$(echo "${KEY_ALG:-RSA}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:lower:]' '[:upper:]')"
# used if RSA only
KEY_SIZE="$(echo "${KEY_SIZE:-4096}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
# used if EC: prime256v1|secp384r1
KEY_CURVE="$(echo "${KEY_CURVE:-prime256v1}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
# used if EdDSA: Ed25519 | Ed448
KEY_EDDSA="$(echo "${KEY_EDDSA:-Ed25519}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"


DN_MAXLEN="${DN_MAXLEN:-128}"
QUIET_OPENSSL="${QUIET_OPENSSL:-1}"

# Key regeneration control options
REKEY_ON_ALG_CHANGE="${REKEY_ON_ALG_CHANGE:-1}"
REKEY_ON_REVOKE="${REKEY_ON_REVOKE:-1}"
FORCE_REUSE_KEY="${FORCE_REUSE_KEY:-0}"
ROTATE_KEY="${ROTATE_KEY:-0}"
INTM_REVOKED="${INTM_REVOKED:-0}"  # manual override (optional)

# ---------------------------
# Resolve target intermediate directory (INT_DIR wins over KIND)
# Rules:
# - If INT_DIR contains a '/', keep as-is (treat as path).
# - If INT_DIR already matches "intm-*-ca", keep as-is.
# - If INT_DIR == ".", keep as-is (current dir).
# - Else, when INT_DIR is set (bare name), expand to "intm-${INT_DIR}-ca".
# - Else, fallback to KIND → "intm-${KIND}-ca", then "intermediate".
# ---------------------------
raw_int="${INT_DIR:-}"
kind="${KIND:-}"

if [[ -n "$raw_int" ]]; then
  if [[ "$raw_int" == "." ]]; then
    INT_DIR="."
  elif [[ "$raw_int" == */* ]]; then
    INT_DIR="$raw_int"
  elif [[ "$raw_int" =~ ^intm-.*-ca$ ]]; then
    INT_DIR="$raw_int"
  else
    INT_DIR="intm-${raw_int}-ca"
  fi
elif [[ -n "$kind" ]]; then
  INT_DIR="intm-${kind}-ca"
else
  INT_DIR="intermediate"
fi

ensure_safe_int_dir "$INT_DIR"

info "Using intermediate directory: ${INT_DIR}"
export CA_DIR="$INT_DIR"

# ---------------------------
# Validate DN
# ---------------------------
CN="$(validate_component_utf8 "CN" "$CN" "$DN_MAXLEN")"
O="$(validate_component_utf8  "O"  "$O"  "$DN_MAXLEN")"
OU="$(validate_component_utf8 "OU" "$OU" "$DN_MAXLEN")"
C="$(validate_country_iso "$C")"

# ---------------------------
# Layout (root must already exist)
# ---------------------------
cd "$ROOT_DIR"
acquire_lock "root-ca"
int_lock_name="$(printf '%s' "$INT_DIR" | tr '/ ' '__')"
acquire_lock "intm-${int_lock_name}"
ensure_root_layout "root"
mkdir -p "$INT_DIR"
ensure_intermediate_layout "$INT_DIR"

ROOT_ABS="$(pwd)/root"
INT_ABS="$(pwd)/${INT_DIR}"
export CA_ABS="$INT_ABS"

# Config file paths (force from resolved dirs)
ROOT_CNF="$ROOT_DIR/root/openssl.cnf"
INT_CNF="$ROOT_DIR/$INT_DIR/openssl.cnf"
mkdir -p "$(dirname "$INT_CNF")"

# ---- Ensure configs exist ----
create_root_openssl_cnf_if_missing "$ROOT_CNF" "$ROOT_ABS" "$DAYS"
create_intermediate_openssl_cnf_if_missing "$INT_CNF" "$INT_ABS" "$DAYS"

# Common paths
ROOT_INDEX="$ROOT_DIR/root/index.txt"
CANON_CERT="$INT_DIR/certs/ca.cert.pem"
CANON_CHAIN="$INT_DIR/certs/ca.chain.cert.pem"

# ---------------------------
# Intermediate private key (with auto rekey if previous intm is revoked)
# ---------------------------
KEY_PATH="$INT_DIR/private/ca.key.pem"
needs_rekey=0

# --- Determine whether issuance can be skipped safely ---
: "${REISSUE_IF_EXPIRES_BEFORE:=2592000}"  # 30 days
: "${FORCE_REISSUE:=0}"
: "${ROTATE_KEY:=0}"

WANT_DN="$(canonical_dn_rfc2253)"  # uses CN/OU/O/C already normalized above

skip_reissue=0
HAVE_DN=""
if [[ -f "$CANON_CERT" ]]; then
  HAVE_DN="$("$OPENSSL" x509 -in "$CANON_CERT" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
fi

# Auto-detect if the previous canonical intermediate cert is revoked in ROOT
intm_revoked_auto=0
if [[ -f "$CANON_CERT" && -f "$ROOT_INDEX" ]]; then
  prev_serial="$("$OPENSSL" x509 -in "$CANON_CERT" -noout -serial 2>/dev/null | sed 's/^serial=//I' | tr '[:lower:]' '[:upper:]' || true)"
  if [[ -n "$prev_serial" ]]; then
    if awk -F'\t' -v s="$prev_serial" '$1=="R" && $4==s {found=1} END{exit(!found)}' "$ROOT_INDEX"; then
      intm_revoked_auto=1
      dbg "Detected previous intermediate revoked in ROOT (serial=$prev_serial)"
    fi
  fi
fi

if [[ -s "$KEY_PATH" ]]; then
  existing_alg=""
  existing_size=""
  existing_curve=""
  existing_eddsa=""

  if "$OPENSSL" rsa -in "$KEY_PATH" -noout >/dev/null 2>&1; then
    existing_alg="RSA"
    existing_size="$("$OPENSSL" rsa -in "$KEY_PATH" -text -noout 2>/dev/null | awk -F'[( )]' '/Private-Key:/ {print $3; exit}')"
  elif "$OPENSSL" ec -in "$KEY_PATH" -noout >/dev/null 2>&1; then
    existing_alg="EC"
    existing_curve="$("$OPENSSL" ec -in "$KEY_PATH" -noout -text 2>/dev/null | awk -F': ' '/ASN1 OID:/ {print $2; exit}')"
    [[ -z "$existing_curve" ]] && existing_curve="$("$OPENSSL" ec -in "$KEY_PATH" -noout -text 2>/dev/null | awk -F': ' '/OID:/ {print $2; exit}')"
  elif "$OPENSSL" pkey -in "$KEY_PATH" -text -noout 2>/dev/null | grep -q 'ED25519'; then
    existing_alg="EdDSA"; existing_curve=""; existing_size=""; existing_eddsa="Ed25519"
  elif "$OPENSSL" pkey -in "$KEY_PATH" -text -noout 2>/dev/null | grep -q 'ED448'; then
    existing_alg="EdDSA"; existing_curve=""; existing_size=""; existing_eddsa="Ed448"
  fi


  want_alg="$KEY_ALG"
  want_size="$KEY_SIZE"
  want_curve="$KEY_CURVE"

  dbg "Existing key: alg='${existing_alg}', size='${existing_size}', curve='${existing_curve}'"
  dbg "Requested key: alg='${want_alg}', size='${want_size}', curve='${want_curve}', eddsa='${KEY_EDDSA}'"

  if [[ "$REKEY_ON_ALG_CHANGE" == "1" ]]; then
    case "$want_alg" in
      RSA)
        if [[ "$existing_alg" != "RSA" || ( -n "$existing_size" && "$existing_size" != "$want_size" ) ]]; then
          needs_rekey=1
        fi
        ;;
      EC)
        if [[ "$existing_alg" != "EC" || ( -n "$existing_curve" && -n "$want_curve" && "$existing_curve" != "$want_curve" ) ]]; then
          needs_rekey=1
        fi
        ;;
      EDDSA|ED25519|ED448)
        if [[ "$existing_alg" != "EdDSA" || ( -n "$existing_eddsa" && "$existing_eddsa" != "$KEY_EDDSA" ) ]]; then
          needs_rekey=1
        fi
        ;;
      *)
        warn "Unknown KEY_ALG='$want_alg' — forcing rekey."
        needs_rekey=1
        ;;
    esac
  fi

  # Auto rekey on revoked previous intermediate (or manual INTM_REVOKED=1)
  if [[ "$REKEY_ON_REVOKE" == "1" && ( "$INTM_REVOKED" == "1" || "$intm_revoked_auto" == "1" ) ]]; then
    needs_rekey=1
  fi

  if [[ "$ROTATE_KEY" == "1" ]]; then
    needs_rekey=1
  fi

  if [[ "$needs_rekey" == "1" && "$FORCE_REUSE_KEY" != "1" ]]; then
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="$INT_DIR/private/ca.key.$ts.bak"
    mv -f "$KEY_PATH" "$backup"
    info "Archived previous key to: $backup"
  fi
fi

if [[ -f "$CANON_CERT" && -f "$KEY_PATH" && "$FORCE_REISSUE" != "1" && "$ROTATE_KEY" != "1" ]]; then
  if "$OPENSSL" x509 -checkend "$REISSUE_IF_EXPIRES_BEFORE" -in "$CANON_CERT" -noout >/dev/null 2>&1 \
    && [[ "$HAVE_DN" == "$WANT_DN" ]] \
    && [[ "$intm_revoked_auto" != "1" ]] \
    && [[ "$INTM_REVOKED" != "1" ]] \
    && [[ "$needs_rekey" != "1" ]]; then
    skip_reissue=1
  fi
fi

if [[ "$skip_reissue" == "1" ]]; then
  info "Intermediate already exists and is still valid (DN='${HAVE_DN}') — skip. Set FORCE_REISSUE=1 or ROTATE_KEY=1 to reissue."
  exit 0
fi

if [[ ! -s "$KEY_PATH" ]]; then
  gen_private_key "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_PATH"
else
  info "Intermediate private key already exists: $KEY_PATH (reuse)"
fi

# ---------------------------
# Render a request config (DN injected; drop empty lines)
# ---------------------------
REQ_CNF="$(mktemp)"
render_req_cnf_with_dn "$INT_CNF" "$REQ_CNF" "$C" "$O" "$OU" "$CN"

# ---------------------------
# CSR for intermediate
# ---------------------------
CSR_PATH="$INT_DIR/csr/ca.csr.pem"
info "Creating CSR for intermediate CN='${CN}' (DN: C='${C}' O='${O}' OU='${OU}')…"
if [[ "$QUIET_OPENSSL" == "1" ]]; then
  "$OPENSSL" req -new -sha256 -config "$REQ_CNF" -key "$KEY_PATH" -out "$CSR_PATH" >/dev/null 2>&1
else
  "$OPENSSL" req -new -sha256 -config "$REQ_CNF" -key "$KEY_PATH" -out "$CSR_PATH"
fi

# ---------------------------
# Sign intermediate with root (v3_intermediate_ca) into a temp file
# ---------------------------
TMPCRT="$INT_DIR/certs/.tmp.$(date +%s).$$.pem"
info "Signing intermediate with root for ${DAYS} days (extensions: v3_intermediate_ca)…"
if [[ "$QUIET_OPENSSL" == "1" ]]; then
  "$OPENSSL" ca -batch \
    -config "$ROOT_CNF" \
    -extensions v3_intermediate_ca \
    -days "$DAYS" -notext -md sha256 \
    -in "$CSR_PATH" \
    -out "$TMPCRT" >/dev/null 2>&1
else
  "$OPENSSL" ca -batch \
    -config "$ROOT_CNF" \
    -extensions v3_intermediate_ca \
    -days "$DAYS" -notext -md sha256 \
    -in "$CSR_PATH" \
    -out "$TMPCRT"
fi

# ---------------------------
# Read actual serial and fix ROOT index.txt filename=unknown on 'V'
# ---------------------------
#SERIAL_HEX_ACTUAL="$("$OPENSSL" x509 -in "$TMPCRT" -noout -serial 2>/dev/null | sed 's/^serial=//I' || true)"
SERIAL_HEX_ACTUAL="$("$OPENSSL" x509 -in "$TMPCRT" -noout -serial 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' | sed 's/^serial=//')"
SERIAL_HEX_ACTUAL="$(printf '%s' "$SERIAL_HEX_ACTUAL" | tr '[:lower:]' '[:upper:]')"
if [[ -z "$SERIAL_HEX_ACTUAL" ]]; then
  SERIAL_HEX_ACTUAL="$(openssl_serial "$TMPCRT" || true)"
fi
if [[ -z "$SERIAL_HEX_ACTUAL" && -f "$ROOT_INDEX" ]]; then
  SERIAL_HEX_ACTUAL="$(awk '/^V\t/ {s=$4} END{print s}' "$ROOT_INDEX")"
fi
SERIAL_HEX_ACTUAL="$(printf '%s' "${SERIAL_HEX_ACTUAL:-}" | tr -d '\r\n' | tr '[:lower:]' '[:upper:]')"
dbg "Issued intermediate serial=${SERIAL_HEX_ACTUAL:-<unknown>}"

if [[ -n "$SERIAL_HEX_ACTUAL" && -f "$ROOT_INDEX" ]]; then
  index_set_filename_for_valid "$ROOT_INDEX" "$SERIAL_HEX_ACTUAL" || true
  awk -v s="$SERIAL_HEX_ACTUAL" 'BEGIN{FS=OFS="\t"} { if ($1=="V" && $4==s && $5=="unknown") $5=sprintf("newcerts/%s.pem", s); print }' \
    "$ROOT_INDEX" > "$ROOT_INDEX.tmp" && mv "$ROOT_INDEX.tmp" "$ROOT_INDEX"
fi

# Tag used to archive the previous generation (cert/chain/meta)
last_archive_tag=""

# ---------------------------
# Rotate previous canonical cert/chain (if present), then install new canonical
# ---------------------------
if [[ -f "$CANON_CERT" ]]; then
  OLD_SERIAL_HEX="$("$OPENSSL" x509 -in "$CANON_CERT" -noout -serial 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | sed 's/^serial=//')"
  OLD_SERIAL_HEX="$(printf '%s' "$OLD_SERIAL_HEX" | tr '[:lower:]' '[:upper:]')"

  if [[ -n "$OLD_SERIAL_HEX" ]]; then
    last_archive_tag="ca-${OLD_SERIAL_HEX}"
    mv -f "$CANON_CERT"  "$INT_DIR/certs/${last_archive_tag}.cert.pem"
    if [[ -f "$CANON_CHAIN" ]]; then
      mv -f "$CANON_CHAIN" "$INT_DIR/certs/${last_archive_tag}.chain.cert.pem"
    fi
    info "Archived previous intermediate to: ${last_archive_tag}.cert.pem (+ chain)"
  else
    ts="$(date +%Y%m%d-%H%M%S)"
    last_archive_tag="ca.${ts}"
    mv -f "$CANON_CERT"  "$INT_DIR/certs/${last_archive_tag}.cert.pem"
    if [[ -f "$CANON_CHAIN" ]]; then
      mv -f "$CANON_CHAIN" "$INT_DIR/certs/${last_archive_tag}.chain.cert.pem"
    fi
    info "Archived previous intermediate to: ${last_archive_tag}.cert.pem (+ chain)"
  fi
fi

# Install new canonical certificate
install -m 0644 "$TMPCRT" "$CANON_CERT"
rm -f "$TMPCRT"
chmod 444 "$CANON_CERT"
info "Intermediate CA certificate ready: $CANON_CERT"

# Build canonical chain: intermediate + root
cat "$CANON_CERT" "$ROOT_DIR/root/certs/ca.cert.pem" > "$CANON_CHAIN"
chmod 444 "$CANON_CHAIN"
info "Chain ready: $CANON_CHAIN"
#ensure_serial_monotonic "$INT_DIR"

# Optional: also archive the new version suffixed by its serial (traceability)
if [[ -n "$SERIAL_HEX_ACTUAL" ]]; then
  NEW_ARCHIVE_CERT="$INT_DIR/certs/ca-${SERIAL_HEX_ACTUAL}.cert.pem"
  NEW_ARCHIVE_CHAIN="$INT_DIR/certs/ca-${SERIAL_HEX_ACTUAL}.chain.cert.pem"
  [[ -f "$NEW_ARCHIVE_CERT" ]]  || cp -p "$CANON_CERT"  "$NEW_ARCHIVE_CERT"
  [[ -f "$NEW_ARCHIVE_CHAIN" ]] || cp -p "$CANON_CHAIN" "$NEW_ARCHIVE_CHAIN"
fi

# ---------------------------
# Écrire le fichier metadata immuable de l'intermédiaire
# ---------------------------
INT_CERT="$CANON_CERT"
INT_KEY="$KEY_PATH"
INT_META="$INT_DIR/ca.meta"
ROOT_CERT_PATH="$ROOT_DIR/root/certs/ca.cert.pem"

# Write fresh metadata (make sure write_ca_meta uses atomic install; see pki-env.sh patch)
write_ca_meta \
  "$INT_CERT" "$INT_KEY" "$INT_META" \
  "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_EDDSA" \
  "$DAYS" "$KIND" "$INT_DIR" "" "$ROOT_CERT_PATH"

info "Metadata written: $INT_META"

# ---------------------------
# Persist the current intermediate serial for tooling
# ---------------------------
INT_SERIAL_FILE="$INT_DIR/serial.last"
INT_SERIAL_CUR="$("$OPENSSL" x509 -in "$CANON_CERT" -noout -serial 2>/dev/null | sed 's/^serial=//I' | tr '[:lower:]' '[:upper:]')"
[[ -n "$INT_SERIAL_CUR" ]] && printf '%s\n' "$INT_SERIAL_CUR" > "$INT_SERIAL_FILE"
dbg "Persisted current intermediate serial to: $INT_SERIAL_FILE"

# ---------------------------
# Re-enable issuance if it was disabled previously
# ---------------------------
DISABLED_FLAG="$INT_DIR/.disabled"
if [[ -f "$DISABLED_FLAG" ]]; then
  rm -f "$DISABLED_FLAG"
  info "Issuance re-enabled for ${INT_DIR}: removed ${DISABLED_FLAG}"
fi

# --- Résoudre DIR de façon sûre (set -u safe) ---
if [[ -z "${DIR:-}" ]]; then
  if [[ -n "${INT_DIR:-}" ]]; then
    DIR="$INT_DIR"
  elif [[ -n "${KIND:-}" ]]; then
    DIR="intm-${KIND}-ca"
  elif [[ -d "./certs" && -f "./openssl.cnf" ]]; then
    # fallback si le script est lancé depuis le dossier de l'intermédiaire
    DIR="."
  else
    die "DIR non défini. Spécifie INT_DIR=... ou KIND=... (ex: INT_DIR=intm-web-ca)."
  fi
fi

# ---------------------------
# Tests d’intégrité post-émission (INTERMÉDIAIRE)
# ---------------------------
ROOT_CRT="root/certs/ca.cert.pem"
INT_CRT="$DIR/certs/ca.cert.pem"

[[ -s "$ROOT_CRT" ]] || die "Certificat ROOT introuvable: $ROOT_CRT"
[[ -s "$INT_CRT"  ]] || die "Certificat INTERMÉDIAIRE introuvable: $INT_CRT"

if "$OPENSSL" verify -CAfile "$ROOT_CRT" "$INT_CRT" >/dev/null; then
  info "Vérification OK (intermédiaire signé par la root)."
else
  die  "Vérification de chaîne échouée pour l’intermédiaire ($INT_CRT)"
fi

# Legacy alias for older tooling: point to the canonical chain.
CHAIN_PATH="$DIR/certs/chain.cert.pem"
ln -sfn "ca.chain.cert.pem" "$CHAIN_PATH"
info "Legacy chain alias refreshed: $CHAIN_PATH -> ca.chain.cert.pem"
