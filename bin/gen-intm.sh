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
# shellcheck source=bin/pki-env.sh
source "$(dirname "$0")/pki-env.sh"
pki_begin

REQ_CNF=""
cleanup() {
  [[ -n "$REQ_CNF" ]] && rm -f "$REQ_CNF"
  return 0
}
trap 'rc=$?; cleanup; pki_exit "$rc"' EXIT

# ---------------------------
# Debug
# ---------------------------
DEBUG="${DEBUG:-0}"
dbg(){ [[ "$DEBUG" == "1" ]] && echo "[DBG ] $*" >&2 || true; }
if [[ "$DEBUG" == "1" ]]; then
  rc=0
  set -o errtrace
  trap 'rc=$?; echo "[DBG ] ERR at ${BASH_SOURCE[0]}:${LINENO} → ${BASH_COMMAND} (rc=${rc})" >&2' ERR
fi

# ---------------------------
# Inputs / defaults
# ---------------------------
KIND="${KIND:-}"
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


normalize_key_request

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
# Keep this aligned with the shared helpers also used by gen-leaf.
# ---------------------------
if [[ -n "${INT_DIR:-}" ]]; then
  INT_DIR="$(normalize_int_dir "$INT_DIR")"
  ensure_safe_int_dir "$INT_DIR"
  if [[ -z "${KIND:-}" ]]; then
    KIND="$(kind_from_int_dir "$INT_DIR")"
  fi
elif [[ -n "${KIND:-}" ]]; then
  INT_DIR="$(resolve_authority "intm-${KIND}-ca")"
  ensure_safe_int_dir "$INT_DIR"
else
  INT_DIR="intermediate"
  ensure_safe_int_dir "$INT_DIR"
fi

info "Using intermediate directory: ${INT_DIR}"
export CA_DIR="$INT_DIR"

# ---------------------------
# Validate DN
# ---------------------------
CN="$(validate_component_utf8 "CN" "$CN" "$DN_MAXLEN")"
O="$(validate_component_utf8  "O"  "$O"  "$DN_MAXLEN")"
OU="$(validate_component_utf8 "OU" "$OU" "$DN_MAXLEN")"
C="$(validate_country_iso "$C")"

check_authority_paths root
# Preflight the signing key and requested key policy before layout writes.
assert_private_key_policy "$ROOT_DIR/root/private/ca.key.pem"
if [[ "${FORCE_REUSE_KEY:-0}" == 1 && -s "$INT_DIR/private/ca.key.pem" ]]; then
  assert_private_key_policy "$INT_DIR/private/ca.key.pem"
else
  check_key_generation_policy "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE"
fi

# ---------------------------
# Layout (root must already exist)
# ---------------------------
cd "$ROOT_DIR"
acquire_lock "root-ca"
int_lock_name="$(printf '%s' "$INT_DIR" | tr '/ ' '__')"
acquire_lock root-ca
open_authority_state root
check_config root
check_next_serial root
check_pair root/certs/ca.cert.pem root/private/ca.key.pem
issuance_validity root/certs/ca.cert.pem
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

# Validate both histories before rekeying or invoking a database writer.
PKI_RECORD_COUNTER="$(cat root/serial)" pki_records serial "$ROOT_INDEX" >/dev/null
check_next_serial "$INT_DIR"

# ---------------------------
# Intermediate private key (with auto rekey if previous intm is revoked)
# ---------------------------
KEY_PATH="$INT_DIR/private/ca.key.pem"
CANON_KEY=""
needs_rekey=0

# --- Determine whether issuance can be skipped safely ---
: "${REISSUE_IF_EXPIRES_BEFORE:=2592000}"  # 30 days
: "${FORCE_REISSUE:=0}"
: "${ROTATE_KEY:=0}"

WANT_DN="$(canonical_dn_rfc2253)"  # uses CN/OU/O/C already normalized above

skip_reissue=0
HAVE_DN=""
if [[ -f "$CANON_CERT" ]]; then
  HAVE_DN="$("$OPENSSL" x509 -in "$CANON_CERT" -noout -subject -nameopt RFC2253,utf8,-esc_msb 2>/dev/null | sed 's/^subject=//')"
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

if [[ -s "$CANON_CERT" ]]; then
  "$OPENSSL" verify -auth_level 2 -no_check_time -CAfile "$ROOT_DIR/root/certs/ca.cert.pem" "$CANON_CERT" >/dev/null || die "Existing intermediate issuer mismatch"
  archive_generation "$INT_DIR"
  backfill_bindings "$INT_DIR"
fi

if [[ -s "$KEY_PATH" ]]; then
  inspect_private_key_metadata "$KEY_PATH"
  existing_alg="$DETECTED_KEY_ALG"; existing_size="$DETECTED_KEY_SIZE"
  existing_curve="$DETECTED_KEY_CURVE"; existing_eddsa="$DETECTED_KEY_EDDSA"


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
        if [[ "$existing_alg" != "$KEY_ALG" ]]; then
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
    backup="$INT_DIR/private/ca.key.$ts.$$.bak"
    authority_path "$INT_DIR" "$ROOT_DIR/$backup" >/dev/null
    recovery_start "intermediate authority=$INT_DIR"
    staged_install "$KEY_PATH" "$backup" 400
    CANON_KEY="$KEY_PATH"
    KEY_PATH="$(mktemp "$INT_DIR/private/.replacement.XXXXXX")"
    recovery_note "old_key=$CANON_KEY backup=$backup staged_key=$KEY_PATH"
    info "Archived previous key to: $backup"
  fi
fi

if [[ -f "$CANON_CERT" && -f "$KEY_PATH" && "$FORCE_REISSUE" != "1" && "$ROTATE_KEY" != "1" ]]; then
  if "$OPENSSL" x509 -checkend "$REISSUE_IF_EXPIRES_BEFORE" -in "$CANON_CERT" -noout >/dev/null 2>&1 \
    && [[ "$HAVE_DN" == "$WANT_DN" ]] \
    && [[ "$intm_revoked_auto" != "1" ]] \
    && [[ "$INTM_REVOKED" != "1" ]] \
    && [[ "$needs_rekey" != "1" ]]; then
    assert_private_key_policy "$KEY_PATH"
    skip_reissue=1
  fi
fi

if [[ "$skip_reissue" == "1" ]]; then
  info "Intermediate already exists and is still valid (DN='${HAVE_DN}') — skip. Set FORCE_REISSUE=1 or ROTATE_KEY=1 to reissue."
  check_pair "$CANON_CERT" "$KEY_PATH"
  "$OPENSSL" verify -auth_level 2 -CAfile "$ROOT_DIR/root/certs/ca.cert.pem" "$CANON_CERT" >/dev/null || die "Existing intermediate has an invalid issuer/validity"
  normalize_ca_artifacts "$INT_DIR"
  write_ca_meta "$CANON_CERT" "$KEY_PATH" "$INT_DIR/ca.meta" "" "" "" "" "$DAYS" "${KIND:-}" "$INT_DIR" "" "$ROOT_DIR/root/certs/ca.cert.pem"
  recovery_complete
  exit 0
fi

[[ ! -s "$KEY_PATH" ]] || assert_private_key_policy "$KEY_PATH"
recovery_start "intermediate authority=$INT_DIR"
recovery_note "key=$KEY_PATH certificate=$CANON_CERT"
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
  "$OPENSSL" req -utf8 -new -sha256 -config "$REQ_CNF" -key "$KEY_PATH" -out "$CSR_PATH" >/dev/null 2>&1
else
  "$OPENSSL" req -utf8 -new -sha256 -config "$REQ_CNF" -key "$KEY_PATH" -out "$CSR_PATH"
fi

# ---------------------------
# Sign intermediate with root (v3_intermediate_ca) into a temp file
# ---------------------------
ensure_serial_monotonic root
TMPCRT="$(mktemp "$INT_DIR/certs/.tmp.XXXXXX")"
recovery_signing root "$TMPCRT"
info "Signing intermediate with root for ${DAYS} days (extensions: v3_intermediate_ca)…"
if [[ "$QUIET_OPENSSL" == "1" ]]; then
  "$OPENSSL" ca -batch \
    -config "$ROOT_CNF" \
    -extensions v3_intermediate_ca \
    -startdate "$ISSUE_NOT_BEFORE" -enddate "$ISSUE_NOT_AFTER" -notext -md sha256 \
    -in "$CSR_PATH" \
    -out "$TMPCRT" >/dev/null 2>&1
else
  "$OPENSSL" ca -batch \
    -config "$ROOT_CNF" \
    -extensions v3_intermediate_ca \
    -startdate "$ISSUE_NOT_BEFORE" -enddate "$ISSUE_NOT_AFTER" -notext -md sha256 \
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

recovery_phase "issuance-committed serial=$SERIAL_HEX_ACTUAL"
check_pair "$TMPCRT" "$KEY_PATH"
"$OPENSSL" verify -auth_level 2 -CAfile "$ROOT_DIR/root/certs/ca.cert.pem" "$TMPCRT" >/dev/null

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
    authority_path "$INT_DIR" "certs/${last_archive_tag}.cert.pem" >/dev/null
    authority_path "$INT_DIR" "certs/${last_archive_tag}.chain.cert.pem" >/dev/null
    staged_install "$CANON_CERT" "$INT_DIR/certs/${last_archive_tag}.cert.pem"
    if [[ -f "$CANON_CHAIN" ]]; then
      staged_install "$CANON_CHAIN" "$INT_DIR/certs/${last_archive_tag}.chain.cert.pem"
    fi
    info "Archived previous intermediate to: ${last_archive_tag}.cert.pem (+ chain)"
  else
    ts="$(date +%Y%m%d-%H%M%S)"
    last_archive_tag="ca.${ts}"
    authority_path "$INT_DIR" "certs/${last_archive_tag}.cert.pem" >/dev/null
    authority_path "$INT_DIR" "certs/${last_archive_tag}.chain.cert.pem" >/dev/null
    staged_install "$CANON_CERT" "$INT_DIR/certs/${last_archive_tag}.cert.pem"
    if [[ -f "$CANON_CHAIN" ]]; then
      staged_install "$CANON_CHAIN" "$INT_DIR/certs/${last_archive_tag}.chain.cert.pem"
    fi
    info "Archived previous intermediate to: ${last_archive_tag}.cert.pem (+ chain)"
  fi
fi

# Install new canonical certificate
if [[ -n "${CANON_KEY:-}" ]]; then
  staged_install "$KEY_PATH" "$CANON_KEY" 400
  rm -f "$KEY_PATH"
  KEY_PATH="$CANON_KEY"
fi
staged_install "$TMPCRT" "$CANON_CERT"
recovery_phase certificate-installed
rm -f "$TMPCRT"
chmod 444 "$CANON_CERT"
info "Intermediate CA certificate ready: $CANON_CERT"

# Build canonical chain: intermediate + root
chain_tmp="$(mktemp "$INT_DIR/certs/.chain.XXXXXX")"
cat "$CANON_CERT" "$ROOT_DIR/root/certs/ca.cert.pem" > "$chain_tmp"
staged_install "$chain_tmp" "$CANON_CHAIN"
rm -f "$chain_tmp"
info "Chain ready: $CANON_CHAIN"
ensure_serial_monotonic "$INT_DIR"

# Optional: also archive the new version suffixed by its serial (traceability)
if [[ -n "$SERIAL_HEX_ACTUAL" ]]; then
  NEW_ARCHIVE_CERT="$INT_DIR/certs/ca-${SERIAL_HEX_ACTUAL}.cert.pem"
  NEW_ARCHIVE_CHAIN="$INT_DIR/certs/ca-${SERIAL_HEX_ACTUAL}.chain.cert.pem"
  [[ -f "$NEW_ARCHIVE_CERT" ]]  || cp -p "$CANON_CERT"  "$NEW_ARCHIVE_CERT"
  [[ -f "$NEW_ARCHIVE_CHAIN" ]] || cp -p "$CANON_CHAIN" "$NEW_ARCHIVE_CHAIN"
fi

# ---------------------------
# Écrire le fichier metadata en lecture seule de l'intermédiaire
# ---------------------------
INT_CERT="$CANON_CERT"
INT_KEY="$KEY_PATH"
INT_META="$INT_DIR/ca.meta"
ROOT_CERT_PATH="$ROOT_DIR/root/certs/ca.cert.pem"

# Write fresh metadata with a same-directory staged rename
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
DIR="$INT_DIR"
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

if "$OPENSSL" verify -auth_level 2 -CAfile "$ROOT_CRT" "$INT_CRT" >/dev/null; then
  info "Vérification OK (intermédiaire signé par la root)."
else
  die  "Vérification de chaîne échouée pour l’intermédiaire ($INT_CRT)"
fi

# Legacy alias for older tooling: point to the canonical chain.
CHAIN_PATH="$DIR/certs/chain.cert.pem"
staged_link "ca.chain.cert.pem" "$CHAIN_PATH"
info "Legacy chain alias refreshed: $CHAIN_PATH -> ca.chain.cert.pem"

archive_generation "$INT_DIR"
normalize_ca_artifacts "$INT_DIR"

recovery_complete
