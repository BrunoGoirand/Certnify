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
#  Environment Options — Root CA Generator (gen-root.sh)
# ===============================================================
# This script initializes a new *Root Certificate Authority*.
# It is idempotent: if a valid root already exists and the DN matches,
# no overwrite occurs unless manually removed.
#
# === Identification ===
# CN                    Common Name (default: "Root CA")
# C                     Country code (2 letters, ex: "FR")
# O                     Organization (optional)
# OU                    Organizational Unit (optional)
# DN_MAXLEN             Maximum length per DN field (default: 128)
#
# === Validity & Lifetime ===
# DAYS                  Certificate validity in days (default: 7300 → ~20 years)
# ROOT_PATHLEN          Path length constraint for intermediates (default: 1)
#                       Set empty ("") to omit the constraint.
#
# === Key Parameters ===
# KEY_ALG               Key algorithm (RSA | EC | EdDSA) — default: RSA
# KEY_SIZE              RSA key size (bits) — default: 4096
# KEY_CURVE             EC curve name — default: prime256v1
#                       Other options: secp384r1, secp521r1
# KEY_EDDSA             EdDSA key type — default: Ed25519
#                       Other option: Ed448
#
# === Behavior & Execution ===
# QUIET_OPENSSL         1 = suppress OpenSSL command output (default: 1)
# DEBUG                 1 = enable verbose debug traces
# OPENSSL               Path to the OpenSSL binary (default: openssl)
#
# === File Layout ===
# ROOT_DIR              Working directory for the root CA (default: current ./root)
# ROOT_CNF              Path to the root’s OpenSSL configuration (default: ROOT_DIR/root/openssl.cnf)
#
# === Behavior & Safety Rules ===
# - If an existing root certificate is found:
#     → DN (RFC2253) is compared with the requested one.
#     → If DN differs, the script aborts safely (no overwrite).
# - If both private key and certificate exist:
#     → A SPKI pin comparison ensures key↔cert integrity.
# - If key exists but cert missing:
#     → The key is reused; algorithm/curve/size parameters are ignored.
#
# === Output Files ===
# root/private/ca.key.pem        Private key (chmod 600)
# root/certs/ca.cert.pem         Self-signed root certificate (chmod 444)
# root/openssl.cnf               OpenSSL configuration (auto-generated)
# root/ca.meta                   Immutable metadata file with:
#                                 • DN / issuer
#                                 • serial / pathLen / SKI / SPKI
#                                 • OpenSSL version / creation timestamp
#
# === Security Notes ===
# - The root certificate is self-signed using SHA-256 (except EdDSA).
# - A pathLen constraint is set to limit intermediate depth unless disabled.
# - All outputs are permissioned strictly (600 for private, 444 for public).
# - Metadata is always written atomically and immutable.
#
# === Example Usage ===
#   # Minimal invocation (default RSA root)
#   make root CN="Root CA"
#
#   # EC root with custom curve and country
#   make root CN="Corp Root CA" C="FR" KEY_ALG="EC" KEY_CURVE="secp384r1"
#
#   # Ed25519 root (no digest argument needed)
#   make root CN="Lightweight Root" KEY_ALG="EdDSA" KEY_EDDSA="Ed25519"
#
# ===============================================================
set -euo pipefail
# shellcheck source=bin/pki-env.sh
source "$(dirname "$0")/pki-env.sh"

# ============================================
#  Root CA generator (hardened)
#  - Refuse overwrite if existing DN (RFC2253) differs
#  - Idempotent layout & CNF
#  - RSA/EC/EdDSA keygen
#  - Key↔Cert match (SPKI pin)
#  - Metadata: fingerprint, SKI, SPKI
# ============================================

# ---- Inputs / defaults (env-driven) ----
CN="${CN:-Root CA}"
C="${C:-}"
O="${O:-}"
OU="${OU:-}"
DN_MAXLEN="${DN_MAXLEN:-128}"

DAYS="${DAYS:-7300}"                  # 20 years

#KEY_ALG="${KEY_ALG:-RSA}"            # RSA | EC | EdDSA
#KEY_SIZE="${KEY_SIZE:-4096}"         # used if RSA only
#KEY_CURVE="${KEY_CURVE:-prime256v1}" # used if EC: prime256v1|secp384r1
#KEY_EDDSA="${KEY_EDDSA:-Ed25519}"    # used if EdDSA: Ed25519 | Ed448

# trim/normalize
# RSA | EC | EdDSA
KEY_ALG="$(echo "${KEY_ALG:-RSA}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:lower:]' '[:upper:]')"
# used if RSA only
KEY_SIZE="$(echo "${KEY_SIZE:-4096}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
# used if EC: prime256v1|secp384r1|secp521r1
KEY_CURVE="$(echo "${KEY_CURVE:-prime256v1}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
# used if EdDSA: Ed25519 | Ed448
KEY_EDDSA="$(echo "${KEY_EDDSA:-Ed25519}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

QUIET_OPENSSL="${QUIET_OPENSSL:-1}"
ROOT_PATHLEN="${ROOT_PATHLEN-1}"     # pathLen for root; empty to omit

# ---- Validate DN ----
CN="$(validate_component_utf8 "CN" "$CN" "$DN_MAXLEN")"
O="$(validate_component_utf8  "O"  "$O"  "$DN_MAXLEN")"
OU="$(validate_component_utf8 "OU" "$OU" "$DN_MAXLEN")"
C="$(validate_country_iso "$C")"

# ---- Layout & CNF ----
cd "$ROOT_DIR"
ensure_root_layout "root"

ROOT_ABS="$(pwd)/root"
ROOT_CNF="${ROOT_CNF:-$ROOT_DIR/root/openssl.cnf}"
mkdir -p "$(dirname "$ROOT_CNF")"

create_root_openssl_cnf_if_missing "$ROOT_CNF" "$ROOT_ABS" "$DAYS" "${ROOT_PATHLEN:-}"
info "Using OpenSSL CNF: $ROOT_CNF"

# ---- Protect existing root (DN + key match) ----
EXISTING_CRT="root/certs/ca.cert.pem"
KEY_PATH="root/private/ca.key.pem"

if [[ -s "$EXISTING_CRT" ]]; then
  "$OPENSSL" x509 -in "$EXISTING_CRT" -noout >/dev/null 2>&1 \
    || die "Certificat root existant illisible/corrompu: $EXISTING_CRT"

  existing_dn="$("$OPENSSL" x509 -in "$EXISTING_CRT" -noout -subject -nameopt RFC2253 \
                | sed -n 's/^subject=\s*//;p')"
  requested_dn="$(canonical_dn_rfc2253)"

  if [[ "$existing_dn" != "$requested_dn" ]]; then
    die "Refus d'écraser la ROOT (DN existant='$existing_dn' ≠ demandé='$requested_dn'). Supprime 'root/' pour réinitialiser."
  fi
fi

# ---- Private key (create if missing) ----
if [[ ! -s "$KEY_PATH" ]]; then
  gen_private_key "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_PATH"
  chmod 600 "$KEY_PATH"
else
  info "Clé privée déjà présente: $KEY_PATH — paramètres KEY_ALG/SIZE/CURVE ignorés."
fi

effective_key_alg="$KEY_ALG"
effective_key_size="$KEY_SIZE"
effective_key_curve="$KEY_CURVE"
effective_key_eddsa="$KEY_EDDSA"

if [[ -s "$KEY_PATH" ]]; then
  inspect_private_key_metadata "$KEY_PATH"
  if [[ -n "${DETECTED_KEY_ALG:-}" ]]; then
    effective_key_alg="$DETECTED_KEY_ALG"
    [[ -n "${DETECTED_KEY_SIZE:-}" ]] && effective_key_size="$DETECTED_KEY_SIZE" || effective_key_size=""
    [[ -n "${DETECTED_KEY_CURVE:-}" ]] && effective_key_curve="$DETECTED_KEY_CURVE" || effective_key_curve=""
    [[ -n "${DETECTED_KEY_EDDSA:-}" ]] && effective_key_eddsa="$DETECTED_KEY_EDDSA" || effective_key_eddsa=""
  fi
fi

# If cert exists too, verify key↔cert match via SPKI pin
if [[ -s "$EXISTING_CRT" && -s "$KEY_PATH" ]]; then
  spki_cert="$(pubkey_sha256_b64 "$EXISTING_CRT" cert || true)"
  spki_key="$(pubkey_sha256_b64 "$KEY_PATH" key || true)"
  [[ -n "$spki_cert" && -n "$spki_key" && "$spki_cert" == "$spki_key" ]] \
    || die "Clé privée et certificat root existants ne correspondent pas. Abandon."
fi

# ---- Build temporary req.cnf with injected DN ----
REQ_CNF="$(mktemp)"
trap 'rm -f "$REQ_CNF"' EXIT
render_req_cnf_with_dn "$ROOT_CNF" "$REQ_CNF" "$C" "$O" "$OU" "$CN"

# ---- Self-sign root certificate if missing ----
CRT_PATH="root/certs/ca.cert.pem"
if [[ ! -s "$CRT_PATH" ]]; then
  info "Using DN: C='${C}' O='${O}' OU='${OU}' CN='${CN}'"
  info "Self-signing ROOT certificate (${CN}) for ${DAYS} days…"

  # EdDSA: pas de -sha256 (OpenSSL l'ignore, mais on évite de le passer)
  use_sha256=1
  case "${effective_key_alg:-}" in
    EDDSA|ED25519|ED448) use_sha256=0 ;;
    *) ;;
  esac

  if [[ "$QUIET_OPENSSL" == "1" ]]; then
    if [[ "$use_sha256" == "1" ]]; then
      "$OPENSSL" req -batch -config "$REQ_CNF" -key "$KEY_PATH" -new -x509 \
        -sha256 -extensions v3_ca -days "$DAYS" -out "$CRT_PATH" >/dev/null 2>&1
    else
      "$OPENSSL" req -batch -config "$REQ_CNF" -key "$KEY_PATH" -new -x509 \
        -extensions v3_ca -days "$DAYS" -out "$CRT_PATH" >/dev/null 2>&1
    fi
  else
    if [[ "$use_sha256" == "1" ]]; then
      "$OPENSSL" req -batch -config "$REQ_CNF" -key "$KEY_PATH" -new -x509 \
        -sha256 -extensions v3_ca -days "$DAYS" -out "$CRT_PATH"
    else
      "$OPENSSL" req -batch -config "$REQ_CNF" -key "$KEY_PATH" -new -x509 \
        -extensions v3_ca -days "$DAYS" -out "$CRT_PATH"
    fi
  fi
  chmod 444 "$CRT_PATH"
  info "Root CA ready: $CRT_PATH"

  # Fingerprint, SKI, SPKI (info)
  fp="$("$OPENSSL" x509 -in "$CRT_PATH" -noout -fingerprint -sha256 | sed 's/^.*=//')"
  ski="$("$OPENSSL" x509 -in "$CRT_PATH" -noout -ext subjectKeyIdentifier \
      | sed -n '1,/Subject Key Identifier/d; 1{s/[[:space:]]//g; p;}')"
  spki="$(pubkey_sha256_b64 "$CRT_PATH" cert)"
  info "Root CA SHA256 Fingerprint: $fp"
  [[ -n "$ski"  ]] && info "Root CA SKI: $ski"
  [[ -n "$spki" ]] && info "Root CA SPKI pin (sha256/base64): $spki"

  # ---------------------------
  # Écriture du metadata root
  # ---------------------------
  ROOT_META="root/ca.meta"

  if declare -F write_ca_meta >/dev/null 2>&1; then
    # Version factorisée (si write_ca_meta est dispo dans pki-env.sh)
    write_ca_meta \
      "$CRT_PATH" "root/private/ca.key.pem" "$ROOT_META" \
      "${effective_key_alg:-}" "${effective_key_size:-}" "${effective_key_curve:-}" "${effective_key_eddsa:-}" \
      "$DAYS" "" "" "${ROOT_PATHLEN:-}" ""
    info "Metadata written: $ROOT_META"
  else
    # Fallback inline (équivalent minimal)
    # --- helpers ---
    trim() { local s="${1-}"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

    # Normalisation ENV
    alg_raw="$(trim "${effective_key_alg:-}")"
    alg_lc="$(echo "$alg_raw" | tr '[:upper:]' '[:lower:]')"
    key_size_raw="$(trim "${effective_key_size:-}")"
    key_curve_raw="$(trim "${effective_key_curve:-}")"
    key_eddsa_raw="$(trim "${effective_key_eddsa:-}")"

    meta_key_size=""
    meta_key_curve=""
    meta_key_eddsa=""

    case "$alg_lc" in
      rsa)     meta_key_size="$key_size_raw" ;;
      ec)      meta_key_curve="$key_curve_raw" ;;
      ed25519) meta_key_eddsa="Ed25519" ;;
      ed448)   meta_key_eddsa="Ed448" ;;
      eddsa)   meta_key_eddsa="${key_eddsa_raw:-Ed25519}" ;;
      *)       ;;
    esac

    # Fallback depuis la clé si besoin
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
        ed_from_key="$("$OPENSSL" pkey -in "$KEY_PATH" -text -noout 2>/dev/null \
          | awk '/ED25519/ {print "Ed25519"; exit} /ED448/ {print "Ed448"; exit}')"
        [[ -n "$ed_from_key" ]] && meta_key_eddsa="$ed_from_key"
      fi
    fi

    # DN/Issuer/SERIAL (self-signed → issuer = subject)
    dn_rfc2253="$("$OPENSSL" x509 -in "$CRT_PATH" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
    serial_hex="$("$OPENSSL" x509 -in "$CRT_PATH" -noout -serial 2>/dev/null | sed 's/^serial=//I' | tr '[:lower:]' '[:upper:]')"
    pathlen_val="${ROOT_PATHLEN:-}"
    if [[ -z "$pathlen_val" ]]; then
      pathlen_val="$( "$OPENSSL" x509 -in "$CRT_PATH" -text -noout 2>/dev/null \
        | awk '/Path Length Constraint/ {print $4; exit}' )"
    fi

    {
      echo "CREATED_AT=$(date -u +%FT%TZ)"
      echo "OPENSSL_VERSION=$($OPENSSL version)"
      echo "DN=$dn_rfc2253"
      echo "ISSUER_DN=$dn_rfc2253"
      echo "ALG=$alg_raw"
      [[ -n "$meta_key_eddsa" ]] && echo "KEY_EDDSA=$meta_key_eddsa"
      [[ -n "$meta_key_size"  ]] && echo "KEY_SIZE=$meta_key_size"
      [[ -n "$meta_key_curve" ]] && echo "KEY_CURVE=$meta_key_curve"
      echo "DAYS=$DAYS"
      [[ -n "$pathlen_val" ]] && echo "PATHLEN=$(trim "$pathlen_val")"
      [[ -n "$serial_hex" ]] && { echo "SERIAL=$serial_hex"; echo "ISSUER_SERIAL=$serial_hex"; }
      echo "SPKI_SHA256=$spki"
    } > "$ROOT_META"
    chmod 444 "$ROOT_META"
    info "Metadata written: $ROOT_META"
  fi
else
  info "Root certificate already exists: $CRT_PATH (skip)"
fi

# ---------------------------
# Tests d’intégrité post-émission (ROOT)
# ---------------------------
if [[ -s "$CRT_PATH" ]]; then
  if "$OPENSSL" verify -CAfile "$CRT_PATH" "$CRT_PATH" >/dev/null; then
    info "Vérification OK (root auto-signée)."
  else
    die  "Vérification de chaîne échouée pour la ROOT ($CRT_PATH)"
  fi
fi

# ---- Success message ----
info "Done"
