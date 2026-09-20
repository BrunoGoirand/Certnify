#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#

# verify.sh — Vérification d'un certificat leaf émis par un intermédiaire
# FILE: authority-relative, matching workspace-relative, or contained absolute path.
#
# Usage :
#   KIND=web FILE=certs/app.example.com.cert.pem VERIFY_CRL=1 VERIFY_MODE=info bin/verify.sh
#   # ou par CN (sans FILE) :
#   INT_DIR="intm-web-ca" CN="app.example.com" VERIFY_MODE=normal bin/verify.sh
#
# Notes :
# - Priorité de ciblage : INT_DIR > KIND (INT_DIR est normalisé : "internet" → "intm-internet-ca")
# - Vérif : root en -CAfile (ancre) + intermédiaire en -untrusted (chaîne)
# - VERIFY_CRL=1 requires valid issuer and root CRLs with full-chain coverage
# - VERIFY_MODE = normal | tolerate_revoked | info

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=bin/pki-env.sh
source "${SCRIPT_DIR}/pki-env.sh"
[[ -z "${CHAIN:-}" ]] || die "CHAIN override is unsupported; select INT_DIR/KIND to use the bound issuer and workspace root"
pki_begin

OPENSSL="${OPENSSL:-openssl}"

# ---------------------------
# Helpers
# ---------------------------



safe() {
  # Sanitize légère si besoin ailleurs (pas utilisée pour la résolution désormais)
  local s="$1"
  s="${s//[^A-Za-z0-9._-]/_}"
  while [[ "$s" == *"__"* ]]; do s="${s//__/_}"; done
  s="${s##_}"; s="${s%%_}"
  echo "$s"
}

# ---------------------------
# Sélection intermédiaire (INT_DIR > KIND) + sanity checks
# ---------------------------

CA_DIR=""
if [[ -n "${INT_DIR:-}" ]]; then
  CA_DIR="$(normalize_int_dir "$INT_DIR")"
elif [[ -n "${KIND:-}" ]]; then
  CA_DIR="intm-${KIND}-ca"
fi

CA_DIR="$(resolve_authority "$CA_DIR")"
check_config "$CA_DIR"
check_config root
[[ -n "${CA_DIR:-}" ]] || die "Spécifie INT_DIR=... ou KIND=... pour cibler l'intermédiaire."
[[ -d "$ROOT_DIR/$CA_DIR" ]] || die "Intermédiaire introuvable: '$ROOT_DIR/$CA_DIR' (génère-le d'abord)."
[[ -f "$ROOT_DIR/$CA_DIR/openssl.cnf" ]] || die "Fichier manquant: '$ROOT_DIR/$CA_DIR/openssl.cnf'."

# ---------------------------
# Entrées & défauts
# ---------------------------

CN="${CN:-}"                          # ex: CN=app.example.com (optionnel si FILE est fourni)
FILE="${FILE:-}"                      # ex: FILE=certs/app.example.com.cert.pem
VERIFY_CRL="${VERIFY_CRL:-0}"         # 1 pour activer la vérif CRL
VERIFY_MODE="${VERIFY_MODE:-normal}"  # normal | tolerate_revoked | info

info "Using intermediate: ${CA_DIR}"
assert_intermediate_ready
cd "$ROOT_DIR/$CA_DIR"

# ---------------------------
# Résolution du fichier certificat — règle UNIQUE
# ---------------------------

if [[ -z "$FILE" ]]; then
  [[ -n "$CN" ]] || die "Specify either FILE=certs/<CN>.cert.pem or CN=<common-name>"
  serial="$(pki_records revoke index.txt)" || exit 1
  FILE="newcerts/$serial.pem"
  if [[ ! -f "$FILE" ]]; then
    FILE="certs/$(leaf_stem "$CN").cert.pem"
    [[ -f "$FILE" && "$(openssl_serial "$FILE")" == "$serial" ]] || die "Missing selected certificate history; use explicit FILE for import"
  fi
fi
FILE="$(resolve_leaf_file "$CA_DIR" "$FILE")"
[[ -f "$FILE" ]] || die "Certificate not found: $FILE (expected canonical path certs/<CN>.cert.pem)"

# ---------------------------
# Chaîne de confiance : root (ancre) + intermédiaire (untrusted)
# ---------------------------

FILE="$(authority_path "$CA_DIR" "$FILE")"
resolve_leaf_issuer "$CA_DIR" "$FILE"
ROOT_CRT="$ROOT_DIR/root/certs/ca.cert.pem"
INT_CRT="$ISSUER_CERT"
[[ -f "$ROOT_CRT" ]] || die "Root CA introuvable: $ROOT_CRT"
[[ -f "$INT_CRT"  ]] || die "Intermediate CA introuvable: $INT_CRT"

# ---------------------------
# Construction des arguments openssl verify
# ---------------------------

case "$VERIFY_MODE" in normal|tolerate_revoked|info) ;; *) die "Unknown VERIFY_MODE: $VERIFY_MODE" ;; esac
[[ "$VERIFY_CRL" == 0 || "$VERIFY_CRL" == 1 ]] || die "VERIFY_CRL must be 0 or 1"
args=( -CAfile "$ROOT_CRT" -no-CApath -untrusted "$INT_CRT" )
bundle=""
trap '[[ -z "$bundle" ]] || rm -f "$bundle"; release_locks' EXIT
if [[ "$VERIFY_CRL" == 1 ]]; then
  int_crl="$ROOT_DIR/$CA_DIR/crl/ca.crl.pem"
  if [[ "$ISSUER_ID" != "$(certificate_id certs/ca.cert.pem)" ]]; then int_crl="$ROOT_DIR/$CA_DIR/generations/$ISSUER_ID/ca.crl.pem"; fi
  int_crl="$(authority_path "$CA_DIR" "$int_crl")"
  root_crl="$ROOT_DIR/root/crl/ca.crl.pem"
  if ! validate_crl "$int_crl" "$INT_CRT" || ! validate_crl "$root_crl" "$ROOT_CRT"; then
    info "VERIFY STATUS: ERROR"
    die "Requested CRL coverage unavailable or invalid; both issuer and root CRLs are required"
  fi
  bundle="$(mktemp)"
  cat "$int_crl" "$root_crl" > "$bundle"
fi

# Establish ordinary chain validity independently: a revoked result must not hide
# an unrelated chain failure. Backend exit status is authoritative for success.
info "Verifying: $FILE"
rc=0
verify_out="$(LC_ALL=C "$OPENSSL" verify -verbose "${args[@]}" "$FILE" 2>&1)" || rc=$?
status=ERROR
if [[ "$rc" == 0 ]]; then
  status=OK
  if [[ "$VERIFY_CRL" == 1 ]]; then
    rc=0
    verify_out="$(LC_ALL=C "$OPENSSL" verify -verbose "${args[@]}" -crl_check_all -CRLfile "$bundle" "$FILE" 2>&1)" || rc=$?
    if [[ "$rc" != 0 ]]; then
      status=ERROR
      # Only the anchored numeric OpenSSL diagnostic is eligible for tolerance.
      # Filenames and certificate subject strings are never regex source.
      if printf '%s\n' "$verify_out" | awk '
        /^error [0-9]+ at [0-9]+ depth lookup:/ { if($2==23) revoked++; else other++ }
        END{exit(!(revoked && !other))}
      '; then status=REVOKED; fi
    fi
  fi
fi
printf '%s\n' "$verify_out"
info "Extensions (from X509v3 extensions)"
if ! "$OPENSSL" x509 -noout -text -in "$FILE" | awk 'BEGIN{p=0}/X509v3 extensions:/{p=1}p{print}'; then status=ERROR; fi
info "VERIFY STATUS: $status"
info "Backend exit status: $rc"
case "$VERIFY_MODE" in
  normal) [[ "$status" == OK ]] ;;
  tolerate_revoked) [[ "$status" == OK || "$status" == REVOKED ]] ;;
  info) exit 0 ;;
esac && exit 0
exit 2
