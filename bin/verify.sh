#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#

# verify.sh — Vérification d'un certificat leaf émis par un intermédiaire
# Convention UNIQUE : le fichier doit s'appeler certs/<CN>.cert.pem
#
# Usage :
#   FILE=certs/app.example.com.cert.pem VERIFY_CRL=1 VERIFY_MODE=info bin/verify.sh
#   # ou par CN (sans FILE) :
#   INT_DIR="intm-web-ca" CN="app.example.com" VERIFY_MODE=normal bin/verify.sh
#
# Notes :
# - Priorité de ciblage : INT_DIR > KIND (INT_DIR est normalisé : "internet" → "intm-internet-ca")
# - Vérif : root en -CAfile (ancre) + intermédiaire en -untrusted (chaîne)
# - VERIFY_CRL=1 active -crl_check[_all] si les CRL existent
# - VERIFY_MODE = normal | tolerate_revoked | info

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "${SCRIPT_DIR}/pki-env.sh"

OPENSSL="${OPENSSL:-openssl}"

# ---------------------------
# Helpers
# ---------------------------

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
  FILE="certs/${CN}.cert.pem"
fi
[[ -f "$FILE" ]] || die "Certificate not found: $FILE (expected canonical path certs/<CN>.cert.pem)"

# ---------------------------
# Chaîne de confiance : root (ancre) + intermédiaire (untrusted)
# ---------------------------

ROOT_CRT="../root/certs/ca.cert.pem"
INT_CRT="certs/ca.cert.pem"
[[ -f "$ROOT_CRT" ]] || die "Root CA introuvable: $ROOT_CRT"
[[ -f "$INT_CRT"  ]] || die "Intermediate CA introuvable: $INT_CRT"

# ---------------------------
# Construction des arguments openssl verify
# ---------------------------

args=( -CAfile "$ROOT_CRT" -untrusted "$INT_CRT" )

if [[ "$VERIFY_CRL" = "1" ]]; then
  int_crl="crl/ca.crl.pem"
  root_crl="../root/crl/ca.crl.pem"
  if [[ -f "$int_crl" && -f "$root_crl" ]]; then
    args+=( -crl_check_all -CRLfile "$int_crl" -CRLfile "$root_crl" )
  elif [[ -f "$int_crl" ]]; then
    args+=( -crl_check -CRLfile "$int_crl" )
    warn "Missing Root CRL ($root_crl). La vérif CRL ne couvre pas l'ancre."
  else
    warn "VERIFY_CRL=1 mais aucune CRL trouvée ($int_crl). Pas de vérif CRL."
  fi
fi

# ---------------------------
# Exécution & statut
# ---------------------------

info "Verifying: $FILE"
verify_out="$($OPENSSL verify -verbose "${args[@]}" "$FILE" 2>&1 || true)"
echo "$verify_out"

status="ERROR"
# Cible strictement la ligne du fichier demandé pour le statut OK
if echo "$verify_out" | awk -v f="$FILE" 'tolower($0) ~ tolower(f": ok$") {found=1} END{exit(!found)}'; then
  status="OK"
elif echo "$verify_out" | grep -qi "certificate revoked"; then
  status="REVOKED"
fi

# ---------------------------
# Extensions (informative)
# ---------------------------

info "Extensions (à partir de 'X509v3 extensions:')"
$OPENSSL x509 -noout -text -in "$FILE" | awk 'BEGIN{p=0}/X509v3 extensions:/{p=1}p{print}'

# ---------------------------
# Politique de sortie
# ---------------------------

case "$VERIFY_MODE" in
  normal)             [[ "$status" = "OK" ]] && exit 0 || exit 2 ;;
  tolerate_revoked)   [[ "$status" = "OK" || "$status" = "REVOKED" ]] && exit 0 || exit 2 ;;
  info)               exit 0 ;;
  *)                  warn "VERIFY_MODE inconnu: $VERIFY_MODE"; exit 2 ;;
esac
