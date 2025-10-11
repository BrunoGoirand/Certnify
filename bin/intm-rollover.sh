#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"

# ------------------------------------------------------------
# Rollover intermédiaire SANS symlink :
# - Renomme l'ancien intm-${KIND}-ca -> intm-${KIND}-ca-legacy-<ts> (si présent)
# - Recrée un NOUVEAU intm-${KIND}-ca et y génère clé/CSR/cert/chain/meta
# ------------------------------------------------------------

: "${DAYS:=3650}"
: "${KEY_ALG:=EC}"
: "${KEY_SIZE:=4096}"
: "${KEY_CURVE:=secp384r1}"
: "${KEY_EDDSA:=Ed25519}"
: "${QUIET_OPENSSL:=1}"

quiet="${QUIET_OPENSSL}"   # pour tout code qui lirait 'quiet' (compat)

[[ -n "${KIND:-}"   ]] || die "Spécifie KIND=web|auth|code|smime|archive"
[[ -n "${INT_CN:-}" ]] || die "Spécifie INT_CN='Nom de l\\'intermédiaire'"

ROOT_CNF="root/openssl.cnf"
ROOT_CERT="root/certs/ca.cert.pem"
ROOT_KEY="root/private/ca.key.pem"
[[ -f "$ROOT_CNF" && -f "$ROOT_CERT" && -f "$ROOT_KEY" ]] || die "Racine manquante (génère root/ d'abord)."

# Runner silencieux selon QUIET_OPENSSL
_run() {
  if [[ "${QUIET_OPENSSL:-1}" == "1" ]]; then "$@" >/dev/null 2>&1; else "$@"; fi
}

# Nom de base et nom legacy unique
BASE_DIR="intm-${KIND}-ca"
ts="$(date +%Y%m%d%H%M%S)"
LEGACY_DIR="${BASE_DIR}-legacy-${ts}"
n=1; while [[ -e "$LEGACY_DIR" ]]; do LEGACY_DIR="${BASE_DIR}-legacy-${ts}-$((n++))"; done

# 0) Préserver l'ancien dossier s'il existe
if [[ -e "$BASE_DIR" ]]; then
  warn "Found existing '${BASE_DIR}' → preserving as '${LEGACY_DIR}'"
  mv "$BASE_DIR" "$LEGACY_DIR"
  info "Preserved previous intermediate directory: ${LEGACY_DIR}"
fi

# 1) Créer le NOUVEAU dossier actif (nom de base)
INT_DIR_NEW="$BASE_DIR"
INT_ABS="$(cd "$ROOT_DIR" && pwd)/${INT_DIR_NEW}"
info "Using intermediate directory: ${INT_DIR_NEW}"

# 2) Layout + openssl.cnf
ensure_intermediate_layout "$INT_DIR_NEW"
create_intermediate_openssl_cnf_if_missing "${INT_DIR_NEW}/openssl.cnf" "$INT_ABS" "$DAYS"
REQ_CNF="${INT_DIR_NEW}/openssl.cnf"
info "Using OpenSSL CNF: ${REQ_CNF}"

# 3) Clé privée
KEY_PATH="${INT_DIR_NEW}/private/ca.key.pem"
gen_private_key "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_PATH"

# 4) CSR
CSR_PATH="${INT_DIR_NEW}/csr/ca.csr.pem"
CN="${INT_CN}"; C="${C:-}"; O="${O:-}"; OU="${OU:-}"
TMP_REQ_CNF="${INT_DIR_NEW}/req.cnf"
render_req_cnf_with_dn "$REQ_CNF" "$TMP_REQ_CNF" "${C:-}" "${O:-}" "${OU:-}" "${CN}"

info "Using DN: C='${C:-}' O='${O:-}' OU='${OU:-}' CN='${INT_CN}'"
info "Generating CSR…"
_run "$OPENSSL" req -new -config "$TMP_REQ_CNF" -key "$KEY_PATH" -out "$CSR_PATH"
info "CSR ready: ${CSR_PATH}"

# 5) Signature par la racine
CRT_PATH="${INT_DIR_NEW}/certs/ca.cert.pem"
info "Signing intermediate via ROOT…"
_run "$OPENSSL" ca -batch -config "$ROOT_CNF" -extensions v3_intermediate_ca -days "$DAYS" \
  -in "$CSR_PATH" -out "$CRT_PATH"
chmod 444 "$CRT_PATH"
info "Intermediate certificate ready: ${CRT_PATH}"

# 6) Chaîne
CHAIN_PATH="${INT_DIR_NEW}/certs/chain.cert.pem"
cat "$CRT_PATH" "$ROOT_CERT" > "$CHAIN_PATH"
chmod 444 "$CHAIN_PATH"
info "Chain ready: ${CHAIN_PATH}"

# 7) Metadata
META_PATH="${INT_DIR_NEW}/meta"
write_ca_meta \
  "$CRT_PATH" "$KEY_PATH" "$META_PATH" \
  "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_EDDSA" \
  "$DAYS" "$KIND" "$INT_DIR_NEW" "" "$ROOT_CERT"
info "Metadata written: ${META_PATH}"

# (option) CRL initiale
# _run "$OPENSSL" ca -config "${INT_DIR_NEW}/openssl.cnf" -gencrl -out "${INT_DIR_NEW}/crl/ca.crl.pem"

# 8) Récapitulatif
echo "[OK ] Intermediate ready: ${INT_DIR_NEW}"
echo "[OK ] Paths:"
echo "      KEY   : ${KEY_PATH}"
echo "      CSR   : ${CSR_PATH}"
echo "      CERT  : ${CRT_PATH}"
echo "      CHAIN : ${CHAIN_PATH}"
echo "      META  : ${META_PATH}"
[[ -e "${LEGACY_DIR:-}" ]] && echo "      LEGACY: ${LEGACY_DIR}"
