#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
# shellcheck source=bin/pki-env.sh
source "$(dirname "$0")/pki-env.sh"

# ------------------------------------------------------------
# Rollback vers un intermédiaire LEGACY (modèle SANS symlink)
# - Renomme l'actif intm-<KIND>-ca -> intm-<KIND>-ca-pre-rollback-<ts>
# - Remet en place le legacy choisi (ou le plus récent) en tant qu'actif
#
# Entrées (env) :
#   KIND=web|auth|code|smime|archive     (si LEGACY_DIR n'est pas donné)
#   LEGACY_DIR=intm-<kind>-ca-legacy-<TS> (optionnel; si non fourni → prend le plus récent)
# ------------------------------------------------------------

# --- Helpers ---
ts_now() { date +%Y%m%d%H%M%S; }

# --- Résolution LEGACY_DIR / KIND ---
LEGACY_DIR="${LEGACY_DIR:-}"
KIND="${KIND:-}"

if [[ -z "$LEGACY_DIR" ]]; then
  [[ -n "$KIND" ]] || die "Spécifie KIND=web|auth|code|smime|archive (ou LEGACY_DIR=...)."
  # Trouve le legacy le plus récent
  shopt -s nullglob
  legacy_dirs=("intm-${KIND}-ca-legacy-"*)
  shopt -u nullglob
  latest_legacy="$(printf '%s\n' "${legacy_dirs[@]}" | sort -r | head -n1 || true)"
  [[ -n "$latest_legacy" ]] || die "Aucun legacy trouvé pour KIND='${KIND}'."
  LEGACY_DIR="$latest_legacy"
else
  # Si LEGACY_DIR est fourni, essaie d'inférer KIND
  if [[ -z "$KIND" ]]; then
    # Extrait le kind depuis le nom intm-<kind>-ca-legacy-<TS>
    base="$(basename "$LEGACY_DIR")"
    KIND="$(printf '%s\n' "$base" | sed -n 's/^intm-\([^/]*\)-ca-legacy-.*/\1/p')"
    [[ -n "$KIND" ]] || die "Impossible d'inférer KIND depuis LEGACY_DIR='${LEGACY_DIR}'. Spécifie KIND=..."
  fi
fi

ACTIVE_DIR="intm-${KIND}-ca"

# --- Sanity checks ---
[[ -d "$LEGACY_DIR" ]] || die "LEGACY_DIR introuvable: ${LEGACY_DIR}"
[[ -f "${LEGACY_DIR}/openssl.cnf" ]] || die "openssl.cnf manquant dans ${LEGACY_DIR}."

# --- Plan d'action ---
echo "[OK ] Rollback KIND='${KIND}'"
echo "[OK ]   LEGACY_DIR : ${LEGACY_DIR}"
echo "[OK ]   ACTIVE_DIR : ${ACTIVE_DIR}"

# 1) Sauvegarder l'actif courant s'il existe
if [[ -e "$ACTIVE_DIR" ]]; then
  backup="${ACTIVE_DIR}-pre-rollback-$(ts_now)"
  mv "$ACTIVE_DIR" "$backup"
  echo "[OK ] Actif courant préservé : ${backup}"
else
  echo "[.. ] Aucun actif courant ('${ACTIVE_DIR}') — rien à préserver."
fi

# 2) Remettre le legacy en actif
mv "$LEGACY_DIR" "$ACTIVE_DIR"
echo "[OK ] Legacy remis en actif : ${ACTIVE_DIR}"

# 3) Petites vérifs post-move
[[ -f "${ACTIVE_DIR}/openssl.cnf" ]] || die "Rollback incomplet : ${ACTIVE_DIR}/openssl.cnf manquant."
[[ -f "${ACTIVE_DIR}/certs/ca.cert.pem" ]] || warn "Attention : ${ACTIVE_DIR}/certs/ca.cert.pem manquant."
[[ -f "${ACTIVE_DIR}/certs/chain.cert.pem" ]] || warn "Attention : ${ACTIVE_DIR}/certs/chain.cert.pem manquant."

# --- Vérifie la présence de la chaîne complète ---
CHAIN_PATH="${ACTIVE_DIR}/certs/chain.cert.pem"
if [[ ! -f "$CHAIN_PATH" ]]; then
  ROOT_CERT="root/certs/ca.cert.pem"
  CA_CERT="${ACTIVE_DIR}/certs/ca.cert.pem"
  if [[ -f "$CA_CERT" && -f "$ROOT_CERT" ]]; then
    cat "$CA_CERT" "$ROOT_CERT" > "$CHAIN_PATH"
    chmod 444 "$CHAIN_PATH"
    info "Chaîne recréée automatiquement : $CHAIN_PATH"
  else
    warn "Attention : ${CHAIN_PATH} manquant et impossible à régénérer (root ou cert intermédiaire absent)."
  fi
fi

echo "[OK ] Rollback terminé."
