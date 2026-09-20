#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
# shellcheck source=bin/pki-env.sh
source "$(dirname "$0")/pki-env.sh"
pki_begin

# ------------------------------------------------------------
# Liste les leafs émis par un intermédiaire (depuis index.txt)
# Par défaut, cible le LEGACY le plus récent (post-rollover).
#
# Entrées (env):
#   KIND=web|auth|code|smime|archive   (ou INT_DIR=... pour forcer)
#   INT_DIR="intm-web-ca-legacy-<TS>"  (prioritaire si fourni)
#   INCLUDE_REVOKED=0                  (1 pour inclure R)
#   INCLUDE_EXPIRED=0                  (1 pour inclure E)
#   OUT=out/web-leafs-<TS>.tsv         (optionnel; auto si vide)
#
# Sortie TSV:
#   SERIAL \t NOTAFTER(UTC) \t CN \t CERT_PATH
# ------------------------------------------------------------

: "${INCLUDE_REVOKED:=0}"
: "${INCLUDE_EXPIRED:=0}"

# 1) Résoudre le répertoire source (legacy le plus récent par défaut)
ts=""
if [[ -n "${INT_DIR:-}" ]]; then
  : # on respecte INT_DIR tel quel
else
  [[ -n "${KIND:-}" ]] || die "Spécifie INT_DIR=... ou KIND=..."
  # Cherche le legacy le plus récent
  shopt -s nullglob
  legacy_dirs=("intm-${KIND}-ca-legacy-"*)
  shopt -u nullglob
  latest_legacy=""
  if (( ${#legacy_dirs[@]} )); then
    latest_legacy="$(printf '%s\n' "${legacy_dirs[@]}" | sort -r | head -n1 || true)"
  fi
  if [[ -n "$latest_legacy" ]]; then
    INT_DIR="$latest_legacy"
    # extrait le timestamp après "-legacy-"
    ts="$(sed -n 's/^intm-'"${KIND}"'-ca-legacy-\(.*\)$/\1/p' <<<"$latest_legacy" || true)"
  else
    # Pas de legacy → lire l'actif
    INT_DIR="intm-${KIND}-ca"
  fi
fi

INT_DIR="$(resolve_authority "$INT_DIR")"
check_authority_paths "$INT_DIR"
INDEX="${INT_DIR}/index.txt"
[[ -f "$INDEX" ]] || die "index.txt introuvable: $INDEX"

# 2) Déduire KIND si absent (utile pour nommer OUT)
if [[ -z "${KIND:-}" ]]; then
  KIND="$(sed -n 's/^intm-\([^/]*\)-ca.*$/\1/p' <<<"$(basename "$INT_DIR")" || true)"
fi

# 3) Nom du fichier de sortie (respecte OUT si fourni)
if [[ -z "${OUT:-}" ]]; then
  if [[ -n "$ts" && -n "${KIND:-}" ]]; then
    OUT="out/${KIND}-leafs-${ts}.tsv"
  elif [[ -n "${KIND:-}" ]]; then
    OUT="out/${KIND}-leafs.tsv"
  else
    OUT="out/leafs.tsv"
  fi
fi

[[ "$OUT" == "-" ]] || OUT="$(workspace_path "$OUT")"

# Validate the entire selection before publishing or replacing an inventory.
TMP_LIST="$(mktemp)"
trap 'rm -f "$TMP_LIST"; release_locks' EXIT
INCLUDE_REVOKED="$INCLUDE_REVOKED" INCLUDE_EXPIRED="$INCLUDE_EXPIRED" \
  pki_records list "$INDEX" > "$TMP_LIST"
info "Listing from index: $INDEX" >&2
if [[ "$OUT" == "-" ]]; then
  cat "$TMP_LIST"
else
  mkdir -p "$(dirname "$OUT")"
  install -m 600 "$TMP_LIST" "$OUT"
  info "Inventory written: $OUT" >&2
fi
exit 0
