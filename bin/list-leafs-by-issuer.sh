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
  latest_legacy="$(printf '%s\n' "${legacy_dirs[@]}" | sort -r | head -n1 || true)"
  if [[ -n "$latest_legacy" ]]; then
    INT_DIR="$latest_legacy"
    # extrait le timestamp après "-legacy-"
    ts="$(sed -n 's/^intm-'"${KIND}"'-ca-legacy-\(.*\)$/\1/p' <<<"$latest_legacy" || true)"
  else
    # Pas de legacy → lire l'actif
    INT_DIR="intm-${KIND}-ca"
  fi
fi

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

if [[ "$OUT" != "-" ]]; then
  mkdir -p "$(dirname "$OUT")"
fi

info "Listing from index: $INDEX"
info "Writing to: $OUT"

# 4) Extraction
if [[ "$OUT" = "-" ]]; then
  awk -F '\t' -v incR="$INCLUDE_REVOKED" -v incE="$INCLUDE_EXPIRED" '
  function ymdhms_to_iso(s,  y,M,d,h,m,S) {
    y=substr(s,1,2)+0; M=substr(s,3,2); d=substr(s,5,2);
    h=substr(s,7,2); m=substr(s,9,2); S=substr(s,11,2);
    if (y < 70) y = 2000 + y; else y = 1900 + y;
    return sprintf("%04d-%s-%sT%s:%s:%sZ", y, M, d, h, m, S);
  }
  BEGIN { OFS="\t" }
  {
    status=$1; expiry=$2; serial=$4; file=$5; dn=$6;
    inc = (status=="V") || (status=="R" && incR=="1") || (status=="E" && incE=="1");
    if (!inc) next;
    cn = "";
    if (dn ~ /CN=/) {
      tmp = dn; sub(/^.*\/CN=/, "", tmp); if (tmp == dn) { tmp = dn; sub(/^.*[, ]CN=/, "", tmp); }
      sub(/[\/,].*$/, "", tmp); cn = tmp;
    }
    print serial, ymdhms_to_iso(expiry), cn, file;
  }' "$INDEX"
else
  awk -F '\t' -v incR="$INCLUDE_REVOKED" -v incE="$INCLUDE_EXPIRED" '
  function ymdhms_to_iso(s,  y,M,d,h,m,S) {
    y=substr(s,1,2)+0; M=substr(s,3,2); d=substr(s,5,2);
    h=substr(s,7,2); m=substr(s,9,2); S=substr(s,11,2);
    if (y < 70) y = 2000 + y; else y = 1900 + y;
    return sprintf("%04d-%s-%sT%s:%s:%sZ", y, M, d, h, m, S);
  }
  BEGIN { OFS="\t" }
  {
    status=$1; expiry=$2; serial=$4; file=$5; dn=$6;
    inc = (status=="V") || (status=="R" && incR=="1") || (status=="E" && incE=="1");
    if (!inc) next;
    cn = "";
    if (dn ~ /CN=/) {
      tmp = dn; sub(/^.*\/CN=/, "", tmp); if (tmp == dn) { tmp = dn; sub(/^.*[, ]CN=/, "", tmp); }
      sub(/[\/,].*$/, "", tmp); cn = tmp;
    }
    print serial, ymdhms_to_iso(expiry), cn, file;
  }' "$INDEX" > "$OUT"
fi

# Log final
if [[ "$OUT" = "-" ]]; then
  : # rien à vérifier proprement
else
  if grep -q . "$OUT"; then
    info "Leafs listed OK."
  else
    warn "Aucune entrée sélectionnée (filtrage ? statut ?)."
  fi
fi
[[ -n "$ts" ]] && info "Rollover timestamp: $ts (legacy: intm-${KIND}-ca-legacy-$ts)"
