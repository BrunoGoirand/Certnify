#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"

# ------------------------------------------------------------------
# Réémission batch des leafs (modèle SANS symlink)
#
# Entrées (env):
#   KIND=web|smime|code|user|archives      (si INPUT ne permet pas de l'inférer)
#   INPUT=out/<kind>-leafs[-<TS>].tsv      (optionnel; auto-sélection si vide)
#   LEGACY_DIR=...                         (optionnel; auto si vide)
#   ACTIVE_DIR=intm-${KIND}-ca             (auto)
#   ISSUE_CMD="INT_DIR=intm-${KIND}-ca PROFILE=server_cert CN='%CN%' SAN='DNS:%CN%' DAYS=397 bin/gen-server.sh"
#   DRY_RUN=0|1
#   COL_SERIAL=1  COL_EXPIRES=2  COL_CN=3
# ------------------------------------------------------------------

: "${DRY_RUN:=0}"
: "${COL_SERIAL:=1}"
: "${COL_EXPIRES:=2}"
: "${COL_CN:=3}"

# Helper macOS-safe: retourne le TSV daté le + récent pour un KIND
newest_tsv_for_kind() {
  local k="$1"
  local c
  shopt -s nullglob
  for c in $(ls -1t out/"${k}"-leafs-*.tsv 2>/dev/null); do
    if [[ -s "$c" ]]; then
      echo "$c"
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob
  printf ''
}

# ---------- 0) Si INPUT fourni, essaie d'inférer KIND ----------
if [[ -n "${INPUT:-}" && -z "${KIND:-}" ]]; then
  base="$(basename "$INPUT")"           # ex: web-leafs-<TS>.tsv | web-leafs.tsv
  KIND="${base%%-leafs*}"
  [[ -n "$KIND" ]] || die "Impossible d'inférer KIND depuis INPUT: $INPUT"
fi

# ---------- 1) Si KIND encore vide, on essaie via les TSV existants ----------
if [[ -z "${KIND:-}" ]]; then
  shopt -s nullglob
  any=(out/*-leafs-*.tsv out/*-leafs.tsv)
  shopt -u nullglob
  [[ ${#any[@]} -gt 0 ]] || die "Spécifie INPUT=... ou KIND=... ; aucun TSV trouvé dans out/*-leafs[-TS].tsv"
  base="$(basename "${any[0]}")"
  KIND="${base%%-leafs*}"
  [[ -n "$KIND" ]] || die "Impossible d'inférer KIND automatiquement."
fi

# ---------- 2) Recherche du DERNIER TS de rollover ----------
latest_legacy=""
latest_ts=""
shopt -s nullglob
legcands=(intm-"${KIND}"-ca-legacy-*)
shopt -u nullglob
if (( ${#legcands[@]} )); then
  latest_legacy="$(ls -1d intm-"${KIND}"-ca-legacy-* 2>/dev/null | sort -r | head -n1 || true)"
  if [[ -n "$latest_legacy" ]]; then
    # extrait tout après "-legacy-"
    latest_ts="${latest_legacy#intm-${KIND}-ca-legacy-}"
  fi
fi

# ---------- 3) Sélection stricte du TSV quand un legacy existe ----------
# Si un rollover a eu lieu (dernier legacy détecté), on attend le TSV
# out/<kind>-leafs-<latest_ts>.tsv ; s'il n'existe pas → on guide l'utilisateur et on sort.
if [[ -n "$latest_ts" ]]; then
  expected_tsv="out/${KIND}-leafs-${latest_ts}.tsv"
  if [[ -z "${INPUT:-}" || "$INPUT" == "out/${KIND}-leafs.tsv" ]]; then
    INPUT="$expected_tsv"
  fi
  if [[ ! -f "$INPUT" ]]; then
    warn "Le TSV attendu pour le dernier rollover est manquant :"
    warn "  attendu : $expected_tsv"
    echo "[HINT] Génère la liste depuis le legacy courant :"
    echo "       make list-leafs-${KIND}"
    echo "       # ou équivalent direct :"
    echo "       KIND='${KIND}' bin/list-leafs-by-issuer.sh"
    die "TSV introuvable pour le dernier rollover (${latest_ts}). Abandon."
  fi
  # S’il existe mais est vide → rien à faire, on sort proprement
  if [[ ! -s "$INPUT" ]]; then
    info "Aucun leaf à réémettre (TSV vide) pour le rollover ${latest_ts} : $INPUT"
    exit 0
  fi
else
  # Aucun legacy détecté → pas de rollover récent : on reste souple (fallback)
  if [[ -z "${INPUT:-}" ]]; then
    sel="$(newest_tsv_for_kind "$KIND")"
    if [[ -n "$sel" ]]; then
      INPUT="$sel"
    else
      INPUT="out/${KIND}-leafs.tsv"
    fi
  fi
  if [[ ! -f "$INPUT" ]]; then
    die "Spécifie INPUT=... (TSV existant), introuvable: $INPUT"
  fi
  # S’il existe mais est vide → rien à réémettre (OK)
  if [[ ! -s "$INPUT" ]]; then
    info "Aucun leaf à réémettre (TSV vide) : $INPUT"
    exit 0
  fi
fi

# ---------- 4) Répertoires actif & legacy ----------
ACTIVE_DIR="${ACTIVE_DIR:-intm-${KIND}-ca}"
[[ -d "$ACTIVE_DIR" ]] || die "Répertoire actif introuvable: $ACTIVE_DIR"

if [[ -z "${LEGACY_DIR:-}" ]]; then
  if [[ -n "$latest_ts" && -d "intm-${KIND}-ca-legacy-${latest_ts}" ]]; then
    LEGACY_DIR="intm-${KIND}-ca-legacy-${latest_ts}"
  else
    LEGACY_DIR="$(ls -1d intm-"${KIND}"-ca-legacy-* 2>/dev/null | sort -r | head -n1 || true)"
    [[ -n "$LEGACY_DIR" ]] || LEGACY_DIR=""
  fi
fi
if [[ -n "${LEGACY_DIR:-}" && ! -d "$LEGACY_DIR" ]]; then
  die "LEGACY_DIR fourni mais introuvable: $LEGACY_DIR"
fi

# ---------- 5) ISSUE_CMD par défaut ----------
if [[ -z "${ISSUE_CMD:-}" ]]; then
  # SAN par défaut : email si CN ressemble à une adresse, sinon DNS
  if [[ "${KIND}" =~ ^(auth|smime)$ ]]; then
    DEFAULT_SAN="email:%CN%"
  else
    DEFAULT_SAN="DNS:%CN%"
  fi

  case "$KIND" in
    web)
      # Certs serveur
      ISSUE_CMD="INT_DIR=intm-web-ca PROFILE=${PROFILE:-server_cert} CN='%CN%' SAN='${DEFAULT_SAN}' DAYS=${DAYS:-397} bin/gen-server.sh"
      ;;

    auth)
      # Certs client (mutual-TLS)
      ISSUE_CMD="INT_DIR=intm-auth-ca PROFILE=${PROFILE:-client_cert} CN='%CN%' SAN='${DEFAULT_SAN}' DAYS=${DAYS:-825} bin/gen-user.sh"
      ;;

    smime)
      # S/MIME
      ISSUE_CMD="INT_DIR=intm-smime-ca PROFILE=${PROFILE:-smime} CN='%CN%' SAN='${DEFAULT_SAN}' DAYS=${DAYS:-730} bin/gen-email.sh"
      ;;

    code)
      # Signature de code
      ISSUE_CMD="INT_DIR=intm-code-ca PROFILE=${PROFILE:-code_sign} CN='%CN%' DAYS=${DAYS:-730} bin/gen-code.sh"
      ;;

    archive|archives)
      # Sceau/archive
      ISSUE_CMD="INT_DIR=intm-archive-ca PROFILE=${PROFILE:-archive} CN='%CN%' DAYS=${DAYS:-3650} bin/gen-archive.sh"
      ;;

    *)
      die "KIND inconnu pour ISSUE_CMD par défaut: '${KIND}' (attendu: web|auth|smime|code|archive)"
      ;;
  esac
fi

# ---------- 6) Sanity checks ----------
[[ -f "${ACTIVE_DIR}/certs/ca.cert.pem" ]]   || die "Cert intermédiaire actif manquant: ${ACTIVE_DIR}/certs/ca.cert.pem"
[[ -f "${ACTIVE_DIR}/certs/chain.cert.pem" ]]|| die "Chaîne active manquante: ${ACTIVE_DIR}/certs/chain.cert.pem"

# ---------- 7) Traitement TSV ----------
total=0; ok=0; ko=0

while IFS=$'\t' read -r col1 col2 col3 col4 rest; do
  [[ -n "$col1$col2$col3$col4" ]] || continue

  arr=("$col1" "$col2" "$col3" "$col4" "$rest")
  getcol() { local idx="$1"; printf '%s' "${arr[$((idx-1))]:-}"; }

  serial="$(getcol "$COL_SERIAL")"
  expires="$(getcol "$COL_EXPIRES")"
  cn="$(getcol "$COL_CN")"

  [[ -n "$serial" && -n "$cn" ]] || continue
  ((total++))

  cmd="${ISSUE_CMD//%CN%/$cn}"
  cmd="${cmd//%SERIAL%/$serial}"
  cmd="${cmd//%EXPIRES%/$expires}"

  export ACTIVE_DIR LEGACY_DIR

  echo "[RUN] $cmd"
  if [[ "$DRY_RUN" == "1" ]]; then
    continue
  fi

  set +e
  bash -c "$cmd"
  rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    ((ok++))
    echo "[OK ] Réémis: CN='$cn' (serial=$serial)"
  else
    ((ko++))
    echo "[!! ] Échec réémission: CN='$cn' (serial=$serial) rc=$rc" >&2
  fi
done < "$INPUT"

info "Batch terminé: total=$total ok=$ok ko=$ko"
