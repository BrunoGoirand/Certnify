#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
# shellcheck source=bin/pki-env.sh
source "$(dirname "$0")/pki-env.sh"
pki_plan_or_begin

# ------------------------------------------------------------------
# Réémission batch des leafs (modèle SANS symlink)
#
# Entrées (env):
#   KIND=web|smime|code|user|archives      (si INPUT ne permet pas de l'inférer)
#   INPUT=out/<kind>-leafs[-<TS>].tsv      (optionnel; auto-sélection si vide)
#   LEGACY_DIR=...                         (optionnel; auto si vide)
#   ACTIVE_DIR=intm-${KIND}-ca             (auto)
#   ISSUE_CMD='SAN="DNS:$CN" DAYS=397 bin/gen-server.sh' (trusted shell command)
#   REISSUE_MODE=preserve|cn-only       (default: preserve; requires source evidence)
#   DRY_RUN=0|1
#   COL_SERIAL=1  COL_EXPIRES=2  COL_CN=3
# ------------------------------------------------------------------

: "${DRY_RUN:=0}"
: "${COL_SERIAL:=1}"
: "${COL_EXPIRES:=2}"
: "${COL_CN:=3}"

# Column mappings describe the four-column compatibility inventory.
for column in "$COL_SERIAL" "$COL_EXPIRES" "$COL_CN"; do
  case "$column" in 1|2|3|4) ;; *) die "Inventory columns must be positions 1..4" ;; esac
done
[[ "$COL_SERIAL" != "$COL_EXPIRES" && "$COL_SERIAL" != "$COL_CN" && "$COL_EXPIRES" != "$COL_CN" ]] \
  || die "Inventory columns must be distinct"

# Helper macOS-safe: retourne le TSV daté le + récent pour un KIND
newest_tsv_for_kind() {
  local k="$1"
  local c
  local matches=()
  shopt -s nullglob
  matches=(out/"${k}"-leafs-*.tsv)
  shopt -u nullglob
  (( ${#matches[@]} )) || return 0
  while IFS= read -r c; do
    if [[ -s "$c" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done < <(printf '%s\n' "${matches[@]}" | sort -r)
  printf ''
}

# ---------- 0) Si INPUT fourni, essaie d'inférer KIND ----------
if [[ -n "${INPUT:-}" && -z "${KIND:-}" ]]; then
  base="$(basename "$INPUT")"           # ex: web-leafs-<TS>.tsv | web-leafs.tsv
  [[ "$base" == *-leafs.tsv || "$base" == *-leafs-*.tsv ]] || die "Specify KIND for a nonstandard INPUT basename"
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
  latest_legacy="$(printf '%s\n' "${legcands[@]}" | sort -r | head -n1 || true)"
  if [[ -n "$latest_legacy" ]]; then
    # extrait tout après "-legacy-"
    latest_ts="${latest_legacy#intm-"${KIND}"-ca-legacy-}"
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
    info "Batch result: total=0 completed=0 already_completed=0 planned=0 failed=0"
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
    info "Batch result: total=0 completed=0 already_completed=0 planned=0 failed=0"
    exit 0
  fi
fi

# ---------- 4) Répertoires actif & legacy ----------
ACTIVE_DIR="${ACTIVE_DIR:-intm-${KIND}-ca}"
ACTIVE_DIR="$(resolve_authority "$ACTIVE_DIR")"
[[ -d "$ACTIVE_DIR" ]] || die "Répertoire actif introuvable: $ACTIVE_DIR"

if [[ -z "${LEGACY_DIR:-}" ]]; then
  if [[ -n "$latest_ts" && -d "intm-${KIND}-ca-legacy-${latest_ts}" ]]; then
    LEGACY_DIR="intm-${KIND}-ca-legacy-${latest_ts}"
  else
    shopt -s nullglob
    legcands=(intm-"${KIND}"-ca-legacy-*)
    shopt -u nullglob
    LEGACY_DIR=""
    if (( ${#legcands[@]} )); then
      LEGACY_DIR="$(printf '%s\n' "${legcands[@]}" | sort -r | head -n1 || true)"
    fi
    [[ -n "$LEGACY_DIR" ]] || LEGACY_DIR=""
  fi
fi
if [[ -n "${LEGACY_DIR:-}" ]]; then LEGACY_DIR="$(resolve_authority "$LEGACY_DIR")"; fi
if [[ -n "${LEGACY_DIR:-}" && ! -d "$LEGACY_DIR" ]]; then
  die "LEGACY_DIR fourni mais introuvable: $LEGACY_DIR"
fi

# Built-in commands receive row values as environment data, never shell source.
case "$KIND" in
  web) ISSUE_SCRIPT=bin/gen-server.sh; DEFAULT_DAYS=397 ;;
  auth|user) ISSUE_SCRIPT=bin/gen-user.sh; DEFAULT_DAYS=825 ;;
  smime) ISSUE_SCRIPT=bin/gen-email.sh; DEFAULT_DAYS=730 ;;
  code) ISSUE_SCRIPT=bin/gen-code.sh; DEFAULT_DAYS=730 ;;
  archive|archives) ISSUE_SCRIPT=bin/gen-archive.sh; DEFAULT_DAYS=3600 ;;
  *) [[ -n "${ISSUE_CMD:-}" ]] || die "Unknown KIND: $KIND" ;;
esac
case "${ISSUE_CMD:-}" in
  *%CN%*|*%SERIAL%*|*%EXPIRES%*)
    die 'ISSUE_CMD placeholders are unsupported; use quoted "$CN", "$SERIAL", "$EXPIRES", and "$ACTIVE_DIR" environment variables' ;;
esac
[[ "$DRY_RUN" == 0 || "$DRY_RUN" == 1 ]] || die "DRY_RUN must be 0 or 1"
REISSUE_MODE="${REISSUE_MODE:-preserve}"
case "$REISSUE_MODE" in preserve|cn-only) ;; *) die "REISSUE_MODE must be preserve or cn-only" ;; esac
if [[ -n "${ISSUE_CMD:-}" ]]; then
  warn "Reissuance mode: custom command; preservation is the command author responsibility."
elif [[ "$REISSUE_MODE" == cn-only ]]; then
  warn "Reissuance mode: legacy CN-only; original subject, SANs, extensions and key policy are not preserved."
else
  [[ -n "${LEGACY_DIR:-}" ]] || die "Preserving migration requires LEGACY_DIR (selected automatically after rollover)"
  source "$ROOT_DIR/bin/pki-migration.sh"
  info "Reissuance mode: preserve subject, SANs, profile and key parameters; generate fresh private keys."
fi

# ---------- 6) Sanity checks ----------
[[ -f "${ACTIVE_DIR}/certs/ca.cert.pem" ]]   || die "Cert intermédiaire actif manquant: ${ACTIVE_DIR}/certs/ca.cert.pem"
[[ -f "${ACTIVE_DIR}/certs/chain.cert.pem" ]]|| die "Chaîne active manquante: ${ACTIVE_DIR}/certs/chain.cert.pem"

# Validate every row before executing any command. Non-whitespace separators
# preserve empty TSV columns; unsupported/malformed input fails as a whole.
source_plan=""
PARSED_INPUT="$(mktemp)"
trap 'rc=$?; rm -f "$PARSED_INPUT" "${source_plan:-}"; pki_exit "$rc"' EXIT
COL_SERIAL="$COL_SERIAL" COL_EXPIRES="$COL_EXPIRES" COL_CN="$COL_CN" \
  pki_records inventory "$INPUT" > "$PARSED_INPUT"
check_config "$ACTIVE_DIR"
export CERTNIFY_EXPECTED_ISSUER="$(certificate_id "$ACTIVE_DIR/certs/ca.cert.pem")"
# Validate the complete source selection and destination policy before any claim.
if [[ "$REISSUE_MODE" == preserve && -z "${ISSUE_CMD:-}" ]]; then
  INT_CNF="$ROOT_DIR/$ACTIVE_DIR/openssl.cnf"
  source_plan="$(mktemp)"
  while IFS=$'\x1F' read -r serial expires cn; do
    source_id="$( set -e; migration_load "$LEGACY_DIR" "$serial" "$cn" "$expires"; migration_preflight "$ACTIVE_DIR"; certificate_id "$MIGRATION_CERT" )"
    printf '%s\037%s\037%s\037%s\n' "$serial" "$expires" "$cn" "$source_id" >> "$source_plan"
  done < "$PARSED_INPUT"
  mv "$source_plan" "$PARSED_INPUT"
fi
release_locks
total=0; ok=0; ko=0; planned=0; completed=0

while IFS=$'\x1F' read -r serial expires cn source_id; do
  total=$((total + 1))
  export ACTIVE_DIR LEGACY_DIR
  if [[ "$DRY_RUN" == 1 ]]; then
    planned=$((planned + 1))
    echo "[ITEM] serial=$serial status=planned cn=$cn"
    continue
  fi

  # Claim under the workspace lock, release it before the child transaction.
  # A failed/abandoned attempt requires review, never an automatic retry.
  pki_begin
  trap 'rc=$?; rm -f "$PARSED_INPUT" "${source_plan:-}"; pki_exit "$rc"' EXIT
  check_config "$ACTIVE_DIR"
  [[ "$(certificate_id "$ACTIVE_DIR/certs/ca.cert.pem")" == "$CERTNIFY_EXPECTED_ISSUER" ]] || die "Active issuer changed during batch"
  # Keep historical receipt IDs for compatibility/custom commands. A preserving
  # attempt has a distinct identity so an old CN-only success cannot satisfy it.
  item_id="$(
    { printf '%s\n' "$CERTNIFY_EXPECTED_ISSUER" "$LEGACY_DIR" "$serial" "$expires" "$cn"
      if [[ -n "${source_id:-}" ]]; then printf 'preserve\n%s\n' "$source_id"; fi
    } | "$OPENSSL" dgst -sha256 | awk '{print $NF}'
  )"
  receipt="$(authority_path "$ACTIVE_DIR" "reissues/$item_id")"
  if [[ -e "$receipt" ]]; then
    state="$(cat "$receipt")"
    release_locks
    if [[ "$state" == completed ]]; then
      completed=$((completed + 1))
      echo "[ITEM] serial=$serial status=already_completed cn=$cn"
    else
      ko=$((ko + 1))
      echo "[ITEM] serial=$serial status=needs_review receipt=$receipt cn=$cn" >&2
    fi
    continue
  fi
  mkdir -p "$(dirname "$receipt")"
  printf 'started\n' > "$receipt"
  release_locks

  rc=0
  if [[ -n "${ISSUE_CMD:-}" ]]; then
    CN="$cn" SERIAL="$serial" EXPIRES="$expires" INT_DIR="$ACTIVE_DIR" bash -c "$ISSUE_CMD" || rc=$?
  elif [[ "$REISSUE_MODE" == preserve ]]; then
    CN="$cn" SERIAL="$serial" EXPIRES="$expires" INT_DIR="$ACTIVE_DIR" \
      CERTNIFY_MIGRATION_SOURCE="$LEGACY_DIR" CERTNIFY_SOURCE_ID="$source_id" \
      DAYS="${DAYS:-$DEFAULT_DAYS}" "$ISSUE_SCRIPT" || rc=$?
  else
    row_san=""
    case "$KIND" in
      web) row_san="DNS:$cn" ;;
      auth|user|smime) [[ "$cn" != *@* ]] || row_san="email:$cn" ;;
    esac
    CN="$cn" SERIAL="$serial" EXPIRES="$expires" INT_DIR="$ACTIVE_DIR" \
      SAN="$row_san" DAYS="${DAYS:-$DEFAULT_DAYS}" "$ISSUE_SCRIPT" || rc=$?
  fi
  pki_begin
  trap 'rc=$?; rm -f "$PARSED_INPUT" "${source_plan:-}"; pki_exit "$rc"' EXIT
  # A concurrent lifecycle move may have moved the receipt. Do not recreate it
  # in a new active authority: leave the retained started receipt for review.
  [[ "$(certificate_id "$ACTIVE_DIR/certs/ca.cert.pem")" == "$CERTNIFY_EXPECTED_ISSUER" && -f "$receipt" ]] || die "Authority moved during batch; inspect retained attempt before retry"
  if [[ "$rc" == 0 ]]; then
    printf 'completed\n' > "$receipt"
    ok=$((ok + 1))
    echo "[ITEM] serial=$serial status=completed cn=$cn"
  else
    printf 'needs_review\n' > "$receipt"
    ko=$((ko + 1))
    echo "[ITEM] serial=$serial status=failed rc=$rc receipt=$receipt cn=$cn" >&2
  fi
  release_locks
done < "$PARSED_INPUT"

info "Batch result: total=$total completed=$ok already_completed=$completed planned=$planned failed=$ko"
[[ "$ko" == 0 ]]
