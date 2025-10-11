#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"

# ============================================================
# publish-final-crl.sh
#
# Génère et (optionnellement) publie la CRL "finale" pour un
# intermédiaire : on étend nextUpdate pour laisser une marge,
# puis on "freeze" (plus de nouvelles CRL prévues).
#
# Entrées (env) :
#   INT_DIR="intm-web-ca"          # sinon KIND=web -> alias intm-web-ca
#   CRL_DAYS=90                    # durée avant nextUpdate (override default_crl_days)
#   CRL_HOURS=                     # optionnel (si tu préfères des heures)
#   OUT_DIR="crl"                  # dossier de sortie relative à INT_DIR
#   PUBLISH_CMD="rsync -av %FILE% user@host:/var/www/crl/"
#     - %FILE% sera substitué par chaque fichier généré (PEM, DER, SHA256)
#
#   FINAL_MODE=1                   # si 1: refuse si des leafs valides restent (sécurité)
#   ALLOW_REMAINING_LEAFS=0        # si 1: autorise malgré des leafs encore valides
#
# Comportement :
#   - Vérifie l’intermédiaire et l’index
#   - Alerte si des leafs valides (status=V) subsistent (et bloque en FINAL_MODE=1)
#   - Génère la CRL PEM avec -crldays/-crlhours si fournis
#   - Écrit une version DER + empreintes SHA256
#   - Met permissions en lecture seule
#   - (Optionnel) publie via PUBLISH_CMD
# ============================================================

: "${CRL_DAYS:=90}"
: "${CRL_HOURS:=}"
: "${OUT_DIR:=crl}"
: "${FINAL_MODE:=1}"
: "${ALLOW_REMAINING_LEAFS:=0}"

# --- Résolution de l'intermédiaire ---
if [[ -z "${INT_DIR:-}" ]]; then
  [[ -n "${KIND:-}" ]] || die "Spécifie INT_DIR=... ou KIND=..."
  INT_DIR="intm-${KIND}-ca"
fi

INT_CNF="${INT_DIR}/openssl.cnf"
INT_CRT="${INT_DIR}/certs/ca.cert.pem"
INT_KEY="${INT_DIR}/private/ca.key.pem"
INDEX="${INT_DIR}/index.txt"

[[ -f "$INT_CNF" ]] || die "Config introuvable: $INT_CNF"
[[ -f "$INT_CRT" ]] || die "Cert intermédiaire introuvable: $INT_CRT"
[[ -f "$INT_KEY" ]] || die "Clé privée intermédiaire introuvable: $INT_KEY"
[[ -f "$INDEX"  ]] || die "index.txt introuvable: $INDEX"

# --- Statistiques index : V(valid), R(revoked), E(expired) ---
read -r cntV cntR cntE <<<"$(awk -F'\t' '
  $1=="V"{v++} $1=="R"{r++} $1=="E"{e++}
  END{printf "%d %d %d", v+0, r+0, e+0}
' "$INDEX")"

info "Index status → V=${cntV} (valides), R=${cntR} (révoqués), E=${cntE} (expirés)"

if [[ "$FINAL_MODE" == "1" && "$ALLOW_REMAINING_LEAFS" != "1" && "$cntV" -gt 0 ]]; then
  die "FINAL_MODE=1 : des leafs valides subsistent (V=${cntV}). Réémets/retire avant la CRL finale ou passe ALLOW_REMAINING_LEAFS=1."
fi

# --- Dossier sortie CRL ---
mkdir -p "${INT_DIR}/${OUT_DIR}"

ts="$(date -u +%Y%m%d%H%M%SZ)"
CRL_PEM="${INT_DIR}/${OUT_DIR}/ca-${ts}.crl.pem"
CRL_DER="${INT_DIR}/${OUT_DIR}/ca-${ts}.crl"
CRL_LATEST_PEM="${INT_DIR}/${OUT_DIR}/ca.crl.pem"
CRL_LATEST_DER="${INT_DIR}/${OUT_DIR}/ca.crl"

# --- Génération CRL ---
info "Génération CRL finale…"
gen_args=( -gencrl -config "$INT_CNF" )
if [[ -n "$CRL_HOURS" ]]; then
  gen_args+=( -crlhours "$CRL_HOURS" )
elif [[ -n "$CRL_DAYS" ]]; then
  gen_args+=( -crldays "$CRL_DAYS" )
fi

"$OPENSSL" ca "${gen_args[@]}" -out "$CRL_PEM" >/dev/null

# --- Conversion DER + empreintes ---
"$OPENSSL" crl -in "$CRL_PEM" -outform DER -out "$CRL_DER" >/dev/null

sha256_pem="$("$OPENSSL" crl -in "$CRL_PEM" -noout -fingerprint -sha256 | sed 's/^SHA256 Fingerprint=//; s/://g')"
sha256_der="$("$OPENSSL" dgst -sha256 -binary "$CRL_DER" | openssl base64)"

printf '%s\n' "$sha256_pem" > "${CRL_PEM}.sha256"
printf '%s\n' "$sha256_der" > "${CRL_DER}.sha256"

chmod 444 "$CRL_PEM" "$CRL_DER" "${CRL_PEM}.sha256" "${CRL_DER}.sha256"

# --- Symlinks "latest" atomiques ---
ln -sfn "$(basename "$CRL_PEM")" "$CRL_LATEST_PEM"
ln -sfn "$(basename "$CRL_DER")" "$CRL_LATEST_DER"

# --- Affichage résumé ---
next_update="$("$OPENSSL" crl -in "$CRL_PEM" -noout -nextupdate | sed 's/^nextUpdate=//')"
last_update="$("$OPENSSL" crl -in "$CRL_PEM" -noout -lastupdate | sed 's/^lastUpdate=//')"

info "CRL émise: $CRL_PEM"
info "lastUpdate=$last_update  nextUpdate=$next_update"
info "DER: $CRL_DER"
info "SHA256(PEM) écrit dans: ${CRL_PEM}.sha256"
info "SHA256(DER-binary) écrit dans: ${CRL_DER}.sha256"
info "Liens: $(basename "$CRL_LATEST_PEM"), $(basename "$CRL_LATEST_DER")"

# --- Publication optionnelle ---
publish_file() {
  local f="$1"
  local cmd="${PUBLISH_CMD//%FILE%/$f}"
  if [[ -n "${PUBLISH_CMD:-}" ]]; then
    echo "[PUB] $cmd"
    bash -c "$cmd"
  fi
}

if [[ -n "${PUBLISH_CMD:-}" ]]; then
  # Publie PEM, DER et leurs .sha256
  pushd "${INT_DIR}/${OUT_DIR}" >/dev/null
  publish_file "$(basename "$CRL_PEM")"
  publish_file "$(basename "$CRL_DER")"
  publish_file "$(basename "${CRL_PEM}.sha256")"
  publish_file "$(basename "${CRL_DER}.sha256")"
  # (option) publier aussi les symlinks "latest" si le serveur sait les gérer
  publish_file "$(basename "$CRL_LATEST_PEM")" || true
  publish_file "$(basename "$CRL_LATEST_DER")" || true
  popd >/dev/null
fi

info "CRL finale publiée avec succès."
