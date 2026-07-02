#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=bin/pki-env.sh
source "${SCRIPT_DIR}/pki-env.sh"

OPENSSL="${OPENSSL:-openssl}"

# ---------------------------
# Inputs (env variables)
# ---------------------------
# INT_DIR / KIND           : target intermediate (INT_DIR has priority; fallback KIND→intm-<KIND>-ca)
# REASON                   : unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL|AACompromise|privilegeWithdrawn
# MAP_PRIV_WITHDRAWN_TO    : mapping when REASON=privilegeWithdrawn (default: cessationOfOperation)
# CRL_UPDATE               : 1 to regenerate CRLs (root + intermediate) after revocation (default: 0)
# CRL_DAYS                 : days for CRL validity when CRL_UPDATE=1 (default: 7)
# LEAF_STATUSES            : which statuses to revoke from intermediate index (comma list; default: "V")
#                            Typical values: "V" (valid only) or "V,E" (valid + expired)
# DRY_RUN                  : 1 to print actions without executing OpenSSL (default: 0)
# QUIET_OPENSSL            : 1 to reduce OpenSSL chatter (default: 1)
# DEBUG                    : 1 to enable verbose debug + ERR trap (default: 0)

REASON="${REASON:-cessationOfOperation}"
MAP_TO="${MAP_PRIV_WITHDRAWN_TO:-cessationOfOperation}"
CRL_UPDATE="${CRL_UPDATE:-0}"
CRL_DAYS="${CRL_DAYS:-7}"
LEAF_STATUSES="${LEAF_STATUSES:-V}"
DRY_RUN="${DRY_RUN:-0}"
QUIET_OPENSSL="${QUIET_OPENSSL:-1}"
DEBUG="${DEBUG:-0}"

# ---------------------------
# Debug helpers
# ---------------------------
dbg(){ [[ "$DEBUG" == "1" ]] && echo "[DBG ] $*" >&2 || true; }
if [[ "$DEBUG" == "1" ]]; then
  rc=0
  set -o errtrace
  trap 'rc=$?; echo "[DBG ] ERR at ${BASH_SOURCE[0]}:${LINENO} → ${BASH_COMMAND} (rc=${rc})" >&2' ERR
fi

ossl() {
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY] $OPENSSL $*"
    return 0
  fi
  if [[ "$QUIET_OPENSSL" == "1" ]]; then
    "$OPENSSL" "$@" >/dev/null 2>&1
  else
    "$OPENSSL" "$@"
  fi
}

# Fallback local si pki-env.sh ne fournit pas in_csv
if ! declare -F in_csv >/dev/null 2>&1; then
  in_csv() {
    local needle="$1" list="$2"
    IFS=',' read -r -a _arr <<<"$list"
    for _x in "${_arr[@]}"; do [[ "$_x" == "$needle" ]] && return 0; done
    return 1
  }
fi

# Normalisation INT_DIR compatible avec le reste du toolkit
normalize_int_dir() {
  local v="$1"
  if   [[ "$v" == "." ]]; then printf "."
  elif [[ "$v" == */* ]]; then printf "%s" "$v"
  elif [[ "$v" =~ ^intm-.*-ca$ ]]; then printf "%s" "$v"
  else printf "intm-%s-ca" "$v"; fi
}

# ---------------------------
# Resolve intermediate dir (INT_DIR > KIND)
# ---------------------------
DIR="${INT_DIR:-}"
if [[ -n "$DIR" ]]; then
  DIR="$(normalize_int_dir "$DIR")"
elif [[ -n "${KIND:-}" ]]; then
  DIR="intm-${KIND}-ca"
fi
[[ -n "$DIR" ]] || die "Specify INT_DIR=... or KIND=..."

info "Using intermediate: ${DIR}"

# ---------------------------
# Resolve paths
# ---------------------------
ROOT_CNF="${ROOT_DIR}/root/openssl.cnf"
INT_CNF="${ROOT_DIR}/${DIR}/openssl.cnf"
ROOT_CRLPATH="${ROOT_DIR}/root/crl/ca.crl.pem"
INT_CRLPATH="${ROOT_DIR}/${DIR}/crl/ca.crl.pem"

INT_CERT="${ROOT_DIR}/${DIR}/certs/ca.cert.pem"
INT_INDEX="${ROOT_DIR}/${DIR}/index.txt"
ROOT_INDEX="${ROOT_DIR}/root/index.txt"

[[ -f "$ROOT_CNF" ]] || die "Root CNF not found: $ROOT_CNF (generate root first)"
[[ -f "$INT_CNF"  ]] || die "Intermediate CNF not found: $INT_CNF (generate intermediate first)"
[[ -f "$INT_CERT" ]] || die "Intermediate cert not found: $INT_CERT (generate intermediate first)"
[[ -f "$INT_INDEX" ]] || die "Intermediate index not found: $INT_INDEX"
[[ -f "$ROOT_INDEX" ]] || die "Root index not found: $ROOT_INDEX"

dbg "DIR=$DIR"
dbg "ROOT_CNF=$ROOT_CNF"
dbg "INT_CNF=$INT_CNF"
dbg "INT_CERT=$INT_CERT"
dbg "INT_INDEX=$INT_INDEX"

# ---------------------------
# Reason normalization (OpenSSL CLI does not accept 'privilegeWithdrawn')
# ---------------------------
case "$REASON" in
  unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL|AACompromise) ;;
  privilegeWithdrawn)
    warn "Reason 'privilegeWithdrawn' is not supported by OpenSSL CLI → mapping to '$MAP_TO'."
    REASON="$MAP_TO"
    ;;
  *) die "Unsupported revocation reason: '$REASON'";;
esac

# ---------------------------
# 1) Revoke intermediate in ROOT (idempotent)
# ---------------------------
info "Revoking intermediate in ROOT: $DIR (reason=$REASON)"
if ! ossl ca -batch -config "$ROOT_CNF" -revoke "$INT_CERT" -crl_reason "$REASON"; then
  if "$OPENSSL" ca -batch -config "$ROOT_CNF" -revoke "$INT_CERT" -crl_reason "$REASON" 2>&1 | grep -qi 'already revoked'; then
    info "Intermediate already revoked in root DB."
  else
    die "OpenSSL revocation failed in root DB."
  fi
fi

# Guard removeFromCRL (utile seulement si intm était en certificateHold)
INT_SERIAL_HEX="$(openssl_serial "$INT_CERT" | tr '[:lower:]' '[:upper:]')"
[[ -n "$INT_SERIAL_HEX" ]] || die "Unable to read intermediate serial: $INT_CERT"

# Normalize ROOT index: set filename=unknown for revoked serial
dbg "Intermediate serial (root DB): ${INT_SERIAL_HEX:-<unknown>}"
if declare -F index_set_filename_for_revoked >/dev/null 2>&1; then
  index_set_filename_for_revoked "$ROOT_INDEX" "$INT_SERIAL_HEX" || true
else
  awk -v s="$INT_SERIAL_HEX" 'BEGIN{FS=OFS="\t"} { if ($1=="R" && $4==s && $5!="unknown") $5="unknown"; print }' \
    "$ROOT_INDEX" > "$ROOT_INDEX.tmp" && mv "$ROOT_INDEX.tmp" "$ROOT_INDEX"
fi
info "Intermediate marked revoked in root/index.txt"

# ---------------------------
# 2) Revoke all leaf certificates issued by the intermediate
# ---------------------------
info "Revoking leaf certificates from ${DIR}/index.txt (statuses: $LEAF_STATUSES)…"

# Use a non-whitespace separator (US, 0x1F) to preserve empty fields when reading in bash.
awk -v US="$(printf '\x1f')" 'BEGIN{FS="\t"}
  /^[[:space:]]*$/ || $1 ~ /^#/ { next }      # skip empty/comment lines
  {
    # Index layout: status expiry revocation serial filename subject(with tabs possible)
    status=$1; expiry=$2; rev=$3; serial=$4; filename=$5;

    # Rebuild subject from $6..$NF (may contain spaces or tabs)
    subject = "";
    if (NF >= 6) {
      subject = $6;
      for (i = 7; i <= NF; i++) subject = subject "\t" $i;
    }

    # Print exactly 6 fields separated by US (non-whitespace)
    printf "%s%s%s%s%s%s%s%s%s%s%s\n", status, US, expiry, US, rev, US, serial, US, filename, US, subject;
  }
' "$INT_INDEX" | while IFS=$'\x1F' read -r status _expiry _revocation serial filename _subject; do
  # Filter by status (e.g., "V" or "V,E")
  if ! in_csv "$status" "$LEAF_STATUSES"; then
    continue
  fi

  # Absolute path for filename from index; fallback to newcerts/<serial>.pem
  cert_path="${ROOT_DIR}/${DIR}/${filename}"
  if [[ "$filename" == "unknown" || ! -f "$cert_path" ]]; then
    cert_path="${ROOT_DIR}/${DIR}/newcerts/${serial}.pem"
  fi

  if [[ -f "$cert_path" ]]; then
    info "  - Revoking leaf serial=$serial ($cert_path)"
    if ! ossl ca -batch -config "$INT_CNF" -revoke "$cert_path" -crl_reason "$REASON"; then
      if "$OPENSSL" ca -batch -config "$INT_CNF" -revoke "$cert_path" -crl_reason "$REASON" 2>&1 | grep -qi 'already revoked'; then
        info "    -> already revoked (serial=$serial)"
      else
        warn "    -> OpenSSL failed for serial=$serial"
      fi
    fi

    # Normalize INT index: set filename=unknown for this serial if now revoked
    awk -v s="$serial" 'BEGIN{FS=OFS="\t"} { if ($1=="R" && $4==s && $5!="unknown") $5="unknown"; print }' \
      "$INT_INDEX" > "$INT_INDEX.tmp" && mv "$INT_INDEX.tmp" "$INT_INDEX"
  else
    warn "  - Skipped serial=$serial (missing file: ${ROOT_DIR}/${DIR}/${filename})"
  fi
done

# ---------------------------
# 3) Regenerate CRLs (optional but recommended)
# ---------------------------
if [[ "$CRL_UPDATE" == "1" ]]; then
  mkdir -p "$(dirname "$ROOT_CRLPATH")" "$(dirname "$INT_CRLPATH")"

  info "Regenerating Root CRL (crldays=$CRL_DAYS)…"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY] $OPENSSL ca -batch -config '$ROOT_CNF' -gencrl -crldays '$CRL_DAYS' -out '$ROOT_CRLPATH'"
  else
    TMP="$(mktemp -t crl.root.XXXXXX || mktemp)"
    ossl ca -batch -config "$ROOT_CNF" -gencrl -crldays "$CRL_DAYS" -out "$TMP"
    install -m 444 "$TMP" "$ROOT_CRLPATH"
    rm -f "$TMP"
  fi
  info "Root CRL updated: ${ROOT_CRLPATH#"$ROOT_DIR/"}"

  info "Regenerating Intermediate CRL (crldays=$CRL_DAYS)…"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "[DRY] $OPENSSL ca -batch -config '$INT_CNF' -gencrl -crldays '$CRL_DAYS' -out '$INT_CRLPATH'"
  else
    TMP2="$(mktemp -t crl.intm.XXXXXX || mktemp)"
    ossl ca -batch -config "$INT_CNF" -gencrl -crldays "$CRL_DAYS" -out "$TMP2"
    install -m 444 "$TMP2" "$INT_CRLPATH"
    rm -f "$TMP2"
  fi
  info "Intermediate CRL updated: ${INT_CRLPATH#"$ROOT_DIR/"}"
fi

# ---------------------------
# 4) Disable further issuance from this intermediate (guard file)
#    gen-intm.sh removes this file to re-enable issuance.
# ---------------------------
DISABLED_FLAG="${ROOT_DIR}/${DIR}/.disabled"
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "[DRY] touch '$DISABLED_FLAG'"
else
  : > "$DISABLED_FLAG"
fi
info "Issuance disabled for ${DIR}: created ${DISABLED_FLAG}"

info "Revocation completed: intermediate + issued leaf certificates."
