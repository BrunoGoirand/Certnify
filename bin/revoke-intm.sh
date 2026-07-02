#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#

# revoke-intm.sh — Revoke an intermediate CA from the ROOT CA database
#
# Usage:
#   KIND=smime REASON=keyCompromise CRL_UPDATE=1 CRL_DAYS=7 bin/revoke-intm.sh
#   INT_DIR="intm-web-ca" REASON=cessationOfOperation bin/revoke-intm.sh
#
# Env:
#   INT_DIR / KIND            : select intermediate (INT_DIR wins; fallback KIND→intm-<KIND>-ca)
#   REASON                    : unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL|AACompromise|privilegeWithdrawn
#   MAP_PRIV_WITHDRAWN_TO     : mapping when REASON=privilegeWithdrawn (default: cessationOfOperation)
#   CRL_UPDATE                : 1 to regenerate Root CRL after revocation (default: 0)
#   CRL_DAYS                  : CRL validity in days for CRL_UPDATE=1 (default: 7)
#   QUIET_OPENSSL             : 1 to reduce OpenSSL chatter (default: 1)
#   DEBUG                     : 1 to enable verbose debug + ERR trap (default: 0)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=bin/pki-env.sh
source "${SCRIPT_DIR}/pki-env.sh"

OPENSSL="${OPENSSL:-openssl}"
QUIET_OPENSSL="${QUIET_OPENSSL:-1}"
DEBUG="${DEBUG:-0}"

# --- Debug helpers ---
dbg(){ [[ "$DEBUG" == "1" ]] && echo "[DBG ] $*" >&2 || true; }
if [[ "$DEBUG" == "1" ]]; then
  rc=0
  set -o errtrace
  trap 'rc=$?; echo "[DBG ] ERR at ${BASH_SOURCE[0]}:${LINENO} → ${BASH_COMMAND} (rc=${rc})" >&2' ERR
fi

ossl() {
  if [[ "$QUIET_OPENSSL" == "1" ]]; then
    "$OPENSSL" "$@" >/dev/null 2>&1
  else
    "$OPENSSL" "$@"
  fi
}

# --- Helpers ---
normalize_int_dir() {
  local v="$1"
  if   [[ "$v" == "." ]]; then printf "."
  elif [[ "$v" == */* ]]; then printf "%s" "$v"
  elif [[ "$v" =~ ^intm-.*-ca$ ]]; then printf "%s" "$v"
  else printf "intm-%s-ca" "$v"; fi
}

# --- Resolve intermediate directory (INT_DIR > KIND) ---
DIR="${INT_DIR:-}"
if [[ -n "$DIR" ]]; then
  DIR="$(normalize_int_dir "$DIR")"
elif [[ -n "${KIND:-}" ]]; then
  DIR="intm-${KIND}-ca"
fi
[[ -n "$DIR" ]] || die "Specify INT_DIR=... or KIND=..."
dbg "DIR=$DIR (INT_DIR='${INT_DIR:-}', KIND='${KIND:-}')"

ROOT_CNF="${ROOT_DIR}/root/openssl.cnf"
ROOT_INDEX="${ROOT_DIR}/root/index.txt"
TARGET="${ROOT_DIR}/${DIR}/certs/ca.cert.pem"
INT_DISABLED_FLAG="${ROOT_DIR}/${DIR}/.disabled"

[[ -f "$ROOT_CNF"   ]] || die "Root CNF not found: $ROOT_CNF (generate root first)"
[[ -f "$ROOT_INDEX" ]] || die "Root index not found: $ROOT_INDEX"
[[ -f "$TARGET"     ]] || die "Intermediate cert not found: $TARGET (generate intermediate first)"

# --- Revocation reason normalization (OpenSSL CLI does not accept 'privilegeWithdrawn') ---
REASON="${REASON:-cessationOfOperation}"
MAP_TO="${MAP_PRIV_WITHDRAWN_TO:-cessationOfOperation}"
case "$REASON" in
  unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL|AACompromise) ;;
  privilegeWithdrawn)
    warn "Reason 'privilegeWithdrawn' is not supported by OpenSSL → mapping to '$MAP_TO'."
    REASON="$MAP_TO"
    ;;
  *) die "Unsupported revocation reason: '$REASON'";;
esac

# --- Pre-status from root index (for removeFromCRL guard) ---
SERIAL_HEX="$(openssl_serial "$TARGET" | tr '[:lower:]' '[:upper:]')"
[[ -n "$SERIAL_HEX" ]] || die "Unable to read intermediate serial: $TARGET"
before_status="$(awk -F'\t' -v s="$SERIAL_HEX" '$4==s{print $1;exit}' "$ROOT_INDEX" || true)"

# --- Guard for removeFromCRL (only valid for certificateHold) ---
if [[ "$REASON" == "removeFromCRL" ]]; then
  if [[ "$before_status" != "R" ]]; then
    warn "removeFromCRL requested but current status in root DB is not 'R'. OpenSSL will likely fail."
  else
    current_reason="$("$OPENSSL" x509 -in "$TARGET" -noout -text 2>/dev/null | awk '/CRL Reason Code/ {getline; gsub(/^ +| +$/,""); print; exit}' || true)"
    if [[ -n "$current_reason" && "$current_reason" != "certificateHold" ]]; then
      warn "removeFromCRL applies only to 'certificateHold' (current: '$current_reason')."
    fi
  fi
fi

# --- Revoke in ROOT DB (idempotent) ---
info "Revoking intermediate: $DIR (reason=$REASON)"
if ! ossl ca -batch -config "$ROOT_CNF" -revoke "$TARGET" -crl_reason "$REASON"; then
  # Rerun noisily to inspect error; treat "already revoked" as success
  if "$OPENSSL" ca -batch -config "$ROOT_CNF" -revoke "$TARGET" -crl_reason "$REASON" 2>&1 | grep -qi 'already revoked'; then
    info "Intermediate already revoked in root DB."
  else
    die "OpenSSL revocation failed in root DB."
  fi
fi

# --- Normalize ROOT index: set filename=unknown for the revoked serial ---
dbg "Intermediate serial in ROOT DB: ${SERIAL_HEX:-<unknown>}"
if [[ -n "$SERIAL_HEX" ]]; then
  index_set_filename_for_revoked "$ROOT_INDEX" "$SERIAL_HEX" || true
fi
info "Intermediate marked revoked in root/index.txt (DIR=$DIR, reason=$REASON)"

# --- Create issuance guard to block new leaf issuance until a new intermediate is generated ---
# gen-intm.sh removes this flag to re-enable issuance.
mkdir -p "$(dirname "$INT_DISABLED_FLAG")"
if [[ ! -f "$INT_DISABLED_FLAG" ]]; then
  : > "$INT_DISABLED_FLAG"
  info "Issuance disabled for ${DIR}: created ${DIR}/.disabled"
else
  dbg "Issuance guard already present: ${DIR}/.disabled"
fi

# --- Optional Root CRL update ---
if [[ "${CRL_UPDATE:-0}" == "1" ]]; then
  CRL_DAYS="${CRL_DAYS:-7}"
  mkdir -p "${ROOT_DIR}/root/crl"
  TMP="$(mktemp -t crl.XXXXXX || mktemp)"
  info "Regenerating Root CRL (crldays=$CRL_DAYS)"
  ossl ca -batch -config "$ROOT_CNF" -gencrl -crldays "$CRL_DAYS" -out "$TMP"
  install -m 444 "$TMP" "${ROOT_DIR}/root/crl/ca.crl.pem"
  rm -f "$TMP"
  info "Root CRL updated: root/crl/ca.crl.pem"
fi
