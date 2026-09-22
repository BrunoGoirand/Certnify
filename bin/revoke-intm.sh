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
#   KIND=web REASON=removeFromCRL CRL_UPDATE=1 bin/revoke-intm.sh
#
# Env:
#   INT_DIR / KIND            : select intermediate (INT_DIR wins; fallback KIND→intm-<KIND>-ca)
#   REASON                    : unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|AACompromise|privilegeWithdrawn
#   MAP_PRIV_WITHDRAWN_TO     : mapping when REASON=privilegeWithdrawn (default: cessationOfOperation)
#   CRL_UPDATE                : 1 to regenerate Root CRL after revocation (default: 0)
#   CRL_DAYS                  : CRL validity in days for CRL_UPDATE=1 (default: 7)
#   QUIET_OPENSSL             : 1 to reduce OpenSSL chatter (default: 1)
#   DEBUG                     : 1 to enable verbose debug + ERR trap (default: 0)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=bin/pki-env.sh
source "${SCRIPT_DIR}/pki-env.sh"
normalize_revocation_reason
pki_plan_or_begin

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


# --- Resolve intermediate directory (INT_DIR > KIND) ---
DIR="${INT_DIR:-}"
if [[ -n "$DIR" ]]; then
  DIR="$(normalize_int_dir "$DIR")"
elif [[ -n "${KIND:-}" ]]; then
  DIR="intm-${KIND}-ca"
fi
[[ -n "$DIR" ]] || die "Specify INT_DIR=... or KIND=..."
DIR="$(resolve_authority "$DIR")"
check_config "$DIR"
check_config root
dbg "DIR=$DIR (INT_DIR='${INT_DIR:-}', KIND='${KIND:-}')"

ROOT_CNF="${ROOT_DIR}/root/openssl.cnf"
ROOT_INDEX="${ROOT_DIR}/root/index.txt"
TARGET="${ROOT_DIR}/${DIR}/certs/ca.cert.pem"
INT_DISABLED_FLAG="${ROOT_DIR}/${DIR}/.disabled"

[[ -f "$ROOT_CNF"   ]] || die "Root CNF not found: $ROOT_CNF (generate root first)"
[[ -f "$ROOT_INDEX" ]] || die "Root index not found: $ROOT_INDEX"
[[ -f "$TARGET"     ]] || die "Intermediate cert not found: $TARGET (generate intermediate first)"

pki_records validate "$ROOT_INDEX" >/dev/null

SERIAL_HEX="$(openssl_serial "$TARGET")"
before_status="$(awk -F '\t' -v s="$SERIAL_HEX" '$4==s{print $1}' "$ROOT_INDEX")"
[[ "$before_status" == V || "$before_status" == E || "$before_status" == R ]] || die "Intermediate is not uniquely recorded in root index"
check_pair "$ROOT_DIR/root/certs/ca.cert.pem" "$ROOT_DIR/root/private/ca.key.pem"
"$OPENSSL" verify -no_check_time -CAfile "$ROOT_DIR/root/certs/ca.cert.pem" "$TARGET" >/dev/null
if [[ "$REASON" == removeFromCRL ]]; then
  release_certificate_hold root "$TARGET" "$ROOT_DIR/root/certs/ca.cert.pem" \
    "$ROOT_DIR/root/private/ca.key.pem" "$ROOT_DIR/root/crl/ca.crl.pem" "$INT_DISABLED_FLAG"
  exit 0
fi
if [[ "${DRY_RUN:-0}" == 1 ]]; then
  info "PLAN intermediate=$DIR current=$before_status crl_refresh=${CRL_UPDATE:-0}; issuance would be disabled"
  exit 0
fi
if [[ "$before_status" == R ]]; then
  info "Intermediate already revoked; CRL refresh requested=${CRL_UPDATE:-0}"
else
  if ! ossl ca -batch -config "$ROOT_CNF" -revoke "$TARGET" -crl_reason "$REASON"; then
    die "Revocation backend failed; inspect root index (revocation may have committed); no automatic retry"
  fi
  after_status="$(awk -F '\t' -v s="$SERIAL_HEX" '$4==s{print $1}' "$ROOT_INDEX")"
  [[ "$after_status" == R ]] || die "Unexpected root index state after revocation"
  index_set_filename_for_revoked "$ROOT_INDEX" "$SERIAL_HEX" || die "Revocation committed; index normalization failed"
fi
if [[ ! -e "$INT_DISABLED_FLAG" ]]; then
  if [[ "$REASON" == certificateHold && "$before_status" != R ]]; then
    printf 'certificateHold:%s\n' "$(certificate_id "$TARGET")" > "$INT_DISABLED_FLAG"
  else : > "$INT_DISABLED_FLAG"; fi
fi
if [[ "${CRL_UPDATE:-0}" == 1 ]]; then
  publish_crl root root/certs/ca.cert.pem root/private/ca.key.pem root/crl/ca.crl.pem -crldays "${CRL_DAYS:-7}" \
    || die "Intermediate revocation is committed; Root CRL refresh failed and previous CRL was preserved"
fi
info "Intermediate revoked; issuance disabled: $DIR"
