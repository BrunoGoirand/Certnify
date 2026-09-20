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
normalize_revocation_reason
pki_plan_or_begin

OPENSSL="${OPENSSL:-openssl}"

# ---------------------------
# Inputs (env variables)
# ---------------------------
# INT_DIR / KIND           : target intermediate (INT_DIR has priority; fallback KIND→intm-<KIND>-ca)
# REASON                   : unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|AACompromise|privilegeWithdrawn
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
DIR="$(resolve_authority "$DIR")"
check_config "$DIR"
check_config root

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

pki_records validate "$ROOT_INDEX" >/dev/null
pki_records validate "$INT_INDEX" >/dev/null

# ---------------------------
# Reason normalization (OpenSSL CLI does not accept 'privilegeWithdrawn')
# ---------------------------

# Freeze selected rows before any mutation. Preflight all historical signers.
PLAN="$(mktemp)"
trap 'rm -f "$PLAN"; release_locks' EXIT
awk -F '\t' 'BEGIN{OFS=sprintf("%c",31)} $1~/^[VRE]$/{print $1,$4,$5}' "$INT_INDEX" > "$PLAN"
total=0; ok=0; ko=0; planned=0; completed=0
[[ "$DRY_RUN" == 0 || "$DRY_RUN" == 1 ]] || die "DRY_RUN must be 0 or 1"
case ",$LEAF_STATUSES," in *,,*) die "Empty LEAF_STATUSES entry" ;; esac
IFS=',' read -r -a selected_statuses <<< "$LEAF_STATUSES"
for selected_status in "${selected_statuses[@]}"; do
  case "$selected_status" in V|R|E) ;; *) die "Unsupported leaf status: $selected_status" ;; esac
done
preflight_failed=0
while IFS=$'\x1F' read -r pre_status pre_serial pre_file; do
  in_csv "$pre_status" "$LEAF_STATUSES" || continue
  [[ "$pre_status" != R ]] || continue
  if (
    [[ "$pre_file" != unknown ]] || pre_file="newcerts/$pre_serial.pem"
    pre_path="$(authority_path "$DIR" "$pre_file")" || exit 1
    [[ -f "$pre_path" ]] || die "Missing selected leaf: $pre_path"
    resolve_leaf_issuer "$DIR" "$pre_path" || exit 1
    check_pair "$ISSUER_CERT" "$ISSUER_KEY" || exit 1
  ); then
    :
  else
    preflight_failed=$((preflight_failed + 1))
    echo "[PREFLIGHT] serial=$pre_serial status=failed" >&2
  fi
done < "$PLAN"
if [[ "$preflight_failed" != 0 ]]; then
  while IFS=$'\x1F' read -r status serial filename; do
    in_csv "$status" "$LEAF_STATUSES" || continue
    echo "[ITEM] serial=$serial status=skipped_required reason=preflight_failure" >&2
  done < "$PLAN"
  die "Batch preflight failed: $preflight_failed; no revocation attempted"
fi

# Do not retry OpenSSL based on an error string: inspect durable state first.
INT_SERIAL_HEX="$(openssl_serial "$INT_CERT")"
parent_status="$(awk -F '\t' -v s="$INT_SERIAL_HEX" '$4==s{print $1}' "$ROOT_INDEX")"
[[ "$parent_status" == V || "$parent_status" == E || "$parent_status" == R ]] || die "Intermediate missing/ambiguous in root index"
if [[ "$DRY_RUN" == 1 ]]; then
  echo "[PARENT] status=planned serial=$INT_SERIAL_HEX"
elif [[ "$parent_status" == R ]]; then
  echo "[PARENT] status=already_completed serial=$INT_SERIAL_HEX"
else
  if ossl ca -batch -config "$ROOT_CNF" -revoke "$INT_CERT" -crl_reason "$REASON"; then
    index_set_filename_for_revoked "$ROOT_INDEX" "$INT_SERIAL_HEX"
    echo "[PARENT] status=completed serial=$INT_SERIAL_HEX"
  else
    echo "[PARENT] status=failed serial=$INT_SERIAL_HEX; inspect root index before retry" >&2
    while IFS=$'\x1F' read -r status serial filename; do
      in_csv "$status" "$LEAF_STATUSES" || continue
      echo "[ITEM] serial=$serial status=skipped_required reason=parent_failure" >&2
    done < "$PLAN"
    exit 1
  fi
fi

while IFS=$'\x1F' read -r status serial filename; do
  in_csv "$status" "$LEAF_STATUSES" || continue
  total=$((total + 1))
  if [[ "$status" == R ]]; then
    completed=$((completed + 1))
    echo "[ITEM] serial=$serial status=already_completed"
    continue
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    planned=$((planned + 1))
    echo "[ITEM] serial=$serial status=planned"
    continue
  fi
  [[ "$filename" != unknown ]] || filename="newcerts/$serial.pem"
  cert_path="$(authority_path "$DIR" "$filename")"
  resolve_leaf_issuer "$DIR" "$cert_path"
  if ossl ca -batch -config "$INT_CNF" -cert "$ISSUER_CERT" -keyfile "$ISSUER_KEY" -revoke "$cert_path" -crl_reason "$REASON"; then
    after_status="$(awk -F '\t' -v s="$serial" '$4==s{print $1}' "$INT_INDEX")"
    if [[ "$after_status" == R ]] && index_set_filename_for_revoked "$INT_INDEX" "$serial"; then
      ok=$((ok + 1))
      echo "[ITEM] serial=$serial status=completed"
    else
      ko=$((ko + 1))
      echo "[ITEM] serial=$serial status=failed reason=unexpected_database_state" >&2
    fi
  else
    ko=$((ko + 1))
    echo "[ITEM] serial=$serial status=failed reason=backend_error; inspect index before retry" >&2
  fi
done < "$PLAN"
info "Batch result: total=$total completed=$ok already_completed=$completed planned=$planned failed=$ko"

# ---------------------------
# 3) Refresh CRLs even for already-revoked records when requested.
if [[ "$CRL_UPDATE" == 1 ]]; then
  if [[ "$DRY_RUN" == 1 ]]; then
    info "PLAN refresh root, current issuer and retained historical CRLs"
  else
    publish_crl root root/certs/ca.cert.pem root/private/ca.key.pem "$ROOT_CRLPATH" -crldays "$CRL_DAYS" \
      || die "Revocations remain committed; Root CRL refresh failed"
    publish_crl "$DIR" "$INT_CERT" "$DIR/private/ca.key.pem" "$INT_CRLPATH" -crldays "$CRL_DAYS" \
      || die "Revocations remain committed; issuer CRL refresh failed"
    for historical_cert in "$ROOT_DIR/$DIR"/generations/*/ca.cert.pem; do
      [[ -f "$historical_cert" ]] || continue
      historical_cert="$(authority_path "$DIR" "$historical_cert")"
      historical_key="${historical_cert%/ca.cert.pem}/ca.key.pem"
      historical_out="$(authority_path "$DIR" "${historical_cert%/ca.cert.pem}/ca.crl.pem")"
      publish_crl "$DIR" "$historical_cert" "$historical_key" "$historical_out" -crldays "$CRL_DAYS" \
        || die "Revocations remain committed; historical CRL refresh failed"
    done
  fi
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

if [[ "$ko" != 0 ]]; then die "Partial revocation: $ko required leaf operation(s) failed"; fi
if [[ "$DRY_RUN" == 1 ]]; then info "Revocation plan completed"; else info "Revocation completed: intermediate + selected leaf certificates"; fi
