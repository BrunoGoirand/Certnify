#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#

# revoke-leaf.sh — revoke a single end-entity certificate (leaf) issued by an intermediate
#
# Usage examples:
#   make revoke KIND="web" CN="app.example.com" REASON="keyCompromise"
#   make revoke INT_DIR="intm-web-ca" CN="app.example.com" REASON="cessationOfOperation"
#   make revoke KIND=web FILE="intm-web-ca/certs/app.example.com.cert.pem" REASON="superseded"
#   make revoke INT_DIR="intm-web-ca" SERIAL="1002" REASON="superseded"
#
# Env:
#   INT_DIR/KIND, CN/FILE/SERIAL (priority FILE > SERIAL > CN), REASON, MAP_PRIV_WITHDRAWN_TO,
#   CRL_UPDATE(=1), CRL_DAYS(=7), DRY_RUN(=0), QUIET_OPENSSL(=1), DEBUG(=0)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=bin/pki-env.sh
source "${SCRIPT_DIR}/pki-env.sh"
normalize_revocation_reason
pki_plan_or_begin

# --- Defaults ---
: "${INT_DIR:=}"; : "${KIND:=}"; : "${CN:=}"; : "${FILE:=}"; : "${SERIAL:=}"
: "${REASON:=cessationOfOperation}"; : "${CRL_UPDATE:=1}"; : "${CRL_DAYS:=7}"
: "${DRY_RUN:=0}"; : "${QUIET_OPENSSL:=1}"; : "${DEBUG:=0}"
OPENSSL="${OPENSSL:-openssl}"


# --- Debug helpers ---
if [[ "$DEBUG" == "1" ]]; then
  rc=0
  set -x; set -o errtrace
  trap 'rc=$?; echo "[DBG ] ERR at ${BASH_SOURCE[0]}:${LINENO} → ${BASH_COMMAND} (rc=${rc})" >&2' ERR
fi
dbg(){ [[ "$DEBUG" == "1" ]] && echo "[DBG ] $*" >&2 || true; }

# --- Helpers (alignés avec verify.sh) ---

safe(){ local s="$1"; s="${s//[^A-Za-z0-9._-]/_}"; while [[ "$s" == *"__"* ]]; do s="${s//__/_}"; done; s="${s##_}"; s="${s%%_}"; echo "$s"; }
ossl(){
  if [[ "$DRY_RUN" == "1" ]]; then echo "[DRY] $OPENSSL $*"; return 0; fi
  if [[ "$QUIET_OPENSSL" == "1" ]]; then "$OPENSSL" "$@" >/dev/null 2>&1; else "$OPENSSL" "$@"; fi
}

# --- Resolve intermediate (INT_DIR > KIND) ---
CA_DIR=""
if [[ -n "$INT_DIR" ]]; then
  CA_DIR="$(normalize_int_dir "$INT_DIR")"
elif [[ -n "$KIND" ]]; then
  CA_DIR="intm-${KIND}-ca"
fi
CA_DIR="$(resolve_authority "$CA_DIR")"
check_config "$CA_DIR"
check_config root
[[ -n "$CA_DIR" ]] || die "Spécifie INT_DIR=... ou KIND=... pour cibler l'intermédiaire."
info "Using intermediate: ${CA_DIR}"
assert_intermediate_ready
cd "$ROOT_DIR/$CA_DIR" || die "Cannot cd to '$ROOT_DIR/$CA_DIR'"

CNF="openssl.cnf"; INDEX_LOCAL="index.txt"
[[ -f "$CNF" ]] || die "Missing $CA_DIR/$CNF"
[[ -f "$INDEX_LOCAL" ]] || die "Missing $CA_DIR/$INDEX_LOCAL"

# Validate history before selecting or mutating any record.
pki_records validate "$INDEX_LOCAL" >/dev/null

# --- Resolve target (FILE > SERIAL > CN) ---
TARGET=""
dbg "Inputs: FILE='${FILE}', SERIAL='${SERIAL}', CN='${CN}'"

# 1) FILE
if [[ -n "$FILE" ]]; then
  FILE="$(resolve_leaf_file "$CA_DIR" "$FILE")"
  [[ -f "$FILE" ]] || die "Specified FILE does not exist: $FILE"
  TARGET="$FILE"
fi

# 2) SERIAL: compare hexadecimal values, retaining the indexed spelling for paths.
if [[ -z "$TARGET" && -n "$SERIAL" ]]; then
  selected="$(PKI_RECORD_SERIAL="$SERIAL" pki_records serial-target "$INDEX_LOCAL")" || exit 1
  if [[ -n "$selected" ]]; then
    IFS=$'\x1F' read -r serial_uc candidate <<< "$selected"
    if [[ -f "newcerts/${serial_uc}.pem" ]]; then
      TARGET="newcerts/${serial_uc}.pem"
    elif [[ "$candidate" != "unknown" && -f "$candidate" ]]; then
      TARGET="$candidate"
    fi
  fi
fi

# An explicit serial must never fall through to a different CN target.
if [[ -z "$TARGET" && -n "$SERIAL" ]]; then
  die "Certificate not found for explicit SERIAL=$SERIAL"
fi

# 3) Exact CN: one active match, otherwise one unambiguous historical record.
if [[ -z "$TARGET" && -n "$CN" ]]; then
  serial_uc="$(pki_records revoke "$INDEX_LOCAL")" || exit 1
  TARGET="newcerts/${serial_uc}.pem"
  if [[ ! -f "$TARGET" ]]; then
    candidate="$(awk -F '\t' -v s="$serial_uc" '$4==s{print $5;exit}' "$INDEX_LOCAL")"
    [[ -n "$candidate" && "$candidate" != "unknown" && -f "$candidate" ]] \
      || die "Missing indexed certificate for serial $serial_uc; use FILE explicitly"
    TARGET="$candidate"
  fi
fi

[[ -n "$TARGET" && -f "$TARGET" ]] || die "Certificate not found.
Hints:
  - FILE=certs/<CN>.cert.pem
  - SERIAL=<hex> (newcerts/<SERIAL>.pem or indexed)
  - CN=<common-name> (certs/<CN>.cert.pem)
Inputs were: CN=${CN:-}, FILE=${FILE:-}, SERIAL=${SERIAL:-}"

# --- Compute serial & check status ---
SERIAL_HEX="$(openssl_serial "$TARGET")"
[[ -n "$SERIAL_HEX" ]] || die "Unable to read serial from $TARGET"
SERIAL_HEX="$(printf '%s' "$SERIAL_HEX" | tr '[:lower:]' '[:upper:]')"

before_status="$(awk -F'\t' -v s="$SERIAL_HEX" '$4==s{st=$1} END{if (st!="") print st}' "$INDEX_LOCAL" || true)"
[[ "$before_status" == V || "$before_status" == E || "$before_status" == R ]] || die "Certificate is not uniquely recorded in issuer index"

# Resolve the signing generation cryptographically before any database mutation.
TARGET="$(authority_path "$CA_DIR" "$TARGET")"
resolve_leaf_issuer "$CA_DIR" "$TARGET"
check_pair "$ISSUER_CERT" "$ISSUER_KEY"
CRL_TARGET="$ROOT_DIR/$CA_DIR/crl/ca.crl.pem"
if [[ "$ISSUER_ID" != "$(certificate_id "$ROOT_DIR/$CA_DIR/certs/ca.cert.pem")" ]]; then
  CRL_TARGET="$ROOT_DIR/$CA_DIR/generations/$ISSUER_ID/ca.crl.pem"
fi

# Validate containment without replacing the destination by its symlink target.
authority_path "$CA_DIR" "$CRL_TARGET" >/dev/null

if [[ "$DRY_RUN" == 1 ]]; then
  info "PLAN serial=$SERIAL_HEX current=$before_status revoke=$([[ "$before_status" == R ]] && echo no || echo yes) crl_refresh=$CRL_UPDATE issuer=$ISSUER_ID"
  exit 0
fi

if [[ "$before_status" == R ]]; then
  info "Serial $SERIAL_HEX already revoked; CRL refresh requested=$CRL_UPDATE"
else
  if ! ossl ca -batch -config "$CNF" -cert "$ISSUER_CERT" -keyfile "$ISSUER_KEY" -revoke "$TARGET" -crl_reason "$REASON"; then
    die "Revocation backend failed for $SERIAL_HEX; inspect index (revocation may have committed); no automatic retry"
  fi
  after_status="$(awk -F '\t' -v s="$SERIAL_HEX" '$4==s{print $1}' "$INDEX_LOCAL")"
  [[ "$after_status" == R ]] || die "Unexpected database state after revocation: $SERIAL_HEX"
  index_set_filename_for_revoked "$INDEX_LOCAL" "$SERIAL_HEX" || die "Revocation committed; index normalization failed"
fi
if [[ "$CRL_UPDATE" == 1 ]]; then
  publish_crl "$CA_DIR" "$ISSUER_CERT" "$ISSUER_KEY" "$CRL_TARGET" -crldays "$CRL_DAYS" \
    || die "Revocation is committed for $SERIAL_HEX; CRL refresh failed and previous CRL was preserved"
  info "CRL updated: $CRL_TARGET"
fi
info "Revoked: $TARGET (serial $SERIAL_HEX)"
