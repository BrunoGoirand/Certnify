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
#   make revoke FILE="intm-web-ca/certs/app.example.com.cert.pem" REASON="superseded"
#   make revoke INT_DIR="intm-web-ca" SERIAL="1002" REASON="superseded"
#
# Env:
#   INT_DIR/KIND, CN/FILE/SERIAL (priority FILE > SERIAL > CN), REASON, MAP_PRIV_WITHDRAWN_TO,
#   CRL_UPDATE(=1), CRL_DAYS(=7), DRY_RUN(=0), QUIET_OPENSSL(=1), DEBUG(=0)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "${SCRIPT_DIR}/pki-env.sh"

# --- Defaults ---
: "${INT_DIR:=}"; : "${KIND:=}"; : "${CN:=}"; : "${FILE:=}"; : "${SERIAL:=}"
: "${REASON:=cessationOfOperation}"; : "${CRL_UPDATE:=1}"; : "${CRL_DAYS:=7}"
: "${DRY_RUN:=0}"; : "${QUIET_OPENSSL:=1}"; : "${DEBUG:=0}"
OPENSSL="${OPENSSL:-openssl}"

# --- Debug helpers ---
if [[ "$DEBUG" == "1" ]]; then
  set -x; set -o errtrace
  trap 'rc=$?; echo "[DBG ] ERR at ${BASH_SOURCE[0]}:${LINENO} → ${BASH_COMMAND} (rc=${rc})" >&2' ERR
fi
dbg(){ [[ "$DEBUG" == "1" ]] && echo "[DBG ] $*" >&2 || true; }

# --- Helpers (alignés avec verify.sh) ---
normalize_int_dir() {
  local v="$1"
  if   [[ "$v" == "." ]]; then printf "."
  elif [[ "$v" == */* ]]; then printf "%s" "$v"
  elif [[ "$v" =~ ^intm-.*-ca$ ]]; then printf "%s" "$v"
  else printf "intm-%s-ca" "$v"; fi
}
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
[[ -n "$CA_DIR" ]] || die "Spécifie INT_DIR=... ou KIND=... pour cibler l'intermédiaire."
info "Using intermediate: ${CA_DIR}"
assert_intermediate_ready
cd "$ROOT_DIR/$CA_DIR" || die "Cannot cd to '$ROOT_DIR/$CA_DIR'"

CNF="openssl.cnf"; INDEX_LOCAL="index.txt"
[[ -f "$CNF" ]] || die "Missing $CA_DIR/$CNF"
[[ -f "$INDEX_LOCAL" ]] || die "Missing $CA_DIR/$INDEX_LOCAL"

# --- Resolve target (FILE > SERIAL > CN), sans variantes ---
TARGET=""; resolved_serial=""
dbg "Inputs: FILE='${FILE}', SERIAL='${SERIAL}', CN='${CN}'"

# 1) FILE
if [[ -n "$FILE" ]]; then
  [[ -f "$FILE" ]] || die "Specified FILE does not exist: $FILE"
  TARGET="$FILE"
fi

# 2) SERIAL
if [[ -z "$TARGET" && -n "$SERIAL" ]]; then
  serial_uc="$(printf '%s' "$SERIAL" | tr '[:lower:]' '[:upper:]')"
  if [[ -f "newcerts/${serial_uc}.pem" ]]; then
    TARGET="newcerts/${serial_uc}.pem"; resolved_serial="$serial_uc"
  else
    candidate="$(awk -F'\t' -v s="$serial_uc" '$4==s{print $5;exit}' "$INDEX_LOCAL" || true)"
    if [[ -n "$candidate" && "$candidate" != "unknown" && -f "$candidate" ]]; then
      TARGET="$candidate"; resolved_serial="$serial_uc"
    fi
  fi
fi

# 3) CN (canonical form only)
if [[ -z "$TARGET" && -n "$CN" ]]; then
  TARGET="certs/${CN}.cert.pem"
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

before_status="$(awk -F'\t' -v s="$SERIAL_HEX" '$4==s{print $1;exit}' "$INDEX_LOCAL" || true)"
if [[ "$before_status" == "R" ]]; then
  info "Serial $SERIAL_HEX is already revoked. Nothing to do."
  exit 0
fi

# --- Sanity: issuer match ---
INT_CA_CERT="$ROOT_DIR/$CA_DIR/certs/ca.cert.pem"
[[ -f "$INT_CA_CERT" ]] || die "Missing intermediate CA cert: $INT_CA_CERT"
target_issuer="$("$OPENSSL" x509 -in "$TARGET" -noout -issuer 2>/dev/null | sed 's/^issuer= *//I')"
int_subject="$("$OPENSSL" x509 -in "$INT_CA_CERT" -noout -subject 2>/dev/null | sed 's/^subject= *//I')"
norm(){ sed 's/, */,/g' | tr -d '\r'; }
if [[ -n "$target_issuer" && -n "$int_subject" ]]; then
  if [[ "$(printf '%s' "$target_issuer" | norm)" != "$(printf '%s' "$int_subject" | norm)" ]]; then
    die "Issuer mismatch: target '$target_issuer' vs intermediate '$int_subject' (wrong INT_DIR/KIND?)"
  fi
fi

# --- Reason normalization ---
map_privilege_withdrawn_to="${MAP_PRIV_WITHDRAWN_TO:-cessationOfOperation}"
case "$REASON" in
  unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|removeFromCRL|AACompromise) ;;
  privilegeWithdrawn)
    warn "Reason 'privilegeWithdrawn' not supported by OpenSSL; mapping to '$map_privilege_withdrawn_to'."
    REASON="$map_privilege_withdrawn_to"
    ;;
  *) die "Unsupported revocation reason: '$REASON'";;
esac

# --- Guard for removeFromCRL ---
if [[ "$REASON" == "removeFromCRL" ]]; then
  if [[ "$before_status" != "R" ]]; then
    warn "removeFromCRL demandé mais le certificat n'est pas marqué R (revoked). OpenSSL va probablement échouer."
  else
    current_reason="$("$OPENSSL" x509 -in "$TARGET" -noout -text 2>/dev/null | awk '/CRL Reason Code/ {getline; gsub(/^ +| +$/,""); print; exit}' || true)"
    if [[ -n "$current_reason" && "$current_reason" != "certificateHold" ]]; then
      warn "removeFromCRL ne s'applique qu'aux certificats en 'certificateHold' (actuel: '$current_reason')."
    fi
  fi
fi

# --- Revoke (idempotent) ---
if ! ossl ca -batch -config "$CNF" -revoke "$TARGET" -crl_reason "$REASON"; then
  if "$OPENSSL" ca -batch -config "$CNF" -revoke "$TARGET" -crl_reason "$REASON" 2>&1 | grep -qi 'already revoked'; then
    info "Serial $SERIAL_HEX was already revoked. Nothing to do."
    exit 0
  fi
  die "OpenSSL revocation failed for serial $SERIAL_HEX"
fi

# --- Update index filename=unknown ---
after_status="$(awk -F'\t' -v s="$SERIAL_HEX" '$4==s{print $1;exit}' "$INDEX_LOCAL" || true)"
[[ "$after_status" == "R" ]] || die "Revocation did not flip status to 'R' for serial $SERIAL_HEX"

awk -F'\t' -v s="$SERIAL_HEX" 'BEGIN{FS=OFS="\t"} { if ($1=="R" && $4==s && $5!="unknown") $5="unknown"; print }' \
  "$INDEX_LOCAL" > "$INDEX_LOCAL.tmp" && mv "$INDEX_LOCAL.tmp" "$INDEX_LOCAL"
info "DB updated for serial $SERIAL_HEX"

# --- Refresh CRL ---
if [[ "$CRL_UPDATE" == "1" ]]; then
  mkdir -p crl
  TMP="$(mktemp -t crl.XXXXXX || mktemp)"
  ossl ca -batch -config "$CNF" -gencrl -crldays "$CRL_DAYS" -out "$TMP"
  install -m 444 "$TMP" crl/ca.crl.pem; rm -f "$TMP"
  info "CRL updated: $CA_DIR/crl/ca.crl.pem"
fi

info "Revoked: $TARGET (serial $SERIAL_HEX, reason: $REASON)"
