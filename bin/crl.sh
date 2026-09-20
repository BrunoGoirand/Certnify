#!/usr/bin/env bash
# Certnify — locked CRL operations (MIT).
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"
pki_begin
operation="${1:-generate}"
if [[ "$operation" == clean ]]; then rm -rf -- root intm-* out; exit 0; fi
generate_crl() {
  local base="$1" tmp cert key output
  local args=()
  check_config "$base"
  pki_records validate "$base/index.txt" >/dev/null
  cert="$base/certs/ca.cert.pem"; key="$base/private/ca.key.pem"; output="$base/crl/ca.crl.pem"
  if [[ -n "${ISSUER_ID:-}" ]]; then
    [[ "$ISSUER_ID" =~ ^[0-9a-f]{64}$ ]] || die "Invalid ISSUER_ID"
    cert="$(authority_path "$base" "generations/$ISSUER_ID/ca.cert.pem")"
    key="$(authority_path "$base" "generations/$ISSUER_ID/ca.key.pem")"
    output="$(authority_path "$base" "generations/$ISSUER_ID/ca.crl.pem")"
    [[ "$(certificate_id "$cert")" == "$ISSUER_ID" ]] || die "Generation fingerprint mismatch"
  fi
  if [[ "$operation" == root ]]; then
    publish_crl "$base" "$cert" "$key" "$output" || return 1
  else
    publish_crl "$base" "$cert" "$key" "$output" -crldays "${CRL_DAYS:-7}" || return 1
  fi
  info "CRL generated: $output"
}
if [[ "$operation" == root ]]; then generate_crl root; exit; fi
if [[ "$operation" == all ]]; then
  shopt -s nullglob
  for base in intm-*; do [[ ! -f "$base/openssl.cnf" ]] || generate_crl "$(resolve_authority "$base")"; done
  exit 0
fi
raw="${CRL_INT_DIR:-${INT_DIR:-}}"
[[ -n "$raw" ]] || raw="intm-${KIND:?INT_DIR or KIND required}-ca"
base="$(resolve_authority "$raw")"
check_config "$base"
case "$operation" in
  generate) generate_crl "$base" ;;
  show) "$OPENSSL" crl -in "$base/crl/ca.crl.pem" -noout -text | sed -n '1,120p' ;;
  verify-intermediate) "$OPENSSL" verify -CAfile root/certs/ca.cert.pem -crl_check -CRLfile root/crl/ca.crl.pem "$base/certs/ca.cert.pem" ;;
  serial)
    serial="$(openssl_serial "$base/certs/ca.cert.pem")"
    echo "Intermediate: $base"
    echo "Serial (hex): $serial"
    echo "Serial (:fmt): $(printf '%s' "$serial" | sed 's/../&:/g;s/:$//')"
    ;;
  root-revoked)
    serial="$(openssl_serial "$base/certs/ca.cert.pem")"
    colon="$(printf '%s' "$serial" | sed 's/../&:/g;s/:$//')"
    "$OPENSSL" crl -in root/crl/ca.crl.pem -noout -text |
      sed -n '/Revoked Certificates:/,/Signature Algorithm/p' |
      grep -E --color=always -n "Serial Number:[[:space:]]*($serial|$colon)|^|$" || true
    ;;
  *) die "Unknown CRL operation: $operation" ;;
esac
