#!/usr/bin/env bash
# Certnify — controlled directory rollover (MIT).
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"
pki_begin
: "${KIND:?KIND required}"
: "${INT_CN:?INT_CN required}"
: "${DAYS:=3650}"; : "${KEY_ALG:=EC}"; : "${KEY_CURVE:=secp384r1}"
normalize_key_request
check_key_generation_policy "$KEY_ALG" "${KEY_SIZE:-4096}" "$KEY_CURVE"
check_config root
check_next_serial root
assert_private_key_policy root/private/ca.key.pem
check_pair root/certs/ca.cert.pem root/private/ca.key.pem
issuance_validity root/certs/ca.cert.pem
BASE_DIR="$(resolve_authority "intm-${KIND}-ca")"
# The active name must be a real directory, never move an alias instead of its target.
[[ "$BASE_DIR" == "intm-${KIND}-ca" && ! -L "$BASE_DIR" ]] || die "Rollover requires a canonical active directory"
CN="$(validate_component_utf8 CN "$INT_CN" "${DN_MAXLEN:-128}")"
if [[ -e "$BASE_DIR" ]]; then
  check_config "$BASE_DIR"
  [[ "$(authority_issuance_kind "$BASE_DIR")" == "$KIND" ]] \
    || die "Rollover cannot change issuance category: $BASE_DIR"
  archive_generation "$BASE_DIR"
  backfill_bindings "$BASE_DIR"
  tag="$(date +%Y%m%d%H%M%S)"; LEGACY_DIR="${BASE_DIR}-legacy-$tag"; n=0
  while [[ -e "$LEGACY_DIR" || -L "$LEGACY_DIR" ]]; do n=$((n+1)); LEGACY_DIR="${BASE_DIR}-legacy-$tag-$n"; done
  recovery_start "intm-rollover"
  recovery_note "$BASE_DIR" "$LEGACY_DIR"
  recovery_phase directory-move-outcome-uncertain
  mv "$BASE_DIR" "$LEGACY_DIR"
  rebind_config "$LEGACY_DIR" "$ROOT_DIR/$BASE_DIR"
  normalize_ca_artifacts "$LEGACY_DIR"
  info "Preserved generation: $LEGACY_DIR"
fi
# Run the normal generator in this shell, retaining the transaction lock.
INT_DIR="$BASE_DIR"
source "$ROOT_DIR/bin/gen-intm.sh"
