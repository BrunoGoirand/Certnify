#!/usr/bin/env bash
# Certnify — controlled directory rollback (MIT).
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"
pki_begin
check_config root
if [[ -z "${LEGACY_DIR:-}" ]]; then
  : "${KIND:?KIND required}"
  shopt -s nullglob
  candidates=("intm-${KIND}-ca-legacy-"*)
  shopt -u nullglob
  (( ${#candidates[@]} )) || die "No legacy authority for $KIND"
  LEGACY_DIR="$(printf '%s\n' "${candidates[@]}" | sort -r | head -n1)"
  [[ -n "$LEGACY_DIR" ]] || die "No legacy authority for $KIND"
fi
LEGACY_DIR="$(resolve_authority "$LEGACY_DIR")"
if [[ -z "${KIND:-}" ]]; then KIND="$(basename "$LEGACY_DIR" | sed -n 's/^intm-\(.*\)-ca-legacy-.*/\1/p')"; fi
: "${KIND:?Cannot infer KIND}"
ACTIVE_DIR="$(resolve_authority "intm-${KIND}-ca")"
[[ "$ACTIVE_DIR" == "intm-${KIND}-ca" && "$LEGACY_DIR" != "$ACTIVE_DIR" && ! -L "$ACTIVE_DIR" ]] || die "Invalid rollback directory roles"
check_authority_paths "$ACTIVE_DIR"
check_config "$LEGACY_DIR"
[[ "$(authority_issuance_kind "$LEGACY_DIR")" == "$KIND" ]] \
  || die "Rollback cannot change issuance category: $LEGACY_DIR -> $ACTIVE_DIR"
if [[ -e "$ACTIVE_DIR" ]]; then
  [[ "$(authority_issuance_kind "$ACTIVE_DIR")" == "$KIND" ]] \
    || die "Rollback target has an inconsistent issuance category: $ACTIVE_DIR"
fi
check_pair "$LEGACY_DIR/certs/ca.cert.pem" "$LEGACY_DIR/private/ca.key.pem"
"$OPENSSL" verify -no_check_time -CAfile root/certs/ca.cert.pem "$LEGACY_DIR/certs/ca.cert.pem" >/dev/null
archive_generation "$LEGACY_DIR"
backfill_bindings "$LEGACY_DIR"
if [[ -e "$ACTIVE_DIR" ]]; then
  check_config "$ACTIVE_DIR"
  check_pair "$ACTIVE_DIR/certs/ca.cert.pem" "$ACTIVE_DIR/private/ca.key.pem"
  tag="$(date +%Y%m%d%H%M%S)"; backup="${ACTIVE_DIR}-pre-rollback-$tag"; n=0
  while [[ -e "$backup" || -L "$backup" ]]; do n=$((n+1)); backup="${ACTIVE_DIR}-pre-rollback-$tag-$n"; done
  check_authority_paths "$backup"
  recovery_start "intm-rollback-to-legacy"
  recovery_note "$ACTIVE_DIR" "$backup"
  recovery_phase directory-move-outcome-uncertain
  mv "$ACTIVE_DIR" "$backup"
  rebind_config "$backup" "$ROOT_DIR/$ACTIVE_DIR"
  normalize_ca_artifacts "$backup"
fi
recovery_start "intm-rollback-to-legacy"
recovery_note "$LEGACY_DIR" "$ACTIVE_DIR"
recovery_phase directory-move-outcome-uncertain
mv "$LEGACY_DIR" "$ACTIVE_DIR"
rebind_config "$ACTIVE_DIR" "$ROOT_DIR/$LEGACY_DIR"
normalize_ca_artifacts "$ACTIVE_DIR"
info "Restored $ACTIVE_DIR (revocation and disabled state retained)"
recovery_complete
