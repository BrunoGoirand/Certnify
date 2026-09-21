#!/usr/bin/env bash
# Advisory final CRL: local generation and remote publication are separate commits.
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"
: "${CRL_DAYS:=90}"; : "${CRL_HOURS:=}"; : "${OUT_DIR:=crl}"
: "${FINAL_MODE:=1}"; : "${ALLOW_REMAINING_LEAFS:=0}"; : "${DRY_RUN:=0}"
for flag in "$FINAL_MODE" "$ALLOW_REMAINING_LEAFS" "$DRY_RUN"; do
  [[ "$flag" == 0 || "$flag" == 1 ]] || die "Final CRL flags must be 0 or 1"
done
pki_plan_or_begin
if [[ -z "${INT_DIR:-}" ]]; then INT_DIR="intm-${KIND:?INT_DIR or KIND required}-ca"; fi
INT_DIR="$(resolve_authority "$INT_DIR")"
check_config "$INT_DIR"
INT_CRT="$INT_DIR/certs/ca.cert.pem"; INT_KEY="$INT_DIR/private/ca.key.pem"
check_pair "$INT_CRT" "$INT_KEY"
output_dir="$(authority_path "$INT_DIR" "$OUT_DIR")"
remaining="$(pki_records remaining "$INT_DIR/index.txt")"
info "Unrevoked, unexpired indexed certificates: $remaining (final publication is advisory; issuance and CRL renewal stay enabled)"
if [[ -z "${FINAL_CRL:-}" && "$FINAL_MODE" == 1 && "$ALLOW_REMAINING_LEAFS" != 1 && "$remaining" -gt 0 ]]; then
  die "FINAL_MODE=1: $remaining unexpired certificates remain; use ALLOW_REMAINING_LEAFS=1 only after review"
fi
if [[ -n "${FINAL_CRL:-}" ]]; then
  CRL_PEM="$(authority_path "$INT_DIR" "$FINAL_CRL")"
  [[ "$(dirname "$CRL_PEM")" == "$output_dir" && "$(basename "$CRL_PEM")" == ca-*.crl.pem && ! -L "$CRL_PEM" ]] || die "FINAL_CRL must select a versioned PEM in OUT_DIR"
  validate_crl "$CRL_PEM" "$INT_CRT" || die "Cannot resume an invalid/stale final CRL"
  resume_state="$(authority_path "$INT_DIR" "$CRL_PEM.resume-state")"
  [[ -f "$resume_state" && ! -L "$CRL_PEM.resume-state" ]] || die "Missing safe CRL resume state; generate a fresh final CRL"
  [[ "$(cat "$resume_state")" == "$(crl_resume_state "$INT_DIR" "$CRL_PEM")" ]] \
    || die "CRL resume state changed (revocations, CRL counter or artifact); generate a fresh final CRL"
else
  duration="${CRL_HOURS:-$CRL_DAYS}"
  [[ "$duration" =~ ^[0-9]+$ && "$duration" =~ [1-9] ]] || die "CRL duration must be a positive integer"
  CRL_PEM="$output_dir/ca-$(date -u +%Y%m%d%H%M%SZ)-$$.crl.pem"
  [[ ! -e "$CRL_PEM" && ! -L "$CRL_PEM" ]] || die "Versioned output exists: $CRL_PEM"
fi
CRL_DER="${CRL_PEM%.pem}"; LATEST_PEM="$output_dir/ca.crl.pem"; LATEST_DER="$output_dir/ca.crl"
for output in "$CRL_PEM" "$CRL_DER" "$CRL_PEM.sha256" "$CRL_DER.sha256" "$CRL_PEM.resume-state" "$CRL_PEM.publication" "$LATEST_PEM" "$LATEST_DER"; do
  authority_path "$INT_DIR" "$output" >/dev/null
  [[ ! -d "$output" ]] || die "Output is a directory: $output"
done
if [[ "$DRY_RUN" == 1 ]]; then
  info "PLAN final_crl=$CRL_PEM resume=${FINAL_CRL:+yes} remote=${PUBLISH_CMD:+configured}; no mutation"
  exit 0
fi
mkdir -p "$output_dir"
local_committed=0
publication_failure() {
  local rc="$?"
  if [[ "$local_committed" == 1 ]]; then
    warn "Local CRL committed: $CRL_PEM; artifact/publication failure. Resume with INT_DIR=$INT_DIR FINAL_CRL=$CRL_PEM (and the same OUT_DIR/PUBLISH_CMD). No CRL or revocation rollback."
  else
    warn "CRL generation failed; inspect crlnumber (it may have advanced). Previous latest artifacts preserved."
  fi
  exit "$rc"
}
trap publication_failure ERR
if [[ -z "${FINAL_CRL:-}" ]]; then
  gen_args=(-crldays "$CRL_DAYS")
  [[ -z "$CRL_HOURS" ]] || gen_args=(-crlhours "$CRL_HOURS")
  publish_crl "$INT_DIR" "$INT_CRT" "$INT_KEY" "$CRL_PEM" "${gen_args[@]}"
fi
local_committed=1
info "Local CRL committed: $CRL_PEM"
staging="$(mktemp -d "$output_dir/.final.XXXXXX")"
trap 'rc=$?; rm -rf "${staging:-}"; pki_exit "$rc"' EXIT
if [[ -z "${FINAL_CRL:-}" ]]; then
  crl_resume_state "$INT_DIR" "$CRL_PEM" > "$staging/resume-state"
  staged_install "$staging/resume-state" "$CRL_PEM.resume-state"
fi
"$OPENSSL" crl -in "$CRL_PEM" -outform DER -out "$staging/crl.der"
# Both sidecars hash exactly the DER bytes. Preserve the intended legacy encodings:
# PEM sidecar = uppercase hex; DER sidecar = base64; one LF, no labels/spaces.
"$OPENSSL" dgst -sha256 -binary "$staging/crl.der" > "$staging/digest"
od -An -v -tx1 "$staging/digest" | tr -d ' \n' | tr 'a-f' 'A-F' > "$staging/hex"
printf '\n' >> "$staging/hex"
"$OPENSSL" base64 -A -in "$staging/digest" > "$staging/base64"
printf '\n' >> "$staging/base64"
staged_install "$staging/crl.der" "$CRL_DER"
staged_install "$staging/hex" "$CRL_PEM.sha256"
staged_install "$staging/base64" "$CRL_DER.sha256"
staged_link "$(basename "$CRL_PEM")" "$LATEST_PEM"
staged_link "$(basename "$CRL_DER")" "$LATEST_DER"
report="$CRL_PEM.publication"
printf 'attempt=%s\nlocal=complete\n' "$(date -u +%FT%TZ)" >> "$report"
if [[ -n "${PUBLISH_CMD:-}" ]]; then
  failed=0
  cd "$output_dir"
  for output in "$CRL_PEM" "$CRL_DER" "$CRL_PEM.sha256" "$CRL_DER.sha256" "$LATEST_PEM" "$LATEST_DER"; do
    file="$(basename "$output")"
    # Only generated basenames enter this trusted operator-supplied shell command.
    command="${PUBLISH_CMD//%FILE%/$file}"
    if bash -c "$command"; then
      printf 'artifact=%s status=published\n' "$file" | tee -a "$report"
    else
      printf 'artifact=%s status=failed\n' "$file" | tee -a "$report" >&2
      failed=$((failed+1))
    fi
  done
  if [[ "$failed" != 0 ]]; then
    warn "Local CRL committed; $failed remote artifacts failed. Resume with INT_DIR=$INT_DIR FINAL_CRL=$CRL_PEM and the same OUT_DIR/PUBLISH_CMD. Receipt: $report"
    exit 1
  fi
  info "All six CRL artifacts published successfully"
else
  printf 'remote=not-requested\n' >> "$report"
  info "Final CRL prepared locally; remote publication not requested"
fi
