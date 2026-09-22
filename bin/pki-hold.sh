# Release only certificateHold records; publish a complete CRL, not a delta (MIT).
release_certificate_hold() {
  local base="$1" cert="$2" issuer="$3" key="$4" output="$5" disabled="${6:-}"
  local serial row status revocation journal="$ROOT_DIR/.recovery/pending" marker
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  serial="$(openssl_serial "$cert")"
  pki_records validate "$base/index.txt" >/dev/null
  row="$(awk -F '\t' -v s="$serial" 'toupper($4)==toupper(s){print $1 " " $3}' "$base/index.txt")"
  [[ "$row" == 'R '* ]] || die "Serial $serial is not suspended; only certificateHold can be released"
  revocation="${row#R }"
  [[ "${revocation#*,}" == certificateHold ]] || die "Serial $serial is not on certificateHold; permanent revocation cannot be undone"
  [[ "${CRL_UPDATE:-1}" == 1 ]] || die "Release from hold requires CRL_UPDATE=1"
  authority_path "$base" "newcerts/$serial.pem" >/dev/null
  [[ "$(certificate_id "$base/newcerts/$serial.pem")" == "$(certificate_id "$cert")" ]] || die "Suspended certificate differs from retained issuance history"
  check_pair "$issuer" "$key"
  "$OPENSSL" verify -no_check_time -partial_chain -trusted "$issuer" "$cert" >/dev/null
  status=V
  if ! "$OPENSSL" x509 -in "$cert" -noout -checkend 0 >/dev/null; then status=E; fi
  if [[ "${DRY_RUN:-0}" == 1 ]]; then
    info "PLAN release certificateHold serial=$serial next_status=$status; refresh complete CRL: $output"
    return 0
  fi
  recovery_start "release-hold authority=${base#"$ROOT_DIR/"} serial=$serial"
  recovery_plan_begin
  install -m 400 "$base/index.txt" "$journal/held-index"
  awk -F '\t' -v s="$serial" -v status="$status" 'BEGIN {OFS="\t"}
    toupper($4)==toupper(s) {$1=status; $3=""; $5="newcerts/" $4 ".pem"} {print}
  ' "$base/index.txt" > "$journal/released-index"
  pki_records validate "$journal/released-index" >/dev/null
  # Only the database is staged. OpenSSL consumes the real CRL counter; failures
  # never roll it back. This generated configuration is not an imported policy.
  PKI_HOLD_INDEX="$journal/released-index" awk '
    /^[ \t]*\[/ {section=$0; gsub(/[ \t\[\]]/,"",section)}
    section=="CA_default" && /^[ \t]*database[ \t]*=/ {print "database = " ENVIRON["PKI_HOLD_INDEX"]; next}
    {print}
  ' "$base/openssl.cnf" > "$journal/release.cnf"
  "$OPENSSL" ca -batch -config "$journal/release.cnf" -cert "$issuer" -keyfile "$key" \
    -gencrl -crldays "${CRL_DAYS:-7}" -out "$journal/released.crl.pem"
  validate_crl "$journal/released.crl.pem" "$issuer"
  LC_ALL=C "$OPENSSL" crl -in "$journal/released.crl.pem" -noout -nextupdate | sed 's/^nextUpdate=/notAfter=/' | recovery_plan_deadline
  if [[ "$status" == V ]]; then
    LC_ALL=C "$OPENSSL" x509 -in "$cert" -noout -enddate | recovery_plan_deadline
  fi
  for marker in "$base/serial" "$base/crlnumber" "$base/openssl.cnf" "$issuer" "$key" "$base/newcerts/$serial.pem"; do
    recovery_plan_guard "$marker"
  done
  recovery_plan_add "$journal/released-index" "$base/index.txt" 600
  recovery_plan_add "$journal/released.crl.pem" "$output"
  if [[ -e "${output%.pem}" || -L "${output%.pem}" ]]; then
    "$OPENSSL" crl -in "$journal/released.crl.pem" -outform DER -out "$journal/released.crl.der"
    recovery_plan_add "$journal/released.crl.der" "${output%.pem}"
  fi
  if [[ -n "$disabled" && -f "$disabled" ]]; then
    marker="certificateHold:$(certificate_id "$cert")"
    if [[ ! -L "$disabled" && "$(cat "$disabled")" == "$marker" ]]; then
      recovery_plan_add "" "$disabled" 600 D
    else warn "Retaining independent issuance disable marker: $disabled"; fi
  fi
  recovery_plan_seal
  recovery_resume
  info "Released certificateHold: serial=$serial status=$status; distribute the new CRL to relying parties"
}
