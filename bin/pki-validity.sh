# Issuer preflight and a fixed issuance interval within the whole chain (MIT).
# The supported root -> intermediate -> leaf hierarchy requires one CA below
# the root. Inspect the signed certificate, never the requested/configured value.
root_allows_intermediate() {
  "$OPENSSL" x509 -in "$1" -noout -text | LC_ALL=C awk '
    /^[ \t]*X509v3 Basic Constraints:/ {
      getline
      if ($0 ~ /CA:TRUE/) ca=1
      if ($0 ~ /pathlen:0([, \t]|$)/) zero=1
    }
    END {exit !(ca && !zero)}
  '
}

issuance_validity() {
  local cert root="$ROOT_DIR/root/certs/ca.cert.pem" stamp expiry label limit=253402300799 limit_label='' limit_cert='' now max_days
  root_allows_intermediate "$root" || die "Root certificate does not permit the root -> intermediate -> leaf hierarchy (requires CA:TRUE and pathlen >= 1 or no limit): $root; changing ROOT_PATHLEN does not update an existing certificate"
  validate_integer DAYS "$DAYS"
  now="$(date -u +%s)"
  for cert in "$@"; do
    "$OPENSSL" verify -auth_level 2 -check_ss_sig -no-CApath -CAfile "$root" "$cert" >/dev/null || die "Issuer chain is not currently valid: $cert"
    "$OPENSSL" x509 -in "$cert" -noout -text | LC_ALL=C awk '
      /^[ \t]*X509v3 Basic Constraints:/ {getline; if($0~/CA:TRUE/) ca=1}
      /^[ \t]*X509v3 Key Usage:/ {getline; if($0~/Certificate Sign/) signing=1}
      END {exit !(ca && signing)}
    ' || die "Issuer lacks CA/signing constraints: $cert"
    stamp="$(LC_ALL=C "$OPENSSL" x509 -in "$cert" -noout -enddate | LC_ALL=C awk -f "$ROOT_DIR/bin/pki-time.awk")" || die "Cannot read issuer expiry: $cert"
    IFS=$'\t' read -r expiry label <<< "$stamp"
    if (( expiry < limit )); then limit="$expiry"; limit_label="$label"; limit_cert="$cert"; fi
  done
  max_days=$(((limit-now)/86400))
  (( max_days >= 0 )) || max_days=0
  (( now + DAYS*86400 <= limit )) || die "DAYS=$DAYS exceeds chain validity; maximum DAYS=$max_days, limiting notAfter=$limit_label ($limit_cert)"
  ISSUE_NOT_BEFORE="$(PKI_TIME_MODE=encode PKI_TIME_VALUE="$now" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-time.awk")"
  ISSUE_NOT_AFTER="$(PKI_TIME_MODE=encode PKI_TIME_VALUE="$((now+DAYS*86400))" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-time.awk")"
}
