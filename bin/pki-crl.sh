# Shared CRL validation/publication and revocation policy (MIT).
normalize_revocation_reason() {
  REASON="${REASON:-cessationOfOperation}"
  if [[ "$REASON" == privilegeWithdrawn ]]; then
    REASON="${MAP_PRIV_WITHDRAWN_TO:-cessationOfOperation}"
    warn "Mapping privilegeWithdrawn to $REASON"
  fi
  case "$REASON" in
    removeFromCRL) die "removeFromCRL is unsupported: release from certificateHold is not implemented" ;;
    unspecified|keyCompromise|CACompromise|affiliationChanged|superseded|cessationOfOperation|certificateHold|AACompromise) ;;
    *) die "Unsupported revocation reason: $REASON" ;;
  esac
  [[ "${DRY_RUN:-0}" == 0 || "${DRY_RUN:-0}" == 1 ]] || die "DRY_RUN must be 0 or 1"
  [[ "${CRL_UPDATE:-0}" == 0 || "${CRL_UPDATE:-0}" == 1 ]] || die "CRL_UPDATE must be 0 or 1"
}

# LC_ALL=C OpenSSL dates are parsed without platform-specific date flags.
validate_crl() {
  local file="$1" cert="$2" issuer subject signature dates
  [[ -s "$file" ]] || { warn "Missing/empty required CRL: $file"; return 1; }
  awk '/^-----BEGIN X509 CRL-----$/{b++} /^-----END X509 CRL-----$/{e++} END{exit(b!=1 || e!=1)}' "$file" || { warn "Expected one PEM CRL: $file"; return 1; }
  issuer="$("$OPENSSL" crl -in "$file" -noout -issuer -nameopt RFC2253)" || return 1
  subject="$("$OPENSSL" x509 -in "$cert" -noout -subject -nameopt RFC2253)" || return 1
  [[ "${issuer#issuer=}" == "${subject#subject=}" ]] || { warn "Wrong CRL issuer: $file"; return 1; }
  signature="$(LC_ALL=C "$OPENSSL" crl -in "$file" -noout -verify -CAfile "$cert" 2>&1)" || { warn "Invalid CRL signature: $file"; return 1; }
  [[ "$signature" == 'verify OK' ]] || { warn "CRL signature verification did not succeed: $file"; return 1; }
  dates="$(LC_ALL=C "$OPENSSL" crl -in "$file" -noout -lastupdate -nextupdate)" || return 1
  if ! printf '%s\n' "$dates" | LC_ALL=C awk -v now="$(date -u +%Y%m%d%H%M%S)" '
    function stamp(v, a,n,m,i,t,d,y,max) {
      sub(/^[^=]*=/,"",v); n=split(v,a,/[ :]+/)
      split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",months," ")
      for(i=1;i<=12;i++) if(a[1]==months[i]) m=i
      if(n!=7 || !m || a[7]!="GMT" || a[2]!~/^[0-9]+$/ || a[3]!~/^[0-9]+$/ || a[4]!~/^[0-9]+$/ || a[5]!~/^[0-9]+$/ || a[6]!~/^[0-9][0-9][0-9][0-9]$/) {bad=1; return ""}
      d=a[2]+0; y=a[6]+0; max=31
      if(m==4 || m==6 || m==9 || m==11) max=30
      if(m==2) max=28+(y%4==0 && (y%100!=0 || y%400==0))
      if(d<1 || d>max || a[3]+0>23 || a[4]+0>59 || a[5]+0>59) bad=1
      return sprintf("%04d%02d%02d%02d%02d%02d",y,m,d,a[3],a[4],a[5])
    }
    /^lastUpdate=/ {last=stamp($0); l++}
    /^nextUpdate=/ {nextdate=stamp($0); n++}
    END {exit(bad || l!=1 || n!=1 || ("x" last)>("x" now) || ("x" nextdate)<=("x" now) || ("x" last)>=("x" nextdate))}
  '; then warn "Expired, future, or invalid CRL validity: $file"; return 1; fi
}

# Subshell owns only temporary output, never the caller's transaction lock.
# OpenSSL may consume a CRL number even on failure; do not roll it back.
publish_crl() (
  set -e
  base="$1"; cert="$2"; key="$3"; output="$4"; shift 4
  [[ "$base" == /* ]] || base="$ROOT_DIR/$base"
  [[ "$cert" == /* ]] || cert="$ROOT_DIR/$cert"
  [[ "$key" == /* ]] || key="$ROOT_DIR/$key"
  [[ "$output" == /* ]] || output="$ROOT_DIR/$output"
  check_config "$base" || exit 1
  authority_path "$base" "$output" >/dev/null || exit 1
  [[ ! -d "$output" ]] || die "CRL destination is a directory: $output"
  check_pair "$cert" "$key" || exit 1
  tmp="$(mktemp "$(dirname "$output")/.crl.XXXXXX")" || exit 1
  trap 'rm -f "$tmp"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if ! "$OPENSSL" ca -batch -config "$base/openssl.cnf" -cert "$cert" -keyfile "$key" -gencrl "$@" -out "$tmp"; then
    warn "CRL generation failed; previous output preserved: $output (counter may have advanced)"; exit 1
  fi
  if ! validate_crl "$tmp" "$cert"; then
    warn "Generated CRL rejected; previous output preserved: $output"; exit 1
  fi
  chmod 444 "$tmp" || exit 1
  mv -f "$tmp" "$output" || exit 1
)
