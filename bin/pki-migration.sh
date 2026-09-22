# Policy-preserving leaf migration using public source artifacts (MIT).
# Never source metadata/configuration as shell code.

migration_extensions() {
  # Compare raw extension values and criticality, independently of display text.
  # SKI and AKI must follow the new key and issuer, not the old certificate.
  "$OPENSSL" asn1parse -in "$1" | LC_ALL=C awk '
    /d=2 .*cons: *cont \[ *3 *\]/ {extensions=1; next}
    extensions && /d=[01] / {extensions=0}
    extensions && /d=5 .*prim: *OBJECT/ {
      oid=$0; sub(/^.*OBJECT *:/,"",oid); critical=0
      if(seen[oid]++) bad=1
      next
    }
    extensions && /d=5 .*prim: *BOOLEAN/ {critical=1; next}
    extensions && /d=5 .*prim: *OCTET STRING/ {
      value=$0; sub(/^.*\[HEX DUMP\]:/,"",value)
      if(value !~ /^[0-9A-Fa-f]+$/ || oid=="") bad=1
      if(oid!="X509v3 Subject Key Identifier" && oid!="X509v3 Authority Key Identifier")
        print oid "|" critical "|" value
      count++; oid=""
    }
    END {if(bad || !count || oid!="") exit 1}
  ' | LC_ALL=C sort
}

migration_subject() (
  set -e
  subject_der="$(mktemp)" || exit 1
  trap 'rm -f "$subject_der"' EXIT
  offset="$("$OPENSSL" asn1parse -in "$1" | awk '
    /d=2 .*cons: *SEQUENCE/ {if(++n==4) {sub(/:.*/,""); gsub(/ /,""); print}}
  ')" || exit 1
  [[ "$offset" =~ ^[0-9]+$ ]] || die "Cannot locate source subject: $1"
  "$OPENSSL" asn1parse -in "$1" -strparse "$offset" -out "$subject_der" -noout || exit 1
  "$OPENSSL" dgst -sha256 < "$subject_der"
)

migration_compare() {
  local before after
  before="$(migration_subject "$1")" || die "Cannot decode original subject"
  after="$(migration_subject "$2")" || die "Cannot decode candidate subject"
  [[ "$before" == "$after" ]] || die "Migration would change the subject: $1"
  before="$(migration_extensions "$1")" || die "Cannot decode original extensions"
  after="$(migration_extensions "$2")" || die "Cannot decode candidate extensions"
  [[ "$before" == "$after" ]] || die "Migration would change SANs/profile extensions: $1 (destination profile $EXT_SECTION)"
}

migration_load() {
  local base="$1" serial="$2" cn="$3" expiry="$4" record locator policy hash public_text algorithm row subject cert_expiry public_algorithm
  base="$(resolve_authority "$base")"
  record="$(PKI_RECORD_SERIAL="$serial" CN="$cn" PKI_REQUIRE_CN=1 pki_records serial-target "$base/index.txt")"
  [[ -n "$record" ]] || die "Source serial $serial not found in $base/index.txt"
  IFS=$'\x1f' read -r serial locator <<< "$record"
  row="$(INCLUDE_REVOKED=1 INCLUDE_EXPIRED=1 pki_records list "$base/index.txt" | PKI_SERIAL="$serial" awk -F '\t' '$1==ENVIRON["PKI_SERIAL"] {print $2}')"
  [[ "$row" == "$expiry" ]] || die "Source inventory expiry mismatch for serial $serial"
  MIGRATION_CERT="$(authority_path "$base" "newcerts/$serial.pem")"
  [[ -s "$MIGRATION_CERT" ]] || die "Missing original certificate: $MIGRATION_CERT"
  [[ "$(openssl_serial "$MIGRATION_CERT")" == "$serial" ]] || die "Source certificate serial mismatch: $MIGRATION_CERT"
  subject="$("$OPENSSL" x509 -in "$MIGRATION_CERT" -noout -subject -nameopt compat)"
  subject="${subject#subject=}"
  printf 'V\t%s\t\t%s\tunknown\t%s\n' "$(printf '%s' "$expiry" | tr -d '\055:T')" "$serial" "$subject" | \
    CN="$cn" PKI_RECORD_SERIAL="$serial" PKI_REQUIRE_CN=1 pki_records serial-target - >/dev/null
  cert_expiry="$(LC_ALL=C "$OPENSSL" x509 -in "$MIGRATION_CERT" -noout -enddate | LC_ALL=C awk -f "$ROOT_DIR/bin/pki-time.awk" | cut -f2)"
  [[ "$cert_expiry" == "$expiry" ]] || die "Certificate/inventory expiry mismatch: $MIGRATION_CERT"
  resolve_leaf_issuer "$base" "$MIGRATION_CERT"
  [[ -z "${CERTNIFY_SOURCE_ID:-}" || "$(certificate_id "$MIGRATION_CERT")" == "$CERTNIFY_SOURCE_ID" ]] || die "Source certificate changed after batch planning"
  policy="$(authority_path "$base" "issuers/$serial.policy")"
  [[ -s "$policy" ]] || die "Missing original profile record: $policy; use an explicit reviewed migration or REISSUE_MODE=cn-only"
  record="$(awk -F= '
    NF!=2 || seen[$1]++ {bad=1}
    $1=="SCHEMA" {if($2!="1") bad=1}
    $1=="POLICY_SHA256" {hash=$2}
    $1=="EXT_SECTION" {section=$2}
    $1=="ALG" {alg=$2}
    END {if(bad || NR!=4 || !seen["SCHEMA"] || !hash || !section || !alg) exit 1; print hash " " section " " alg}
  ' "$policy")" || die "Malformed original profile record: $policy"
  read -r hash EXT_SECTION algorithm <<< "$record"
  [[ "$hash" =~ ^[0-9a-f]{64}$ && "$EXT_SECTION" =~ ^[A-Za-z0-9_]+$ ]] || die "Invalid source profile record: $policy"
  policy="$(authority_path "$base" "policies/$hash.cnf")"
  [[ -s "$policy" && "$("$OPENSSL" dgst -sha256 "$policy" | awk '{print $NF}')" == "$hash" ]] || die "Missing/changed source policy archive: $policy"
  # Public key parameters suffice; old private keys are never required/copied.
  public_text="$("$OPENSSL" x509 -in "$MIGRATION_CERT" -pubkey -noout | "$OPENSSL" pkey -pubin -text -noout)"
  KEY_SIZE=4096; KEY_CURVE=prime256v1; KEY_EDDSA=Ed25519
  public_algorithm="$("$OPENSSL" x509 -in "$MIGRATION_CERT" -noout -text | awk '/Public Key Algorithm:/ {print $NF}')"
  case "$algorithm:$public_algorithm" in
    RSA:rsaEncryption|EC:id-ecPublicKey|ED25519:ED25519|ED448:ED448) ;;
    *) die "Unsupported or mismatched source public key algorithm: $public_algorithm" ;;
  esac
  case "$algorithm" in
    RSA)
      [[ "$public_text" == *Modulus:* ]] || die "Source key/profile algorithm mismatch"
      KEY_SIZE="$(awk -F'[() ]' '/Public-Key:/ {for(i=1;i<=NF;i++) if($i~/^[0-9]+$/) {print $i; exit}}' <<< "$public_text")"
      [[ "$public_text" == *'Exponent: 65537 '* ]] || die "Unsupported source RSA exponent" ;;
    EC)
      KEY_CURVE="$(awk -F': *' '/ASN1 OID:/ {print $2}' <<< "$public_text")" ;;
    ED25519|ED448)
      [[ "$public_text" == *"$algorithm"* ]] || die "Source key/profile algorithm mismatch"
      [[ "$algorithm" != ED448 ]] || KEY_EDDSA=Ed448 ;;
    *) die "Unsupported original key algorithm: $algorithm" ;;
  esac
  KEY_ALG="$algorithm"
  check_key_generation_policy "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE"
  EXT_SECTION_USER_SET=1
  select_leaf_policy "$KEY_ALG"
  FORCE_NEW_KEY=rotate
  SAN=''; SAN_DNS=''; SAN_IP=''; SAN_EMAIL=''; SAN_URI=''
}

migration_request() {
  "$OPENSSL" x509 -x509toreq -in "$MIGRATION_CERT" -signkey "$1" \
    -copy_extensions copy -ext subjectAltName -out "$2"
}

migration_preflight() (
  # Only temporary files and a disposable key: no CA signing or state updates.
  set -e
  stage="$(mktemp -d)" || exit 1
  trap 'rm -rf "$stage"' EXIT
  copying="$(awk '
    /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s)}
    s=="CA_default" && /^[ \t]*copy_extensions[ \t]*=/ {sub(/^[^=]*=[ \t]*/,""); sub(/[ \t]+$/,""); print}
  ' "$INT_CNF")"
  [[ "$copying" == copy ]] || die "Preserving migration requires copy_extensions = copy"
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$stage/key.pem" >/dev/null 2>&1 || die "Cannot generate migration preflight key"
  migration_request "$stage/key.pem" "$stage/request.pem" >/dev/null 2>&1 || die "Cannot preserve certificate request; migration requires OpenSSL 3.x"
  "$OPENSSL" x509 -req -in "$stage/request.pem" -signkey "$stage/key.pem" \
    -copy_extensions copy -extfile "$INT_CNF" -extensions "$EXT_SECTION" -days 1 \
    -out "$stage/candidate.pem" >/dev/null 2>&1 || die "Cannot compile destination migration profile: $EXT_SECTION"
  migration_compare "$MIGRATION_CERT" "$stage/candidate.pem"
)
