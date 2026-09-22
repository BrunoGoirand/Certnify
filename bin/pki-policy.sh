# Effective cryptographic policy and safe artifact identities (MIT).

# Read authority-owned metadata as data, never as shell code. Caller KIND and
# action routing are not authoritative. Canonical names support legacy metadata.
authority_issuance_kind() {
  local base="$1" recorded="" inferred="" meta
  meta="$(authority_path "$base" ca.meta)"
  # Older layouts use meta; read it before any normalization writes occur.
  if [[ ! -f "$meta" ]]; then meta="$(authority_path "$base" meta)"; fi
  if [[ -f "$meta" ]]; then
    recorded="$(awk -F= '$1=="KIND" {if(++n>1 || NF!=2 || $2=="") exit 1; value=$2} END {print value}' "$meta")" \
      || die "Malformed issuance category in $meta"
  fi
  case "$base" in
    intm-web-ca) inferred=web ;; intm-auth-ca) inferred=auth ;;
    intm-code-ca) inferred=code ;; intm-smime-ca) inferred=smime ;;
    intm-archive-ca) inferred=archive ;; intm-generic-ca) inferred=generic ;;
  esac
  [[ -z "$recorded" || -z "$inferred" || "$recorded" == "$inferred" ]] \
    || die "Issuance category conflicts with authority directory: $meta ($recorded, expected $inferred)"
  recorded="${recorded:-$inferred}"
  case "$recorded" in web|auth|code|smime|archive|generic) ;;
    *) die "Missing/unsupported issuance category in $meta; restore or explicitly review the authority metadata" ;;
  esac
  printf '%s\n' "$recorded"
}

# Decode signed extension values, rejecting duplicate extensions (including OID
# aliases). Shared with preserving migration; SKI/AKI depend on key and issuer.
certificate_policy_extensions() {
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

assert_certificate_issuance_kind() {
  local cert="$1" base="$2" kind extensions eku expected bc
  kind="$(authority_issuance_kind "$base")" || return 1
  extensions="$(certificate_policy_extensions "$cert")" || die "Cannot decode unique extensions: $cert"
  bc="$(printf '%s\n' "$extensions" | awk -F'|' '$1=="X509v3 Basic Constraints" {print $3}')"
  [[ "$bc" == 3000 ]] || die "Issuance requires CA:false: $base / $EXT_SECTION"
  eku="$(printf '%s\n' "$extensions" | awk -F'|' '$1=="X509v3 Extended Key Usage" {print $3}')"
  # DER: a SEQUENCE containing exactly one id-kp-* OID. Missing, additional,
  # unknown and anyExtendedKeyUsage values fail for restricted categories.
  case "$kind" in
    web) expected=300A06082B06010505070301 ;;
    auth) expected=300A06082B06010505070302 ;;
    code) expected=300A06082B06010505070303 ;;
    smime) expected=300A06082B06010505070304 ;;
    archive)
      case "$EXT_SECTION:$eku" in
        archive:|archive_seal:) return 0 ;;
        *:300A06082B06010505070308) return 0 ;;
      esac
      die "Issuance category archive requires archive/archive_seal without EKU or timeStamping only: $base / $EXT_SECTION"
      ;;
    generic) return 0 ;;
  esac
  [[ "$eku" == "$expected" ]] || die "Issuance category $kind rejects profile $EXT_SECTION in $base (incompatible or missing EKU)"
}

issuance_category_preflight() (
  # Compile the actual installed profile without touching any authority state.
  set -e
  local stage kind
  kind="$(authority_issuance_kind "$INT_DIR")"
  if [[ -n "${ACTION:-}" && "$kind" != generic ]]; then
    [[ "$(expected_kind_for_action "$ACTION")" == "$kind" ]] \
      || die "Issuance category $kind rejects action $ACTION in $INT_DIR"
  fi
  stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$stage/key.pem" >/dev/null 2>&1
  "$OPENSSL" req -new -x509 -key "$stage/key.pem" -subj /CN=issuance-preflight \
    -config "$INT_CNF" -extensions "$EXT_SECTION" -days 1 -out "$stage/candidate.pem" >/dev/null 2>&1 \
    || die "Cannot compile issuance profile: $INT_CNF / $EXT_SECTION"
  assert_certificate_issuance_kind "$stage/candidate.pem" "$INT_DIR"
)

check_key_generation_policy() {
  local alg bits="$2" curve="$3"
  alg="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
  case "$alg" in
    RSA)
      validate_integer KEY_SIZE "$bits"
      (( 10#$bits >= 2048 )) || die "RSA keys must have at least 2048 bits (requested/effective: $bits)"
      ;;
    EC)
      case "$curve" in prime256v1|secp384r1|secp521r1) ;; *) die "Unsupported EC curve: $curve" ;; esac
      ;;
    ED25519|ED448) ;;
    EDDSA)
      case "${KEY_EDDSA:-Ed25519}" in Ed25519|ed25519|Ed448|ed448) ;; *) die "Unsupported EdDSA variant" ;; esac
      ;;
    *) die "Unsupported KEY_ALG: $alg" ;;
  esac
}

assert_private_key_policy() {
  inspect_private_key_metadata "$1"
  check_key_generation_policy "$DETECTED_KEY_ALG" "$DETECTED_KEY_SIZE" "$DETECTED_KEY_CURVE"
}

normalize_key_request() {
  KEY_ALG="$(printf '%s' "${KEY_ALG:-RSA}" | tr '[:lower:]' '[:upper:]')"
  case "$KEY_ALG" in
    ED25519) KEY_EDDSA=Ed25519 ;;
    ED448) KEY_EDDSA=Ed448 ;;
    EDDSA)
      case "$(printf '%s' "${KEY_EDDSA:-Ed25519}" | tr '[:lower:]' '[:upper:]')" in
        ED25519) KEY_ALG=ED25519; KEY_EDDSA=Ed25519 ;;
        ED448) KEY_ALG=ED448; KEY_EDDSA=Ed448 ;;
        *) die "Unsupported EdDSA variant" ;;
      esac ;;
    RSA|EC) ;;
    *) die "Unsupported KEY_ALG: $KEY_ALG" ;;
  esac
}

leaf_stem() {
  local cn="$1" reserved=0
  case "$(printf '%s' "$cn" | tr '[:upper:]' '[:lower:]')" in ca|ca.*|ca-*|chain|chain.*|cn-*|srl-*|rot-*|*.fullchain) reserved=1 ;; esac
  if [[ "$reserved" == 0 && "$cn" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._@+-]*$ ]]; then
    printf '%s\n' "$cn"
  else
    printf 'cn-%s\n' "$(printf '%s' "$cn" | "$OPENSSL" dgst -sha256 | awk '{print $NF}')"
  fi
}

cnf_quote() {
  local value="$1"
  value="${value//\\/\\\\}"; value="${value//\"/\\\"}"; value="${value//\$/\\\$}"
  printf '"%s"' "$value"
}

# Validate complete native configurations; custom sections are retained.
validate_policy_config() {
  local cnf="$1" base="$2" required
  required='ca CA_default req req_distinguished_name'
  if [[ "$base" == "$ROOT_DIR/root" ]]; then
    required="$required v3_ca v3_intermediate_ca"
  else
    required="$required v3_intermediate_ca server_cert server_ec client_cert client_ec code_sign smime smime_sign smime_encrypt archive archive_seal timestamping"
  fi
  PKI_REQUIRED="$required" LC_ALL=C awk '
    /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s); seen[s]++; if(s~/^certnify_(request_san|request_names|san_check)$/) bad=1; next}
    /^[ \t]*[#;]/ {next}
    /=/ {key=$0; sub(/=.*/,"",key); gsub(/[ \t]/,"",key); val=$0; sub(/^[^=]*=[ \t]*/,"",val); if((s SUBSEP key) in values && values[s SUBSEP key]!=val) bad=1; values[s SUBSEP key]=val; count[s]++}
    END {
      n=split(ENVIRON["PKI_REQUIRED"],a," "); for(i=1;i<=n;i++) if(!count[a[i]]) bad=1
      if(!values["CA_default" SUBSEP "default_md"] || !values["CA_default" SUBSEP "default_days"] || !values["CA_default" SUBSEP "default_crl_days"]) bad=1
      if(!count[values["req" SUBSEP "x509_extensions"]]) bad=1
      if(values["ca" SUBSEP "default_ca"]!="CA_default") bad=1
      p=values["CA_default" SUBSEP "policy"]; if(!count[p]) bad=1
      if(values["req" SUBSEP "distinguished_name"]!="req_distinguished_name") bad=1
      if(!values["req_distinguished_name" SUBSEP "CN"]) bad=1
      for(s in seen) if(s~/^(v3_ca|v3_intermediate_ca|server_cert|server_ec|client_cert|client_ec|code_sign|smime|smime_sign|smime_encrypt|archive|archive_seal|timestamping)$/) {
        if(!values[s SUBSEP "basicConstraints"] || !values[s SUBSEP "keyUsage"]) bad=1
        ku=values[s SUBSEP "keyUsage"]; gsub(/[ \t]/,"",ku); z=split(ku,usages,",")
        for(q=1;q<=z;q++) if(usages[q]!~/^(critical|digitalSignature|nonRepudiation|contentCommitment|keyEncipherment|dataEncipherment|keyAgreement|keyCertSign|cRLSign|encipherOnly|decipherOnly)$/) bad=1
        bc=values[s SUBSEP "basicConstraints"]; gsub(/[ \t]/,"",bc)
        if(bc!~/^(critical,)?CA:(true|false)(,pathlen:[0-9]+)?$/) bad=1
      }
      exit bad
    }
  ' "$cnf" || die "Incomplete/duplicate policy configuration: $cnf; review and repair explicitly"
}

# Build in the destination directory; publish only a complete validated config.
create_root_openssl_cnf_if_missing() (
  cnf="$1"; base="$2"
  if [[ -f "$cnf" ]]; then check_config "$base" "$cnf"; exit; fi
  [[ ! -s "$base/certs/ca.cert.pem" && ! -s "$base/private/ca.key.pem" ]] || die "Missing authority policy: $cnf; restore and review explicitly"
  stage="$(mktemp "$(dirname "$cnf")/.policy.XXXXXX")"
  trap 'rm -f "$stage" "$stage.bak"' EXIT
  _build_root_cnf "$stage" "$2" "$3" "${4:-}"
  check_config "$base" "$stage"
  digest="$("$OPENSSL" dgst -sha256 "$stage" | awk '{print $NF}')"
  printf '\n# CERTNIFY_POLICY_SCHEMA=1\n# CERTNIFY_INITIAL_POLICY_SHA256=%s\n' "$digest" >> "$stage"
  mv "$stage" "$cnf"
)
create_intermediate_openssl_cnf_if_missing() (
  cnf="$1"; base="$2"
  if [[ -f "$cnf" ]]; then check_config "$base" "$cnf"; exit; fi
  [[ ! -s "$base/certs/ca.cert.pem" && ! -s "$base/private/ca.key.pem" ]] || die "Missing authority policy: $cnf; restore and review explicitly"
  stage="$(mktemp "$(dirname "$cnf")/.policy.XXXXXX")"
  trap 'rm -f "$stage"' EXIT
  _build_intermediate_cnf "$stage" "$2" "$3"
  check_config "$base" "$stage"
  digest="$("$OPENSSL" dgst -sha256 "$stage" | awk '{print $NF}')"
  printf '\n# CERTNIFY_POLICY_SCHEMA=1\n# CERTNIFY_INITIAL_POLICY_SHA256=%s\n' "$digest" >> "$stage"
  mv "$stage" "$cnf"
)

# Defaults follow the effective key. Explicit sections are validated by keyUsage.
select_leaf_policy() {
  local algorithm="$1" usage
  if [[ "$EXT_SECTION_USER_SET" == 0 ]]; then
    case "${ACTION:-server}:$algorithm" in
      server:RSA) EXT_SECTION=server_cert ;;
      server:*) EXT_SECTION=server_ec ;;
      user:RSA) EXT_SECTION=client_cert ;;
      user:*) EXT_SECTION=client_ec ;;
    esac
  fi
  [[ "$EXT_SECTION" =~ ^[A-Za-z0-9_]+$ ]] || die "Unsafe extension section: $EXT_SECTION"
  usage="$(PKI_SECTION="$EXT_SECTION" awk '
    /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s)}
    s==ENVIRON["PKI_SECTION"] && /^[ \t]*keyUsage[ \t]*=/ {sub(/^[^=]*=/,""); print}
  ' "$INT_CNF")"
  [[ -n "$usage" && "$usage" != *'$'* && "$usage" != *'@'* ]] || die "Missing or indirect keyUsage in $EXT_SECTION"
  local constraints
  constraints="$(PKI_SECTION="$EXT_SECTION" awk '
    /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s)}
    s==ENVIRON["PKI_SECTION"] && /^[ \t]*basicConstraints[ \t]*=/ {sub(/^[^=]*=/,""); print}
  ' "$INT_CNF")"
  [[ "$constraints" == *CA:false* && "$constraints" != *CA:true* && "$usage" != *keyCertSign* && "$usage" != *cRLSign* ]] || die "Section $EXT_SECTION is not a leaf policy"
  case "$algorithm:$usage" in
    RSA:*) [[ "$usage" != *keyAgreement* ]] || die "RSA cannot perform keyAgreement" ;;
    *:*)
      [[ "$usage" != *keyEncipherment* && "$usage" != *dataEncipherment* ]] || die "Profile $EXT_SECTION requires an RSA encryption key (effective key: $algorithm)"
      if [[ "$algorithm" == ED25519 || "$algorithm" == ED448 ]]; then
        [[ "$usage" != *keyAgreement* ]] || die "EdDSA keys cannot perform keyAgreement"
      fi ;;
  esac
}

prepare_sans() {
  local t prefix value
  if [[ -n "${SAN:-}" ]]; then
    ! has_control_chars "$SAN" || die "Control character in SAN"
    [[ "$SAN" != ,* && "$SAN" != *, && "$SAN" != *,,* ]] || die "Empty SAN entry"
    IFS=',' read -r -a tokens <<< "$SAN"
    for t in "${tokens[@]}"; do
      t="$(trim_spaces "$t")"
      if [[ "$t" == *:* ]]; then prefix="${t%%:*}"; value="${t#*:}"; else prefix=DNS; value="$t"; fi
      [[ -n "$value" ]] || die "Empty SAN entry"
      case "$(printf '%s' "$prefix" | tr '[:lower:]' '[:upper:]')" in
        DNS) SAN_DNS="${SAN_DNS:+$SAN_DNS,}$value" ;;
        IP) SAN_IP="${SAN_IP:+$SAN_IP,}$value" ;;
        EMAIL) SAN_EMAIL="${SAN_EMAIL:+$SAN_EMAIL,}$value" ;;
        URI) SAN_URI="${SAN_URI:+$SAN_URI,}$value" ;;
        *) die "Unsupported SAN type: $prefix" ;;
      esac
    done
  fi
  if [[ -z "$SAN_DNS$SAN_IP$SAN_EMAIL$SAN_URI" ]]; then
    case "${ACTION:-}" in server) SAN_DNS="$CN" ;; user|email) [[ "$CN" != *@* ]] || SAN_EMAIL="$CN" ;; esac
  fi
  SAN_DNS="$(PKI_SAN_TYPE=DNS PKI_SAN_VALUES="$SAN_DNS" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-san.awk")"
  SAN_IP="$(PKI_SAN_TYPE=IP PKI_SAN_VALUES="$SAN_IP" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-san.awk")"
  SAN_EMAIL="$(PKI_SAN_TYPE=EMAIL PKI_SAN_VALUES="$SAN_EMAIL" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-san.awk")"
  SAN_URI="$(PKI_SAN_TYPE=URI PKI_SAN_VALUES="$SAN_URI" LC_ALL=C awk -f "$ROOT_DIR/bin/pki-san.awk")"
}

claim_leaf_name() {
  local mapping serial match
  mapping="$(authority_path "$INT_DIR" "names/$ARTIFACT_STEM.cn")"
  if [[ -e "$mapping" ]]; then
    [[ "$(cat "$mapping")" == "$CN" ]] || die "Artifact name collision for $CN: $mapping"
    return 0
  fi
  if [[ -f "$CRT_PATH" ]]; then
    serial="$(openssl_serial "$CRT_PATH")"
    match="$(PKI_RECORD_SERIAL="$serial" PKI_REQUIRE_CN=1 pki_records serial-target "$INT_DIR/index.txt")" || return 1
    [[ -n "$match" ]] || die "Unbound existing certificate at $CRT_PATH; use explicit import/FILE rather than overwrite"
  fi
  [[ "${1:-}" != check ]] || return 0
  mkdir -p "$(dirname "$mapping")"
  printf '%s\n' "$CN" > "$mapping"
  chmod 444 "$mapping"
}

# Use the backend's decoded SANs so equivalent IP spellings compare identically.
san_names() {
  local mode="$1" file="$2"
  if [[ "$mode" == certificate ]]; then
    LC_ALL=C "$OPENSSL" x509 -in "$file" -noout -ext subjectAltName
  else
    LC_ALL=C "$OPENSSL" req -in "$file" -noout -text
  fi | LC_ALL=C awk -f "$ROOT_DIR/bin/pki-san-output.awk" | LC_ALL=C sort -u
}

# Compile request/profile SANs before any CA mutation, using a disposable key.
# These are CSRs only: no CA key is used and no certificate is issued.
expected_leaf_sans() (
  set -e
  stage="$(mktemp -d)" || exit 1
  trap 'rm -rf "$stage"' EXIT
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$stage/key.pem" >/dev/null 2>&1 || exit 1
  request_args=(-new -utf8 -config "$REQ_CNF_DN" -key "$stage/key.pem" -out "$stage/request.pem")
  [[ -z "$SAN_DNS$SAN_IP$SAN_EMAIL$SAN_URI" ]] || request_args+=(-reqexts certnify_request_san)
  "$OPENSSL" req "${request_args[@]}" >/dev/null || exit 1
  requested="$(san_names request "$stage/request.pem")" || exit 1
  definition="$(PKI_SECTION="$EXT_SECTION" awk '
    /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s)}
    s==ENVIRON["PKI_SECTION"] && /^[ \t]*subjectAltName[ \t]*=/ {value=$0}
    END {print value}
  ' "$INT_CNF")"
  if [[ -n "$definition" ]]; then
    cat "$REQ_CNF_DN" > "$stage/profile.cnf" || exit 1
    printf '\n[ certnify_san_check ]\n%s\n' "$definition" >> "$stage/profile.cnf" || exit 1
    "$OPENSSL" req -new -utf8 -config "$stage/profile.cnf" -key "$stage/key.pem" -reqexts certnify_san_check -out "$stage/profile.pem" >/dev/null || exit 1
    configured="$(san_names request "$stage/profile.pem")" || exit 1
    [[ -z "$requested" || "$requested" == "$configured" ]] || die "Profile $EXT_SECTION SAN conflicts with requested SANs; no certificate issued"
    printf '%s' "$configured"
  else
    if [[ -n "$requested" ]]; then
      copying="$(awk '
        /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s)}
        s=="CA_default" && /^[ \t]*copy_extensions[ \t]*=/ {v=$0; sub(/^[^=]*=[ \t]*/,"",v); sub(/[ \t]+$/,"",v)}
        END {print v}
      ' "$INT_CNF")"
      [[ "$copying" == copy ]] || die "Requested SANs require copy_extensions = copy"
    fi
    printf '%s' "$requested"
  fi
)
