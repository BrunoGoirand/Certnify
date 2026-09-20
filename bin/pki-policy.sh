# Effective cryptographic policy and safe artifact identities (MIT).
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
    /^[ \t]*\[/ {s=$0; gsub(/[ \t\[\]]/,"",s); seen[s]++; next}
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
