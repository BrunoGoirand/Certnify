# Shared scalar validation. Called before locks, layouts or backend writes (MIT).
validate_integer() {
  local name="$1" value="$2" allow_zero="${3:-0}"
  [[ "$value" =~ ^[0-9]+$ && ${#value} -le 9 ]] || die "$name must be a decimal integer of at most 9 digits"
  [[ "$allow_zero" == 1 || "$value" =~ [1-9] ]] || die "$name must be positive"
}

validate_public_inputs() {
  local name value
  for name in DAYS KEY_SIZE DN_MAXLEN CRL_DAYS CRL_HOURS; do
    value="${!name-}"
    if [[ -n "$value" ]]; then
      validate_integer "$name" "$value"
      printf -v "$name" '%s' "$((10#$value))"
    fi
  done
  for name in LOCK_TIMEOUT REISSUE_IF_EXPIRES_BEFORE ROOT_PATHLEN; do
    value="${!name-}"
    if [[ -n "$value" ]]; then
      validate_integer "$name" "$value" 1
      printf -v "$name" '%s' "$((10#$value))"
    fi
  done
  for name in QUIET_OPENSSL DEBUG DRY_RUN VERIFY_CRL CRL_UPDATE ALLOW_DUPLICATE_CN ALLOW_SIGN_WITH_REVOKED_INT AUTO_UPDATEDB REFRESH_CRL_BEFORE_ISSUE FORCE_REISSUE FORCE_REUSE_KEY ROTATE_KEY REKEY_ON_ALG_CHANGE REKEY_ON_REVOKE INTM_REVOKED REQUIRE_STRICT_KIND ALLOW_KIND_FROM_DIR INCLUDE_REVOKED INCLUDE_EXPIRED FINAL_MODE ALLOW_REMAINING_LEAFS MAKE_ALIAS; do
    value="${!name-}"
    case "$value" in ''|0|1) ;; *) die "$name must be 0 or 1" ;; esac
  done
  case "${FORCE_NEW_KEY:-}" in ''|0|1|rotate) ;; *) die "FORCE_NEW_KEY must be 0, 1 or rotate" ;; esac
  for name in CLEAN_APPLY CRL_HISTORY AUTO_RECOVER RELOCATE_APPLY; do
    value="${!name-}"
    case "$value" in ''|0|1) ;; *) die "$name must be 0 or 1" ;; esac
  done
  case "${VERIFY_MODE:-}" in ''|normal|tolerate_revoked|info|strict) ;; *) die "Unknown VERIFY_MODE: $VERIFY_MODE" ;; esac
}
