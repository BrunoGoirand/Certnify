#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=bin/pki-env.sh
source "${SCRIPT_DIR}/pki-env.sh"

# CN requis (sinon gen-leaf le vérifiera plus loin au moment du DN)
: "${CN:?Common Name (CN) required}"

smime_mode="$(printf '%s' "${SMIME_MODE:-combined}" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
case "$smime_mode" in
  combined|legacy|"")
    default_profile="smime"
    ;;
  sign)
    default_profile="smime_sign"
    ;;
  encrypt)
    default_profile="smime_encrypt"
    ;;
  *)
    echo "[ERR] Invalid SMIME_MODE: '${SMIME_MODE}' (expected: combined, sign, or encrypt)" >&2
    exit 1
    ;;
esac

# Une seule chose à dire: ACTION=email – gen-leaf fait tout le reste.
# PROFILE reste accepté pour compat, mais gen-leaf consomme EXT_SECTION.
env ACTION="email" CN="${CN}" \
  SAN="${SAN:-}" DAYS="${DAYS:-730}" \
  PROFILE="${PROFILE:-$default_profile}" EXT_SECTION="${EXT_SECTION:-${PROFILE:-$default_profile}}" \
  "${SCRIPT_DIR}/gen-leaf.sh"
