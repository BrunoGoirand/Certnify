#!/usr/bin/env bash
# Certnify — explicit-profile issuance from a generic authority (MIT).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
: "${CN:?Common Name (CN) required}"
: "${EXT_SECTION:=${PROFILE:-}}"
: "${EXT_SECTION:?Specify PROFILE or EXT_SECTION for generic issuance}"
exec env ACTION=generic KIND="${KIND:-generic}" EXT_SECTION="$EXT_SECTION" \
  "$SCRIPT_DIR/gen-leaf.sh"
