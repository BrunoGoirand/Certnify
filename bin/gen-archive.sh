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

# Une seule chose à dire: ACTION=doc – gen-leaf fait tout le reste.
# PROFILE reste accepté pour compat, mais gen-leaf consomme EXT_SECTION.
env ACTION="doc" CN="${CN}" \
  SAN="${SAN:-}" DAYS="${DAYS:-3650}" \
  PROFILE="${PROFILE:-archive}" EXT_SECTION="${EXT_SECTION:-${PROFILE:-archive}}" \
  "${SCRIPT_DIR}/gen-leaf.sh"
