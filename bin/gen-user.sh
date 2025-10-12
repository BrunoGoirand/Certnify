#!/usr/bin/env bash
#
# Certnify — PKI Toolkit © 2025 Bruno Goirand
# Licensed under MIT (SPDX-License-Identifier: MIT)
# Part of the Certnify PKI Toolkit — https://github.com/brunogoirand/certnify
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "${SCRIPT_DIR}/pki-env.sh"

# CN requis (sinon gen-leaf le vérifiera plus loin au moment du DN)
: "${CN:?Common Name (CN) required}"

# Une seule chose à dire: ACTION=server – gen-leaf fait tout le reste.
env ACTION="user" CN="${CN}" \
  SAN="${SAN:-DNS:${CN}}" DAYS="${DAYS:-730}" PROFILE="${PROFILE:-server_cert}" \
  "${SCRIPT_DIR}/gen-leaf.sh"