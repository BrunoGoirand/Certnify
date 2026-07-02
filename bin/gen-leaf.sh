#!/usr/bin/env bash
# ===============================================================
#  Certnify — PKI Toolkit
#  Copyright (c) 2025 Bruno Goirand
#
#  This file is part of the Certnify PKI Toolkit.
#  Certnify simplifies the creation and management of private
#  certification authorities (root, intermediates, and leafs),
#  following modern PKI best practices.
#
#  License: SPDX-License-Identifier: MIT
#  Permission is hereby granted, free of charge, to any person
#  obtaining a copy of this software and associated documentation
#  files (the “Software”), to deal in the Software without restriction,
#  including without limitation the rights to use, copy, modify,
#  merge, publish, distribute, sublicense, and/or sell copies of
#  the Software, subject to the inclusion of this notice in all
#  copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#  NONINFRINGEMENT.
#
#  Project: https://github.com/brunogoirand/certnify
# ===============================================================

# ---------------------------------------------------------------
#  Options and Environment Variables
# ---------------------------------------------------------------
#
#  ── Identity / DN Fields ─────────────────────────────────────
#  CN="<common name>"            # e.g., app.example.com or user@example.com
#  O="<organization>"            # Optional, organization name
#  OU="<org unit>"               # Optional, department/division
#  C="<country>"                 # Optional, 2-letter ISO code (e.g., FR)
#  DN_MAXLEN=128                 # Max DN component length (default: 128)
#
#  ── Certificate Profile / Purpose ─────────────────────────────
#  ACTION="server|user|dev|email|doc"   # Preferred mode selector
#  TYPE="server|user|dev|email|doc"     # Legacy alias (maps to ACTION)
#  EXT_SECTION="<openssl.cnf section>"  # Overrides default section
#
#  Defaults by ACTION:
#    server → EXT_SECTION=server_cert, DAYS=397
#    user   → EXT_SECTION=client_cert, DAYS=825
#    dev    → EXT_SECTION=code_sign,   DAYS=730
#    email  → EXT_SECTION=smime,       DAYS=730
#    doc    → EXT_SECTION=archive,     DAYS=3650
#
#  ── Intermediate Selection ────────────────────────────────────
#  INT_DIR="intm-web-ca"         # Full or relative path to intermediate
#  KIND="web|auth|code|smime|archive"  # Shorthand to derive INT_DIR
#
#  ── SAN (Subject Alternative Names) ───────────────────────────
#  SAN="DNS:example.com,IP:10.0.0.1,email:admin@example.com"
#      # Legacy combined syntax (auto-split into SAN_DNS/IP/EMAIL/URI)
#
#  SAN_DNS="example.com,www.example.com"     # Comma-separated DNS list
#  SAN_IP="127.0.0.1,10.0.0.10"              # Comma-separated IPs
#  SAN_EMAIL="admin@example.com,security@example.com"
#  SAN_URI="https://example.com,urn:uuid:1234..."
#
#  ── Key Generation ────────────────────────────────────────────
#  KEY_ALG="RSA|EC|EDDSA"        # Algorithm (default: RSA)
#  KEY_SIZE="2048|4096"          # RSA key size (default: 4096)
#  KEY_CURVE="prime256v1|secp384r1"   # EC curve (default: prime256v1)
#  KEY_EDDSA="Ed25519|Ed448"     # For EdDSA (default: Ed25519)
#
#  FORCE_NEW_KEY=1               # Régénère une nouvelle clé privée même si private/<CN>.key.pem existe (sauvegarde .bak auto)
#  FORCE_NEW_KEY=rotate          # N’écrase rien : nouvelle clé/CSR/cert sous <CN>-<tag>, puis renommés en <CN>-<SERIAL> après émission
#
#  ── Validity / Lifetime ───────────────────────────────────────
#  DAYS=825                      # Leaf validity (default depends on ACTION)
#
#  ── Behaviour / Safety Switches ───────────────────────────────
#  ALLOW_DUPLICATE_CN=1          # Skip duplicate CN check
#  ALLOW_SIGN_WITH_REVOKED_INT=1 # Force issuance even if intermediate revoked
#  AUTO_UPDATEDB=1               # Auto-update OpenSSL DB (default: 1)
#  REFRESH_CRL_BEFORE_ISSUE=1    # Rebuild CRL before issuing (default: 0)
#  CRL_DAYS=7                    # CRL validity in days (default: 7)
#
#  ── Output Control ────────────────────────────────────────────
#  QUIET_OPENSSL=1               # Suppress OpenSSL chatter (default: 1)
#
#  ── File Layout (resolved automatically) ──────────────────────
#  KEY_PATH="intm-*/private/<CN>.key.pem"
#  CSR_PATH="intm-*/csr/<CN>.csr.pem"
#  CRT_PATH="intm-*/certs/<CN>.cert.pem"
#  CHAIN_PATH="intm-*/certs/<CN>.fullchain.cert.pem"
#
#  ── Examples ──────────────────────────────────────────────────
#  make server CN="app.example.com" KIND="web"
#  make user   CN="user@example.com" KIND="auth"
#  make dev    CN="signer" KIND="code" SAN_URI="urn:signer:1234"
#  make email  CN="contact@example.com" KIND="smime"
#  make doc    CN="archive-2025" KIND="archive"
#
# ---------------------------------------------------------------
set -euo pipefail
# shellcheck source=bin/pki-env.sh
source "$(dirname "$0")/pki-env.sh"

REQ_CNF_TMP=""
REQ_CNF_DN=""
EXT_SECTION_USER_SET=0
[[ -n "${EXT_SECTION:-}" ]] && EXT_SECTION_USER_SET=1
cleanup() {
  [[ -n "$REQ_CNF_TMP" ]] && rm -f "$REQ_CNF_TMP"
  [[ -n "$REQ_CNF_DN"  ]] && rm -f "$REQ_CNF_DN"
  release_locks
}
trap cleanup EXIT

# --- Action-aware mode (server|user|dev|email|doc) ---
# Priorité à ACTION; TYPE reste supporté pour compat (TYPE=server → ACTION=server)
ACTION="${ACTION:-${TYPE:-}}"

if [[ -n "$ACTION" ]]; then
  # mapping strict et INT_DIR cohérent (via pki-env.sh)
  require_int_dir_for_action "$ACTION"

  # Défauts par action (overridables par l'env appelant)
  case "$ACTION" in
    server)
      : "${EXT_SECTION:=server_cert}"
      : "${DAYS:=397}"
      ;;
    user)
      # selon ta conf openssl.cnf: client_cert | usr_cert
      : "${EXT_SECTION:=client_cert}"
      : "${DAYS:=825}"
      # petit confort: si aucun SAN_* défini et CN ressemble à un email → SAN_EMAIL=CN
      if [[ -z "${SAN_DNS:-}${SAN_IP:-}${SAN_EMAIL:-}" && "$CN" =~ @ ]]; then
        SAN_EMAIL="${CN}"
      fi
      ;;
    dev)
      : "${EXT_SECTION:=code_sign}"
      : "${DAYS:=730}"
      ;;
    email)
      : "${EXT_SECTION:=smime}"
      : "${DAYS:=730}"
      # si rien de posé et CN est email → SAN_EMAIL=CN
      if [[ -z "${SAN_DNS:-}${SAN_IP:-}${SAN_EMAIL:-}" && "$CN" =~ @ ]]; then
        SAN_EMAIL="${CN}"
      fi
      ;;
    doc)
      : "${EXT_SECTION:=archive}"
      : "${DAYS:=3650}"
      ;;
    *)
      die "Action inconnue: '$ACTION' (attendu: server|user|dev|email|doc)"
      ;;
  esac

  # Compat "legacy SAN=" : SAN="DNS:...,IP:...,email:...,URI:..."
  # -> remplit SAN_DNS / SAN_IP / SAN_EMAIL / SAN_URI (sans écraser si déjà posés, concatène avec des virgules)
  if [[ -n "${SAN:-}" ]]; then
    # helper pour concaténer dans une CSV (var name + value)
    _append_csv() {
      # $1=varname, $2=value
      local _vn="$1" _val="$2"
      [[ -z "$_val" ]] && return 0
      # shellcheck disable=SC2154
      local _cur; _cur="$(eval "printf '%s' \"\${$_vn:-}\"")"
      if [[ -n "$_cur" ]]; then
        eval "$_vn=\"\$_cur,\$_val\""
      else
        eval "$_vn=\"\$_val\""
      fi
    }

    IFS=',' read -r -a _tokens <<< "$SAN"
    for t in "${_tokens[@]}"; do
      t="$(trim_spaces "$t")"
      [[ -z "$t" ]] && continue

      # Sépare prefixe/valeur et normalise le prefixe en MAJ
      if [[ "$t" == *:* ]]; then
        prefix="${t%%:*}"
        value="${t#*:}"
        upper="$(printf '%s' "$prefix" | tr '[:lower:]' '[:upper:]')"
        case "$upper" in
          DNS)
            _append_csv SAN_DNS "$value"
            ;;
          IP)
            _append_csv SAN_IP "$value"
            ;;
          EMAIL)
            _append_csv SAN_EMAIL "$value"
            ;;
          URI)
            _append_csv SAN_URI "$value"
            ;;
          *)
            # Si pas reconnu mais pas de ':', on peut l’assimiler à DNS plus haut; ici on ignore
            ;;
        esac
      else
        # Valeur brute sans préfixe → interpréter comme DNS si rien n’est encore posé
        if [[ -z "$SAN_DNS" ]]; then
          _append_csv SAN_DNS "$t"
        fi
      fi
    done
  fi
fi

# ---- Inputs / defaults ----
CN="${CN:-example.com}"
C="${C:-}"
O="${O:-}"
OU="${OU:-}"
DN_MAXLEN="${DN_MAXLEN:-128}"

# ---- Behaviour / Safety Switches ----
# 0 (défaut)  : comportement normal
# 1           : force une nouvelle clé (sauvegarde l’ancienne en .bak)
# rotate      : garde l’ancienne intacte et écrit la nouvelle série (key/csr/cert) sous un suffixe
FORCE_NEW_KEY="${FORCE_NEW_KEY:-0}"   # 0|1|rotate

# trim/normalize
# RSA | EC | EdDSA
KEY_ALG="$(echo "${KEY_ALG:-RSA}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:lower:]' '[:upper:]')"
# used if RSA only
KEY_SIZE="$(echo "${KEY_SIZE:-4096}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
# used if EC: prime256v1|secp384r1
KEY_CURVE="$(echo "${KEY_CURVE:-prime256v1}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
# used if EdDSA: Ed25519 | Ed448
KEY_EDDSA="$(echo "${KEY_EDDSA:-Ed25519}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

# SANs (comma-separated lists)
#   SAN_DNS="example.com,www.example.com"
#   SAN_IP="127.0.0.1,10.0.0.10"
#   SAN_EMAIL="admin@example.com,security@example.com"
#   SAN_URI="https://example.com,urn:uuid:..."
SAN_DNS="${SAN_DNS:-}"
SAN_IP="${SAN_IP:-}"
SAN_EMAIL="${SAN_EMAIL:-}"
SAN_URI="${SAN_URI:-}"

# Extension section from intermediate cnf (e.g., server_cert, client_cert)
EXT_SECTION="${EXT_SECTION:-server_cert}"

if [[ "$EXT_SECTION_USER_SET" == "0" && -n "${ACTION:-}" ]]; then
  case "$ACTION:$KEY_ALG" in
    server:EC|server:EDDSA)
      EXT_SECTION="server_ec"
      ;;
    user:EC|user:EDDSA)
      EXT_SECTION="client_ec"
      ;;
  esac
fi

# Reduce OpenSSL chatter by default (align with gen-root.sh)
QUIET_OPENSSL="${QUIET_OPENSSL:-1}"

# ---- Resolve intermediate dir ----
# Si ACTION est défini, require_int_dir_for_action a déjà résolu/validé.
# Sinon, on retombe sur la même logique partagée que le reste du toolkit.
if [[ -z "${INT_DIR:-}" && -z "${KIND:-}" ]]; then
  die "INT_DIR manquant (ou fournis ACTION/KIND pour résolution) ; ex: INT_DIR=intm-web-ca ou INT_DIR=internet"
fi

if [[ -z "${ACTION:-}" ]]; then
  if [[ -n "${INT_DIR:-}" ]]; then
    INT_DIR="$(normalize_int_dir "$INT_DIR")"
    ensure_safe_int_dir "$INT_DIR"
    if [[ -z "${KIND:-}" ]]; then
      KIND="$(kind_from_int_dir "$INT_DIR")"
    fi
  else
    INT_DIR="intm-${KIND}-ca"
    ensure_safe_int_dir "$INT_DIR"
  fi
fi

info "Using intermediate directory: ${INT_DIR}"

# ---- Validate DN ----
CN="$(validate_component_utf8 "CN" "$CN" "$DN_MAXLEN")"
O="$(validate_component_utf8  "O"  "$O"  "$DN_MAXLEN")"
OU="$(validate_component_utf8 "OU" "$OU" "$DN_MAXLEN")"
C="$(validate_country_iso "$C")"

# ---- Paths & layout ----
cd "$ROOT_DIR"
int_lock_name="$(printf '%s' "$INT_DIR" | tr '/ ' '__')"
acquire_lock "intm-${int_lock_name}"
ensure_intermediate_layout "$INT_DIR"

# Always force INT_CNF to match INT_DIR
INT_CNF="$ROOT_DIR/$INT_DIR/openssl.cnf"
[[ -f "$INT_CNF" ]] || die "Intermediate openssl.cnf not found: $INT_CNF (create the intermediate first)"

# ---- Rotate mode (chemin suffixé) ----
ROTATE_MODE=0
ROTATE_TAG=""
if [[ "${FORCE_NEW_KEY:-0}" == "rotate" ]]; then
  ROTATE_MODE=1
  ROTATE_TAG="r$(date +%Y%m%d%H%M%S 2>/dev/null || date +%s)"
fi

# Base des noms de fichiers pour cette émission
BASE_CN="${CN}"
if [[ "$ROTATE_MODE" == "1" ]]; then
  BASE_CN="${CN}-${ROTATE_TAG}"
fi

KEY_PATH="$INT_DIR/private/${BASE_CN}.key.pem"
CSR_PATH="$INT_DIR/csr/${BASE_CN}.csr.pem"
CRT_PATH="$INT_DIR/certs/${BASE_CN}.cert.pem"

# ---- Preflight: block issuance if intermediate is revoked/disabled ----
INT_CA_CERT="$INT_DIR/certs/ca.cert.pem"
INT_DISABLED_FLAG="$INT_DIR/.disabled"
[[ -f "$INT_CA_CERT" ]] || die "Missing intermediate CA cert: $INT_CA_CERT"

# 1) Simple kill-switch file (set by your revoke-all script)
if [[ -f "$INT_DISABLED_FLAG" && "${ALLOW_SIGN_WITH_REVOKED_INT:-0}" != "1" ]]; then
  die "Issuance disabled for '$INT_DIR' (found $INT_DISABLED_FLAG). Set ALLOW_SIGN_WITH_REVOKED_INT=1 to override."
fi

# 2) Check root DB for this intermediate's serial marked as revoked
INT_SERIAL_HEX="$("$OPENSSL" x509 -in "$INT_CA_CERT" -noout -serial 2>/dev/null | sed 's/^serial=//I' | tr '[:lower:]' '[:upper:]')"
ROOT_INDEX="$ROOT_DIR/root/index.txt"
if [[ -n "$INT_SERIAL_HEX" && -f "$ROOT_INDEX" ]]; then
  INT_STATUS_IN_ROOT="$(awk -v s="$INT_SERIAL_HEX" 'BEGIN{FS=OFS="\t"} $4==s{print $1; exit}' "$ROOT_INDEX" || true)"
  if [[ "$INT_STATUS_IN_ROOT" == "R" && "${ALLOW_SIGN_WITH_REVOKED_INT:-0}" != "1" ]]; then
    die "Intermediate '$INT_DIR' is revoked in root (serial=$INT_SERIAL_HEX). Refusing to issue. Set ALLOW_SIGN_WITH_REVOKED_INT=1 to override."
  fi
fi

# ---- Preflight: ensure intermediate cert matches its private key ----
INT_CA_CERT="$INT_DIR/certs/ca.cert.pem"
INT_CA_KEY="$INT_DIR/private/ca.key.pem"
[[ -f "$INT_CA_CERT" ]] || die "Missing intermediate CA cert: $INT_CA_CERT"
[[ -f "$INT_CA_KEY"  ]] || die "Missing intermediate CA key:  $INT_CA_KEY"

ca_pub_fp="$("$OPENSSL" x509 -in "$INT_CA_CERT" -noout -pubkey 2>/dev/null \
            | "$OPENSSL" pkey -pubin -outform DER 2>/dev/null \
            | "$OPENSSL" dgst -sha256 2>/dev/null | awk '{print $2}')"

key_pub_fp="$("$OPENSSL" pkey -in "$INT_CA_KEY" -pubout -outform DER 2>/dev/null \
             | "$OPENSSL" dgst -sha256 2>/dev/null | awk '{print $2}')"

if [[ -n "$ca_pub_fp" && -n "$key_pub_fp" && "$ca_pub_fp" != "$key_pub_fp" ]]; then
  warn "Intermediate CA certificate doesn't match its private key."
  warn "Fix: rotate the canonical files to a coherent pair:"
  warn "  openssl x509 -in '$INT_CA_CERT' -noout -serial"
  die  "Refusing to sign with a mismatched CA cert/key."
fi

# ---- Optional: refresh intermediate DB & CRL before duplicate check (Bash 3.2-safe) ----
# AUTO_UPDATEDB=1            → run "openssl ca -updatedb" to flip expired entries to 'E'
# REFRESH_CRL_BEFORE_ISSUE=0 → set to 1 to regenerate intermediate CRL right before issuing
AUTO_UPDATEDB="${AUTO_UPDATEDB:-1}"
REFRESH_CRL_BEFORE_ISSUE="${REFRESH_CRL_BEFORE_ISSUE:-0}"
CRL_DAYS="${CRL_DAYS:-7}"

# Keep the index up-to-date (marks expired entries as 'E')
if [[ "$AUTO_UPDATEDB" == "1" ]]; then
  if [[ "$QUIET_OPENSSL" == "1" ]]; then
    "$OPENSSL" ca -config "$INT_CNF" -updatedb >/dev/null 2>&1 || true
  else
    "$OPENSSL" ca -config "$INT_CNF" -updatedb || true
  fi
fi

# Optionally refresh the intermediate CRL (does not affect duplicate logic)
if [[ "$REFRESH_CRL_BEFORE_ISSUE" == "1" ]]; then
  mkdir -p "$INT_DIR/crl"
  TMP_CRL="$(mktemp -t crl.intm.XXXXXX || mktemp)"
  if [[ "$QUIET_OPENSSL" == "1" ]]; then
    "$OPENSSL" ca -batch -config "$INT_CNF" -gencrl -crldays "$CRL_DAYS" -out "$TMP_CRL" >/dev/null 2>&1 || true
  else
    "$OPENSSL" ca -batch -config "$INT_CNF" -gencrl -crldays "$CRL_DAYS" -out "$TMP_CRL" || true
  fi
  install -m 444 "$TMP_CRL" "$INT_DIR/crl/ca.crl.pem"
  rm -f "$TMP_CRL"
fi

# ---- Preflight: refuse issuing if an active (non-expired, non-revoked) cert already exists for this CN ----
# Set ALLOW_DUPLICATE_CN=1 to bypass.
if [[ "${ALLOW_DUPLICATE_CN:-0}" != "1" ]]; then
  INT_INDEX="$INT_DIR/index.txt"
  [[ -f "$INT_INDEX" ]] || die "Missing intermediate index: $INT_INDEX"

  # Current UTC time in OpenSSL index format (YYMMDDHHMMSSZ)
  NOW_YYMMDDHHMMSSZ="$(date -u +%y%m%d%H%M%SZ 2>/dev/null || date +%y%m%d%H%M%SZ)"

  # Use US (0x1F) as delimiter to preserve tabs/spaces in subject when piping to read
  DUPS_TMP="$(mktemp -t dupcn.XXXXXX || mktemp)"
  awk -v now="$NOW_YYMMDDHHMMSSZ" -v cn="$CN" -v US="$(printf '\x1f')" 'BEGIN{FS="\t"}
    /^[[:space:]]*$/ || $1 ~ /^#/ { next }
    {
      status=$1; expiry=$2; serial=$4; filename=$5;
      subj = (NF>=6 ? $6 : "");
      for (i=7; i<=NF; i++) subj = subj "\t" $i;

      # Active if status==V and expiry > now (string compare OK for YYMMDDHHMMSSZ)
      if (status=="V" && expiry > now) {
        # Exact CN match: /CN=<cn> followed by "/" or end of string
        if (subj ~ ("(/CN=" cn "(/|$))")) {
          printf "%s%s%s\n", serial, US, filename;
        }
      }
    }
  ' "$INT_INDEX" > "$DUPS_TMP"

  # Iterate without mapfile (Bash 3.2): while-read over the temp file
  found=0
  DUP_LIST=""
  while IFS=$'\x1F' read -r serial filename; do
    [[ -z "$serial" ]] && continue
    found=1
    # If filename is 'unknown', show fallback newcerts/<serial>.pem for clarity
    if [[ "$filename" == "unknown" || -z "$filename" ]]; then
      disp_path="${INT_DIR}/newcerts/${serial}.pem"
    else
      disp_path="${INT_DIR}/${filename}"
    fi
    # Append with a real newline
    DUP_LIST="${DUP_LIST}  - serial=${serial} file=${disp_path}"$'\n'
  done < "$DUPS_TMP"
  rm -f "$DUPS_TMP"

  if [[ "$found" -eq 1 ]]; then
    # Build the error message with real newlines (no \n literals)
    msg="Refusing to issue: active certificate(s) for CN='${CN}' already exist in ${INT_INDEX}:"$'\n'"${DUP_LIST}"$'\n'"Use revoke first (bin/revoke-leaf.sh) or set ALLOW_DUPLICATE_CN=1 to override."
    die "$msg"
  fi
fi

# ---- Private key ----
# Si FORCE_NEW_KEY=1 et une clé existe, on la sauvegarde puis on régénère.
if [[ -s "$KEY_PATH" && "${FORCE_NEW_KEY:-0}" == "1" ]]; then
  ts="$(date +%Y%m%d%H%M%S 2>/dev/null || date +%s)"
  bak="${KEY_PATH%.key.pem}.key.${ts}.bak.pem"
  info "FORCE_NEW_KEY=1 → previous key backup to: $bak"
  # Sauvegarde avec permissions strictes (600). install si possible, fallback cp.
  if install -m 0600 "$KEY_PATH" "$bak" 2>/dev/null; then
    :
  else
    cp -p "$KEY_PATH" "$bak"
    chmod 600 "$bak" 2>/dev/null || true
  fi

  # Détruire l’ancienne clé avant régénération (secure delete si dispo)
  if command -v shred >/dev/null 2>&1; then
    shred -u "$KEY_PATH" || rm -f "$KEY_PATH"
  else
    rm -f "$KEY_PATH"
  fi
fi

# En mode rotate, le KEY_PATH est déjà suffixé → on génère systématiquement une nouvelle clé si absente
if [[ ! -s "$KEY_PATH" ]]; then
  gen_private_key "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_PATH"
  chmod 600 "$KEY_PATH" 2>/dev/null || true
else
  info "Leaf private key already exists: $KEY_PATH (skip)"
fi

# ---- Build a transient req config with DN and SAN ----
REQ_CNF_TMP="$(mktemp)"
REQ_CNF_DN="$(mktemp)"

# 1) Start from intermediate CNF (must contain req/req_distinguished_name and placeholders)
cp "$INT_CNF" "$REQ_CNF_TMP"

# 2) Render DN placeholders and drop empty DN lines
render_req_cnf_with_dn "$REQ_CNF_TMP" "$REQ_CNF_DN" "$C" "$O" "$OU" "$CN"

# Normalize SAN lists to unique values (order-preserving)
SAN_DNS="$(dedup_csv "${SAN_DNS}")"
SAN_IP="$(dedup_csv "${SAN_IP}")"
SAN_EMAIL="$(dedup_csv "${SAN_EMAIL}")"
SAN_URI="$(dedup_csv "${SAN_URI}")"

# 3) Append SAN section if provided (any of SAN_* present)
if [[ -n "$SAN_DNS" || -n "$SAN_IP" || -n "$SAN_EMAIL" || -n "${SAN_URI:-}" ]]; then
  {
    echo ""
    echo "[ req_ext ]"
    echo "subjectAltName = @alt_names"
    echo ""
    echo "[ alt_names ]"
  } >> "$REQ_CNF_DN"

  idx=1

  # DNS entries
  if [[ -n "$SAN_DNS" ]]; then
    IFS=',' read -r -a _dns <<< "$SAN_DNS"
    for d in "${_dns[@]}"; do
      d="$(trim_spaces "$d")"; [[ -z "$d" ]] && continue
      printf "DNS.%d = %s\n" "$idx" "$d" >> "$REQ_CNF_DN"
      ((idx++))
    done
  fi

  # IP entries
  if [[ -n "$SAN_IP" ]]; then
    IFS=',' read -r -a _ips <<< "$SAN_IP"
    for ip in "${_ips[@]}"; do
      ip="$(trim_spaces "$ip")"; [[ -z "$ip" ]] && continue
      printf "IP.%d = %s\n" "$idx" "$ip" >> "$REQ_CNF_DN"
      ((idx++))
    done
  fi

  # Email entries
  if [[ -n "$SAN_EMAIL" ]]; then
    IFS=',' read -r -a _mails <<< "$SAN_EMAIL"
    for em in "${_mails[@]}"; do
      em="$(trim_spaces "$em")"; [[ -z "$em" ]] && continue
      printf "email.%d = %s\n" "$idx" "$em" >> "$REQ_CNF_DN"
      ((idx++))
    done
  fi

  # URI entries (nouveau)
  if [[ -n "$SAN_URI" ]]; then
    IFS=',' read -r -a _uris <<< "$SAN_URI"
    for u in "${_uris[@]}"; do
      u="$(trim_spaces "$u")"; [[ -z "$u" ]] && continue
      printf "URI.%d = %s\n" "$idx" "$u" >> "$REQ_CNF_DN"
      ((idx++))
    done
  fi
fi

# ---- CSR ----
info "Creating CSR for CN='${CN}' (DN: C='${C}' O='${O}' OU='${OU}')…"
if [[ "$QUIET_OPENSSL" == "1" ]]; then
  "$OPENSSL" req -new -sha256 \
    -config "$REQ_CNF_DN" \
    ${SAN_DNS:+-reqexts req_ext} ${SAN_IP:+-reqexts req_ext} ${SAN_EMAIL:+-reqexts req_ext} ${SAN_URI:+-reqexts req_ext} \
    -key "$KEY_PATH" \
    -out "$CSR_PATH" >/dev/null 2>&1
else
  "$OPENSSL" req -new -sha256 \
    -config "$REQ_CNF_DN" \
    ${SAN_DNS:+-reqexts req_ext} ${SAN_IP:+-reqexts req_ext} ${SAN_EMAIL:+-reqexts req_ext} ${SAN_URI:+-reqexts req_ext} \
    -key "$KEY_PATH" \
    -out "$CSR_PATH"
fi

# ---- Make sure next serial won't collide with index.txt ----
ensure_serial_monotonic "$INT_DIR"

# Trace & garde-fou : montrer le next serial et refuser s'il est absurde
_next_hex="$(tr -d '\r\n' < "$INT_DIR/serial" | tr '[:lower:]' '[:upper:]')"
# borne "raisonnable": si > 16 hex digits (~ 64 bits) on bloque (ça protège des nexts farfelus type ECE1000F venu d'ailleurs)
if [[ ! "$_next_hex" =~ ^[0-9A-F]{1,16}$ ]]; then
  die "Next serial in '$INT_DIR/serial' looks invalid: '$_next_hex' (expected 1..16 hex digits). Fix the file then retry."
fi
info "Next leaf serial (preview): ${_next_hex}"
unset _next_hex

# ---- Sign with intermediate into a temp file ----
TMPCRT="$INT_DIR/certs/.tmp.$(date +%s).$$.pem"
info "Signing leaf via intermediate '$INT_DIR' for ${DAYS} days (extensions: ${EXT_SECTION})…"
if [[ "$QUIET_OPENSSL" == "1" ]]; then
  "$OPENSSL" ca -batch \
    -config "$INT_CNF" \
    -extensions "$EXT_SECTION" \
    -days "$DAYS" -notext -md sha256 \
    -in "$CSR_PATH" \
    -out "$TMPCRT" >/dev/null 2>&1
else
  "$OPENSSL" ca -batch \
    -config "$INT_CNF" \
    -extensions "$EXT_SECTION" \
    -days "$DAYS" -notext -md sha256 \
    -in "$CSR_PATH" \
    -out "$TMPCRT"
fi

# ---- Read actual serial and fix INTERMEDIATE index.txt filename=unknown ----
SERIAL_HEX_ACTUAL="$("$OPENSSL" x509 -in "$TMPCRT" -noout -serial 2>/dev/null | sed 's/^serial=//I' || true)"
if [[ -z "$SERIAL_HEX_ACTUAL" ]]; then
  SERIAL_HEX_ACTUAL="$(openssl_serial "$TMPCRT" || true)"
fi
INT_INDEX="$INT_DIR/index.txt"
if [[ -z "$SERIAL_HEX_ACTUAL" && -f "$INT_INDEX" ]]; then
  SERIAL_HEX_ACTUAL="$(awk '/^V\t/ {s=$4} END{print s}' "$INT_INDEX")"
fi
SERIAL_HEX_ACTUAL="$(printf '%s' "${SERIAL_HEX_ACTUAL:-}" | tr -d '\r\n' | tr '[:lower:]' '[:upper:]')"

if [[ -n "$SERIAL_HEX_ACTUAL" && -f "$INT_INDEX" ]]; then
  index_set_filename_for_valid "$INT_INDEX" "$SERIAL_HEX_ACTUAL" || true
  awk -v s="$SERIAL_HEX_ACTUAL" 'BEGIN{FS=OFS="\t"} { if ($1=="V" && $4==s && $5=="unknown") $5=sprintf("newcerts/%s.pem", s); print }' \
    "$INT_INDEX" > "$INT_INDEX.tmp" && mv "$INT_INDEX.tmp" "$INT_INDEX"
fi

# ---- If destination exists, suffix with the serial to avoid overwrite ----
if [[ -e "$CRT_PATH" && -n "$SERIAL_HEX_ACTUAL" ]]; then
  CRT_PATH="$INT_DIR/certs/${CN}-${SERIAL_HEX_ACTUAL}.cert.pem"
fi

# ---- Atomic install to final destination + perms ----
install -m 0644 "$TMPCRT" "$CRT_PATH"
rm -f "$TMPCRT"
chmod 444 "$CRT_PATH"
info "Leaf certificate ready: $CRT_PATH"

# After installing $CRT_PATH and before building the full chain / running verify
if [[ -n "$SAN_DNS$SAN_IP$SAN_EMAIL$SAN_URI" ]]; then
  if ! "$OPENSSL" x509 -in "$CRT_PATH" -noout -text | grep -q "Subject Alternative Name"; then
    die "The issued certificate does not contain a SAN. Ensure '$INT_CNF' has 'copy_extensions = copy' in [CA_default], \
or pass -extfile \"$REQ_CNF_DN\" at signing time."
  fi
fi

# ---- Rotate: renommer les artefacts en <CN>-<SERIAL> ----
if [[ "$ROTATE_MODE" == "1" && -n "$SERIAL_HEX_ACTUAL" ]]; then
  NEW_BASE="${CN}-${SERIAL_HEX_ACTUAL}"
  NEW_KEY="$INT_DIR/private/${NEW_BASE}.key.pem"
  NEW_CRT="$INT_DIR/certs/${NEW_BASE}.cert.pem"
  NEW_CSR="$INT_DIR/csr/${NEW_BASE}.csr.pem"

  # Renommer si les chemins actuels diffèrent
  [[ "$KEY_PATH" != "$NEW_KEY" && -f "$KEY_PATH" ]] && mv -f "$KEY_PATH" "$NEW_KEY"
  [[ "$CRT_PATH" != "$NEW_CRT" && -f "$CRT_PATH" ]] && mv -f "$CRT_PATH" "$NEW_CRT"
  [[ -f "$CSR_PATH" ]] && [[ "$CSR_PATH" != "$NEW_CSR" ]] && mv -f "$CSR_PATH" "$NEW_CSR"

  KEY_PATH="$NEW_KEY"
  CRT_PATH="$NEW_CRT"
  CSR_PATH="$NEW_CSR"
  info "Rotate: artefacts renommés → ${NEW_BASE}.*.pem"
fi

# ---- Full chain next to the cert (optional but handy) ----
CHAIN_PATH="${CRT_PATH%.cert.pem}.fullchain.cert.pem"
if [[ -f "$INT_DIR/certs/ca.cert.pem" ]]; then
  cat "$CRT_PATH" "$INT_DIR/certs/ca.cert.pem" > "$CHAIN_PATH"
  chmod 444 "$CHAIN_PATH"
  info "Full chain ready: $CHAIN_PATH"
fi

# ---------------------------
# Tests d’intégrité post-émission (LEAF)
# ---------------------------
INT_CRT="${INT_DIR}/certs/ca.cert.pem"
ROOT_CRT="root/certs/ca.cert.pem"

[[ -s "$INT_CRT"  ]] || die "Certificat intermédiaire introuvable: $INT_CRT"
[[ -s "$ROOT_CRT" ]] || die "Certificat ROOT introuvable: $ROOT_CRT"

if [[ -s "$CRT_PATH" ]]; then
  # Intermédiaire en -untrusted (chaîne non ancrée), ROOT en -CAfile (ancrage de confiance)
  if "$OPENSSL" verify -untrusted "$INT_CRT" -CAfile "$ROOT_CRT" "$CRT_PATH" >/dev/null; then
    info "Vérification OK (leaf valide sous l’intermédiaire et la root)."
  else
    die  "Vérification de chaîne échouée pour le leaf ($CRT_PATH)"
  fi
fi
