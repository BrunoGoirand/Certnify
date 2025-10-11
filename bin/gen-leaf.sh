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
set -euo pipefail
source "$(dirname "$0")/pki-env.sh"

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

DAYS="${DAYS:-825}"                 # ~27 months typical leaf

#KEY_ALG="${KEY_ALG:-RSA}"
#KEY_SIZE="${KEY_SIZE:-2048}"
#KEY_CURVE="${KEY_CURVE:-prime256v1}"

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

# Reduce OpenSSL chatter by default (align with gen-root.sh)
QUIET_OPENSSL="${QUIET_OPENSSL:-1}"

# ---- Resolve intermediate dir ----
# Logique:
# - Si ACTION est défini, require_int_dir_for_action a peut-être fixé INT_DIR.
# - On normalise INT_DIR si fourni nu (ex: "internet" → "intm-internet-ca").
# - Sinon, si KIND est fourni → "intm-${KIND}-ca".
# - Sinon, on exige INT_DIR explicite (pas de fallback silencieux).
#
# Règles de normalisation :
#   "."            → reste "."
#   contient "/"   → garder tel quel (chemin)
#   ^intm-.*-ca$   → garder tel quel (déjà normalisé)
#   sinon          → "intm-${INT_DIR}-ca"

_raw_int="${INT_DIR:-}"
_kind="${KIND:-}"

normalize_int_dir() {
  local v="$1"
  if [[ "$v" == "." ]]; then
    printf "%s" "."
  elif [[ "$v" == */* ]]; then
    printf "%s" "$v"
  elif [[ "$v" =~ ^intm-.*-ca$ ]]; then
    printf "%s" "$v"
  else
    printf "intm-%s-ca" "$v"
  fi
}

if [[ -n "$_raw_int" ]]; then
  INT_DIR="$(normalize_int_dir "$_raw_int")"
elif [[ -n "$_kind" ]]; then
  INT_DIR="intm-${_kind}-ca"
else
  die "INT_DIR manquant (ou fournis ACTION/KIND pour résolution) ; ex: INT_DIR=intm-web-ca ou INT_DIR=internet"
fi

info "Using intermediate directory: ${INT_DIR}"

# ---- Validate DN ----
CN="$(validate_component_utf8 "CN" "$CN" "$DN_MAXLEN")"
O="$(validate_component_utf8  "O"  "$O"  "$DN_MAXLEN")"
OU="$(validate_component_utf8 "OU" "$OU" "$DN_MAXLEN")"
C="$(validate_country_iso "$C")"

# ---- Paths & layout ----
cd "$ROOT_DIR"
ensure_intermediate_layout "$INT_DIR"

# Always force INT_CNF to match INT_DIR
INT_CNF="$ROOT_DIR/$INT_DIR/openssl.cnf"
[[ -f "$INT_CNF" ]] || die "Intermediate openssl.cnf not found: $INT_CNF (create the intermediate first)"

KEY_PATH="$INT_DIR/private/${CN}.key.pem"
CSR_PATH="$INT_DIR/csr/${CN}.csr.pem"
CRT_PATH="$INT_DIR/certs/${CN}.cert.pem"

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
if [[ ! -s "$KEY_PATH" ]]; then
  gen_private_key "$KEY_ALG" "$KEY_SIZE" "$KEY_CURVE" "$KEY_PATH"
else
  info "Leaf private key already exists: $KEY_PATH (skip)"
fi

# ---- Build a transient req config with DN and SAN ----
REQ_CNF_TMP="$(mktemp)"
REQ_CNF_DN="$(mktemp)"
trap 'rm -f "$REQ_CNF_TMP" "$REQ_CNF_DN"' EXIT

# 1) Start from intermediate CNF (must contain req/req_distinguished_name and placeholders)
cp "$INT_CNF" "$REQ_CNF_TMP"

# 2) Render DN placeholders and drop empty DN lines
render_req_cnf_with_dn "$REQ_CNF_TMP" "$REQ_CNF_DN" "$C" "$O" "$OU" "$CN"

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
    ${SAN_DNS:+-reqexts req_ext} ${SAN_IP:+-reqexts req_ext} ${SAN_EMAIL:+-reqexts req_ext} \
    -key "$KEY_PATH" \
    -out "$CSR_PATH" >/dev/null 2>&1
else
  "$OPENSSL" req -new -sha256 \
    -config "$REQ_CNF_DN" \
    ${SAN_DNS:+-reqexts req_ext} ${SAN_IP:+-reqexts req_ext} ${SAN_EMAIL:+-reqexts req_ext} \
    -key "$KEY_PATH" \
    -out "$CSR_PATH"
fi

# ---- Make sure next serial won't collide with index.txt ----
#ensure_serial_monotonic "$INT_DIR"

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
