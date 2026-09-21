# PKI Toolkit — Makefile
# -------------------------------------------------------------
# Vue d’ensemble
#   Boîte à outils PKI pour générer une racine, des intermédiaires spécialisés
#   (web, auth, code, smime, archive) et émettre/vérifier/révoquer des certificats.
#
# Cibles principales
#   make help
#   make root CN="Root CA" [DAYS=7300]
#   make intermediate KIND=web CN="Web Issuing CA" [DAYS=3650]
#   make int-web | int-auth | int-code | int-smime | int-archive [CN="..."]
#
# Émission de certificats (feuilles) — **INT_DIR auto-déduit** depuis la cible :
#   Mapping par défaut :
#     server → KIND=web      → INT_DIR=intm-web-ca
#     user   → KIND=auth     → INT_DIR=intm-auth-ca
#     dev    → KIND=code     → INT_DIR=intm-code-ca
#     email  → KIND=smime    → INT_DIR=intm-smime-ca
#     doc    → KIND=archive  → INT_DIR=intm-archive-ca
#
#   Exemples :
#   make server  CN="app.example.com"   [SAN="DNS:app.example.com"] [DAYS=397]
#   make user    CN="john@example.com"  [SAN="email:john@example.com"] [DAYS=825]
#   make dev     CN="CI Signing Key"    [DAYS=730]
#   make email   CN="john@example.com"  [SAN="email:john@example.com"] [DAYS=730]
#   make doc     CN="Records Seal"      [DAYS=3600]
#   Alias compat : make code / make archive
#
#   (Override possible à tout moment : KIND=… ou INT_DIR=…)
#     ex. make server KIND=staging          → INT_DIR=intm-staging-ca
#     ex. make user   INT_DIR=intm-clients  → INT_DIR prioritaire
#
# Vérification / Révocation (feuilles)
#   make verify KIND=web FILE="path/to/cert.crt" [VERIFY_CRL=0|1] [VERIFY_MODE=normal|tolerate_revoked|info]
#     - ou via résolution par CN et choix d’intermédiaire :
#       make verify KIND=web  CN="app.example.com"
#       make verify INT_DIR="intm-smime-ca" CN="john@example.com"
#
#   make revoke KIND=web FILE="path/to/cert.crt"
#     - ou via CN + choix d’intermédiaire :
#       make revoke KIND=web  CN="app.example.com"        REASON="keyCompromise"
#       make revoke INT_DIR="intm-smime-ca" CN="john@example.com" REASON="cessationOfOperation"
#
# Gestion des CRL (intermédiaires & racine)
#   make crl-root
#   make crl       [CRL_INT_DIR=... | INT_DIR=... | KIND=...] [CRL_DAYS=7]
#   make crl-show  [CRL_INT_DIR=... | INT_DIR=... | KIND=...]
#   make crl-all   [CRL_DAYS=7]
#
# Révocation / Vérif d’un intermédiaire depuis la racine
#   make revoke-intermediate INT_DIR=intm-my-issuing-ca REASON=cessationOfOperation [CRL_UPDATE=1] [CRL_DAYS=7]
#     - ou : make revoke-intermediate KIND=web REASON=keyCompromise
#     - Note : 'privilegeWithdrawn' est mappé (OpenSSL ne l’accepte pas) via MAP_PRIV_WITHDRAWN_TO=...
#
#   make verify-intermediate-revoked INT_DIR=intm-my-issuing-ca
#     - ou : make verify-intermediate-revoked KIND=smime
#
# Aide & utilitaires
#   make ls-web | ls-auth | ls-code | ls-smime | ls-archive
#   make tree
#   make clean
#     Preview only; CLEAN_APPLY=1 explicitly deletes validated PKI/output directories.
#   make show-intermediate-serial INT_DIR=intm-web-ca
#     - ou : make show-intermediate-serial KIND=web
#   make crl-root-revoked INT_DIR=intm-web-ca
#     - ou : make crl-root-revoked KIND=web
#   make test-smoke
#
# Variables utiles
#   CN        : Common Name (ex. app.example.com, john@example.com, etc.)
#   SAN       : subjectAltName (ex. DNS:app.example.com | email:john@example.com | URI:...)
#   DAYS      : Validité (jours). Valeurs par défaut selon le TYPE (server/user/dev/email/doc).
#   KIND      : Catégorie d’intermédiaire: web | auth | code | smime | archive | generic
#   INT_DIR   : Dossier intermédiaire, ex. intm-web-ca (prioritaire sur KIND lorsqu’il est fourni).
#   PROFILE   : Section d’extensions d’openssl.cnf (défauts déjà posés par TYPE).
#   VERIFY_CRL: 0/1 — active la vérif CRL dans `make verify`.
#   VERIFY_MODE: normal | tolerate_revoked | info — contrôle le code de sortie de `make verify`.
#   CRL_DAYS  : Périodicité CRL (jours) pour `make crl`, `crl-all`, `revoke-intermediate` (CRL_UPDATE=1).
#   MAP_PRIV_WITHDRAWN_TO : Raison de repli si REASON=privilegeWithdrawn (non supporté par OpenSSL CLI).
#
# Conventions & remarques
#   - Intermédiaires : intm-<KIND>-ca (ex. intm-web-ca, intm-auth-ca, …), créés via `make intermediate`.
#   - CN identity is distinct from filenames; see doc/crypto-policy-en.md.
#     Ordinary names keep spaces/@; unsafe/reserved names use a digest.
#   - Les SAN sont injectés dans le CSR et recopiés à la signature (copy_extensions = copy).
#   - Les scripts corrigent l’index OpenSSL si `filename=unknown` (newcerts/<serial>.pem).
# -------------------------------------------------------------

SHELL := /bin/bash

# --- Aide ---
.PHONY: help
help:
	@echo 'PKI Toolkit — commandes disponibles:'
	@echo '  make root CN="Root CA" [DAYS=7300]'
	@echo '  make intermediate KIND=web CN="Web Issuing CA" [DAYS=3650]'
	@echo '  make int-web|int-auth|int-code|int-smime|int-archive [CN="..."]'
	@echo '  -- Feuilles (INT_DIR auto-déduit; override possible via KIND=... ou INT_DIR=...):'
	@echo '  make server  CN="app.example.com"   [SAN="DNS:app.example.com"] [DAYS=397]'
	@echo '  make user    CN="john@example.com"  [SAN="email:john@example.com"] [DAYS=825]'
	@echo '  make dev     CN="CI Signing Key"    [DAYS=730]'
	@echo '  make email   CN="john@example.com"  [SAN="email:john@example.com"] [DAYS=730]'
	@echo '  make doc     CN="Records Seal"      [DAYS=3600]'
	@echo '  aliases: make code / make archive'
	@echo '  -- Vérification & Révocation:'
	@echo '  make verify KIND=web FILE=".../cert.crt" [VERIFY_CRL=0|1] [VERIFY_MODE=normal|tolerate_revoked|info]'
	@echo '  make revoke KIND=web FILE=".../cert.crt" (ou variables acceptées par revoke-leaf.sh)'
	@echo '  make test-smoke'
	@echo '  make clean [CLEAN_APPLY=1] (preview by default; apply deletes keys/history)'
	@echo '  make verify KIND=web CN="..." VERIFY_MODE=strict VERIFY_DNS="..." VERIFY_PURPOSE=sslserver'
	@echo '  make crl-all CRL_HISTORY=1 (root + current and retained issuer CRLs)'
	@echo ''

# --- Defaults ---

# Allow overriding the OpenSSL binary (e.g., OPENSSL=/usr/local/opt/openssl@3/bin/openssl)
OPENSSL      ?= openssl

# RSA | EC | EdDSA | Ed25519 | Ed448
KEY_ALG       ?= RSA
# RSA only
KEY_SIZE      ?= 4096
# EC only (prime256v1|secp384r1)
KEY_CURVE     ?= prime256v1
# EdDSA only (Ed25519|Ed448)
KEY_EDDSA     ?= Ed25519

# pathLen for root; empty to omit
ROOT_PATHLEN  ?= 1

C             ?=
O             ?=
OU            ?=

# SAN defaults (for modern scripts like gen-leaf.sh)
SAN_DNS       ?=
SAN_IP        ?=
SAN_EMAIL     ?=
SAN_URI       ?=

# Verbosity aligned with scripts
QUIET_OPENSSL ?= 1

# Generic profile fallback for leaf scripts that expect it
PROFILE       ?=

# Freeze public parameters without evaluating Make expressions. Recipes read
# environment data; never interpolate these values into shell source.
override OPENSSL := $(value OPENSSL)
export OPENSSL
override CERTNIFY_PROFILES_DIR := $(value CERTNIFY_PROFILES_DIR)
export CERTNIFY_PROFILES_DIR
override ACTION := $(value ACTION)
export ACTION
override TYPE := $(value TYPE)
export TYPE
override CN := $(value CN)
export CN
override C := $(value C)
export C
override O := $(value O)
export O
override OU := $(value OU)
export OU
override SAN := $(value SAN)
export SAN
override SAN_DNS := $(value SAN_DNS)
export SAN_DNS
override SAN_IP := $(value SAN_IP)
export SAN_IP
override SAN_EMAIL := $(value SAN_EMAIL)
export SAN_EMAIL
override SAN_URI := $(value SAN_URI)
export SAN_URI
override PROFILE := $(value PROFILE)
export PROFILE
override EXT_SECTION := $(value EXT_SECTION)
export EXT_SECTION
override FILE := $(value FILE)
export FILE
override CHAIN := $(value CHAIN)
export CHAIN
override INT_CN := $(value INT_CN)
export INT_CN
override INT_DIR := $(value INT_DIR)
export INT_DIR
override KIND := $(value KIND)
export KIND
override DAYS := $(value DAYS)
export DAYS
override KEY_ALG := $(value KEY_ALG)
export KEY_ALG
override KEY_SIZE := $(value KEY_SIZE)
export KEY_SIZE
override KEY_CURVE := $(value KEY_CURVE)
export KEY_CURVE
override KEY_EDDSA := $(value KEY_EDDSA)
export KEY_EDDSA
override ROOT_PATHLEN := $(value ROOT_PATHLEN)
export ROOT_PATHLEN
override ROOT_CNF := $(value ROOT_CNF)
export ROOT_CNF
override QUIET_OPENSSL := $(value QUIET_OPENSSL)
export QUIET_OPENSSL
override FORCE_NEW_KEY := $(value FORCE_NEW_KEY)
export FORCE_NEW_KEY
override VERIFY_CRL := $(value VERIFY_CRL)
export VERIFY_CRL
override VERIFY_MODE := $(value VERIFY_MODE)
export VERIFY_MODE
override VERIFY_DNS := $(value VERIFY_DNS)
export VERIFY_DNS
override VERIFY_IP := $(value VERIFY_IP)
export VERIFY_IP
override VERIFY_EMAIL := $(value VERIFY_EMAIL)
export VERIFY_EMAIL
override VERIFY_PURPOSE := $(value VERIFY_PURPOSE)
export VERIFY_PURPOSE
override CLEAN_APPLY := $(value CLEAN_APPLY)
export CLEAN_APPLY
override CRL_HISTORY := $(value CRL_HISTORY)
export CRL_HISTORY
override SERIAL := $(value SERIAL)
export SERIAL
override REASON := $(value REASON)
export REASON
override CRL_UPDATE := $(value CRL_UPDATE)
export CRL_UPDATE
override CRL_DAYS := $(value CRL_DAYS)
export CRL_DAYS
override CRL_HOURS := $(value CRL_HOURS)
export CRL_HOURS
override DRY_RUN := $(value DRY_RUN)
export DRY_RUN
override DEBUG := $(value DEBUG)
export DEBUG
override MAP_PRIV_WITHDRAWN_TO := $(value MAP_PRIV_WITHDRAWN_TO)
export MAP_PRIV_WITHDRAWN_TO
override LEAF_STATUSES := $(value LEAF_STATUSES)
export LEAF_STATUSES
override CRL_INT_DIR := $(value CRL_INT_DIR)
export CRL_INT_DIR
override INT_DIR_NEW := $(value INT_DIR_NEW)
export INT_DIR_NEW
override MAKE_ALIAS := $(value MAKE_ALIAS)
export MAKE_ALIAS
override INCLUDE_REVOKED := $(value INCLUDE_REVOKED)
export INCLUDE_REVOKED
override INCLUDE_EXPIRED := $(value INCLUDE_EXPIRED)
export INCLUDE_EXPIRED
override OUT := $(value OUT)
export OUT
override ACTIVE_DIR := $(value ACTIVE_DIR)
export ACTIVE_DIR
override INPUT := $(value INPUT)
export INPUT
override LEGACY_DIR := $(value LEGACY_DIR)
export LEGACY_DIR
override ISSUE_CMD := $(value ISSUE_CMD)
export ISSUE_CMD
override PUBLISH_CMD := $(value PUBLISH_CMD)
export PUBLISH_CMD
override COL_SERIAL := $(value COL_SERIAL)
export COL_SERIAL
override COL_EXPIRES := $(value COL_EXPIRES)
export COL_EXPIRES
override COL_CN := $(value COL_CN)
export COL_CN
override FORCE_REISSUE := $(value FORCE_REISSUE)
export FORCE_REISSUE
override FORCE_REUSE_KEY := $(value FORCE_REUSE_KEY)
export FORCE_REUSE_KEY
override ROTATE_KEY := $(value ROTATE_KEY)
export ROTATE_KEY
override REKEY_ON_ALG_CHANGE := $(value REKEY_ON_ALG_CHANGE)
export REKEY_ON_ALG_CHANGE
override REKEY_ON_REVOKE := $(value REKEY_ON_REVOKE)
export REKEY_ON_REVOKE
override INTM_REVOKED := $(value INTM_REVOKED)
export INTM_REVOKED
override REISSUE_IF_EXPIRES_BEFORE := $(value REISSUE_IF_EXPIRES_BEFORE)
export REISSUE_IF_EXPIRES_BEFORE
override DN_MAXLEN := $(value DN_MAXLEN)
export DN_MAXLEN
override AUTO_UPDATEDB := $(value AUTO_UPDATEDB)
export AUTO_UPDATEDB
override ALLOW_DUPLICATE_CN := $(value ALLOW_DUPLICATE_CN)
export ALLOW_DUPLICATE_CN
override ALLOW_SIGN_WITH_REVOKED_INT := $(value ALLOW_SIGN_WITH_REVOKED_INT)
export ALLOW_SIGN_WITH_REVOKED_INT
override REFRESH_CRL_BEFORE_ISSUE := $(value REFRESH_CRL_BEFORE_ISSUE)
export REFRESH_CRL_BEFORE_ISSUE
override LOCK_TIMEOUT := $(value LOCK_TIMEOUT)
export LOCK_TIMEOUT
override REQUIRE_STRICT_KIND := $(value REQUIRE_STRICT_KIND)
export REQUIRE_STRICT_KIND
override ALLOW_KIND_FROM_DIR := $(value ALLOW_KIND_FROM_DIR)
export ALLOW_KIND_FROM_DIR
override SMIME_MODE := $(value SMIME_MODE)
export SMIME_MODE
override ARCHIVE_MODE := $(value ARCHIVE_MODE)
export ARCHIVE_MODE
override FINAL_MODE := $(value FINAL_MODE)
export FINAL_MODE
override ALLOW_REMAINING_LEAFS := $(value ALLOW_REMAINING_LEAFS)
export ALLOW_REMAINING_LEAFS
override OUT_DIR := $(value OUT_DIR)
export OUT_DIR
override FINAL_CRL := $(value FINAL_CRL)
export FINAL_CRL
override ISSUER_ID := $(value ISSUER_ID)
export ISSUER_ID
override RECOVERY_ACTION := $(value RECOVERY_ACTION)
export RECOVERY_ACTION
override RECOVERY_ID := $(value RECOVERY_ID)
export RECOVERY_ID
override RECOVERY_NOTE := $(value RECOVERY_NOTE)
export RECOVERY_NOTE

# Automatic target names are data too, including pattern-rule stems.
override CERTNIFY_TARGET = $@
export CERTNIFY_TARGET

# --- Root ---
.PHONY: root

root:
	CN="$${CN:-}" C="$${C:-}" O="$${O:-}" OU="$${OU:-}" DAYS="$${DAYS:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	KEY_EDDSA="$${KEY_EDDSA:-}" ROOT_PATHLEN="$${ROOT_PATHLEN:-}" \
	ROOT_CNF="$${ROOT_CNF:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-root.sh

# --- Intermediates (generic + KIND shortcuts) ---
.PHONY: intermediate int-web int-auth int-code int-smime int-archive

intermediate:
	KIND="$${KIND:-web}" CN="$${CN:-Web Issuing CA}" DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	INT_DIR="$${INT_DIR:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-intm.sh

int-web:
	KIND="web" CN="$${CN:-Web Issuing CA}" DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-intm.sh

int-auth:
	KIND="auth" CN="$${CN:-Auth Issuing CA}" DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-intm.sh

int-code:
	KIND="code" CN="$${CN:-Code Signing Issuing CA}" DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-intm.sh

int-smime:
	KIND="smime" CN="$${CN:-S/MIME Issuing CA}" DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-intm.sh

int-archive:
	KIND="archive" CN="$${CN:-Archive Issuing CA}" DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-intm.sh

# --- Leaf issuance ---
.PHONY: server user dev email doc code archive

# Server certs (legacy SAN kept + SAN_* pour scripts modernes)
server:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-server.sh

# User (client auth)
user:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-user.sh

# Code signing
dev:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-code_sign}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-code.sh

# S/MIME
email:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-}" SMIME_MODE="$${SMIME_MODE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-email.sh

# Archival / Time-stamp, etc.
doc:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-}" ARCHIVE_MODE="$${ARCHIVE_MODE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-archive.sh

code:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-code_sign}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-code.sh

archive:
	INT_DIR="$${INT_DIR:-}" CN="$${CN:-}" \
	DAYS="$${DAYS:-}" PROFILE="$${PROFILE:-}" ARCHIVE_MODE="$${ARCHIVE_MODE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" \
	FORCE_NEW_KEY="$${FORCE_NEW_KEY:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/gen-archive.sh

# --- Vérification & Révocation ---
.PHONY: verify revoke

verify:
	FILE="$${FILE:-}" \
	CHAIN="$${CHAIN:-}" \
	VERIFY_CRL="$${VERIFY_CRL:-0}" \
	VERIFY_MODE="$${VERIFY_MODE:-normal}" \
	INT_DIR="$${INT_DIR:-}" \
	KIND="$${KIND:-}" \
	bin/verify.sh

revoke:
	INT_DIR="$${INT_DIR:-}" \
	KIND="$${KIND:-}" \
	CN="$${CN:-}" \
	FILE="$${FILE:-}" \
	SERIAL="$${SERIAL:-}" \
	REASON="$${REASON:-cessationOfOperation}" \
	CRL_UPDATE="$${CRL_UPDATE:-1}" \
	CRL_DAYS="$${CRL_DAYS:-7}" \
	DRY_RUN="$${DRY_RUN:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-1}" \
	DEBUG="$${DEBUG:-0}" \
	bin/revoke-leaf.sh

# ========= Révocation d'un intermédiaire (depuis la RACINE) =========
# Usage:
#   make revoke-intermediate INT_DIR=intm-my-issuing-ca REASON=cessationOfOperation [CRL_UPDATE=1] [CRL_DAYS=7]
#   make revoke-intermediate KIND=smime REASON=keyCompromise
.PHONY: revoke-intermediate revoke-intm-and-leafs verify-intermediate-revoked

# Révoque un intermédiaire (intm-*-ca) depuis la racine
revoke-intermediate:
	INT_DIR="$${INT_DIR:-}" \
	KIND="$${KIND:-}" \
	REASON="$${REASON:-cessationOfOperation}" \
	MAP_PRIV_WITHDRAWN_TO="$${MAP_PRIV_WITHDRAWN_TO:-cessationOfOperation}" \
	CRL_UPDATE="$${CRL_UPDATE:-1}" \
	CRL_DAYS="$${CRL_DAYS:-7}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-1}" \
	DEBUG="$${DEBUG:-0}" \
	bin/revoke-intm.sh

# Revoke intermediate + all its issued leafs
# Révoque un intermédiaire + tous ses certificats leafs valides
revoke-intm-and-leafs:
	INT_DIR="$${INT_DIR:-}" \
	KIND="$${KIND:-}" \
	REASON="$${REASON:-cessationOfOperation}" \
	CRL_UPDATE="$${CRL_UPDATE:-1}" \
	CRL_DAYS="$${CRL_DAYS:-7}" \
	LEAF_STATUSES="$${LEAF_STATUSES:-V}" \
	DRY_RUN="$${DRY_RUN:-0}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-1}" \
	DEBUG="$${DEBUG:-0}" \
	bin/revoke-intm-and-leafs.sh

verify-intermediate-revoked:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh verify-intermediate

# --- Qualité de vie ---
.PHONY: ls-web ls-auth ls-code ls-smime ls-archive test-smoke
ls-web:
	@ls -l intm-web-ca/certs || true

ls-auth:
	@ls -l intm-auth-ca/certs || true

ls-code:
	@ls -l intm-code-ca/certs || true

ls-smime:
	@ls -l intm-smime-ca/certs || true

ls-archive:
	@ls -l intm-archive-ca/certs || true

test-smoke:
	test/smoke.sh

# ========= Divers =========
tree:
	@find . -maxdepth 3 -type d -print | sed 's,^./,,'

clean:
	# aperçu ; CLEAN_APPLY=1 supprime les répertoires PKI reconnus
	bin/crl.sh clean

# ========= CRL de la RACINE =========
# Usage: make crl-root
crl-root:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh root

# ========= CRL de l’intermédiaire choisi (par CRL_INT_DIR, INT_DIR ou KIND) =========
# Exemples :
#   make crl CRL_INT_DIR=intm-intertwo-ca
#   make crl INT_DIR=intm-smime-ca
#   make crl KIND=smime
.PHONY: crl crl-show crl-all

crl:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh generate

crl-show:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh show

# ========= Régénérer les CRL de TOUS les intermédiaires intm-* (s’ils ont openssl.cnf) =========
crl-all:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh all

# ========= Affiche le serial de l'intermédiaire choisi =========
# Usage :
#   make show-intermediate-serial INT_DIR=intm-interone-ca
#   make show-intermediate-serial KIND=web
.PHONY: show-intermediate-serial
show-intermediate-serial:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh serial

# ========= Liste des entrées révoquées de la CRL racine en surlignant l'intermédiaire choisi =========
# Usage :
#   make crl-root-revoked INT_DIR=intm-interone-ca
#   make crl-root-revoked KIND=smime
.PHONY: crl-root-revoked
crl-root-revoked:
	INT_DIR="$${INT_DIR:-}" KIND="$${KIND:-}" CRL_INT_DIR="$${CRL_INT_DIR:-}" bin/crl.sh root-revoked

# --- Rollover d'un intermédiaire (nouvelle clé/CSR/cert + alias optionnel) ---
.PHONY: rollover-%
rollover-%:
	KIND="$${CERTNIFY_TARGET#rollover-}"; export KIND; \
	INT_CN="$${INT_CN:-$$(printf '%s' "$$KIND" | tr a-z A-Z) CA v2}" \
	DAYS="$${DAYS:-3650}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$${KEY_ALG:-}" KEY_SIZE="$${KEY_SIZE:-}" KEY_CURVE="$${KEY_CURVE:-}" KEY_EDDSA="$${KEY_EDDSA:-}" \
	INT_DIR_NEW="$${INT_DIR_NEW:-}" \
	MAKE_ALIAS="$${MAKE_ALIAS:-1}" \
	QUIET_OPENSSL="$${QUIET_OPENSSL:-}" \
	bin/intm-rollover.sh

# --- Liste des leafs émis par un intermédiaire (TSV) ---
list-leafs-%:
	@set -euo pipefail ; \
	KIND="$${CERTNIFY_TARGET#list-leafs-}"; \
	INCLUDE_REVOKED="$${INCLUDE_REVOKED:-0}"; \
	INCLUDE_EXPIRED="$${INCLUDE_EXPIRED:-0}"; \
	KIND="$$KIND" INCLUDE_REVOKED="$$INCLUDE_REVOKED" INCLUDE_EXPIRED="$$INCLUDE_EXPIRED" OUT="$${OUT:-}" \
	bin/list-leafs-by-issuer.sh

.PHONY: reissue-leafs-%
reissue-leafs-%:
	@KIND="$${CERTNIFY_TARGET#reissue-leafs-}"; export KIND; \
	ACTIVE_DIR="$${ACTIVE_DIR:-intm-$$KIND-ca}" \
	INPUT="$${INPUT:-}" LEGACY_DIR="$${LEGACY_DIR:-}" \
	ISSUE_CMD="$${ISSUE_CMD:-}" DRY_RUN="$${DRY_RUN:-0}" \
	COL_SERIAL="$${COL_SERIAL:-1}" COL_EXPIRES="$${COL_EXPIRES:-2}" COL_CN="$${COL_CN:-3}" \
	PROFILE="$${PROFILE:-}" DAYS="$${DAYS:-}" \
	bin/intm-reissue-leafs.sh

.PHONY: rollback-%
rollback-%:
	KIND="$${CERTNIFY_TARGET#rollback-}" LEGACY_DIR="$${LEGACY_DIR:-}" bin/intm-rollback-to-legacy.sh

# Source-only packaging and regression fixture gate (test dependency: Python 3).
.PHONY: test-stage0
test-stage0:
	python3 -B test/stage0.py

.PHONY: test-stage1
test-stage1:
	python3 -B test/stage1.py

.PHONY: test-stage2
test-stage2:
	python3 -B test/stage2.py

.PHONY: test-stage3
test-stage3:
	python3 -B test/stage3.py

.PHONY: test-stage4
test-stage4:
	python3 -B test/stage4.py

.PHONY: test-stage5
test-stage5:
	python3 -B test/stage5.py

export PROFILE

.PHONY: test-stage6
test-stage6:
	python3 -B test/stage6.py

.PHONY: test-stage7
test-stage7:
	python3 -B test/stage7.py

.PHONY: test-stage8
test-stage8:
	python3 -B test/stage8.py
