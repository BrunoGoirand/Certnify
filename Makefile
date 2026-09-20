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
#   make doc     CN="Records Seal"      [DAYS=3650]
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
	@echo '  make doc     CN="Records Seal"      [DAYS=3650]'
	@echo '  aliases: make code / make archive'
	@echo '  -- Vérification & Révocation:'
	@echo '  make verify KIND=web FILE=".../cert.crt" [VERIFY_CRL=0|1] [VERIFY_MODE=normal|tolerate_revoked|info]'
	@echo '  make revoke KIND=web FILE=".../cert.crt" (ou variables acceptées par revoke-leaf.sh)'
	@echo '  make test-smoke'
	@echo ''

# --- Defaults ---

# Allow overriding the OpenSSL binary (e.g., OPENSSL=/usr/local/opt/openssl@3/bin/openssl)
OPENSSL      ?= openssl
export OPENSSL := $(strip $(OPENSSL))

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

# Normalisation/strip
export KEY_ALG      := $(strip $(KEY_ALG))
export KEY_SIZE     := $(strip $(KEY_SIZE))
export KEY_CURVE    := $(strip $(KEY_CURVE))
export KEY_EDDSA    := $(strip $(KEY_EDDSA))
export ROOT_PATHLEN := $(strip $(ROOT_PATHLEN))

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

# Keep identity/configuration data out of recipe shell source.
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

# --- Root ---
.PHONY: root

root:
	CN="$${CN:-}" C="$${C:-}" O="$${O:-}" OU="$${OU:-}" DAYS="$(DAYS)" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	KEY_EDDSA="$(KEY_EDDSA)" ROOT_PATHLEN="$(ROOT_PATHLEN)" \
	ROOT_CNF="$(ROOT_CNF)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-root.sh

# --- Intermediates (generic + KIND shortcuts) ---
.PHONY: intermediate int-web int-auth int-code int-smime int-archive

intermediate:
	KIND="$(or $(KIND),web)" CN="$${CN:-Web Issuing CA}" DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	INT_DIR="$(INT_DIR)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-intm.sh

int-web:
	KIND="web" CN="$${CN:-Web Issuing CA}" DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-intm.sh

int-auth:
	KIND="auth" CN="$${CN:-Auth Issuing CA}" DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-intm.sh

int-code:
	KIND="code" CN="$${CN:-Code Signing Issuing CA}" DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-intm.sh

int-smime:
	KIND="smime" CN="$${CN:-S/MIME Issuing CA}" DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-intm.sh

int-archive:
	KIND="archive" CN="$${CN:-Archive Issuing CA}" DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-intm.sh

# --- Leaf issuance ---
.PHONY: server user dev email doc code archive

# ===== Auto-mapping KIND / INT_DIR (définitions & macro) =====
# (Définir avant les déclencheurs pour que $(eval $(call ...)) voie la macro)
DEFAULT_KIND_server = web
DEFAULT_KIND_user   = auth
DEFAULT_KIND_dev    = code
DEFAULT_KIND_email  = smime
DEFAULT_KIND_doc    = archive
define SET_DEFAULTS
KIND    ?= $(DEFAULT_KIND_$(1))
INT_DIR ?= intm-$(KIND)-ca
endef

server: KIND ?= $(DEFAULT_KIND_server)
server: INT_DIR ?= intm-$(KIND)-ca
server: DAYS ?= 397

user:   KIND ?= $(DEFAULT_KIND_user)
user:   INT_DIR ?= intm-$(KIND)-ca
user:   DAYS ?= 825

dev:    KIND ?= $(DEFAULT_KIND_dev)
dev:    INT_DIR ?= intm-$(KIND)-ca
dev:    DAYS ?= 730
dev:    PROFILE ?= code_sign

email:  KIND ?= $(DEFAULT_KIND_email)
email:  INT_DIR ?= intm-$(KIND)-ca
email:  DAYS ?= 730

doc:    KIND ?= $(DEFAULT_KIND_doc)
doc:    INT_DIR ?= intm-$(KIND)-ca
doc:    DAYS ?= 3650

code:   KIND ?= $(DEFAULT_KIND_dev)
code:   INT_DIR ?= intm-$(KIND)-ca
code:   DAYS ?= 730
code:   PROFILE ?= code_sign

archive: KIND ?= $(DEFAULT_KIND_doc)
archive: INT_DIR ?= intm-$(KIND)-ca
archive: DAYS ?= 3650

# Server certs (legacy SAN kept + SAN_* pour scripts modernes)
server:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-server.sh

# User (client auth)
user:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-user.sh

# Code signing
dev:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-code_sign}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-code.sh

# S/MIME
email:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-}" SMIME_MODE="$(SMIME_MODE)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-email.sh

# Archival / Time-stamp, etc.
doc:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-}" ARCHIVE_MODE="$(ARCHIVE_MODE)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-archive.sh

code:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-code_sign}" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-code.sh

archive:
	INT_DIR="$(INT_DIR)" CN="$${CN:-}" \
	DAYS="$(DAYS)" PROFILE="$${PROFILE:-}" ARCHIVE_MODE="$(ARCHIVE_MODE)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	SAN_DNS="$${SAN_DNS:-}" SAN_IP="$${SAN_IP:-}" SAN_EMAIL="$${SAN_EMAIL:-}" SAN_URI="$${SAN_URI:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" \
	FORCE_NEW_KEY="$(or $(FORCE_NEW_KEY),0)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/gen-archive.sh

# --- Vérification & Révocation ---
.PHONY: verify revoke

verify:
	FILE="$${FILE:-}" \
	CHAIN="$${CHAIN:-}" \
	VERIFY_CRL="$(or $(VERIFY_CRL),0)" \
	VERIFY_MODE="$(or $(VERIFY_MODE),normal)" \
	INT_DIR="$(INT_DIR)" \
	KIND="$(KIND)" \
	bin/verify.sh

revoke:
	INT_DIR="$(INT_DIR)" \
	KIND="$(KIND)" \
	CN="$${CN:-}" \
	FILE="$${FILE:-}" \
	SERIAL="$(SERIAL)" \
	REASON="$(or $(REASON),cessationOfOperation)" \
	CRL_UPDATE="$(or $(CRL_UPDATE),1)" \
	CRL_DAYS="$(or $(CRL_DAYS),7)" \
	DRY_RUN="$(or $(DRY_RUN),0)" \
	QUIET_OPENSSL="$(or $(QUIET_OPENSSL),1)" \
	DEBUG="$(or $(DEBUG),0)" \
	bin/revoke-leaf.sh

# ========= Révocation d'un intermédiaire (depuis la RACINE) =========
# Usage:
#   make revoke-intermediate INT_DIR=intm-my-issuing-ca REASON=cessationOfOperation [CRL_UPDATE=1] [CRL_DAYS=7]
#   make revoke-intermediate KIND=smime REASON=keyCompromise
.PHONY: revoke-intermediate revoke-intm-and-leafs verify-intermediate-revoked

# Révoque un intermédiaire (intm-*-ca) depuis la racine
revoke-intermediate:
	INT_DIR="$(INT_DIR)" \
	KIND="$(KIND)" \
	REASON="$(or $(REASON),cessationOfOperation)" \
	MAP_PRIV_WITHDRAWN_TO="$(or $(MAP_PRIV_WITHDRAWN_TO),cessationOfOperation)" \
	CRL_UPDATE="$(or $(CRL_UPDATE),1)" \
	CRL_DAYS="$(or $(CRL_DAYS),7)" \
	QUIET_OPENSSL="$(or $(QUIET_OPENSSL),1)" \
	DEBUG="$(or $(DEBUG),0)" \
	bin/revoke-intm.sh

# Revoke intermediate + all its issued leafs
# Révoque un intermédiaire + tous ses certificats leafs valides
revoke-intm-and-leafs:
	INT_DIR="$(INT_DIR)" \
	KIND="$(KIND)" \
	REASON="$(or $(REASON),cessationOfOperation)" \
	CRL_UPDATE="$(or $(CRL_UPDATE),1)" \
	CRL_DAYS="$(or $(CRL_DAYS),7)" \
	LEAF_STATUSES="$(or $(LEAF_STATUSES),V)" \
	DRY_RUN="$(or $(DRY_RUN),0)" \
	QUIET_OPENSSL="$(or $(QUIET_OPENSSL),1)" \
	DEBUG="$(or $(DEBUG),0)" \
	bin/revoke-intm-and-leafs.sh

verify-intermediate-revoked:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh verify-intermediate

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
	# détruit racine et tous les intermédiaires
	bin/crl.sh clean

# ========= CRL de la RACINE =========
# Usage: make crl-root
crl-root:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh root

# ========= CRL de l’intermédiaire choisi (par CRL_INT_DIR, INT_DIR ou KIND) =========
# Exemples :
#   make crl CRL_INT_DIR=intm-intertwo-ca
#   make crl INT_DIR=intm-smime-ca
#   make crl KIND=smime
.PHONY: crl crl-show crl-all

crl:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh generate

crl-show:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh show

# ========= Régénérer les CRL de TOUS les intermédiaires intm-* (s’ils ont openssl.cnf) =========
crl-all:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh all

# ========= Affiche le serial de l'intermédiaire choisi =========
# Usage :
#   make show-intermediate-serial INT_DIR=intm-interone-ca
#   make show-intermediate-serial KIND=web
.PHONY: show-intermediate-serial
show-intermediate-serial:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh serial

# ========= Liste des entrées révoquées de la CRL racine en surlignant l'intermédiaire choisi =========
# Usage :
#   make crl-root-revoked INT_DIR=intm-interone-ca
#   make crl-root-revoked KIND=smime
.PHONY: crl-root-revoked
crl-root-revoked:
	INT_DIR="$(INT_DIR)" KIND="$(KIND)" CRL_INT_DIR="$(CRL_INT_DIR)" bin/crl.sh root-revoked

# --- Rollover d'un intermédiaire (nouvelle clé/CSR/cert + alias optionnel) ---
.PHONY: rollover-%
rollover-%:
	KIND="$*" \
	INT_CN="$${INT_CN:-$(shell echo $* | tr a-z A-Z) CA v2}" \
	DAYS="$(or $(DAYS),3650)" \
	C="$${C:-}" O="$${O:-}" OU="$${OU:-}" \
	KEY_ALG="$(KEY_ALG)" KEY_SIZE="$(KEY_SIZE)" KEY_CURVE="$(KEY_CURVE)" KEY_EDDSA="$(KEY_EDDSA)" \
	INT_DIR_NEW="$(INT_DIR_NEW)" \
	MAKE_ALIAS="$(or $(MAKE_ALIAS),1)" \
	QUIET_OPENSSL="$(QUIET_OPENSSL)" \
	bin/intm-rollover.sh

# --- Liste des leafs émis par un intermédiaire (TSV) ---
list-leafs-%:
	@set -euo pipefail ; \
	KIND="$*"; \
	INCLUDE_REVOKED="$${INCLUDE_REVOKED:-0}"; \
	INCLUDE_EXPIRED="$${INCLUDE_EXPIRED:-0}"; \
	KIND="$$KIND" INCLUDE_REVOKED="$$INCLUDE_REVOKED" INCLUDE_EXPIRED="$$INCLUDE_EXPIRED" OUT="$${OUT:-}" \
	bin/list-leafs-by-issuer.sh

.PHONY: reissue-leafs-%
reissue-leafs-%:
	@KIND="$*" ACTIVE_DIR="$${ACTIVE_DIR:-intm-$*-ca}" \
	INPUT="$${INPUT:-}" LEGACY_DIR="$${LEGACY_DIR:-}" \
	ISSUE_CMD="$${ISSUE_CMD:-}" DRY_RUN="$${DRY_RUN:-0}" \
	COL_SERIAL="$${COL_SERIAL:-1}" COL_EXPIRES="$${COL_EXPIRES:-2}" COL_CN="$${COL_CN:-3}" \
	PROFILE="$${PROFILE:-}" DAYS="$(DAYS)" \
	bin/intm-reissue-leafs.sh

.PHONY: rollback-%
rollback-%:
	KIND="$*" LEGACY_DIR="$(LEGACY_DIR)" bin/intm-rollback-to-legacy.sh

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
