#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL="${OPENSSL:-openssl}"
TMPDIR_ROOT="${TMPDIR_ROOT:-${TMPDIR:-/private/tmp}}"

die() { echo "[ERR] $*" >&2; exit 1; }
info() { echo "[OK ] $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

assert_file() {
  local path="$1"
  [[ -f "$path" ]] || die "Missing file: $path"
}

assert_symlink_target() {
  local path="$1" expected="$2"
  [[ -L "$path" ]] || die "Expected symlink: $path"
  local target
  target="$(readlink "$path")" || die "Unable to read symlink: $path"
  [[ "$target" == "$expected" ]] || die "Unexpected symlink target for $path: '$target' != '$expected'"
}

assert_contains() {
  local haystack="$1" needle="$2" label="$3"
  grep -Fq "$needle" <<<"$haystack" || die "Expected '$needle' in $label"
}

assert_not_contains() {
  local haystack="$1" needle="$2" label="$3"
  if grep -Fq "$needle" <<<"$haystack"; then
    die "Did not expect '$needle' in $label"
  fi
}

assert_cert_text_contains() {
  local cert="$1" needle="$2" label="$3"
  local text
  text="$("$OPENSSL" x509 -in "$cert" -noout -text 2>/dev/null)" || die "Unable to read certificate: $cert"
  assert_contains "$text" "$needle" "$label"
}

assert_cert_text_not_contains() {
  local cert="$1" needle="$2" label="$3"
  local text
  text="$("$OPENSSL" x509 -in "$cert" -noout -text 2>/dev/null)" || die "Unable to read certificate: $cert"
  assert_not_contains "$text" "$needle" "$label"
}

require_cmd "$OPENSSL"
require_cmd tar
require_cmd mktemp
require_cmd make

WORKDIR="$(mktemp -d "$TMPDIR_ROOT/certnify-smoke.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

info "Workspace: $WORKDIR"

tar \
  --exclude=.git \
  --exclude=.DS_Store \
  --exclude=root \
  --exclude='intm-*' \
  --exclude=draft \
  --exclude=plan \
  --exclude=test-results \
  -cf - -C "$ROOT_DIR" . | tar -xf - -C "$WORKDIR"

cd "$WORKDIR"

run_make() {
  info "make $*"
  make "$@" >/dev/null
}

clone_workspace() {
  local target="$1"
  mkdir -p "$target"
  tar \
    --exclude=.git \
    --exclude=.DS_Store \
    --exclude=root \
    --exclude='intm-*' \
    --exclude=draft \
    --exclude=plan \
    --exclude=test-results \
    -cf - -C "$ROOT_DIR" . | tar -xf - -C "$target"
}

run_make root CN="Smoke Root CA"
run_make int-web CN="Smoke Web CA"
run_make int-auth CN="Smoke Auth CA"
run_make int-code CN="Smoke Code CA"
run_make int-smime CN="Smoke S/MIME CA"
run_make int-archive CN="Smoke Archive CA"

run_make server CN="app.example.test"
run_make user CN="john@example.test"
run_make code CN="Smoke Signing Key"
run_make email CN="john@example.test"
run_make archive CN="Smoke Archive Seal"

assert_file "root/certs/ca.cert.pem"
assert_file "intm-web-ca/certs/app.example.test.cert.pem"
assert_file "intm-auth-ca/certs/john@example.test.cert.pem"
assert_file "intm-code-ca/certs/Smoke Signing Key.cert.pem"
assert_file "intm-smime-ca/certs/john@example.test.cert.pem"
assert_file "intm-archive-ca/certs/Smoke Archive Seal.cert.pem"
assert_symlink_target "intm-web-ca/certs/chain.cert.pem" "ca.chain.cert.pem"

assert_cert_text_contains "intm-web-ca/certs/app.example.test.cert.pem" "TLS Web Server Authentication" "server EKU"
assert_cert_text_contains "intm-auth-ca/certs/john@example.test.cert.pem" "TLS Web Client Authentication" "user EKU"
assert_cert_text_contains "intm-code-ca/certs/Smoke Signing Key.cert.pem" "Code Signing" "code EKU"
assert_cert_text_contains "intm-smime-ca/certs/john@example.test.cert.pem" "E-mail Protection" "email EKU"
assert_cert_text_contains "intm-auth-ca/certs/john@example.test.cert.pem" "email:john@example.test" "user SAN"
assert_cert_text_contains "intm-smime-ca/certs/john@example.test.cert.pem" "email:john@example.test" "email SAN"
assert_cert_text_contains "intm-archive-ca/certs/Smoke Archive Seal.cert.pem" "CA:FALSE" "archive basic constraints"

verify_output="$(make verify KIND=web CN="app.example.test" 2>&1)" || die "make verify failed"
assert_contains "$verify_output" "VERIFY STATUS: OK" "verify output"

dup_output="$(make server CN="app.example.test" 2>&1 || true)"
assert_contains "$dup_output" "Refusing to issue: active certificate(s) for CN='app.example.test' already exist" "duplicate CN refusal"

run_make revoke KIND=web CN="app.example.test" REASON="cessationOfOperation"
verify_revoked="$(make verify KIND=web CN="app.example.test" VERIFY_CRL=1 VERIFY_MODE=info 2>&1)" || die "verify revoked failed"
assert_contains "$verify_revoked" "VERIFY STATUS: REVOKED" "revoked verify output"

run_make crl-root
revoked_int_output="$(make verify-intermediate-revoked KIND=web 2>&1 || true)"
assert_contains "$revoked_int_output" "OK" "verify-intermediate-revoked command wiring"

rollback_preview="$(make -n rollback-web)"
assert_contains "$rollback_preview" "bin/intm-rollback-to-legacy.sh" "rollback recipe"

EDDSA_CASE="$(mktemp -d "$TMPDIR_ROOT/certnify-root-eddsa.XXXXXX")"
clone_workspace "$EDDSA_CASE"
(
  cd "$EDDSA_CASE"
  run_make root CN="Reusable EdDSA Root" KEY_ALG="Ed25519"
  rm -f root/certs/ca.cert.pem root/ca.meta
  run_make root CN="Reusable EdDSA Root" KEY_ALG="RSA" KEY_SIZE="4096"
  eddsa_meta="$(cat root/ca.meta)"
  assert_contains "$eddsa_meta" "ALG=ED25519" "root metadata effective alg"
  assert_contains "$eddsa_meta" "KEY_EDDSA=Ed25519" "root metadata effective eddsa"
  assert_not_contains "$eddsa_meta" "KEY_SIZE=4096" "root metadata stale rsa size"
)

PATHLEN_CASE="$(mktemp -d "$TMPDIR_ROOT/certnify-root-pathlen.XXXXXX")"
clone_workspace "$PATHLEN_CASE"
(
  cd "$PATHLEN_CASE"
  run_make root CN="No PathLen Root" ROOT_PATHLEN=""
  v3_ca_block="$(awk '/^\[ v3_ca \]$/{flag=1;next}/^\[/{flag=0}flag{print}' root/openssl.cnf)"
  assert_contains "$v3_ca_block" "basicConstraints       = critical, CA:true" "root openssl.cnf v3_ca constraints"
  assert_not_contains "$v3_ca_block" "pathlen:" "root openssl.cnf pathlen omission"
  assert_cert_text_not_contains "root/certs/ca.cert.pem" "Path Length Constraint" "root certificate pathlen omission"
)

CUSTOM_CNF_CASE="$(mktemp -d "$TMPDIR_ROOT/certnify-root-cnf.XXXXXX")"
clone_workspace "$CUSTOM_CNF_CASE"
(
  cd "$CUSTOM_CNF_CASE"
  run_make root CN="Custom CNF Root" ROOT_CNF="custom/root.cnf"
  assert_file "custom/root.cnf"
)

INTM_REKEY_CASE="$(mktemp -d "$TMPDIR_ROOT/certnify-intm-rekey.XXXXXX")"
clone_workspace "$INTM_REKEY_CASE"
(
  cd "$INTM_REKEY_CASE"
  run_make root CN="Rekey Root"
  run_make int-web CN="Rekey Web CA" KEY_ALG="RSA" KEY_SIZE="4096"
  serial_before="$("$OPENSSL" x509 -in intm-web-ca/certs/ca.cert.pem -noout -serial | sed 's/^serial=//I')"
  run_make int-web CN="Rekey Web CA" KEY_ALG="EC" KEY_CURVE="secp384r1"
  serial_after="$("$OPENSSL" x509 -in intm-web-ca/certs/ca.cert.pem -noout -serial | sed 's/^serial=//I')"
  [[ "$serial_before" != "$serial_after" ]] || die "Intermediate serial did not change after requested key algorithm change"
  rekey_meta="$(cat intm-web-ca/ca.meta)"
  assert_contains "$rekey_meta" "ALG=EC" "intermediate metadata effective alg after rekey"
  assert_contains "$rekey_meta" "KEY_CURVE=secp384r1" "intermediate metadata effective curve after rekey"
)

INTM_REVOKE_CASE="$(mktemp -d "$TMPDIR_ROOT/certnify-intm-revoke.XXXXXX")"
clone_workspace "$INTM_REVOKE_CASE"
(
  cd "$INTM_REVOKE_CASE"
  run_make root CN="Revoked Root"
  run_make int-web CN="Revoked Web CA"
  serial_before="$("$OPENSSL" x509 -in intm-web-ca/certs/ca.cert.pem -noout -serial | sed 's/^serial=//I')"
  run_make revoke-intermediate KIND="web" REASON="keyCompromise"
  run_make int-web CN="Revoked Web CA"
  serial_after="$("$OPENSSL" x509 -in intm-web-ca/certs/ca.cert.pem -noout -serial | sed 's/^serial=//I')"
  [[ "$serial_before" != "$serial_after" ]] || die "Intermediate serial did not change after revoked intermediate reissue"
)

INTM_PATH_CASE="$(mktemp -d "$TMPDIR_ROOT/certnify-intm-path.XXXXXX")"
clone_workspace "$INTM_PATH_CASE"
(
  cd "$INTM_PATH_CASE"
  run_make root CN="Path Root"
  invalid_path_output="$(make intermediate INT_DIR="../escape" CN="Escape CA" 2>&1 || true)"
  assert_contains "$invalid_path_output" "INT_DIR must stay within the workspace" "unsafe INT_DIR rejection"
)

info "Smoke test passed"
