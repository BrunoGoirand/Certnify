# Verified file-installation plans. Never replay a signing command (MIT).
# All paths are workspace-relative; journals are data, never shell programs.
recovery_digest() { "$OPENSSL" dgst -sha256 < "$1" | awk '{print $NF}'; }

recovery_identity() {
  local path="$1"
  if [[ -L "$path" ]]; then
    printf 'L%s\n' "$(readlink "$path" | "$OPENSSL" dgst -sha256 | awk '{print $NF}')"
  elif [[ -f "$path" ]]; then printf 'F%s\n' "$(recovery_digest "$path")"
  elif [[ ! -e "$path" ]]; then printf 'M\n'
  else die "Unsupported recovery artifact: $path"; fi
}

recovery_relative() {
  local path="$1" parent kind="${2:-F}"
  [[ "$path" == /* ]] || path="$ROOT_DIR/$path"
  case "$path" in "$ROOT_DIR"/*) path="${path#"$ROOT_DIR/"}" ;; *) die "Recovery path outside workspace" ;; esac
  ! has_control_chars "$path" || die "Control character in recovery path"
  case "/$path/" in */../*|*/./*|*//* ) die "Noncanonical recovery path: $path" ;; esac
  if [[ "$kind" == L ]]; then
    data_path "$path" entry >/dev/null
  else
    data_path "$path" >/dev/null
  fi
  [[ "$path" == */* || "$kind" == L ]] || die "Recovery destination must belong to an authority: $path"
  parent="$(dirname "$ROOT_DIR/$path")"
  [[ -d "$parent" && "$(cd "$parent" && pwd -P)" == "$parent" ]] || die "Missing or aliased recovery parent: $parent"
  printf '%s\n' "$path"
}

recovery_plan_begin() {
  [[ -n "$PKI_RECOVERY_OWNED" ]] || die "Recovery plan requires an owned journal"
  mkdir "$ROOT_DIR/.recovery/pending/files"
  : > "$ROOT_DIR/.recovery/pending/manifest"
  : > "$ROOT_DIR/.recovery/pending/guards"
}

recovery_plan_guard() {
  local path resolved
  path="$(recovery_relative "$1")"
  printf '%s\t%s\n' "$path" "$(recovery_identity "$ROOT_DIR/$path")" >> "$ROOT_DIR/.recovery/pending/guards"
  if [[ -L "$ROOT_DIR/$path" ]]; then
    resolved="$(workspace_path "$ROOT_DIR/$path")"
    [[ -f "$resolved" ]] || die "Recovery evidence alias has no regular target: $path"
    recovery_plan_guard "$resolved"
  fi
}

recovery_plan_deadline() {
  local stamp
  stamp="$(LC_ALL=C awk -f "$ROOT_DIR/bin/pki-time.awk")"
  stamp="${stamp%%$'\t'*}"
  [[ "$stamp" =~ ^[0-9]+$ ]] || die "Invalid recovery validity deadline"
  printf '@valid-until\t%s\n' "$stamp" >> "$ROOT_DIR/.recovery/pending/guards"
}

# F: replace with staged bytes; L: replace symlink; D: remove a regular marker.
recovery_plan_add() {
  local source="$1" path mode="${3:-444}" kind="${4:-F}" number digest journal="$ROOT_DIR/.recovery/pending"
  path="$(recovery_relative "$2" "$kind")"
  number="$(awk 'END {print NR+1}' "$journal/manifest")"
  case "$kind" in
    F) install -m 400 "$source" "$journal/files/$number" ;;
    L) printf '%s\n' "$source" > "$journal/files/$number" ;;
    D) : > "$journal/files/$number" ;;
    *) die "Invalid recovery action" ;;
  esac
  digest="$(recovery_digest "$journal/files/$number")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$number" "$kind" "$mode" "$path" \
    "$(recovery_identity "$ROOT_DIR/$path")" "$digest" "$kind$digest" >> "$journal/manifest"
}

recovery_plan_seal() {
  local journal="$ROOT_DIR/.recovery/pending"
  # The ready marker is published last, after all evidence has been copied.
  { printf 'SCHEMA=1\n'; recovery_digest "$journal/manifest"; recovery_digest "$journal/guards"; } > "$journal/ready.new"
  mv "$journal/ready.new" "$journal/ready"
  # Persist backend state, guards, sources and readiness before any installation.
  durability seal || die "Cannot persist installation checkpoint"
}

recovery_resume() {
  local journal="$ROOT_DIR/.recovery/pending" file path expected actual number kind mode before digest after extra count=0 identity
  [[ ! -L "$ROOT_DIR/.recovery" && ! -L "$journal" && ! -L "$journal/files" ]] || die "Unsafe recovery journal"
  for file in operation manifest guards ready; do
    [[ -f "$journal/$file" && ! -L "$journal/$file" ]] || die "No complete verified installation plan; manual review required ($file)"
  done
  [[ "$(cat "$journal/ready")" == "$(printf 'SCHEMA=1\n'; recovery_digest "$journal/manifest"; recovery_digest "$journal/guards")" ]] || die "Recovery plan integrity mismatch"
  identity="$(sed -n '1s/^id=//p' "$journal/operation")"
  [[ "$identity" =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] || die "Invalid recovery ID"
  [[ ! -e "$ROOT_DIR/.recovery/completed-$identity" && ! -L "$ROOT_DIR/.recovery/completed-$identity" ]] || die "Recovery receipt already exists"
  while IFS=$'\t' read -r path expected extra; do
    [[ -n "$path" && -z "$extra" ]] || die "Malformed recovery guard"
    if [[ "$path" == @valid-until ]]; then
      [[ "$expected" =~ ^[0-9]{1,12}$ ]] || die "Malformed recovery validity deadline"
      (( $(date -u +%s) < 10#$expected )) || die "Recovery artifact expired; manual review and fresh CRL publication may be required"
      continue
    fi
    [[ "$(recovery_relative "$path")" == "$path" ]] || die "Invalid recovery guard path"
    [[ "$(recovery_identity "$ROOT_DIR/$path")" == "$expected" ]] || die "Recovery evidence changed: $path"
  done < "$journal/guards"
  # Validate the entire plan before writing anything, including already installed entries.
  while IFS=$'\t' read -r number kind mode path before digest after extra; do
    count=$((count+1))
    [[ "$number" == "$count" && -z "$extra" && "$digest" =~ ^[0-9a-f]{64}$ && "$after" == "$kind$digest" ]] || die "Malformed recovery manifest"
    case "$mode" in 400|444|600) ;; *) die "Invalid recovery permissions" ;; esac
    case "$kind" in F|L|D) ;; *) die "Invalid recovery action" ;; esac
    [[ "$(recovery_relative "$path" "$kind")" == "$path" ]] || die "Invalid recovery path"
    [[ ! -d "$ROOT_DIR/$path" || ( "$kind" == L && -L "$ROOT_DIR/$path" ) ]] || die "Recovery destination is a directory: $path"
    [[ -f "$journal/files/$number" && ! -L "$journal/files/$number" && "$(recovery_digest "$journal/files/$number")" == "$digest" ]] || die "Recovery source changed: $number"
    actual="$(recovery_identity "$ROOT_DIR/$path")"
    [[ "$kind" != D ]] || after=M
    [[ "$actual" == "$before" || "$actual" == "$after" || ( "$kind" == L && "$actual" == M ) ]] || die "Recovery destination changed: $path"
    if [[ "$kind" == L ]]; then
      expected="$(cat "$journal/files/$number")"
      [[ "$expected" == /* ]] || expected="$(dirname "$ROOT_DIR/$path")/$expected"
      data_path "$expected" >/dev/null
    fi
  done < "$journal/manifest"
  (( count > 0 )) || die "Empty recovery plan"
  durability_resume_admit || die "Installation plan has no durable checkpoint"
  while IFS=$'\t' read -r number kind mode path before digest after; do
    [[ "$kind" != D ]] || after=M
    [[ "$(recovery_identity "$ROOT_DIR/$path")" != "$after" ]] || continue
    case "$kind" in
      F)
        # Replace the directory entry itself, even when it is a CRL alias.
        file="$(mktemp "$(dirname "$ROOT_DIR/$path")/.install.XXXXXX")"
        cat "$journal/files/$number" > "$file"
        chmod "$mode" "$file"
        mv -f "$file" "$ROOT_DIR/$path"
        ;;
      L)
        # Portable mv follows directory symlinks. Unlink only the alias itself;
        # a crash in this gap is resumable from the accepted missing state.
        if [[ -L "$ROOT_DIR/$path" ]]; then rm "$ROOT_DIR/$path"; fi
        ln -s "$(cat "$journal/files/$number")" "$ROOT_DIR/$path"
        ;;
      D) rm -f "$ROOT_DIR/$path" ;;
    esac
    [[ "$(recovery_identity "$ROOT_DIR/$path")" == "$after" ]] || die "Recovery installation mismatch: $path"
  done < "$journal/manifest"
  durability_flush || die "Cannot persist resumed installation"
  mv "$journal" "$ROOT_DIR/.recovery/completed-$identity"
  durability_flush || die "Cannot persist installation receipt"
  PKI_RECOVERY_OWNED=""
  info "Verified installation completed: $identity (no certificate reissued)"
}
