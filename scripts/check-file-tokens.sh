#!/usr/bin/env bash
# Fails on any file over MAX_TOKENS (bytes / 4). Staged files by default; `--all` checks the tree.
set -euo pipefail

MAX_TOKENS=5000

# Not written by agents: lockfiles, the license, vendored skills and research records.
EXCLUDE_PATTERNS=(
  "Cargo.lock"
  "fuzz/Cargo.lock"
  "skills-lock.json"
  "LICENSE"
  ".agents/skills/*"
  ".claude/skills/*"
  "docs/research/*"
)

file_list() {
  if [ "${1:-}" = "--all" ]; then
    git ls-files
  else
    git diff --cached --name-only --diff-filter=d
  fi
}

excluded() {
  local pattern
  for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    # shellcheck disable=SC2254
    case "$1" in $pattern) return 0 ;; esac
  done
  return 1
}

over=()
while IFS= read -r file; do
  if [ ! -f "$file" ] || [ -L "$file" ] || excluded "$file"; then continue; fi
  if file --mime-encoding "$file" | grep -q binary; then continue; fi
  tokens=$(($(wc -c <"$file") / 4))
  if [ "$tokens" -gt "$MAX_TOKENS" ]; then over+=("  $file (~$tokens tokens)"); fi
done < <(file_list "${1:-}")

if [ ${#over[@]} -eq 0 ]; then exit 0; fi

cat >&2 <<EOF
These files exceed ${MAX_TOKENS} tokens (bytes / 4):

$(printf '%s\n' "${over[@]}")

Split each into smaller modules by responsibility, re-exporting with pub use so callers
do not change. Inline tests go to src/foo/tests.rs behind "#[cfg(test)] mod tests;".
EOF
exit 1
