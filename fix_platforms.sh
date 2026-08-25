#!/usr/bin/env bash
# Fix "${1}" -> "${1:-}" in platform files (only in top-level if statements, not function bodies)
cd "$(dirname "$0")"
for f in modules/osint/platforms/*.sh; do
    [[ -f "$f" ]] || continue
    sed -i '/^if \[\[ "${1}"/s/"\${1}"/"${1:-}"/g' "$f"
    echo "fixed: $f"
done
