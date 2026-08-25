#!/usr/bin/env bash
cd "$(dirname "$0")"
for f in tests/test-osint-*.sh; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "test-osint.sh" ]] && continue
    sed -i 's/^SCRIPT_DIR=/TEST_SCRIPT_DIR=/' "$f"
    sed -i 's/\$SCRIPT_DIR/\$TEST_SCRIPT_DIR/g' "$f"
    echo "fixed: $f"
done
