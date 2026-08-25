#!/usr/bin/env bash
# Fix CYBERSEC_ROOT conflict in test files
# Remove CYBERSEC_ROOT= lines (config.sh handles it via readonly)
cd "$(dirname "$0")"
for f in tests/test-osint-*.sh; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "test-osint.sh" ]] && continue
    sed -i '/^CYBERSEC_ROOT=/d' "$f"
    echo "fixed: $f"
done
