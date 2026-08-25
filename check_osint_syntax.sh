#!/usr/bin/env bash
cd "$(dirname "$0")"
pass=0
fail=0
echo "=== OSINT File Syntax Checks ==="
echo ""
for f in core/osint/*.sh modules/osint/*.sh modules/osint/platforms/*.sh tests/test-osint*.sh cybersec-agent.sh; do
    [[ -f "$f" ]] || continue
    if bash -n "$f" 2>/dev/null; then
        echo "OK: $f"
        ((pass++))
    else
        echo "FAIL: $f"
        ((fail++))
    fi
done
echo ""
echo "Total: $pass passed, $fail failed"
