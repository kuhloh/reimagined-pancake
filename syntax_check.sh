#!/usr/bin/env bash
cd "$(dirname "$0")"
for f in tests/test-osint*.sh; do
    [[ -f "$f" ]] || continue
    echo -n "SYNTAX: $(basename "$f") ... "
    if bash -n "$f" 2>&1; then
        echo "OK"
    else
        echo "FAIL"
    fi
done
