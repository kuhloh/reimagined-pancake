#!/usr/bin/env bash
# Fix CYBERSEC_ROOT readonly conflicts in OSINT modules
cd "$(dirname "$0")"

for f in modules/osint/company.sh modules/osint/domain.sh modules/osint/email-harvester.sh modules/osint/email.sh modules/osint/exporters.sh modules/osint/exposure-check.sh modules/osint/graph.sh modules/osint/identity-correlation.sh modules/osint/profile-discovery.sh modules/osint/sources.sh modules/osint/scoring.sh modules/osint/username.sh; do
    if [[ -f "$f" ]]; then
        # Replace bare CYBERSEC_ROOT= with guarded version
        sed -i '/^CYBERSEC_ROOT=/{
            s/^CYBERSEC_ROOT="\(.*\)"/if [[ -z "${CYBERSEC_ROOT:-}" ]]; then CYBERSEC_ROOT="\1"; fi/
            s/^CYBERSEC_ROOT=$(\(.*\))/if [[ -z "${CYBERSEC_ROOT:-}" ]]; then CYBERSEC_ROOT=$(\1); fi/
        }' "$f"
        echo "fixed: $f"
    fi
done
