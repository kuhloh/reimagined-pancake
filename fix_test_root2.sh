#!/usr/bin/env bash
# Fix test files: replace CYBERSEC_ROOT references before config.sh is sourced
cd "$(dirname "$0")"

for f in tests/test-osint-*.sh; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "test-osint.sh" ]] && continue
    
    # Replace the sourcing block that uses $CYBERSEC_ROOT with one that
    # computes root from TEST_SCRIPT_DIR, sources config.sh first,
    # then sources osint libs and modules
    python3 -c "
import re, sys
with open('$f', 'r') as fh:
    content = fh.read()

# Pattern: lines from 'for lib in \"\$CYBERSEC_ROOT\"/core/' through the module source line
old_pattern = r'for lib in \"\$CYBERSEC_ROOT\"/core/\*\.sh;\n.*?source \"\$lib\"\n.*?done\n.*?for lib in \"\$CYBERSEC_ROOT\"/core/osint/\*\.sh;\n.*?source \"\$lib\"\n.*?done\n.*?(?:\[\[ -f \"\$CYBERSEC_ROOT/modules/osint/\w+\.sh\" \]\] && \\\\\n.*?source \"\$CYBERSEC_ROOT/modules/osint/\w+\.sh\")'

# Find the module name
m = re.search(r'source \"\$CYBERSEC_ROOT/modules/osint/(\w+)\.sh\"', content)
mod = m.group(1) if m else 'UNKNOWN'

new_block = '''CYBERSEC_ROOT=\"\$(cd \"\$TEST_SCRIPT_DIR/..\" && pwd)\"

for lib in \"\$CYBERSEC_ROOT\"/core/*.sh; do
    [[ -f \"\$lib\" ]] && source \"\$lib\"
done
for lib in \"\$CYBERSEC_ROOT\"/core/osint/*.sh; do
    [[ -f \"\$lib\" ]] && source \"\$lib\"
done
[[ -f \"\$CYBERSEC_ROOT/modules/osint/''' + mod + '''\.sh\" ]] && \\\\
    source \"\$CYBERSEC_ROOT/modules/osint/''' + mod + '''\.sh\"'''

# Actually let's just do a simpler approach: 
# After TEST_SCRIPT_DIR line, add CYBERSEC_ROOT derivation
# The for loops already use CYBERSEC_ROOT, so we just need to add the assignment
" 2>/dev/null
    
    # Simpler approach: just insert CYBERSEC_ROOT= after TEST_SCRIPT_DIR= line
    # But NOT with readonly, just plain assignment (config.sh's readonly will take over when sourced)
    # Wait - readonly fails if already set. So we need a different approach.
    
    # Actually, just use TEST_SCRIPT_DIR/.. directly in the for loops
    sed -i 's|"\\\$CYBERSEC_ROOT"/core/\*\.sh|"\\$TEST_SCRIPT_DIR/../core/*.sh"|g' "$f"
    sed -i 's|"\\\$CYBERSEC_ROOT"/core/osint/\*\.sh|"\\$TEST_SCRIPT_DIR/../core/osint/*.sh"|g' "$f"
    sed -i 's|\\\$CYBERSEC_ROOT/modules/osint/|\\$TEST_SCRIPT_DIR/../modules/osint/|g' "$f"
    
    echo "fixed: $f"
done
