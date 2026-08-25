#!/usr/bin/env bash
# Fix all test-osint-*.sh files:
# 1. Use _INIT_ROOT for initial path resolution (before config.sh)
# 2. Source config.sh first to set readonly CYBERSEC_ROOT
# 3. Then source osint libs and modules using CYBERSEC_ROOT
cd "$(dirname "$0")"

for f in tests/test-osint-*.sh; do
    [[ -f "$f" ]] || continue
    [[ "$(basename "$f")" == "test-osint.sh" ]] && continue
    
    # Get module name from the file
    mod=$(grep -oP 'source "\$CYBERSEC_ROOT/modules/osint/\K\w+' "$f" 2>/dev/null || echo "")
    if [[ -z "$mod" ]]; then
        mod=$(grep -oP 'source "\$TEST_SCRIPT_DIR/../modules/osint/\K\w+' "$f" 2>/dev/null || echo "")
    fi
    
    python3 << PYEOF
import re

with open("$f", "r") as fh:
    lines = fh.readlines()

# Find the line with TEST_SCRIPT_DIR
out = []
i = 0
while i < len(lines):
    line = lines[i]
    
    # Replace TEST_SCRIPT_DIR line with _INIT_ROOT
    if 'TEST_SCRIPT_DIR=' in line and 'BASH_SOURCE' in line:
        out.append('_INIT_ROOT="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"\n')
        out.append('CYBERSEC_ROOT="\$(cd "\$_INIT_ROOT/.." && pwd)"\n')
        i += 1
        continue
    
    # Replace any for-loop referencing CYBERSEC_ROOT or TEST_SCRIPT_DIR for core
    if 'for lib in' in line and ('/core/' in line):
        # Skip the entire for block and replace with config.sh sourcing + osint sourcing
        # Skip until we find the module source line
        while i < len(lines) and 'source' not in lines[i]:
            i += 1
        # Skip the module source line too
        i += 1
        # Skip done
        while i < len(lines) and lines[i].strip() != 'done':
            i += 1
        i += 1  # skip done
        
        # Check if there's a second for-loop (osint libs)
        while i < len(lines) and lines[i].strip() == '':
            out.append(lines[i])
            i += 1
        if i < len(lines) and 'for lib in' in lines[i]:
            # Skip second for block
            while i < len(lines) and 'source' not in lines[i]:
                i += 1
            i += 1  # source line
            while i < len(lines) and lines[i].strip() != 'done':
                i += 1
            i += 1  # done
        
        # Check if there's a module source line
        while i < len(lines) and lines[i].strip() == '':
            out.append(lines[i])
            i += 1
        if i < len(lines) and 'CYBERSEC_ROOT/modules/osint/' in lines[i]:
            i += 1  # skip module source
        
        # Now write our replacement
        out.append('for _lib in "\$CYBERSEC_ROOT"/core/*.sh; do\n')
        out.append('    [[ -f "\${_lib}" ]] && source "\${_lib}"\n')
        out.append('done\n')
        out.append('for _lib in "\$CYBERSEC_ROOT"/core/osint/*.sh; do\n')
        out.append('    [[ -f "\${_lib}" ]] && source "\${_lib}"\n')
        out.append('done\n')
        out.append('[[-f "\$CYBERSEC_ROOT/modules/osint/$mod.sh" ]] && \\\\\n')
        out.append('    source "\$CYBERSEC_ROOT/modules/osint/$mod.sh"\n')
        continue
    
    out.append(line)
    i += 1

with open("$f", "w") as fh:
    fh.writelines(out)

PYEOF
    echo "fixed: $f"
done
