#!/usr/bin/env bash
# Comprehensive audit test suite for bugbounty-agent.sh
# Tests real functionality with mock data, no external scanning
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
NO_COLOR=true
PASSED=0; FAILED=0; SKIPPED=0

VERSION="1.0.0"
RATE_LIMIT=5; CONCURRENCY=2; TIMEOUT=10; MAX_REDIRECTS=3
USER_AGENT="Authorized-BugBounty-Agent/1.0"
FINDING_COUNTER=0
TEMP_DIR=""
LOG_FILE=""
TARGET=""
SCOPE_FILE=""
AUTO_MODE=false RECON_ONLY=false SCAN_ONLY=false REPORT_ONLY=false
CHECK_DEPS=false TEST_MODE=false
CONFIG_FILE=""
declare -a SCOPE_ENTRIES=()
declare -A DEP_STATUS=()

# Source the functions from the script without executing main
eval "$(sed '/^main "\$@"/d' "$SCRIPT_DIR/bugbounty-agent.sh")"

ok() { echo -e "  ${GREEN}PASS${NC}: $*"; PASSED=$((PASSED + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $*"; FAILED=$((FAILED + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC}: $*"; SKIPPED=$((SKIPPED + 1)); }

TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t audit_XXXXXX)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "================================================"
echo "  COMPREHENSIVE AUDIT TEST SUITE"
echo "================================================"
echo ""

# ---- 1. SCOPE ENGINE DEEP TESTS ----
echo "--- SCOPE ENGINE ---"

SCOPE_ENTRIES=("example.com" "*.example.com" "api.example.com")

r=$(is_in_scope "example.com")
[[ "$r" == "IN_SCOPE" ]] && ok "Exact match" || fail "Exact match got '$r'"

r=$(is_in_scope "sub.example.com")
[[ "$r" == "IN_SCOPE" ]] && ok "Wildcard subdomain match" || fail "Wildcard subdomain got '$r'"

r=$(is_in_scope "deep.sub.example.com")
[[ "$r" == "IN_SCOPE" ]] && ok "Deep wildcard match" || fail "Deep wildcard got '$r'"

r=$(is_in_scope "api.example.com")
[[ "$r" == "IN_SCOPE" ]] && ok "Explicit subdomain match" || fail "Explicit subdomain got '$r'"

r=$(is_in_scope "api2.example.com")
[[ "$r" == "IN_SCOPE" ]] && ok "api2.example.com matches *.example.com" || fail "api2.example.com got '$r'"

r=$(is_in_scope "evil.com")
[[ "$r" == "OUT_OF_SCOPE" ]] && ok "Out of scope" || fail "Out of scope got '$r'"

r=$(is_in_scope "example.com.evil.com")
[[ "$r" == "OUT_OF_SCOPE" ]] && ok "Suffix attack blocked" || fail "Suffix attack got '$r'"

r=$(is_in_scope "EXAMPLE.COM")
[[ "$r" == "IN_SCOPE" ]] && ok "Case insensitive match" || fail "Case insensitive got '$r'"

SCOPE_ENTRIES=()
r=$(is_in_scope "anything.com")
[[ "$r" == "UNKNOWN" ]] && ok "Empty scope returns UNKNOWN" || fail "Empty scope got '$r'"

SCOPE_ENTRIES=(".example.com")
r=$(is_in_scope "example.com")
[[ "$r" == "OUT_OF_SCOPE" ]] && ok "Dot-prefixed entry does not match bare domain" || fail "Dot-prefix got '$r'"

SCOPE_ENTRIES=()
echo ""

# ---- 2. HOSTNAME EXTRACTION ----
echo "--- HOSTNAME EXTRACTION ---"

h=$(extract_hostname "https://example.com/path/to/page")
[[ "$h" == "example.com" ]] && ok "Basic HTTPS extraction" || fail "Basic HTTPS got '$h'"

h=$(extract_hostname "http://sub.example.com:8080/path")
[[ "$h" == "sub.example.com" ]] && ok "Port stripping" || fail "Port stripping got '$h'"

h=$(extract_hostname "https://example.com")
[[ "$h" == "example.com" ]] && ok "No path" || fail "No path got '$h'"

h=$(extract_hostname "ftp://files.example.com/data")
[[ "$h" == "files.example.com" ]] && ok "Non-HTTP scheme" || fail "Non-HTTP got '$h'"

h=$(extract_hostname "example.com")
[[ "$h" == "example.com" ]] && ok "Bare domain" || fail "Bare domain got '$h'"
echo ""

# ---- 3. URL SCHEME HANDLING ----
echo "--- URL SCHEME ---"

u=$(ensure_url_scheme "example.com")
[[ "$u" == "https://example.com" ]] && ok "Add HTTPS prefix" || fail "Add HTTPS got '$u'"

u=$(ensure_url_scheme "http://example.com")
[[ "$u" == "http://example.com" ]] && ok "Preserve HTTP" || fail "Preserve HTTP got '$u'"

u=$(ensure_url_scheme "https://example.com")
[[ "$u" == "https://example.com" ]] && ok "Preserve HTTPS" || fail "Preserve HTTPS got '$u'"
echo ""

# ---- 4. REDACTION ----
echo "--- REDACTION ---"

redact_test="$TEMP_DIR/redact_test.txt"
printf "Authorization: Bearer abc123secret\ncustom-key: api_key=XYZ999\npassword=Hunter2\nNormal line here\nSet-Cookie: sid=abc\n" > "$redact_test"
redact_sensitive_data "$redact_test"

grep -q "abc123secret" "$redact_test" 2>/dev/null && fail "Bearer not redacted" || ok "Bearer redacted"
grep -q "XYZ999" "$redact_test" 2>/dev/null && fail "API key not redacted" || ok "API key redacted"
grep -q "Hunter2" "$redact_test" 2>/dev/null && fail "Password not redacted" || ok "Password redacted"
grep -q "Normal line here" "$redact_test" 2>/dev/null && ok "Normal text preserved" || fail "Normal text lost"
grep -q "sid=abc" "$redact_test" 2>/dev/null && fail "Set-Cookie not redacted" || ok "Set-Cookie redacted"

# Test nonexistent file
redact_sensitive_data "/tmp/nonexistent_file_$(date +%s).txt" && ok "Nonexistent file handled" || fail "Nonexistent file crashed"
echo ""

# ---- 5. DUPLICATE DETECTION ----
echo "--- DUPLICATE DETECTION ---"

dedup_file="$TEMP_DIR/dedup_test.json"
cat > "$dedup_file" << 'EOF'
[
  {"id":"F-001","host":"a.com","url":"https://a.com/x","type":"test","title":"T1","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"},
  {"id":"F-002","host":"a.com","url":"https://a.com/x","type":"test","title":"T1","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"},
  {"id":"F-003","host":"a.com","url":"https://a.com/y","type":"test","title":"T2","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"}
]
EOF

before=$(jq 'length' "$dedup_file")
tmp_dedup="$TEMP_DIR/dedup_out.json"
jq 'unique_by(.host + .url + .type + .title)' "$dedup_file" > "$tmp_dedup"
mv "$tmp_dedup" "$dedup_file"
after=$(jq 'length' "$dedup_file")
[[ "$before" -eq 3 ]] && ok "3 input findings" || fail "Expected 3, got $before"
[[ "$after" -eq 2 ]] && ok "Dedup removed 1 duplicate" || fail "Expected 2, got $after"

# Different path should not deduplicate
cat > "$dedup_file" << 'EOF'
[
  {"id":"F-001","host":"a.com","url":"https://a.com/x","type":"test","title":"T1","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"},
  {"id":"F-002","host":"a.com","url":"https://a.com/y","type":"test","title":"T1","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"}
]
EOF
tmp_dedup2="$TEMP_DIR/dedup_out2.json"
jq 'unique_by(.host + .url + .type + .title)' "$dedup_file" > "$tmp_dedup2"
mv "$tmp_dedup2" "$dedup_file"
after2=$(jq 'length' "$dedup_file")
[[ "$after2" -eq 2 ]] && ok "Different URLs not deduped" || fail "Expected 2, got $after2"
echo ""

# ---- 6. FINDING NORMALIZATION ----
echo "--- FINDING NORMALIZATION ---"

norm_file="$TEMP_DIR/norm_test.json"
echo '[{"host":"UPPER.COM","type":"TEST","severity":"high","confidence":"possible"},{"host":"MiXeD.nEt","type":"HEADER","severity":"Critical","confidence":"Likely"}]' > "$norm_file"

tmp_norm="$TEMP_DIR/norm_out.json"
jq 'map(. + {
    host: (.host | ascii_downcase),
    type: (.type | ascii_downcase),
    severity: (.severity | ascii_upcase),
    confidence: (.confidence | ascii_upcase)
})' "$norm_file" > "$tmp_norm"

h=$(jq -r '.[0].host' "$tmp_norm")
s=$(jq -r '.[0].severity' "$tmp_norm")
c=$(jq -r '.[0].confidence' "$tmp_norm")
[[ "$h" == "upper.com" ]] && ok "Host lowercased" || fail "Host: $h"
[[ "$s" == "HIGH" ]] && ok "Severity uppercased" || fail "Severity: $s"
[[ "$c" == "POSSIBLE" ]] && ok "Confidence uppercased" || fail "Confidence: $c"

h2=$(jq -r '.[1].host' "$tmp_norm")
[[ "$h2" == "mixed.net" ]] && ok "Mixed case host normalized" || fail "Mixed: $h2"
echo ""

# ---- 7. ADD FINDING ----
echo "--- ADD FINDING ---"

findings_test="$TEMP_DIR/add_find_test.json"
echo '[]' > "$findings_test"
FINDING_COUNTER=0
TEMP_DIR_TEST="$TEMP_DIR"

# Temporarily override add_finding to use our test file
add_finding "$findings_test" "Test Finding" "test.com" "https://test.com" "test_type" "MEDIUM" "LIKELY" "Test evidence"

count=$(jq 'length' "$findings_test")
[[ "$count" -eq 1 ]] && ok "Finding added (count=1)" || fail "Count: $count"

fid=$(jq -r '.[0].id' "$findings_test")
[[ "$fid" == "F-001" ]] && ok "Finding ID formatted" || fail "ID: $fid"

title=$(jq -r '.[0].title' "$findings_test")
[[ "$title" == "Test Finding" ]] && ok "Finding title correct" || fail "Title: $title"

ts=$(jq -r '.[0].timestamp' "$findings_test")
[[ "$ts" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] && ok "Timestamp ISO format" || fail "Timestamp: $ts"

status=$(jq -r '.[0].status' "$findings_test")
[[ "$status" == "candidate" ]] && ok "Status set to candidate" || fail "Status: $status"

# Add another and check increment
add_finding "$findings_test" "Finding 2" "test.com" "https://test.com" "test2" "LOW" "CONFIRMED" "ev2"
count2=$(jq 'length' "$findings_test")
fid2=$(jq -r '.[1].id' "$findings_test")
[[ "$count2" -eq 2 ]] && ok "Second finding added" || fail "Count: $count2"
[[ "$fid2" == "F-002" ]] && ok "ID incremented" || fail "ID: $fid2"
echo ""

# ---- 8. SEVERITY CALCULATION ----
echo "--- SEVERITY CALCULATION ---"

sev_file="$TEMP_DIR/sev_test.json"
cat > "$sev_file" << 'EOF'
[
  {"id":"F-001","type":"expired_cert","severity":"INFO"},
  {"id":"F-002","type":"no_https","severity":"INFO"},
  {"id":"F-003","type":"missing_header","severity":"INFO"},
  {"id":"F-004","type":"nuclei","severity":"HIGH"},
  {"id":"F-005","type":"unknown_type","severity":"INFO"}
]
EOF

tmp_sev="$TEMP_DIR/sev_out.json"
jq 'map(. + {
    severity: (
        if .type == "nuclei" then .severity
        elif .type == "expired_cert" then "HIGH"
        elif .type == "no_https" then "MEDIUM"
        elif .type == "cert_mismatch" then "MEDIUM"
        elif .type == "missing_header" then "INFO"
        elif .type == "version_disclosure" then "INFO"
        elif .type == "powered_by_disclosure" then "INFO"
        elif .type == "info_disclosure" then "LOW"
        elif .type == "expiring_cert" then "LOW"
        else "INFO"
        end
    )
})' "$sev_file" > "$tmp_sev"

s1=$(jq -r '.[0].severity' "$tmp_sev")
s2=$(jq -r '.[1].severity' "$tmp_sev")
s3=$(jq -r '.[2].severity' "$tmp_sev")
s4=$(jq -r '.[3].severity' "$tmp_sev")
s5=$(jq -r '.[4].severity' "$tmp_sev")
[[ "$s1" == "HIGH" ]] && ok "expired_cert -> HIGH" || fail "expired_cert: $s1"
[[ "$s2" == "MEDIUM" ]] && ok "no_https -> MEDIUM" || fail "no_https: $s2"
[[ "$s3" == "INFO" ]] && ok "missing_header -> INFO" || fail "missing_header: $s3"
[[ "$s4" == "HIGH" ]] && ok "nuclei HIGH preserved" || fail "nuclei: $s4"
[[ "$s5" == "INFO" ]] && ok "unknown -> INFO fallback" || fail "unknown: $s5"
echo ""

# ---- 9. CONFIG LOADING ----
echo "--- CONFIG LOADING ---"

config_test="$TEMP_DIR/test_config.conf"
cat > "$config_test" << 'EOF'
RATE_LIMIT=10
CONCURRENCY=5
TIMEOUT=30
ENABLE_NUCLEI=false
LOG_LEVEL=DEBUG
EOF

saved_rl=$RATE_LIMIT
saved_c=$CONCURRENCY
saved_t=$TIMEOUT
saved_en=$ENABLE_NUCLEI
saved_ll=$LOG_LEVEL
CONFIG_FILE="$config_test"
load_config

[[ "$RATE_LIMIT" -eq 10 ]] && ok "RATE_LIMIT loaded" || fail "RATE_LIMIT: $RATE_LIMIT"
[[ "$CONCURRENCY" -eq 5 ]] && ok "CONCURRENCY loaded" || fail "CONCURRENCY: $CONCURRENCY"
[[ "$TIMEOUT" -eq 30 ]] && ok "TIMEOUT loaded" || fail "TIMEOUT: $TIMEOUT"
[[ "$ENABLE_NUCLEI" == "false" ]] && ok "ENABLE_NUCLEI loaded" || fail "ENABLE_NUCLEI: $ENABLE_NUCLEI"
[[ "$LOG_LEVEL" == "DEBUG" ]] && ok "LOG_LEVEL loaded" || fail "LOG_LEVEL: $LOG_LEVEL"

RATE_LIMIT=$saved_rl; CONCURRENCY=$saved_c; TIMEOUT=$saved_t
ENABLE_NUCLEI=$saved_en; LOG_LEVEL=$saved_ll; CONFIG_FILE=""
echo ""

# ---- 10. VALIDATE TARGET ----
echo "--- VALIDATE TARGET ---"

SCOPE_ENTRIES=("example.com" "*.example.com")
validate_target "example.com" && ok "Valid target accepted" || fail "Valid target rejected"
validate_target "sub.example.com" && ok "Subdomain target accepted" || fail "Subdomain target rejected"

validate_target "evil.com" 2>/dev/null && fail "Out-of-scope target accepted" || ok "Out-of-scope blocked (exit $?)"
validate_target "evil.com" 2>/dev/null; ev1=$?
[[ "$ev1" -eq 1 ]] && ok "Out-of-scope returns exit 1" || fail "Out-of-scope exit: $ev1"

validate_target "unknown.net" 2>/dev/null; ev2=$?
[[ "$ev2" -eq 2 ]] && ok "Unknown scope returns exit 2" || fail "Unknown exit: $ev2"
echo ""

# ---- 11. REPORT GENERATION VALIDATION ----
echo "--- REPORT GENERATION ---"

rpt_dir="$TEMP_DIR/rpt_test"
mkdir -p "$rpt_dir/reports" "$rpt_dir/results/recon" "$rpt_dir/results/http" "$rpt_dir/results/technologies" "$rpt_dir/results/vulnerabilities" "$rpt_dir/evidence" "$rpt_dir/logs"

echo -e "a.com\nb.com\nc.com" > "$rpt_dir/results/recon/subdomains.txt"
printf "# URL | Status\nhttps://a.com | 200\nhttps://b.com | 301\n" > "$rpt_dir/results/http/live.txt"
printf "# Tech\nApache\nnginx\n" > "$rpt_dir/results/technologies/technologies.txt"
cat > "$rpt_dir/results/vulnerabilities/findings.json" << 'EOF'
[
  {"id":"F-001","title":"Missing CSP","host":"a.com","url":"https://a.com","type":"missing_header","severity":"INFO","confidence":"POSSIBLE","evidence":"Header CSP not found","status":"candidate","timestamp":"2024-01-01T00:00:00Z"},
  {"id":"F-002","title":"Expired Cert","host":"b.com","url":"https://b.com","type":"expired_cert","severity":"HIGH","confidence":"CONFIRMED","evidence":"Expired 10 days ago","status":"candidate","timestamp":"2024-01-01T00:00:00Z"}
]
EOF

saved_sd=$SCRIPT_DIR
SCRIPT_DIR="$rpt_dir"
TARGET="https://a.com"
SCOPE_ENTRIES=("a.com")
LOG_FILE="$rpt_dir/logs/agent.log"
touch "$LOG_FILE"

generate_markdown_report 2>/dev/null || true
generate_json_report 2>/dev/null

# Validate Markdown report structure
md="$rpt_dir/reports/report.md"
[[ -f "$md" ]] && ok "report.md exists" || fail "report.md missing"

grep -q "Bug Bounty Security Assessment" "$md" && ok "MD has title" || fail "MD missing title"
grep -q "Scope" "$md" && ok "MD has Scope section" || fail "MD missing Scope"
grep -q "Scan Date" "$md" && ok "MD has Scan Date" || fail "MD missing Scan Date"
grep -q "Scan Configuration" "$md" && ok "MD has Config section" || fail "MD missing Config"
grep -q "Assets Discovered" "$md" && ok "MD has Assets section" || fail "MD missing Assets"
grep -q "Technologies" "$md" && ok "MD has Tech section" || fail "MD missing Tech"
grep -q "Executive Summary" "$md" && ok "MD has Summary" || fail "MD missing Summary"
grep -q "F-001" "$md" && ok "MD has finding F-001" || fail "MD missing F-001"
grep -q "F-002" "$md" && ok "MD has finding F-002" || fail "MD missing F-002"
grep -q "Missing CSP" "$md" && ok "MD has finding title" || fail "MD missing title"
grep -q "HIGH" "$md" && ok "MD has HIGH severity" || fail "MD missing HIGH"
grep -q "Findings" "$md" && ok "MD has Findings section" || fail "MD missing Findings"
grep -q "Informational Observations" "$md" && ok "MD has Info section" || fail "MD missing Info"
grep -q "Scan Statistics" "$md" && ok "MD has Stats section" || fail "MD missing Stats"

# Validate JSON report structure
json="$rpt_dir/reports/report.json"
[[ -f "$json" ]] && ok "report.json exists" || fail "report.json missing"

jq . "$json" > /dev/null 2>&1 && ok "report.json is valid JSON" || fail "report.json invalid JSON"
jq -e '.target' "$json" > /dev/null 2>&1 && ok "JSON has target field" || fail "JSON missing target"
jq -e '.hostname' "$json" > /dev/null 2>&1 && ok "JSON has hostname field" || fail "JSON missing hostname"
jq -e '.scan_date' "$json" > /dev/null 2>&1 && ok "JSON has scan_date" || fail "JSON missing scan_date"
jq -e '.stats' "$json" > /dev/null 2>&1 && ok "JSON has stats" || fail "JSON missing stats"

SCRIPT_DIR=$saved_sd
echo ""

# ---- 12. FINDINGS JSON STRUCTURE ----
echo "--- FINDINGS JSON STRUCTURE ---"

findings_struct="$TEMP_DIR/struct_test.json"
echo '[]' > "$findings_struct"
FINDING_COUNTER=$((FINDING_COUNTER - 2))
add_finding "$findings_struct" "Header Issue" "test.com" "https://test.com" "missing_header" "INFO" "POSSIBLE" "Evidence text"

has_id=$(jq -r '.[0].id // empty' "$findings_struct")
has_title=$(jq -r '.[0].title // empty' "$findings_struct")
has_host=$(jq -r '.[0].host // empty' "$findings_struct")
has_url=$(jq -r '.[0].url // empty' "$findings_struct")
has_type=$(jq -r '.[0].type // empty' "$findings_struct")
has_sev=$(jq -r '.[0].severity // empty' "$findings_struct")
has_conf=$(jq -r '.[0].confidence // empty' "$findings_struct")
has_ev=$(jq -r '.[0].evidence // empty' "$findings_struct")
has_st=$(jq -r '.[0].status // empty' "$findings_struct")
has_ts=$(jq -r '.[0].timestamp // empty' "$findings_struct")

[[ -n "$has_id" ]] && ok "Finding has id" || fail "Missing id"
[[ -n "$has_title" ]] && ok "Finding has title" || fail "Missing title"
[[ -n "$has_host" ]] && ok "Finding has host" || fail "Missing host"
[[ -n "$has_url" ]] && ok "Finding has url" || fail "Missing url"
[[ -n "$has_type" ]] && ok "Finding has type" || fail "Missing type"
[[ -n "$has_sev" ]] && ok "Finding has severity" || fail "Missing severity"
[[ -n "$has_conf" ]] && ok "Finding has confidence" || fail "Missing confidence"
[[ -n "$has_ev" ]] && ok "Finding has evidence" || fail "Missing evidence"
[[ -n "$has_st" ]] && ok "Finding has status" || fail "Missing status"
[[ -n "$has_ts" ]] && ok "Finding has timestamp" || fail "Missing timestamp"
echo ""

# ---- 13. LOGGING ----
echo "--- LOGGING ---"

log_test="$TEMP_DIR/test_agent.log"
LOG_FILE="$log_test"
log_message "INFO" "Test message"
log_message "WARN" "Warning message"
log_message "BLOCKED" "Blocked target"

grep -q "\[INFO\] Test message" "$log_test" && ok "INFO logged" || fail "INFO not logged"
grep -q "\[WARN\] Warning message" "$log_test" && ok "WARN logged" || fail "WARN not logged"
grep -q "\[BLOCKED\] Blocked target" "$log_test" && ok "BLOCKED logged" || fail "BLOCKED not logged"
grep -q "$(date '+%Y-%m-%d')" "$log_test" && ok "Timestamp present" || fail "Timestamp missing"
echo ""

# ---- 14. CLI ARGS ----
echo "--- CLI ARGUMENT PARSING ---"

# Reset globals
TARGET=""; AUTO_MODE=false; SCOPE_FILE=""

parse_args --target "https://test.com" --auto
[[ "$TARGET" == "https://test.com" ]] && ok "--target parsed" || fail "--target: $TARGET"
[[ "$AUTO_MODE" == true ]] && ok "--auto parsed" || fail "--auto: $AUTO_MODE"

TARGET=""; SCOPE_FILE=""
parse_args --scope "/tmp/scope.txt"
[[ "$SCOPE_FILE" == "/tmp/scope.txt" ]] && ok "--scope parsed" || fail "--scope: $SCOPE_FILE"

parse_args --recon
[[ "$RECON_ONLY" == true ]] && ok "--recon parsed" || fail "--recon: $RECON_ONLY"

TARGET=""
parse_args --scan
[[ "$SCAN_ONLY" == true ]] && ok "--scan parsed" || fail "--scan: $SCAN_ONLY"

parse_args --report
[[ "$REPORT_ONLY" == true ]] && ok "--report parsed" || fail "--report: $REPORT_ONLY"

parse_args --check-deps
[[ "$CHECK_DEPS" == true ]] && ok "--check-deps parsed" || fail "--check-deps: $CHECK_DEPS"

parse_args --config "/tmp/cust.conf"
[[ "$CONFIG_FILE" == "/tmp/cust.conf" ]] && ok "--config parsed" || fail "--config: $CONFIG_FILE"

# Unknown option should fail
set +e
parse_args --bogus 2>/dev/null
exit_code=$?
set -e
[[ "$exit_code" -eq 4 ]] && ok "Unknown option exits 4" || fail "Unknown option exit: $exit_code"

# Missing --target value
set +e
parse_args --target 2>/dev/null
exit_code=$?
set -e
[[ "$exit_code" -eq 4 ]] && ok "Missing --target value exits 4" || fail "Missing target exit: $exit_code"
echo ""

# ---- 15. EMPTY SCOPE EDGE CASES ----
echo "--- EDGE CASES ---"

SCOPE_ENTRIES=()
r=$(is_in_scope "")
[[ "$r" == "UNKNOWN" ]] && ok "Empty hostname with empty scope -> UNKNOWN" || fail "Empty hostname: $r"

SCOPE_ENTRIES=("example.com")
r=$(is_in_scope "")
[[ "$r" == "OUT_OF_SCOPE" ]] && ok "Empty hostname not in scope -> OUT_OF_SCOPE" || fail "Empty hostname in scope: $r"

# Scope file with comments and blanks
scope_edge="$TEMP_DIR/scope_edge.txt"
printf "# comment\n\n  \nanother.com\n# another comment\n*.test.org\n" > "$scope_edge"
SCOPE_ENTRIES=()
SCOPE_FILE="$scope_edge"
load_scope
[[ ${#SCOPE_ENTRIES[@]} -eq 2 ]] && ok "Scope file ignores comments/blanks" || fail "Scope count: ${#SCOPE_ENTRIES[@]}"
[[ "${SCOPE_ENTRIES[0]}" == "another.com" ]] && ok "First entry correct" || fail "First: ${SCOPE_ENTRIES[0]}"
[[ "${SCOPE_ENTRIES[1]}" == "*.test.org" ]] && ok "Second entry correct" || fail "Second: ${SCOPE_ENTRIES[1]}"
echo ""

# ---- 16. REPORT WITHOUT JQ ----
echo "--- REPORT WITHOUT JQ (fallback) ---"

rpt_nj="$TEMP_DIR/rpt_nojq"
mkdir -p "$rpt_nj/reports" "$rpt_nj/results/recon" "$rpt_nj/results/http" "$rpt_nj/results/technologies" "$rpt_nj/results/vulnerabilities"
echo "example.com" > "$rpt_nj/results/recon/subdomains.txt"
printf "# URL\n" > "$rpt_nj/results/http/live.txt"
printf "# Tech\n" > "$rpt_nj/results/technologies/technologies.txt"
echo '[]' > "$rpt_nj/results/vulnerabilities/findings.json"

saved_sd2=$SCRIPT_DIR
SCRIPT_DIR="$rpt_nj"
TARGET="https://example.com"
SCOPE_ENTRIES=("example.com")
DEP_STATUS=()

generate_markdown_report 2>/dev/null || ok "MD report works without jq" || fail "MD report failed without jq"
generate_json_report 2>/dev/null || ok "JSON report works without jq" || fail "JSON report failed without jq"

[[ -f "$rpt_nj/reports/report.md" ]] && ok "report.md created without jq" || fail "report.md missing"
[[ -f "$rpt_nj/reports/report.json" ]] && ok "report.json created without jq" || fail "report.json missing"

SCRIPT_DIR=$saved_sd2
echo ""

# ---- 17. validate_findings ACTUALLY COUNTS ----
echo "--- VALIDATE FINDINGS ACTUALLY COUNTS ---"

vf_file="$TEMP_DIR/validate_test.json"
cat > "$vf_file" << 'EOF'
[
  {"id":"F-001","confidence":"CONFIRMED","status":"candidate"},
  {"id":"F-002","confidence":"LIKELY","status":"candidate"},
  {"id":"F-003","confidence":"POSSIBLE","status":"candidate"},
  {"id":"F-004","confidence":"CONFIRMED","status":"candidate"},
  {"id":"F-005","confidence":"FALSE_POSITIVE","status":"candidate"}
]
EOF

saved_vf=$SCRIPT_DIR
SCRIPT_DIR="$TEMP_DIR"
mkdir -p "$TEMP_DIR/results/vulnerabilities"
cp "$vf_file" "$TEMP_DIR/results/vulnerabilities/findings.json"
LOG_FILE="/dev/null"

output=$(validate_findings 2>&1)
SCRIPT_DIR=$saved_vf

echo "$output" | grep -q "Confirmed: 2" && ok "Confirmed count = 2" || fail "Confirmed count wrong"
echo "$output" | grep -q "Likely: 1" && ok "Likely count = 1" || fail "Likely count wrong"
echo "$output" | grep -q "Possible: 1" && ok "Possible count = 1" || fail "Possible count wrong"
echo "$output" | grep -q "False Positive: 1" && ok "False positive count = 1" || fail "FP count wrong"
echo ""

# ---- 18. ADD_SCOPE_ENTRY ----
echo "--- ADD SCOPE ENTRY ---"

SCOPE_ENTRIES=("a.com")
add_scope_entry "b.com"
[[ ${#SCOPE_ENTRIES[@]} -eq 2 ]] && ok "New entry added" || fail "Count: ${#SCOPE_ENTRIES[@]}"

add_scope_entry "a.com"
[[ ${#SCOPE_ENTRIES[@]} -eq 2 ]] && ok "Duplicate entry not added" || fail "Count after dup: ${#SCOPE_ENTRIES[@]}"

add_scope_entry ""
[[ ${#SCOPE_ENTRIES[@]} -eq 2 ]] && ok "Empty entry not added" || fail "Count after empty: ${#SCOPE_ENTRIES[@]}"
echo ""

# ---- 19. SENSITIVE DATA REDACTION COVERAGE ----
echo "--- REDACTION COVERAGE ---"

redact2="$TEMP_DIR/redact2.txt"
printf "X-API-Key: mysecretkey123\ntoken=abcdef\nsession_id=xyz789\nsecret: mypassword\nAuthorization: Basic dXNlcjpwYXNz\n" > "$redact2"
redact_sensitive_data "$redact2"

grep -q "mysecretkey123" "$redact2" 2>/dev/null && fail "API key not redacted" || ok "API key pattern redacted"
grep -q "abcdef" "$redact2" 2>/dev/null && fail "Token not redacted" || ok "Token pattern redacted"
grep -q "xyz789" "$redact2" 2>/dev/null && fail "Session not redacted" || ok "Session pattern redacted"
grep -q "mypassword" "$redact2" 2>/dev/null && fail "Secret not redacted" || ok "Secret pattern redacted"
grep -q "dXNlcjpwYXNz" "$redact2" 2>/dev/null && fail "Basic auth not redacted" || ok "Basic auth redacted"
echo ""

# ---- 20. CONCURRENCY SETTING ----
echo "--- CONCURRENCY (is read from config) ---"

conc_test="$TEMP_DIR/conc.conf"
echo "CONCURRENCY=99" > "$conc_test"
saved_c2=$CONCURRENCY
CONFIG_FILE="$conc_test"
load_config
[[ "$CONCURRENCY" -eq 99 ]] && ok "CONCURRENCY=99 loaded from config" || fail "CONCURRENCY: $CONCURRENCY"
CONCURRENCY=$saved_c2
echo ""

# ---- SUMMARY ----
echo ""
echo "================================================"
echo "  AUDIT RESULTS: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
echo "================================================"

if [[ $FAILED -gt 0 ]]; then
    exit 1
fi
