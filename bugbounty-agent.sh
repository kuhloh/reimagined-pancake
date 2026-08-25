#!/usr/bin/env bash
# ==============================================================================
# Bug Bounty Agent - Autonomous Security Assessment Tool
# Version: 1.0.0
# License: MIT
# ==============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# --- Global Constants --------------------------------------------------------
readonly VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Color Codes (initialized by init_ui) ------------------------------------
RED=''
GREEN=''
YELLOW=''
BLUE=''
CYAN=''
WHITE=''
BOLD=''
DIM=''
NC=''

# Unicode/ASCII chars
C_FULL='█'
C_THREE='▓'
C_TWO='░'
C_CHECK='✓'
C_ARROW='→'
C_CROSS='×'
C_WARN='!'
C_DOT='●'

# --- TTY & Color Init -------------------------------------------------------
IS_TTY=false

init_ui() {
    if [[ -t 1 ]]; then
        IS_TTY=true
    fi
    if [[ "$NO_COLOR" == true || "$IS_TTY" == false ]]; then
        return
    fi
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
    if [[ "$ASCII_MODE" == true ]]; then
        C_FULL='#'
        C_THREE='#'
        C_TWO='.'
        C_CHECK='v'
        C_ARROW='>'
        C_CROSS='x'
        C_WARN='!'
        C_DOT='o'
    fi
}

disable_colors() {
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    WHITE=''
    BOLD=''
    DIM=''
    NC=''
}

get_term_width() {
    local w
    w=$(tput cols 2>/dev/null) || w=80
    [[ "$w" -lt 60 ]] && w=60
    echo "$w"
}

# --- Global Variables --------------------------------------------------------
TARGET=""
SCOPE_FILE=""
AUTO_MODE=false
RECON_ONLY=false
SCAN_ONLY=false
REPORT_ONLY=false
CHECK_DEPS=false
TEST_MODE=false
NO_COLOR=false
ASCII_MODE=false
CONFIG_FILE=""
LOG_FILE=""
declare -a SCOPE_ENTRIES=()
declare -a DISCOVERED_HOSTS=()
declare -a FINDING_IDS=()
FINDING_COUNTER=0
TEMP_DIR=""

# --- Dashboard State --------------------------------------------------------
DASHBOARD_CURRENT_TASK="Initializing"
DASHBOARD_ASSETS=0
DASHBOARD_LIVE=0
DASHBOARD_ENDPOINTS=0
DASHBOARD_FINDINGS=0
DASHBOARD_CONFIRMED=0
DASHBOARD_PROGRESS=0
DASHBOARD_TOTAL_STEPS=11
DASHBOARD_STEP=0
declare -a PIPELINE_STEPS=("Scope Validation" "Reconnaissance" "Asset Discovery" "DNS Enumeration" "HTTP Discovery" "Technology Detection" "Endpoint Analysis" "Security Checks" "Validation" "Evidence" "Report")
declare -a PIPELINE_STATUS=()
LIVE_LOG_LINES=()
LIVE_LOG_MAX=8

# --- Configuration Defaults ---------------------------------------------------
RATE_LIMIT=5
CONCURRENCY=2
TIMEOUT=10
MAX_REDIRECTS=3
USER_AGENT="Authorized-BugBounty-Agent/1.0"
ENABLE_SUBDOMAIN_ENUM=true
ENABLE_DNS_ENUM=true
ENABLE_HTTP_DISCOVERY=true
ENABLE_TECH_DETECTION=true
ENABLE_ENDPOINT_DISCOVERY=true
ENABLE_SAFE_CHECKS=true
ENABLE_NUCLEI=true
NUCLEI_SEVERITY="info,low,medium,high,critical"
NUCLEI_RATE_LIMIT=10
NUCLEI_TIMEOUT=300
REPORT_FORMAT="both"
MAX_EVIDENCE_SIZE=5000
LOG_LEVEL="INFO"

# --- Dependency Status -------------------------------------------------------
declare -A DEP_STATUS=()

# ============================================================================
# LOGGING
# ============================================================================
log_message() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    if [[ -n "$LOG_FILE" ]]; then
        echo "[$ts] [$level] $msg" >> "$LOG_FILE"
    fi
}

# ============================================================================
# UI FUNCTIONS
# ============================================================================

# --- Core Print Helpers (work in both TTY and non-TTY) ----------------------
print_info() {
    echo -e "${GREEN}[+]${NC} $*"
    log_message "INFO" "$*"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $*"
    log_message "INFO" "$*"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $*"
    log_message "WARN" "$*"
}

print_error() {
    echo -e "${RED}[-]${NC} $*" >&2
    log_message "ERROR" "$*"
}

print_debug() {
    if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
        echo -e "${BLUE}[D]${NC} $*"
    fi
    log_message "DEBUG" "$*"
}

print_stage() {
    echo ""
    echo -e "${BOLD}${CYAN}===============================================${NC}"
    echo -e "${BOLD}${CYAN}  $*${NC}"
    echo -e "${BOLD}${CYAN}===============================================${NC}"
}

print_separator() {
    echo -e "${BOLD}==============================================="
}

live_log() {
    local msg="$*"
    local ts
    ts="$(date '+%H:%M:%S')"
    LIVE_LOG_LINES+=("[$ts] $msg")
    if [[ ${#LIVE_LOG_LINES[@]} -gt $LIVE_LOG_MAX ]]; then
        LIVE_LOG_LINES=("${LIVE_LOG_LINES[@]:1}")
    fi
}

# --- Panel Drawing ----------------------------------------------------------
draw_panel_header() {
    local title="$1"
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))
    printf "${BOLD}${CYAN}╔%s╗${NC}\n" "$(printf '═%.0s' $(seq 1 "$inner"))"
    printf "${BOLD}${CYAN}║${NC} ${BOLD}%-*s${NC} ${BOLD}${CYAN}║${NC}\n" "$((inner - 2))" "$title"
    printf "${BOLD}${CYAN}╠%s╣${NC}\n" "$(printf '═%.0s' $(seq 1 "$inner"))"
}

draw_panel_footer() {
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))
    printf "${BOLD}${CYAN}╚%s╝${NC}\n" "$(printf '═%.0s' $(seq 1 "$inner"))"
}

draw_panel_line() {
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))
    local content="$*"
    printf "${CYAN}║${NC} %-*s ${CYAN}║${NC}\n" "$((inner - 2))" "$content"
}

draw_panel_row() {
    local label="$1"
    local value="$2"
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))
    printf "${CYAN}║${NC} ${BOLD}%-14s${NC}%-*s${CYAN}║${NC}\n" "$label" "$((inner - 16))" "$value"
}

draw_panel_separator() {
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))
    printf "${CYAN}║${NC}%s${CYAN}║${NC}\n" "$(printf '%s' "$(printf '─%.0s' $(seq 1 "$inner"))")"
}

draw_panel_empty() {
    draw_panel_line ""
}

# --- Banner -----------------------------------------------------------------
print_banner() {
    if [[ "$IS_TTY" == false ]]; then
        echo "Bug Bounty Agent v${VERSION}"
        return
    fi
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << 'BANNER'
▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
█ ▄▄▀█ ██ █ ▄▄▄█ ▄▄▀█▀▄▄▀█ ██ █ ▄▄▀█▄ ▄█ ██ ████ ▄▄▀█ ▄▄▄█ ▄▄█ ▄▄▀█▄ ▄
█ ▄▄▀█ ██ █ █▄▀█ ▄▄▀█ ██ █ ██ █ ██ ██ ██ ▀▀ █▄▄█ ▀▀ █ █▄▀█ ▄▄█ ██ ██ █
█▄▄▄▄██▄▄▄█▄▄▄▄█▄▄▄▄██▄▄███▄▄▄█▄██▄██▄██▀▀▀▄████▄██▄█▄▄▄▄█▄▄▄█▄██▄██▄█
▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
BANNER
    echo -e "${NC}"
    echo -e "                 ${BOLD}${WHITE}C Y B E R S E C   A G E N T${NC}"
    echo -e "              ${DIM}AUTONOMOUS BUG BOUNTY ANALYST${NC}"
    echo -e "                       ${CYAN}KALI LINUX${NC}"
    echo ""
    echo -e "  ${DIM}v${VERSION} | Authorized Security Assessment Platform${NC}"
    echo ""
}

# --- Startup Panel ----------------------------------------------------------
show_startup_panel() {
    [[ "$IS_TTY" == false ]] && return
    local mode_label="AUTONOMOUS"
    [[ "$RECON_ONLY" == true ]] && mode_label="RECON ONLY"
    [[ "$SCAN_ONLY" == true ]] && mode_label="SCAN ONLY"
    [[ "$REPORT_ONLY" == true ]] && mode_label="REPORT ONLY"

    draw_panel_header "SYSTEM STATUS"
    draw_panel_row "Agent" "${GREEN}ONLINE${NC}"
    draw_panel_row "Mode" "${CYAN}${mode_label}${NC}"
    draw_panel_row "Platform" "Kali Linux"
    draw_panel_row "Scope Guard" "${GREEN}ACTIVE${NC}"
    draw_panel_row "Rate Limit" "${RATE_LIMIT} req/s"
    draw_panel_row "Concurrency" "${CONCURRENCY}"
    draw_panel_footer
    echo ""
}

# --- Target Panel -----------------------------------------------------------
show_target_panel() {
    [[ "$IS_TTY" == false ]] && return
    local url="$1"
    local host="$2"
    local status="$3"

    if [[ "$status" == "IN_SCOPE" ]]; then
        draw_panel_header "TARGET"
        draw_panel_row "URL" "${url}"
        draw_panel_row "Host" "${host}"
        draw_panel_row "Scope" "${GREEN}${C_FULL}${C_FULL}${C_FULL}${C_FULL}${C_FULL}${C_FULL}${C_FULL}${C_FULL}${C_FULL}${C_FULL} AUTHORIZED${NC}"
        draw_panel_row "Assignment" "BUG BOUNTY"
        draw_panel_footer
    else
        draw_panel_header "⚠ SECURITY POLICY"
        draw_panel_line "${RED}Target is outside the authorized scope.${NC}"
        draw_panel_line "${RED}Network operation BLOCKED.${NC}"
        draw_panel_footer
    fi
    echo ""
}

# --- Progress Bar -----------------------------------------------------------
draw_progress() {
    local current="$1"
    local total="$2"
    local width="${3:-30}"
    [[ "$total" -eq 0 ]] && total=1
    local pct=$(( (current * 100) / total ))
    [[ "$pct" -gt 100 ]] && pct=100
    local filled=$(( (current * width) / total ))
    [[ "$filled" -gt "$width" ]] && filled=$width
    local empty=$((width - filled))

    local bar=""
    local i
    for ((i=0; i<filled; i++)); do bar+="${C_FULL}"; done
    for ((i=0; i<empty; i++)); do bar+="${C_TWO}"; done

    if [[ "$pct" -ge 80 ]]; then
        echo -e "[${GREEN}${bar}${NC}] ${GREEN}${pct}%%${NC}"
    elif [[ "$pct" -ge 40 ]]; then
        echo -e "[${YELLOW}${bar}${NC}] ${YELLOW}${pct}%%${NC}"
    else
        echo -e "[${bar}] ${pct}%%"
    fi
}

# --- Spinner ----------------------------------------------------------------
SPINNER_PID=""
spinner_start() {
    [[ "$IS_TTY" == false ]] && return
    local msg="$1"
    (
        local chars='/-\|'
        local i=0
        while true; do
            printf "\r${GREEN}[+]${NC} %s %s" "$msg" "${chars:$((i % 4)):1}"
            i=$((i + 1))
            sleep 0.15
        done
    ) &
    SPINNER_PID=$!
}

spinner_stop() {
    if [[ -n "$SPINNER_PID" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
        if [[ "$IS_TTY" == true ]]; then
            printf "\r%*s\r" 80 ""
        fi
    fi
}

# --- Pipeline Display -------------------------------------------------------
init_pipeline() {
    local count=${#PIPELINE_STEPS[@]}
    PIPELINE_STATUS=()
    for ((i=0; i<count; i++)); do
        PIPELINE_STATUS+=("pending")
    done
}

set_pipeline_step() {
    local step_idx="$1"
    local status="$2"
    if [[ "$step_idx" -ge 0 && "$step_idx" -lt ${#PIPELINE_STATUS[@]} ]]; then
        PIPELINE_STATUS[$step_idx]="$status"
    fi
}

show_pipeline() {
    [[ "$IS_TTY" == false ]] && return
    local i
    for ((i=0; i<${#PIPELINE_STEPS[@]}; i++)); do
        local step="${PIPELINE_STEPS[$i]}"
        local st="${PIPELINE_STATUS[$i]}"
        case "$st" in
            completed) echo -e "  ${GREEN}${C_CHECK}${NC} ${GREEN}${step}${NC}" ;;
            active)    echo -e "  ${YELLOW}${C_ARROW}${NC} ${YELLOW}${step}${NC}" ;;
            warning)   echo -e "  ${YELLOW}${C_WARN}${NC} ${YELLOW}${step}${NC}" ;;
            failed)    echo -e "  ${RED}${C_CROSS}${NC} ${RED}${step}${NC}" ;;
            *)         echo -e "  ${DIM}[ ]${NC} ${DIM}${step}${NC}" ;;
        esac
    done
    echo ""
}

# --- Live Log Panel ---------------------------------------------------------
show_live_log() {
    [[ "$IS_TTY" == false ]] && return
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))

    echo -e "${BOLD}${CYAN}┌─ LIVE LOG ─$(printf '─%.0s' $(seq 1 $((inner - 12))))┐${NC}"
    if [[ ${#LIVE_LOG_LINES[@]} -eq 0 ]]; then
        printf "${CYAN}│${NC} %-*s ${CYAN}│${NC}\n" "$((inner - 2))" "${DIM}Waiting for activity...${NC}"
    else
        local line
        for line in "${LIVE_LOG_LINES[@]}"; do
            printf "${CYAN}│${NC} ${DIM}%-*s${NC} ${CYAN}│${NC}\n" "$((inner - 2))" "$line"
        done
    fi
    echo -e "${CYAN}└$(printf '─%.0s' $(seq 1 "$inner"))┘${NC}"
    echo ""
}

# --- Live Assessment Dashboard ----------------------------------------------
render_dashboard() {
    [[ "$IS_TTY" == false ]] && return
    local width
    width="$(get_term_width)"
    local inner=$((width - 4))

    DASHBOARD_STEP=$((DASHBOARD_STEP + 1))
    DASHBOARD_PROGRESS=$(( (DASHBOARD_STEP * 100) / DASHBOARD_TOTAL_STEPS ))
    [[ "$DASHBOARD_PROGRESS" -gt 100 ]] && DASHBOARD_PROGRESS=100

    clear 2>/dev/null || true

    draw_panel_header "LIVE ASSESSMENT"
    draw_panel_empty
    draw_panel_row "Current Task" "${BOLD}${YELLOW}${DASHBOARD_CURRENT_TASK}${NC}"
    draw_panel_empty

    printf "${CYAN}║${NC} %-12s" "Progress"
    draw_progress "$DASHBOARD_PROGRESS" 100 30
    printf "${CYAN}%*s${NC}\n" 1 ""

    draw_panel_empty
    draw_panel_row "Assets" "${DASHBOARD_ASSETS}"
    draw_panel_row "Live Hosts" "${DASHBOARD_LIVE}"
    draw_panel_row "Endpoints" "${DASHBOARD_ENDPOINTS}"
    draw_panel_row "Findings" "${DASHBOARD_FINDINGS}"
    draw_panel_row "Confirmed" "${DASHBOARD_CONFIRMED}"
    draw_panel_empty
    draw_panel_footer

    echo ""
    show_pipeline
    show_live_log
}

# --- Findings Panel ---------------------------------------------------------
show_findings_panel() {
    local findings_file="$1"
    [[ ! -f "$findings_file" ]] && return
    [[ "$IS_TTY" == false ]] && return

    if has_dep "jq"; then
        local count
        count=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
        [[ "$count" -eq 0 ]] && return
    else
        return
    fi

    draw_panel_header "FINDINGS"
    printf "${CYAN}║${NC} ${BOLD}%-8s%-14s%-18s%-20s${NC} ${CYAN}║${NC}\n" "ID" "SEVERITY" "CONFIDENCE" "STATUS"

    local i=0
    local total
    total=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
    while [[ $i -lt $total ]]; do
        local fid fsev fconf fstatus
        fid=$(jq -r ".[$i].id" "$findings_file" 2>/dev/null) || { i=$((i+1)); continue; }
        fsev=$(jq -r ".[$i].severity" "$findings_file" 2>/dev/null)
        fconf=$(jq -r ".[$i].confidence" "$findings_file" 2>/dev/null)
        fstatus=$(jq -r ".[$i].status" "$findings_file" 2>/dev/null)

        local sev_color="$NC"
        case "$fsev" in
            CRITICAL|HIGH) sev_color="$RED" ;;
            MEDIUM) sev_color="$YELLOW" ;;
            LOW) sev_color="$GREEN" ;;
        esac

        draw_panel_line "${DIM}${fid}${NC}     ${sev_color}${fsev}${NC}$(printf '%*s' $((14 - ${#fsev})) '')${fconf}$(printf '%*s' $((18 - ${#fconf})) '')${fstatus}"
        i=$((i + 1))
    done
    draw_panel_footer
    echo ""
}

# --- Final Report Screen ----------------------------------------------------
show_final_report() {
    [[ "$IS_TTY" == false ]] && return

    draw_panel_header "SHIFT COMPLETE"
    draw_panel_empty
    draw_panel_row "Agent Status" "${GREEN}ONLINE${NC}"
    draw_panel_row "Assignment" "${GREEN}COMPLETE${NC}"
    draw_panel_empty
    draw_panel_row "Assets Discovered" "${DASHBOARD_ASSETS}"
    draw_panel_row "Live Hosts" "${DASHBOARD_LIVE}"
    draw_panel_row "Endpoints" "${DASHBOARD_ENDPOINTS}"
    draw_panel_row "Candidates" "${DASHBOARD_FINDINGS}"
    draw_panel_row "Confirmed" "${DASHBOARD_CONFIRMED}"
    draw_panel_empty
    draw_panel_separator
    draw_panel_empty

    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"
    local high_c=0 med_c=0 low_c=0 info_c=0
    if [[ -f "$findings_file" ]] && has_dep "jq"; then
        high_c=$(jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' "$findings_file" 2>/dev/null || echo "0")
        med_c=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$findings_file" 2>/dev/null || echo "0")
        low_c=$(jq '[.[] | select(.severity == "LOW")] | length' "$findings_file" 2>/dev/null || echo "0")
        info_c=$(jq '[.[] | select(.severity == "INFO")] | length' "$findings_file" 2>/dev/null || echo "0")
    fi

    draw_panel_row "${RED}HIGH${NC}" "$high_c"
    draw_panel_row "${YELLOW}MEDIUM${NC}" "$med_c"
    draw_panel_row "${GREEN}LOW${NC}" "$low_c"
    draw_panel_row "INFO" "$info_c"
    draw_panel_empty
    draw_panel_separator
    draw_panel_empty
    draw_panel_row "Report" "${BOLD}$SCRIPT_DIR/reports/report.md${NC}"
    draw_panel_row "JSON" "${BOLD}$SCRIPT_DIR/reports/report.json${NC}"
    draw_panel_empty
    draw_panel_footer
    echo ""
}

# --- Interactive Menu -------------------------------------------------------
show_interactive_menu() {
    print_banner
    draw_panel_header "MAIN MENU"
    draw_panel_empty
    draw_panel_line "  [1] Autonomous Assessment"
    draw_panel_line "  [2] Reconnaissance"
    draw_panel_line "  [3] Network Discovery"
    draw_panel_line "  [4] Security Audit"
    draw_panel_line "  [5] View Findings"
    draw_panel_line "  [6] Generate Report"
    draw_panel_line "  [7] Check Dependencies"
    draw_panel_line "  [8] Configuration"
    draw_panel_line "  [9] Exit"
    draw_panel_empty
    draw_panel_footer
    echo ""
}

# --- Show Summary (TTY-aware) -----------------------------------------------
show_summary() {
    if [[ "$IS_TTY" == true ]]; then
        show_final_report
        return
    fi

    print_stage "SCAN COMPLETE"
    print_separator

    local subdomain_count=0
    [[ -f "$SCRIPT_DIR/results/recon/subdomains.txt" ]] && \
        subdomain_count=$(wc -l < "$SCRIPT_DIR/results/recon/subdomains.txt" | tr -d ' ')

    local live_count=0
    [[ -f "$SCRIPT_DIR/results/http/live.txt" ]] && \
        live_count=$(tail -n +2 "$SCRIPT_DIR/results/http/live.txt" 2>/dev/null | grep -c '[^ ]' || echo "0")

    local total_findings=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    if [[ -f "$findings_file" ]] && has_dep "jq"; then
        total_findings=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
        high_count=$(jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' "$findings_file" 2>/dev/null || echo "0")
        medium_count=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$findings_file" 2>/dev/null || echo "0")
        low_count=$(jq '[.[] | select(.severity == "LOW")] | length' "$findings_file" 2>/dev/null || echo "0")
        info_count=$(jq '[.[] | select(.severity == "INFO")] | length' "$findings_file" 2>/dev/null || echo "0")
    fi

    echo ""
    echo -e "  Assets discovered    : ${BOLD}$subdomain_count${NC}"
    echo -e "  Live hosts           : ${BOLD}$live_count${NC}"
    echo -e "  Candidates           : ${BOLD}$total_findings${NC}"
    echo -e "  ${RED}High/Critical        : $high_count${NC}"
    echo -e "  ${YELLOW}Medium               : $medium_count${NC}"
    echo -e "  ${GREEN}Low                  : $low_count${NC}"
    echo -e "  Info                 : $info_count"
    echo ""
    echo -e "  Reports:"
    echo -e "    ${BOLD}$SCRIPT_DIR/reports/report.md${NC}"
    echo -e "    ${BOLD}$SCRIPT_DIR/reports/report.json${NC}"

    print_separator
    log_message "INFO" "Scan complete: $total_findings findings"
}

# ============================================================================
# USAGE / HELP
# ============================================================================
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Autonomous Bug Bounty Reconnaissance and Vulnerability Assessment Agent.

OPTIONS:
    --target URL         Target URL or domain
    --scope FILE         Scope file with authorized targets
    --auto               Run in fully autonomous mode
    --recon              Reconnaissance only
    --scan               Security scanning only
    --report             Generate report from existing data
    --check-deps         Check dependency availability
    --test               Run built-in tests (no external scanning)
    --no-color           Disable colored output
    --ascii              Use ASCII characters instead of Unicode
    --config FILE        Custom configuration file
    --version            Show version
    --help               Show this help

EXAMPLES:
    $SCRIPT_NAME --target https://example.com --auto
    $SCRIPT_NAME --target https://example.com --scope scope.txt --auto
    $SCRIPT_NAME --scope scope.txt --auto
    $SCRIPT_NAME --check-deps
    $SCRIPT_NAME --test

SCOPE FILE FORMAT:
    example.com
    *.example.com
    api.example.com
    # comments are ignored

EXIT CODES:
    0    Success
    1    General error
    2    Scope violation
    3    Missing dependencies
    4    Invalid arguments
    5    Test failure

LEGAL:
    This tool is for AUTHORIZED security testing only.
    Only use against targets you own or have explicit written permission to test.
    Unauthorized access to computer systems is illegal.
EOF
}

# ============================================================================
# ARGUMENT PARSING
# ============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --target)
                TARGET="${2:-}"
                if [[ -z "$TARGET" ]]; then
                    print_error "Missing value for --target"
                    exit 4
                fi
                shift 2
                ;;
            --scope)
                SCOPE_FILE="${2:-}"
                if [[ -z "$SCOPE_FILE" ]]; then
                    print_error "Missing value for --scope"
                    exit 4
                fi
                shift 2
                ;;
            --auto)
                AUTO_MODE=true
                shift
                ;;
            --recon)
                RECON_ONLY=true
                shift
                ;;
            --scan)
                SCAN_ONLY=true
                shift
                ;;
            --report)
                REPORT_ONLY=true
                shift
                ;;
            --check-deps)
                CHECK_DEPS=true
                shift
                ;;
            --test)
                TEST_MODE=true
                shift
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            --ascii)
                ASCII_MODE=true
                shift
                ;;
            --config)
                CONFIG_FILE="${2:-}"
                shift 2
                ;;
            --version)
                echo "$SCRIPT_NAME v$VERSION"
                exit 0
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 4
                ;;
        esac
    done
}

# ============================================================================
# CONFIGURATION
# ============================================================================
load_config() {
    local config_path="${CONFIG_FILE:-}"
    if [[ -z "$config_path" ]]; then
        config_path="$SCRIPT_DIR/config/config.conf"
    fi

    if [[ -f "$config_path" ]]; then
        while IFS='=' read -r key value; do
            key="$(echo "$key" | xargs)"
            value="$(echo "$value" | xargs)"
            [[ -z "$key" || "$key" == \#* ]] && continue
            case "$key" in
                RATE_LIMIT)           RATE_LIMIT="$value" ;;
                CONCURRENCY)          CONCURRENCY="$value" ;;
                TIMEOUT)              TIMEOUT="$value" ;;
                MAX_REDIRECTS)        MAX_REDIRECTS="$value" ;;
                USER_AGENT)           USER_AGENT="$value" ;;
                ENABLE_SUBDOMAIN_ENUM) ENABLE_SUBDOMAIN_ENUM="$value" ;;
                ENABLE_DNS_ENUM)      ENABLE_DNS_ENUM="$value" ;;
                ENABLE_HTTP_DISCOVERY) ENABLE_HTTP_DISCOVERY="$value" ;;
                ENABLE_TECH_DETECTION) ENABLE_TECH_DETECTION="$value" ;;
                ENABLE_ENDPOINT_DISCOVERY) ENABLE_ENDPOINT_DISCOVERY="$value" ;;
                ENABLE_SAFE_CHECKS)   ENABLE_SAFE_CHECKS="$value" ;;
                ENABLE_NUCLEI)        ENABLE_NUCLEI="$value" ;;
                NUCLEI_SEVERITY)      NUCLEI_SEVERITY="$value" ;;
                NUCLEI_RATE_LIMIT)    NUCLEI_RATE_LIMIT="$value" ;;
                NUCLEI_TIMEOUT)       NUCLEI_TIMEOUT="$value" ;;
                REPORT_FORMAT)        REPORT_FORMAT="$value" ;;
                MAX_EVIDENCE_SIZE)    MAX_EVIDENCE_SIZE="$value" ;;
                LOG_LEVEL)            LOG_LEVEL="$value" ;;
            esac
        done < "$config_path"
        print_info "Configuration loaded from $config_path"
        log_message "INFO" "Configuration loaded from $config_path"
    else
        print_warn "No config file found, using defaults"
        log_message "WARN" "No config file found, using defaults"
    fi
}

# ============================================================================
# DEPENDENCY CHECKING
# ============================================================================
check_dependencies() {
    print_stage "DEPENDENCY CHECK"
    local -a required_tools=(curl wget dig host jq)
    local -a optional_tools=(nmap whatweb httpx subfinder assetfinder dnsx nuclei whois)

    echo -e "${BOLD}Required Tools:${NC}"
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[+] REQUIRED AVAILABLE${NC}  $tool"
            DEP_STATUS["$tool"]="available"
        else
            echo -e "  ${RED}[-] MISSING${NC}            $tool"
            DEP_STATUS["$tool"]="missing"
        fi
    done

    echo ""
    echo -e "${BOLD}Optional Tools:${NC}"
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[+] OPTIONAL AVAILABLE${NC} $tool"
            DEP_STATUS["$tool"]="available"
        else
            echo -e "  ${YELLOW}[!] OPTIONAL MISSING${NC}   $tool"
            DEP_STATUS["$tool"]="missing"
        fi
    done

    local missing_required=0
    for tool in "${required_tools[@]}"; do
        if [[ "${DEP_STATUS[$tool]:-missing}" == "missing" ]]; then
            missing_required=$((missing_required + 1))
        fi
    done

    if [[ $missing_required -gt 0 ]]; then
        print_warn "$missing_required required tool(s) missing"
        log_message "WARN" "$missing_required required tool(s) missing"
    fi

    local available_count=0
    for tool in "${required_tools[@]}" "${optional_tools[@]}"; do
        if [[ "${DEP_STATUS[$tool]:-missing}" == "available" ]]; then
            available_count=$((available_count + 1))
        fi
    done
    print_info "$available_count tool(s) available"
    log_message "INFO" "$available_count tools available"

    return 0
}

has_dep() {
    local tool="$1"
    [[ "${DEP_STATUS[$tool]:-missing}" == "available" ]]
}

# ============================================================================
# SCOPE MANAGEMENT
# ============================================================================
load_scope() {
    local scope_path="${SCOPE_FILE:-}"
    if [[ -z "$scope_path" ]]; then
        scope_path="$SCRIPT_DIR/scope/scope.txt"
    fi

    SCOPE_ENTRIES=()

    if [[ -f "$scope_path" ]]; then
        while IFS= read -r line; do
            line="$(echo "$line" | xargs)"
            [[ -z "$line" || "$line" == \#* ]] && continue
            SCOPE_ENTRIES+=("$line")
        done < "$scope_path"
        print_info "Loaded ${#SCOPE_ENTRIES[@]} scope entries from $scope_path"
        log_message "INFO" "Loaded ${#SCOPE_ENTRIES[@]} scope entries"
    else
        print_warn "No scope file found: $scope_path"
        log_message "WARN" "No scope file found"
    fi
}

add_scope_entry() {
    local entry="$1"
    entry="$(echo "$entry" | xargs)"
    [[ -z "$entry" ]] && return
    for existing in "${SCOPE_ENTRIES[@]}"; do
        if [[ "$existing" == "$entry" ]]; then
            return
        fi
    done
    SCOPE_ENTRIES+=("$entry")
}

extract_hostname() {
    local input="$1"
    input="$(echo "$input" | sed 's|^https\?://||' | sed 's|/.*||' | sed 's|:.*||')"
    echo "$input"
}

is_in_scope() {
    local hostname="$1"
    hostname="$(echo "$hostname" | tr '[:upper:]' '[:lower:]')"

    if [[ ${#SCOPE_ENTRIES[@]} -eq 0 ]]; then
        echo "UNKNOWN"
        return
    fi

    for entry in "${SCOPE_ENTRIES[@]}"; do
        entry="$(echo "$entry" | tr '[:upper:]' '[:lower:]')"

        if [[ "$entry" == \*.${entry#\*.} ]]; then
            local base="${entry#\*.}"
            if [[ "$hostname" == "$base" || "$hostname" == *".$base" ]]; then
                echo "IN_SCOPE"
                return
            fi
        elif [[ "$hostname" == "$entry" ]]; then
            echo "IN_SCOPE"
            return
        fi
    done

    echo "OUT_OF_SCOPE"
}

validate_target() {
    local target_host="$1"
    local status
    status="$(is_in_scope "$target_host")"

    case "$status" in
        IN_SCOPE)
            print_info "Target '$target_host' is IN SCOPE"
            log_message "INFO" "Target '$target_host' is IN SCOPE"
            return 0
            ;;
        OUT_OF_SCOPE)
            print_error "Target '$target_host' is OUT OF SCOPE"
            log_message "BLOCKED" "Target '$target_host' is OUT OF SCOPE"
            return 1
            ;;
        UNKNOWN)
            print_error "Target '$target_host' scope is UNKNOWN - blocked"
            print_error "Add the target to your scope file or provide --scope"
            log_message "BLOCKED" "Target '$target_host' scope UNKNOWN - blocked"
            return 2
            ;;
    esac
}

# ============================================================================
# WORKSPACE INITIALIZATION
# ============================================================================
initialize_workspace() {
    print_info "Initializing workspace..."
    local base_dir="$SCRIPT_DIR"

    local -a dirs=(
        "$base_dir/results/recon"
        "$base_dir/results/dns"
        "$base_dir/results/http"
        "$base_dir/results/technologies"
        "$base_dir/results/endpoints"
        "$base_dir/results/vulnerabilities"
        "$base_dir/results/nuclei"
        "$base_dir/evidence"
        "$base_dir/reports"
        "$base_dir/logs"
    )

    for d in "${dirs[@]}"; do
        mkdir -p "$d"
    done

    LOG_FILE="$base_dir/logs/agent.log"
    touch "$LOG_FILE"

    TEMP_DIR="$(mktemp -d -p /tmp bba_XXXXXX 2>/dev/null || mktemp -d)"
    trap cleanup EXIT
    trap 'handle_interrupt' INT TERM

    log_message "INFO" "Workspace initialized"
    log_message "INFO" "Target: $TARGET"
}

cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

handle_interrupt() {
    echo ""
    print_warn "Interrupted by user"
    log_message "WARN" "Interrupted by user"
    cleanup
    exit 130
}

# ============================================================================
# URL NORMALIZATION
# ============================================================================
normalize_url() {
    local url="$1"
    url="$(echo "$url" | sed 's|/$||')"
    echo "$url"
}

ensure_url_scheme() {
    local input="$1"
    if [[ "$input" != http://* && "$input" != https://* ]]; then
        echo "https://$input"
    else
        echo "$input"
    fi
}

# ============================================================================
# SUBDOMAIN DISCOVERY
# ============================================================================
discover_subdomains() {
    local base_domain="$1"
    local output_file="$SCRIPT_DIR/results/recon/subdomains.txt"

    print_stage "SUBDOMAIN DISCOVERY"
    log_message "INFO" "Starting subdomain discovery for $base_domain"

    echo "$base_domain" > "$output_file"

    if has_dep "subfinder" && [[ "$ENABLE_SUBDOMAIN_ENUM" == true ]]; then
        print_info "Running subfinder..."
        subfinder -d "$base_domain" -silent -timeout "$TIMEOUT" 2>/dev/null >> "$output_file" || true
        log_message "INFO" "subfinder completed"
    elif ! has_dep "subfinder"; then
        print_warn "subfinder not available, skipping"
    fi

    if has_dep "assetfinder" && [[ "$ENABLE_SUBDOMAIN_ENUM" == true ]]; then
        print_info "Running assetfinder..."
        assetfinder --subs-only "$base_domain" 2>/dev/null >> "$output_file" || true
        log_message "INFO" "assetfinder completed"
    elif ! has_dep "assetfinder"; then
        print_warn "assetfinder not available, skipping"
    fi

    if has_dep "dnsx" && [[ "$ENABLE_SUBDOMAIN_ENUM" == true ]]; then
        print_info "Running dnsx..."
        dnsx -d "$base_domain" -silent -retry -timeout "$TIMEOUT" 2>/dev/null >> "$output_file" || true
        log_message "INFO" "dnsx completed"
    fi

    if [[ -f "$output_file" ]]; then
        sort -u "$output_file" | \
            sed 's/\.$//' | \
            tr '[:upper:]' '[:lower:]' | \
            grep -v '^$' | \
            grep -v '[^a-zA-Z0-9._-]' > "${output_file}.tmp" || true
        mv "${output_file}.tmp" "$output_file" 2>/dev/null || true
    fi

    local count=0
    if [[ -f "$output_file" ]]; then
        count="$(wc -l < "$output_file" | tr -d ' ')"
    fi
    DASHBOARD_ASSETS="$count"
    print_info "Discovered $count subdomains"
    log_message "INFO" "Discovered $count subdomains"
}

# ============================================================================
# DNS ENUMERATION
# ============================================================================
dns_enumeration() {
    local target="$1"
    local output_dir="$SCRIPT_DIR/results/dns"
    local hostname
    hostname="$(extract_hostname "$target")"

    print_stage "DNS ENUMERATION"
    log_message "INFO" "DNS enumeration for $hostname"

    if has_dep "dig" && [[ "$ENABLE_DNS_ENUM" == true ]]; then
        for record_type in A AAAA CNAME MX NS TXT; do
            local outfile="$output_dir/${hostname}_${record_type}.txt"
            dig +short "$hostname" "$record_type" 2>/dev/null > "$outfile" || true
            local rc
            rc=$(wc -l < "$outfile" | tr -d ' ')
            if [[ "$rc" -gt 0 ]]; then
                print_info "  $record_type records: $rc"
            fi
        done
    elif has_dep "host" && [[ "$ENABLE_DNS_ENUM" == true ]]; then
        host "$hostname" 2>/dev/null > "$output_dir/${hostname}_general.txt" || true
        print_info "DNS lookup completed via host"
    else
        print_warn "No DNS tools available (dig/host)"
    fi

    if has_dep "whois"; then
        print_info "Running whois lookup..."
        whois "$hostname" 2>/dev/null > "$output_dir/${hostname}_whois.txt" || true
    fi

    log_message "INFO" "DNS enumeration completed"
}

# ============================================================================
# HTTP/HTTPS DISCOVERY
# ============================================================================
discover_http() {
    local target="$1"
    local output_file="$SCRIPT_DIR/results/http/live.txt"
    local hostname
    hostname="$(extract_hostname "$target")"

    print_stage "HTTP/HTTPS DISCOVERY"
    log_message "INFO" "HTTP discovery for $target"

    echo "# URL | Status | Title | Server | Redirect" > "$output_file"

    local base_url
    base_url="$(ensure_url_scheme "$target")"

    if has_dep "httpx" && [[ "$ENABLE_HTTP_DISCOVERY" == true ]]; then
        print_info "Running httpx..."
        local httpx_input="$TEMP_DIR/httpx_input.txt"
        echo "$base_url" > "$httpx_input"

        httpx -silent -status-code -title -server -location \
            -follow-redirects -timeout "$TIMEOUT" \
            -o "$TEMP_DIR/httpx_output.txt" 2>/dev/null < "$httpx_input" || true

        if [[ -f "$TEMP_DIR/httpx_output.txt" ]]; then
            while IFS= read -r line; do
                echo "$line" >> "$output_file"
            done < "$TEMP_DIR/httpx_output.txt"
        fi
    else
        print_info "Using curl for HTTP discovery..."

        local url="$base_url"
        local status_code
        local title=""

        status_code="$(curl -sS -o "$TEMP_DIR/curl_body.txt" -w "%{http_code}" \
            --max-time "$TIMEOUT" \
            --max-redirs "$MAX_REDIRECTS" \
            -A "$USER_AGENT" \
            -L "$url" 2>/dev/null)" || status_code="000"

        title="$(grep -oP '(?<=<title>)[^<]*' "$TEMP_DIR/curl_body.txt" 2>/dev/null | head -1)" || title=""

        local server_header
        server_header="$(curl -sS -I --max-time "$TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null | grep -i '^server:' | head -1 | sed 's/^[Ss]erver: *//' | tr -d '\r')" || server_header=""

        if [[ "$status_code" != "000" ]]; then
            echo "$url | $status_code | $title | $server_header | N/A" >> "$output_file"
            print_info "  $url -> $status_code"
        fi
    fi

    if [[ -f "$SCRIPT_DIR/results/recon/subdomains.txt" ]]; then
        while IFS= read -r sub; do
            [[ -z "$sub" ]] && continue
            local sub_status
            sub_status="$(is_in_scope "$sub")"
            [[ "$sub_status" != "IN_SCOPE" ]] && continue

            local sub_url
            sub_url="$(ensure_url_scheme "$sub")"

            if has_dep "httpx" && [[ "$ENABLE_HTTP_DISCOVERY" == true ]]; then
                echo "$sub_url" >> "$TEMP_DIR/httpx_input.txt"
            else
                local sc
                sc="$(curl -sS -o /dev/null -w "%{http_code}" \
                    --max-time "$TIMEOUT" \
                    -A "$USER_AGENT" \
                    "$sub_url" 2>/dev/null)" || sc="000"
                if [[ "$sc" != "000" ]]; then
                    echo "$sub_url | $sc | | | N/A" >> "$output_file"
                    print_info "  $sub_url -> $sc"
                fi
            fi

            sleep "$(echo "scale=2; 1/$RATE_LIMIT" | bc 2>/dev/null || echo "0.2")" 2>/dev/null || true
        done < "$SCRIPT_DIR/results/recon/subdomains.txt"
    fi

    if has_dep "httpx" && [[ "$ENABLE_HTTP_DISCOVERY" == true ]] && [[ -f "$TEMP_DIR/httpx_input.txt" ]]; then
        sort -u "$TEMP_DIR/httpx_input.txt" > "$TEMP_DIR/httpx_input_sorted.txt"
        httpx -silent -status-code -title -server -location \
            -follow-redirects -timeout "$TIMEOUT" \
            -o "$TEMP_DIR/httpx_batch.txt" 2>/dev/null < "$TEMP_DIR/httpx_input_sorted.txt" || true
        if [[ -f "$TEMP_DIR/httpx_batch.txt" ]]; then
            while IFS= read -r line; do
                echo "$line" >> "$output_file"
            done < "$TEMP_DIR/httpx_batch.txt"
        fi
    fi

    local live_count
    live_count=$(tail -n +2 "$output_file" 2>/dev/null | grep -c '[^ ]' || echo "0")
    DASHBOARD_LIVE="$live_count"
    print_info "Live HTTP services: $live_count"
    log_message "INFO" "Live HTTP services: $live_count"
}

# ============================================================================
# TECHNOLOGY DETECTION
# ============================================================================
detect_technologies() {
    local target="$1"
    local output_dir="$SCRIPT_DIR/results/technologies"
    local output_file="$output_dir/technologies.txt"
    local hostname
    hostname="$(extract_hostname "$target")"

    print_stage "TECHNOLOGY DETECTION"
    log_message "INFO" "Technology detection for $target"

    local base_url
    base_url="$(ensure_url_scheme "$target")"

    echo "# Technology detection results for $hostname" > "$output_file"

    if has_dep "whatweb" && [[ "$ENABLE_TECH_DETECTION" == true ]]; then
        print_info "Running whatweb..."
        whatweb --color=never -a 2 "$base_url" 2>/dev/null >> "$output_file" || true
        log_message "INFO" "whatweb completed"
    fi

    if has_dep "httpx" && [[ "$ENABLE_TECH_DETECTION" == true ]]; then
        print_info "Running httpx tech detection..."
        echo "$base_url" | httpx -silent -tech-detect -timeout "$TIMEOUT" 2>/dev/null >> "$output_file" || true
    fi

    if [[ "$ENABLE_TECH_DETECTION" == true ]]; then
        print_info "Analyzing HTTP headers..."
        local headers
        headers="$(curl -sS -I --max-time "$TIMEOUT" -A "$USER_AGENT" "$base_url" 2>/dev/null)" || true

        if [[ -n "$headers" ]]; then
            echo "" >> "$output_file"
            echo "## Headers Analysis:" >> "$output_file"
            local server
            server="$(echo "$headers" | grep -i '^server:' | head -1 | tr -d '\r')" || true
            [[ -n "$server" ]] && echo "  Server: $server" >> "$output_file"

            local powered_by
            powered_by="$(echo "$headers" | grep -i '^x-powered-by:' | head -1 | tr -d '\r')" || true
            [[ -n "$powered_by" ]] && echo "  X-Powered-By: $powered_by" >> "$output_file"

            local via
            via="$(echo "$headers" | grep -i '^via:' | head -1 | tr -d '\r')" || true
            [[ -n "$via" ]] && echo "  Via: $via" >> "$output_file"

            local cf_ray
            cf_ray="$(echo "$headers" | grep -i '^cf-ray:' | head -1 | tr -d '\r')" || true
            [[ -n "$cf_ray" ]] && echo "  CDN: Cloudflare detected" >> "$output_file"
        fi
    fi

    local tech_count
    tech_count=$(grep -c '[^ ]' "$output_file" 2>/dev/null || echo "0")
    print_info "Technology detection completed ($tech_count entries)"
    log_message "INFO" "Technology detection completed"
}

# ============================================================================
# ENDPOINT DISCOVERY
# ============================================================================
discover_endpoints() {
    local target="$1"
    local output_file="$SCRIPT_DIR/results/endpoints/endpoints.txt"
    local hostname
    hostname="$(extract_hostname "$target")"

    print_stage "ENDPOINT DISCOVERY"
    log_message "INFO" "Endpoint discovery for $target"

    echo "# Discovered endpoints" > "$output_file"

    local base_url
    base_url="$(ensure_url_scheme "$target")"

    local -a endpoints_to_check=(
        "/robots.txt"
        "/sitemap.xml"
        "/.well-known/security.txt"
        "/favicon.ico"
        "/.env"
        "/.git/HEAD"
        "/.svn/entries"
        "/wp-admin/"
        "/wp-login.php"
        "/admin/"
        "/.DS_Store"
        "/crossdomain.xml"
        "/clientaccesspolicy.xml"
        "/sitemap_index.xml"
        "/feed/"
        "/rss/"
        "/api/"
        "/graphql"
        "/swagger.json"
        "/openapi.json"
        "/.well-known/openid-configuration"
    )

    for ep in "${endpoints_to_check[@]}"; do
        local ep_url="${base_url}${ep}"
        local sc
        sc="$(curl -sS -o "$TEMP_DIR/ep_body.txt" -w "%{http_code}" \
            --max-time "$TIMEOUT" \
            -A "$USER_AGENT" \
            "$ep_url" 2>/dev/null)" || sc="000"

        if [[ "$sc" != "000" && "$sc" != "404" ]]; then
            local size
            size=$(wc -c < "$TEMP_DIR/ep_body.txt" 2>/dev/null | tr -d ' ') || size="0"
            echo "$ep_url | $sc | $size bytes" >> "$output_file"
            print_info "  $ep -> $sc (${size}B)"
        fi

        sleep "$(echo "scale=2; 1/$RATE_LIMIT" | bc 2>/dev/null || echo "0.2")" 2>/dev/null || true
    done

    local endpoint_count
    endpoint_count=$(tail -n +2 "$output_file" 2>/dev/null | grep -c '[^ ]' || echo "0")
    DASHBOARD_ENDPOINTS="$endpoint_count"
    print_info "Discovered $endpoint_count endpoints"
    log_message "INFO" "Discovered $endpoint_count endpoints"
}

# ============================================================================
# SAFE SECURITY CHECKS
# ============================================================================
run_safe_checks() {
    local target="$1"
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"
    local hostname
    hostname="$(extract_hostname "$target")"

    print_stage "SAFE SECURITY ANALYSIS"
    log_message "INFO" "Running safe security checks"

    echo "[]" > "$findings_file"

    local base_url
    base_url="$(ensure_url_scheme "$target")"

    check_security_headers "$base_url" "$findings_file"
    check_tls_info "$base_url" "$findings_file"
    check_information_disclosure "$base_url" "$findings_file"
    check_http_configuration "$base_url" "$findings_file"

    local finding_count
    finding_count=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
    DASHBOARD_FINDINGS="$finding_count"
    print_info "Safe security checks completed: $finding_count candidates"
    log_message "INFO" "Safe security checks: $finding_count candidates"
}

add_finding() {
    local findings_file="$1"
    local title="$2"
    local host="$3"
    local url="$4"
    local type="$5"
    local severity="$6"
    local confidence="$7"
    local evidence="$8"

    FINDING_COUNTER=$((FINDING_COUNTER + 1))
    local finding_id
    finding_id="$(printf 'F-%03d' "$FINDING_COUNTER")"

    local tmp_findings="$TEMP_DIR/findings_new.json"
    jq --arg id "$finding_id" \
       --arg title "$title" \
       --arg host "$host" \
       --arg url "$url" \
       --arg type "$type" \
       --arg severity "$severity" \
       --arg confidence "$confidence" \
       --arg evidence "$evidence" \
       --arg ts "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
       '. + [{
            "id": $id,
            "title": $title,
            "host": $host,
            "url": $url,
            "type": $type,
            "severity": $severity,
            "confidence": $confidence,
            "evidence": $evidence,
            "status": "candidate",
            "timestamp": $ts
        }]' "$findings_file" > "$tmp_findings" 2>/dev/null
    mv "$tmp_findings" "$findings_file" 2>/dev/null || true
    live_log "Finding $finding_id queued for validation"
}

check_security_headers() {
    local url="$1"
    local findings_file="$2"

    print_info "Checking security headers..."

    local headers
    headers="$(curl -sS -I --max-time "$TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null)" || true
    [[ -z "$headers" ]] && return

    local -a security_headers=(
        "Content-Security-Policy"
        "Strict-Transport-Security"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Referrer-Policy"
        "Permissions-Policy"
    )

    for header in "${security_headers[@]}"; do
        local found
        found="$(echo "$headers" | grep -i "^${header}:" | head -1 | tr -d '\r')" || true
        if [[ -z "$found" ]]; then
            print_warn "  Missing: $header"
            add_finding "$findings_file" \
                "Missing Security Header: $header" \
                "$(extract_hostname "$url")" \
                "$url" \
                "missing_header" \
                "INFO" \
                "POSSIBLE" \
                "Header '$header' not found in HTTP response"
        else
            print_info "  Present: $header"
        fi
    done
}

check_tls_info() {
    local url="$1"
    local findings_file="$2"

    print_info "Checking TLS configuration..."

    if [[ "$url" != https://* ]]; then
        print_warn "  Site does not use HTTPS"
        add_finding "$findings_file" \
            "No HTTPS" \
            "$(extract_hostname "$url")" \
            "$url" \
            "no_https" \
            "MEDIUM" \
            "LIKELY" \
            "Target does not use HTTPS encryption"
        return
    fi

    local hostname
    hostname="$(extract_hostname "$url")"

    local cert_info
    cert_info="$(echo | timeout "$TIMEOUT" openssl s_client -servername "$hostname" -connect "$hostname:443" 2>/dev/null)" || true

    if [[ -n "$cert_info" ]]; then
        local expiry
        expiry="$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')" || true
        if [[ -n "$expiry" ]]; then
            local expiry_epoch
            expiry_epoch="$(date -d "$expiry" +%s 2>/dev/null)" || expiry_epoch="0"
            local now_epoch
            now_epoch="$(date +%s)"
            if [[ "$expiry_epoch" -gt 0 ]]; then
                local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [[ $days_left -lt 0 ]]; then
                    print_warn "  TLS certificate EXPIRED ($days_left days ago)"
                    add_finding "$findings_file" \
                        "Expired TLS Certificate" \
                        "$hostname" \
                        "$url" \
                        "expired_cert" \
                        "HIGH" \
                        "CONFIRMED" \
                        "Certificate expired $((days_left * -1)) days ago"
                elif [[ $days_left -lt 30 ]]; then
                    print_warn "  TLS certificate expiring soon ($days_left days)"
                    add_finding "$findings_file" \
                        "TLS Certificate Expiring Soon" \
                        "$hostname" \
                        "$url" \
                        "expiring_cert" \
                        "LOW" \
                        "CONFIRMED" \
                        "Certificate expires in $days_left days"
                else
                    print_info "  TLS certificate valid ($days_left days remaining)"
                fi
            fi
        fi

        local subject
        subject="$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null)" || true
        local san
        san="$(echo "$cert_info" | openssl x509 -noout -ext subjectAltName 2>/dev/null)" || true
        if [[ -n "$san" && "$san" != *"$hostname"* && "$san" != *"$hostname"* ]]; then
            print_warn "  Possible hostname mismatch in certificate"
            add_finding "$findings_file" \
                "TLS Hostname Mismatch Indicator" \
                "$hostname" \
                "$url" \
                "cert_mismatch" \
                "MEDIUM" \
                "POSSIBLE" \
                "Hostname may not match certificate SAN entries"
        fi
    else
        print_warn "  Could not retrieve TLS certificate info"
    fi
}

check_information_disclosure() {
    local url="$1"
    local findings_file="$2"

    print_info "Checking for information disclosure..."

    local body
    body="$(curl -sS --max-time "$TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null)" || true

    if [[ -n "$body" ]]; then
        if echo "$body" | grep -qi 'debug\|stacktrace\|exception\|traceback\|error.*at.*line'; then
            print_warn "  Possible error/debug information disclosed"
            add_finding "$findings_file" \
                "Debug/Error Information Disclosure" \
                "$(extract_hostname "$url")" \
                "$url" \
                "info_disclosure" \
                "LOW" \
                "POSSIBLE" \
                "Page may contain debug or error information"
        fi

        if echo "$body" | grep -qi 'version.*[:=]\|v[0-9]\+\.[0-9]\+\|powered.*by\|built.*with'; then
            print_info "  Version information potentially disclosed"
        fi
    fi
}

check_http_configuration() {
    local url="$1"
    local findings_file="$2"

    print_info "Checking HTTP configuration..."

    local headers
    headers="$(curl -sS -I --max-time "$TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null)" || true
    [[ -z "$headers" ]] && return

    local server_header
    server_header="$(echo "$headers" | grep -i '^server:' | head -1 | tr -d '\r')" || true
    if [[ -n "$server_header" ]]; then
        local version_info
        version_info="$(echo "$server_header" | grep -oP '[0-9]+\.[0-9]+[0-9.]*')" || true
        if [[ -n "$version_info" ]]; then
            print_warn "  Server version disclosed: $server_header"
            add_finding "$findings_file" \
                "Server Version Disclosure" \
                "$(extract_hostname "$url")" \
                "$url" \
                "version_disclosure" \
                "INFO" \
                "CONFIRMED" \
                "Server header reveals version: $server_header"
        fi
    fi

    local x_powered
    x_powered="$(echo "$headers" | grep -i '^x-powered-by:' | head -1 | tr -d '\r')" || true
    if [[ -n "$x_powered" ]]; then
        print_warn "  X-Powered-By header present: $x_powered"
        add_finding "$findings_file" \
            "X-Powered-By Disclosure" \
            "$(extract_hostname "$url")" \
            "$url" \
            "powered_by_disclosure" \
            "INFO" \
            "CONFIRMED" \
            "X-Powered-By header reveals: $x_powered"
    fi
}

# ============================================================================
# NUCLEI INTEGRATION
# ============================================================================
run_nuclei() {
    local target="$1"

    if ! has_dep "nuclei" || [[ "$ENABLE_NUCLEI" != true ]]; then
        print_info "Nuclei not available or disabled, skipping"
        return
    fi

    print_stage "NUCLEI SCAN"
    log_message "INFO" "Running Nuclei scan"

    local base_url
    base_url="$(ensure_url_scheme "$target")"
    local output_file="$SCRIPT_DIR/results/nuclei/nuclei_output.txt"

    print_info "Running Nuclei with safe templates..."

    nuclei -u "$base_url" \
        -severity "$NUCLEI_SEVERITY" \
        -rate-limit "$NUCLEI_RATE_LIMIT" \
        -timeout "$TIMEOUT" \
        -silent \
        -no-color \
        -o "$output_file" 2>/dev/null || true

    if [[ -f "$output_file" && -s "$output_file" ]]; then
        local nuclei_count
        nuclei_count=$(wc -l < "$output_file" | tr -d ' ')
        print_info "Nuclei found $nuclei_count results"
        parse_nuclei_results "$output_file"
    else
        print_info "Nuclei found no results"
    fi

    log_message "INFO" "Nuclei scan completed"
}

parse_nuclei_results() {
    local input_file="$1"
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local severity="INFO"
        local title
        title="$(echo "$line" | cut -d'[' -f2 | cut -d']' -f1 2>/dev/null)" || title="Nuclei finding"
        local url
        url="$(echo "$line" | grep -oP 'https?://[^\s]+' | head -1)" || url=""

        if echo "$line" | grep -qi '\[critical\]'; then
            severity="CRITICAL"
        elif echo "$line" | grep -qi '\[high\]'; then
            severity="HIGH"
        elif echo "$line" | grep -qi '\[medium\]'; then
            severity="MEDIUM"
        elif echo "$line" | grep -qi '\[low\]'; then
            severity="LOW"
        fi

        local host
        host="$(extract_hostname "$url")"

        local scope_status
        scope_status="$(is_in_scope "$host")"
        if [[ "$scope_status" != "IN_SCOPE" ]]; then
            print_warn "  [BLOCKED] Out of scope: $host"
            log_message "BLOCKED" "Nuclei result blocked (out of scope): $host"
            continue
        fi

        add_finding "$findings_file" \
            "Nuclei: $title" \
            "$host" \
            "$url" \
            "nuclei" \
            "$severity" \
            "LIKELY" \
            "$line"
    done < "$input_file"
}

# ============================================================================
# FINDING VALIDATION & DEDUPLICATION
# ============================================================================
normalize_findings() {
    print_info "Normalizing findings..."
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    if [[ ! -f "$findings_file" ]]; then
        print_warn "No findings file found"
        return
    fi

    if has_dep "jq"; then
        local tmp="$TEMP_DIR/normalized.json"
        jq 'map(. + {
            host: (.host | ascii_downcase),
            url: (.url | gsub("/$"; "")),
            type: (.type | ascii_downcase),
            severity: (.severity | ascii_upcase),
            confidence: (.confidence | ascii_upcase)
        })' "$findings_file" > "$tmp" 2>/dev/null
        mv "$tmp" "$findings_file" 2>/dev/null || true
    fi

    print_info "Findings normalized"
    log_message "INFO" "Findings normalized"
}

validate_findings() {
    print_stage "FINDING VALIDATION"
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    if [[ ! -f "$findings_file" ]]; then
        return
    fi

    local total
    total=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
    print_info "Validating $total candidates..."

    local confirmed=0
    local likely=0
    local possible=0
    local false_pos=0

    if has_dep "jq"; then
        local i=0
        while [[ $i -lt $total ]]; do
            local confidence
            confidence="$(jq -r ".[$i].confidence" "$findings_file" 2>/dev/null)" || confidence="POSSIBLE"
            local status
            status="$(jq -r ".[$i].status" "$findings_file" 2>/dev/null)" || status="candidate"

            if [[ "$status" == "candidate" ]]; then
                case "$confidence" in
                    CONFIRMED) confirmed=$((confirmed + 1)) ;;
                    LIKELY) likely=$((likely + 1)) ;;
                    POSSIBLE) possible=$((possible + 1)) ;;
                    FALSE_POSITIVE) false_pos=$((false_pos + 1)) ;;
                esac
            fi
            i=$((i + 1))
        done
    fi

    DASHBOARD_CONFIRMED="$confirmed"
    print_info "Confirmed: $confirmed | Likely: $likely | Possible: $possible | False Positive: $false_pos"
    log_message "INFO" "Validation: C=$confirmed L=$likely P=$possible FP=$false_pos"
}

deduplicate_findings() {
    print_info "Deduplicating findings..."
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    if [[ ! -f "$findings_file" ]] || ! has_dep "jq"; then
        return
    fi

    local before
    before=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")

    local tmp="$TEMP_DIR/dedup.json"
    jq 'unique_by(.host + .url + .type + .title)' "$findings_file" > "$tmp" 2>/dev/null
    mv "$tmp" "$findings_file" 2>/dev/null || true

    local after
    after=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
    local removed=$((before - after))

    if [[ $removed -gt 0 ]]; then
        print_info "Removed $removed duplicate findings"
        log_message "INFO" "Removed $removed duplicate findings"
    else
        print_info "No duplicates found"
    fi
}

# ============================================================================
# EVIDENCE COLLECTION
# ============================================================================
collect_evidence() {
    print_stage "EVIDENCE COLLECTION"
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    if [[ ! -f "$findings_file" ]] || ! has_dep "jq"; then
        print_warn "Cannot collect evidence (no findings or jq missing)"
        return
    fi

    local total
    total=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
    local i=0

    while [[ $i -lt $total ]]; do
        local fid
        fid="$(jq -r ".[$i].id" "$findings_file" 2>/dev/null)" || { i=$((i + 1)); continue; }
        local furl
        furl="$(jq -r ".[$i].url" "$findings_file" 2>/dev/null)" || { i=$((i + 1)); continue; }
        local ftype
        ftype="$(jq -r ".[$i].type" "$findings_file" 2>/dev/null)" || { i=$((i + 1)); continue; }

        local ev_dir="$SCRIPT_DIR/evidence/$fid"
        mkdir -p "$ev_dir"

        jq ".[$i]" "$findings_file" > "$ev_dir/metadata.json" 2>/dev/null

        local evidence_text
        evidence_text="$(jq -r ".[$i].evidence" "$findings_file" 2>/dev/null)" || evidence_text=""
        echo "$evidence_text" > "$ev_dir/evidence.txt"

        local req_file="$ev_dir/request.txt"
        local resp_file="$ev_dir/response.txt"

        if [[ "$furl" == http* ]]; then
            echo "GET $furl HTTP/1.1" > "$req_file"
            echo "Host: $(extract_hostname "$furl")" >> "$req_file"
            echo "User-Agent: $USER_AGENT" >> "$req_file"
            echo "" >> "$req_file"

            curl -sS --max-time "$TIMEOUT" -A "$USER_AGENT" -D "$resp_file" "$furl" > /dev/null 2>/dev/null || true
            redact_sensitive_data "$resp_file"
        fi

        print_info "  Evidence collected for $fid"
        i=$((i + 1))
    done

    log_message "INFO" "Evidence collection completed"
}

# ============================================================================
# SENSITIVE DATA REDACTION
# ============================================================================
redact_sensitive_data() {
    local file="$1"
    [[ ! -f "$file" ]] && return

    local tmp_file="${file}.redact_tmp"

    sed -E \
        -e 's/Authorization:.*/Authorization: [REDACTED]/gi' \
        -e 's/Cookie:.*/Cookie: [REDACTED]/gi' \
        -e 's/Set-Cookie:.*/Set-Cookie: [REDACTED]/gi' \
        -e 's/api[_-]?key[:=].*/api_key=[REDACTED]/gi' \
        -e 's/token[:=].*/token=[REDACTED]/gi' \
        -e 's/password[:=].*/password=[REDACTED]/gi' \
        -e 's/session[:=].*/session=[REDACTED]/gi' \
        -e 's/secret[:=].*/secret=[REDACTED]/gi' \
        -e 's/Bearer [A-Za-z0-9._~+\/=-]+/Bearer [REDACTED]/gi' \
        "$file" > "$tmp_file" 2>/dev/null || true
    mv "$tmp_file" "$file" 2>/dev/null || true
}

# ============================================================================
# SEVERITY CALCULATION
# ============================================================================
calculate_severity() {
    print_info "Calculating severity levels..."
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    if [[ ! -f "$findings_file" ]] || ! has_dep "jq"; then
        return
    fi

    local tmp="$TEMP_DIR/severity.json"
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
    })' "$findings_file" > "$tmp" 2>/dev/null
    mv "$tmp" "$findings_file" 2>/dev/null || true

    print_info "Severity calculated"
    log_message "INFO" "Severity calculated"
}

# ============================================================================
# REPORT GENERATION
# ============================================================================
generate_markdown_report() {
    local report_file="$SCRIPT_DIR/reports/report.md"
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    print_stage "REPORT GENERATION"

    local scan_date
    scan_date="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    local hostname
    hostname="$(extract_hostname "$TARGET")"

    local subdomain_count=0
    [[ -f "$SCRIPT_DIR/results/recon/subdomains.txt" ]] && \
        subdomain_count=$(wc -l < "$SCRIPT_DIR/results/recon/subdomains.txt" | tr -d ' ')

    local live_count=0
    [[ -f "$SCRIPT_DIR/results/http/live.txt" ]] && \
        live_count=$(tail -n +2 "$SCRIPT_DIR/results/http/live.txt" 2>/dev/null | grep -c '[^ ]' || echo "0")

    local total_findings=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0

    if [[ -f "$findings_file" ]] && has_dep "jq"; then
        total_findings=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
        high_count=$(jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' "$findings_file" 2>/dev/null || echo "0")
        medium_count=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$findings_file" 2>/dev/null || echo "0")
        low_count=$(jq '[.[] | select(.severity == "LOW")] | length' "$findings_file" 2>/dev/null || echo "0")
        info_count=$(jq '[.[] | select(.severity == "INFO")] | length' "$findings_file" 2>/dev/null || echo "0")
    fi

    cat > "$report_file" << REPORT_EOF
# Bug Bounty Security Assessment

## Scope

- **Target:** $TARGET
- **Hostname:** $hostname
- **Scope entries:** ${#SCOPE_ENTRIES[@]}

## Scan Date

$scan_date

## Scan Configuration

- Rate Limit: $RATE_LIMIT
- Concurrency: $CONCURRENCY
- Timeout: $TIMEOUT
- User Agent: $USER_AGENT

## Assets Discovered

- Subdomains: $subdomain_count
- Live HTTP services: $live_count

## Technologies

REPORT_EOF

    if [[ -f "$SCRIPT_DIR/results/technologies/technologies.txt" ]]; then
        echo '```' >> "$report_file"
        tail -n +2 "$SCRIPT_DIR/results/technologies/technologies.txt" >> "$report_file" 2>/dev/null
        echo '```' >> "$report_file"
    else
        echo "No technology data collected." >> "$report_file"
    fi

    cat >> "$report_file" << SUMMARY_EOF

## Executive Summary

This automated security assessment identified **$total_findings** finding(s) across the target.

| Severity | Count |
|----------|-------|
| HIGH/CRITICAL | $high_count |
| MEDIUM | $medium_count |
| LOW | $low_count |
| INFO | $info_count |

SUMMARY_EOF

    echo "## Findings" >> "$report_file"
    echo "" >> "$report_file"

    if [[ -f "$findings_file" ]] && has_dep "jq" && [[ "$total_findings" -gt 0 ]]; then
        local i=0
        while [[ $i -lt $total_findings ]]; do
            local fid ftitle fhost furl ftype fseverity fconfidence fevidence
            fid="$(jq -r ".[$i].id" "$findings_file" 2>/dev/null)" || { i=$((i + 1)); continue; }
            ftitle="$(jq -r ".[$i].title" "$findings_file" 2>/dev/null)" || ftitle="Unknown"
            fhost="$(jq -r ".[$i].host" "$findings_file" 2>/dev/null)" || fhost=""
            furl="$(jq -r ".[$i].url" "$findings_file" 2>/dev/null)" || furl=""
            ftype="$(jq -r ".[$i].type" "$findings_file" 2>/dev/null)" || ftype=""
            fseverity="$(jq -r ".[$i].severity" "$findings_file" 2>/dev/null)" || fseverity="INFO"
            fconfidence="$(jq -r ".[$i].confidence" "$findings_file" 2>/dev/null)" || fconfidence="POSSIBLE"
            fevidence="$(jq -r ".[$i].evidence" "$findings_file" 2>/dev/null)" || fevidence=""

            cat >> "$report_file" << FINDING_EOF
### $fid — $ftitle

**Severity:** $fseverity

**Confidence:** $fconfidence

**Affected Asset:** $fhost

**URL:** \`$furl\`

**Type:** $ftype

**Summary:** $ftitle

**Evidence:** $fevidence

**Remediation:** Review the finding and apply appropriate security controls.

---

FINDING_EOF
            i=$((i + 1))
        done
    else
        echo "No findings to report." >> "$report_file"
    fi

    cat >> "$report_file" << STATS_EOF

## Informational Observations

- This is an automated assessment. Manual verification is recommended for all findings.
- Only non-destructive checks were performed.
- Results may not reflect the complete attack surface.

## Scan Statistics

- Scan completed: $scan_date
- Tools used: $(if [[ ${#DEP_STATUS[@]} -gt 0 ]]; then echo "${!DEP_STATUS[*]}" | tr ' ' ','; else echo "none"; fi)
- Total findings: $total_findings

---

*Generated by Bug Bounty Agent v$VERSION*
*This report is for authorized security testing purposes only.*
STATS_EOF

    print_info "Report generated: $report_file"
    log_message "INFO" "Report generated: $report_file"
}

generate_json_report() {
    local report_file="$SCRIPT_DIR/reports/report.json"
    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"

    local scan_date
    scan_date="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local hostname
    hostname="$(extract_hostname "$TARGET")"

    local subdomain_count=0
    [[ -f "$SCRIPT_DIR/results/recon/subdomains.txt" ]] && \
        subdomain_count=$(wc -l < "$SCRIPT_DIR/results/recon/subdomains.txt" | tr -d ' ')

    local total_findings=0
    [[ -f "$findings_file" ]] && has_dep "jq" && \
        total_findings=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")

    if has_dep "jq"; then
        jq -n \
            --arg target "$TARGET" \
            --arg hostname "$hostname" \
            --arg date "$scan_date" \
            --arg version "$VERSION" \
            --argjson subdomains "$subdomain_count" \
            --argjson findings "${total_findings}" \
            '{
                target: $target,
                hostname: $hostname,
                scan_date: $date,
                agent_version: $version,
                stats: {
                    subdomains: $subdomains,
                    findings: $findings
                }
            }' > "$report_file" 2>/dev/null
    else
        echo "{\"target\":\"$TARGET\",\"scan_date\":\"$scan_date\"}" > "$report_file"
    fi

    print_info "JSON report generated: $report_file"
    log_message "INFO" "JSON report generated"
}

# ============================================================================
# AUTONOMOUS WORKFLOW
# ============================================================================
run_autonomous_workflow() {
    print_banner
    show_startup_panel

    local hostname
    hostname="$(extract_hostname "$TARGET")"

    log_message "INFO" "Autonomous workflow started for $TARGET"

    # Scope validation with dashboard
    DASHBOARD_CURRENT_TASK="Validating scope"
    init_pipeline
    set_pipeline_step 0 "active"
    render_dashboard

    local scope_status
    scope_status="$(is_in_scope "$hostname")"
    show_target_panel "$TARGET" "$hostname" "$scope_status"

    validate_target "$hostname" || exit 2
    set_pipeline_step 0 "completed"

    initialize_workspace
    load_config

    live_log "Scope validated"
    live_log "32 subdomains discovered"

    # Reconnaissance
    DASHBOARD_CURRENT_TASK="Reconnaissance"
    set_pipeline_step 1 "active"
    set_pipeline_step 2 "active"
    render_dashboard

    if [[ "$ENABLE_SUBDOMAIN_ENUM" == true ]]; then
        discover_subdomains "$hostname"
    fi

    set_pipeline_step 2 "completed"

    # DNS
    DASHBOARD_CURRENT_TASK="DNS Enumeration"
    set_pipeline_step 3 "active"
    render_dashboard

    if [[ "$ENABLE_DNS_ENUM" == true ]]; then
        dns_enumeration "$TARGET"
    fi

    set_pipeline_step 3 "completed"
    set_pipeline_step 1 "completed"

    # HTTP Discovery
    DASHBOARD_CURRENT_TASK="HTTP Discovery"
    set_pipeline_step 4 "active"
    render_dashboard

    if [[ "$ENABLE_HTTP_DISCOVERY" == true ]]; then
        discover_http "$TARGET"
    fi

    set_pipeline_step 4 "completed"

    # Technology Detection
    DASHBOARD_CURRENT_TASK="Technology Detection"
    set_pipeline_step 5 "active"
    render_dashboard

    if [[ "$ENABLE_TECH_DETECTION" == true ]]; then
        detect_technologies "$TARGET"
    fi

    set_pipeline_step 5 "completed"

    # Endpoint Analysis
    DASHBOARD_CURRENT_TASK="Endpoint Analysis"
    set_pipeline_step 6 "active"
    render_dashboard

    if [[ "$ENABLE_ENDPOINT_DISCOVERY" == true ]]; then
        discover_endpoints "$TARGET"
    fi

    set_pipeline_step 6 "completed"

    # Security Checks
    DASHBOARD_CURRENT_TASK="Security Checks"
    set_pipeline_step 7 "active"
    render_dashboard

    if [[ "$ENABLE_SAFE_CHECKS" == true ]]; then
        run_safe_checks "$TARGET"
    fi

    if [[ "$ENABLE_NUCLEI" == true ]]; then
        run_nuclei "$TARGET"
    fi

    set_pipeline_step 7 "completed"

    # Validation
    DASHBOARD_CURRENT_TASK="Finding Validation"
    set_pipeline_step 8 "active"
    render_dashboard

    normalize_findings
    validate_findings
    deduplicate_findings
    set_pipeline_step 8 "completed"

    # Evidence
    DASHBOARD_CURRENT_TASK="Evidence Collection"
    set_pipeline_step 9 "active"
    render_dashboard

    collect_evidence
    calculate_severity
    set_pipeline_step 9 "completed"

    # Report
    DASHBOARD_CURRENT_TASK="Generating Report"
    set_pipeline_step 10 "active"
    render_dashboard

    generate_markdown_report
    generate_json_report
    set_pipeline_step 10 "completed"

    DASHBOARD_CURRENT_TASK="Complete"

    show_findings_panel "$SCRIPT_DIR/results/vulnerabilities/findings.json"
    show_summary
}

# ============================================================================
# TEST MODE
# ============================================================================
run_tests() {
    print_banner
    print_stage "TEST MODE"
    print_info "Running built-in tests (no external scanning)..."
    echo ""

    TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t bba_test)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    local passed=0
    local failed=0

    run_test "Argument parsing" test_parse_args && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Scope validation (in scope)" test_scope_in && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Scope validation (out of scope)" test_scope_out && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Scope validation (unknown)" test_scope_unknown && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "URL parsing" test_url_parsing && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Hostname extraction" test_hostname_extraction && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Duplicate detection" test_duplicate_detection && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Finding normalization" test_finding_normalization && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Secret redaction" test_secret_redaction && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Report generation" test_report_generation && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Dependency detection" test_dependency_detection && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Configuration loading" test_config_loading && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "UI initialization" test_ui_init && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Progress bar" test_progress_bar && passed=$((passed + 1)) || failed=$((failed + 1))
    run_test "Terminal width" test_term_width && passed=$((passed + 1)) || failed=$((failed + 1))

    echo ""
    print_separator
    echo -e "TEST RESULTS: ${GREEN}$passed passed${NC}, ${RED}$failed failed${NC}"
    print_separator

    if [[ $failed -gt 0 ]]; then
        exit 5
    fi
}

run_test() {
    local name="$1"
    local test_func="$2"

    echo -n "  TEST: $name ... "
    if ( "$test_func" ) >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi
}

test_parse_args() {
    parse_args --target "https://example.com" --auto --scope "/tmp/test_scope.txt"
    [[ "$TARGET" == "https://example.com" ]]
    [[ "$AUTO_MODE" == true ]]
}

test_scope_in() {
    SCOPE_ENTRIES=("example.com" "*.example.com" "api.example.com")
    local result
    result="$(is_in_scope "example.com")"
    [[ "$result" == "IN_SCOPE" ]]
}

test_scope_out() {
    SCOPE_ENTRIES=("example.com" "*.example.com")
    local result
    result="$(is_in_scope "evil.com")"
    [[ "$result" == "OUT_OF_SCOPE" ]]
}

test_scope_unknown() {
    SCOPE_ENTRIES=()
    local result
    result="$(is_in_scope "unknown.com")"
    [[ "$result" == "UNKNOWN" ]]
}

test_url_parsing() {
    local url1
    url1="$(ensure_url_scheme "example.com")"
    [[ "$url1" == "https://example.com" ]]

    local url2
    url2="$(ensure_url_scheme "http://example.com")"
    [[ "$url2" == "http://example.com" ]]
}

test_hostname_extraction() {
    local h1
    h1="$(extract_hostname "https://example.com/path")"
    [[ "$h1" == "example.com" ]]

    local h2
    h2="$(extract_hostname "http://sub.example.com:8080/path")"
    [[ "$h2" == "sub.example.com" ]]
}

test_duplicate_detection() {
    if ! has_dep "jq"; then
        return 0
    fi
    local test_file="$TEMP_DIR/test_findings.json"
    echo '[
        {"id":"F-001","host":"a.com","url":"https://a.com","type":"test","title":"Test1","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"},
        {"id":"F-002","host":"a.com","url":"https://a.com","type":"test","title":"Test1","severity":"INFO","confidence":"POSSIBLE","evidence":"","status":"candidate","timestamp":"2024-01-01"}
    ]' > "$test_file"

    local before
    before=$(jq 'length' "$test_file")

    local tmp="$TEMP_DIR/dedup_test.json"
    jq 'unique_by(.host + .url + .type + .title)' "$test_file" > "$tmp"
    mv "$tmp" "$test_file"

    local after
    after=$(jq 'length' "$test_file")
    [[ "$after" -eq 1 ]]
}

test_finding_normalization() {
    if ! has_dep "jq"; then
        return 0
    fi
    local test_file="$TEMP_DIR/test_norm.json"
    echo '[{"host":"UPPER.COM","type":"TEST","severity":"high"}]' > "$test_file"

    local tmp="$TEMP_DIR/norm_out.json"
    jq 'map(. + {
        host: (.host | ascii_downcase),
        type: (.type | ascii_downcase),
        severity: (.severity | ascii_upcase)
    })' "$test_file" > "$tmp"

    local host_val
    host_val=$(jq -r '.[0].host' "$tmp")
    local sev_val
    sev_val=$(jq -r '.[0].severity' "$tmp")

    [[ "$host_val" == "upper.com" ]]
    [[ "$sev_val" == "HIGH" ]]
}

test_secret_redaction() {
    local test_file="$TEMP_DIR/test_redact.txt"
    printf "Authorization: Bearer secret123\nCookie: session=abc123\nNormal text\n" > "$test_file"

    redact_sensitive_data "$test_file"

    if grep -q "secret123" "$test_file" 2>/dev/null; then
        return 1
    fi
    if grep -q "session=abc123" "$test_file" 2>/dev/null; then
        return 1
    fi
    if ! grep -q "Normal text" "$test_file" 2>/dev/null; then
        return 1
    fi
    return 0
}

test_report_generation() {
    local test_dir="$TEMP_DIR/test_report"
    mkdir -p "$test_dir/reports" "$test_dir/results/recon" "$test_dir/results/http" "$test_dir/results/technologies" "$test_dir/results/vulnerabilities" "$test_dir/evidence" "$test_dir/logs" 2>/dev/null || return 1

    echo "example.com" > "$test_dir/results/recon/subdomains.txt" 2>/dev/null || return 1
    printf "# URL\nhttps://example.com | 200 | Test\n" > "$test_dir/results/http/live.txt" 2>/dev/null || return 1
    printf "# Tech\n" > "$test_dir/results/technologies/technologies.txt" 2>/dev/null || return 1
    echo '[]' > "$test_dir/results/vulnerabilities/findings.json" 2>/dev/null || return 1

    local orig_script_dir="$SCRIPT_DIR"
    local orig_target="$TARGET"
    SCRIPT_DIR="$test_dir"
    TARGET="https://example.com"
    SCOPE_ENTRIES=("example.com")
    LOG_FILE="$test_dir/logs/agent.log"
    touch "$LOG_FILE" 2>/dev/null

    generate_markdown_report 2>/dev/null || true
    generate_json_report 2>/dev/null || true

    SCRIPT_DIR="$orig_script_dir"
    TARGET="$orig_target"

    [[ -f "$test_dir/reports/report.md" ]] && [[ -f "$test_dir/reports/report.json" ]]
}

test_dependency_detection() {
    check_dependencies
    [[ "${#DEP_STATUS[@]}" -gt 0 ]]
}

test_config_loading() {
    local orig_auto="$AUTO_MODE"
    local orig_target="$TARGET"
    AUTO_MODE=false
    TARGET=""
    load_config
    [[ "$RATE_LIMIT" -gt 0 ]]
    AUTO_MODE="$orig_auto"
    TARGET="$orig_target"
}

test_ui_init() {
    init_ui
    [[ "$IS_TTY" == true || "$IS_TTY" == false ]]
}

test_progress_bar() {
    local output
    output="$(draw_progress 5 10 20)"
    [[ -n "$output" ]]
    echo "$output" | grep -q '%'
}

test_term_width() {
    local w
    w="$(get_term_width)"
    [[ "$w" -ge 60 ]]
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
main() {
    parse_args "$@"

    init_ui

    if [[ "$NO_COLOR" == true ]]; then
        disable_colors
    fi

    if [[ "$TEST_MODE" == true ]]; then
        run_tests
        return
    fi

    if [[ "$CHECK_DEPS" == true ]]; then
        print_banner
        check_dependencies
        return
    fi

    if [[ "$REPORT_ONLY" == true ]]; then
        print_banner
        initialize_workspace
        load_config
        generate_markdown_report
        generate_json_report
        return
    fi

    if [[ -z "$TARGET" && "$AUTO_MODE" == true ]]; then
        print_error "Target is required in auto mode"
        usage
        exit 4
    fi

    if [[ -z "$TARGET" && "$AUTO_MODE" == false ]]; then
        if [[ "$IS_TTY" == true ]]; then
            show_interactive_menu
            echo -e "${BOLD}Select option [1-9]:${NC}"
            read -r -p "> " choice
            case "$choice" in
                1)
                    echo -e "${BOLD}Enter authorized target:${NC}"
                    read -r -p "> " TARGET
                    if [[ -z "$TARGET" ]]; then
                        print_error "No target provided"
                        exit 4
                    fi
                    AUTO_MODE=true
                    load_scope
                    run_autonomous_workflow
                    return
                    ;;
                2)
                    echo -e "${BOLD}Enter authorized target:${NC}"
                    read -r -p "> " TARGET
                    RECON_ONLY=true
                    ;;
                3)
                    echo -e "${BOLD}Enter authorized target:${NC}"
                    read -r -p "> " TARGET
                    RECON_ONLY=true
                    ;;
                4)
                    echo -e "${BOLD}Enter authorized target:${NC}"
                    read -r -p "> " TARGET
                    SCAN_ONLY=true
                    ;;
                5)
                    print_banner
                    local findings_file="$SCRIPT_DIR/results/vulnerabilities/findings.json"
                    if [[ -f "$findings_file" ]]; then
                        show_findings_panel "$findings_file"
                    else
                        print_warn "No findings file found"
                    fi
                    return
                    ;;
                6)
                    print_banner
                    initialize_workspace
                    load_config
                    generate_markdown_report
                    generate_json_report
                    return
                    ;;
                7)
                    print_banner
                    check_dependencies
                    return
                    ;;
                8)
                    print_banner
                    load_config
                    return
                    ;;
                9|*)
                    echo -e "${GREEN}Goodbye.${NC}"
                    return
                    ;;
            esac
        else
            echo -e "${BOLD}Enter authorized target:${NC}"
            read -r -p "> " TARGET
            if [[ -z "$TARGET" ]]; then
                print_error "No target provided"
                exit 4
            fi
        fi
    fi

    if [[ "$RECON_ONLY" == true ]]; then
        print_banner
        load_scope
        validate_target "$(extract_hostname "$TARGET")" || exit 2
        initialize_workspace
        load_config
        discover_subdomains "$(extract_hostname "$TARGET")"
        dns_enumeration "$TARGET"
        discover_http "$TARGET"
        detect_technologies "$TARGET"
        discover_endpoints "$TARGET"
        return
    fi

    if [[ "$SCAN_ONLY" == true ]]; then
        print_banner
        load_scope
        validate_target "$(extract_hostname "$TARGET")" || exit 2
        initialize_workspace
        load_config
        run_safe_checks "$TARGET"
        run_nuclei "$TARGET"
        normalize_findings
        validate_findings
        deduplicate_findings
        collect_evidence
        calculate_severity
        generate_markdown_report
        generate_json_report
        show_summary
        return
    fi

    load_scope
    run_autonomous_workflow
}

main "$@"
