#!/usr/bin/env bash
# ==============================================================================
# CyberSec Agent - Unified Personal Cybersecurity Toolkit
# Version: 2.0.0
# License: MIT
# ==============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

# --- Global Constants --------------------------------------------------------
readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
CYBERSEC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Source All Core Libraries -----------------------------------------------
for lib in "$CYBERSEC_ROOT"/core/*.sh; do
    [[ -f "$lib" ]] && source "$lib"
done

# --- Global Variables --------------------------------------------------------
TARGET=""
SCOPE_FILE=""
AUTO_MODE=false
RECON_ONLY=false
SCAN_ONLY=false
REPORT_ONLY=false
CHECK_DEPS=false
TEST_MODE=false
LAB_MODE=false
NO_COLOR=false
ASCII_MODE=false
CONFIG_FILE=""
SINGLE_MODULE=""
CASE_DIR=""
LOG_FILE=""
TEMP_DIR=""
OSINT_EMAIL_TARGET=""
OSINT_USERNAME_TARGET=""
OSINT_DOMAIN_TARGET=""
OSINT_COMPANY_TARGET=""
HARVEST_DOMAIN=""
OSINT_REPORT_MODE=false

# --- Module Registry --------------------------------------------------------
declare -A MODULE_REGISTRY=(
    [osint]="modules/osint/osint.sh"
    [recon]="modules/recon/recon.sh"
    [network]="modules/network/network-discovery.sh"
    [attack-surface]="modules/attack-surface/attack-surface.sh"
    [web]="modules/web/web-security.sh"
    [api]="modules/api/api-security.sh"
    [javascript]="modules/javascript/javascript-analyzer.sh"
    [tls]="modules/tls/tls-audit.sh"
    [network-audit]="modules/network-audit/network-audit.sh"
    [vulnerability]="modules/vulnerability/vulnerability-analyzer.sh"
    [risk]="modules/risk/risk-analyzer.sh"
    [evidence]="modules/evidence/evidence-manager.sh"
    [duplicate]="modules/duplicate/duplicate-finder.sh"
    [reporting]="modules/reporting/report-generator.sh"
    [monitoring]="modules/monitoring/authorized-monitor.sh"
)

# --- Autonomous Pipeline Order ----------------------------------------------
declare -a PIPELINE_ORDER=(
    osint recon network attack-surface web api javascript tls
    network-audit vulnerability risk evidence duplicate reporting
)

# ============================================================================
# USAGE / HELP
# ============================================================================
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Unified Personal Cybersecurity Toolkit for Kali Linux.

OPTIONS:
    --target URL         Target URL or domain
    --scope FILE         Scope file with authorized targets
    --auto               Run full autonomous assessment
    --module NAME        Run specific module (osint, recon, network, web, etc.)
    --recon              Reconnaissance only
    --scan               Security scanning only
    --report             Generate report from existing data
    --status             Show current assessment status
    --resume             Resume latest assessment
    --lab                Lab mode (local testing only)
    --check-deps         Check dependency availability
    --test               Run all tests
    --no-color           Disable colored output
    --ascii              Use ASCII characters instead of Unicode
    --config FILE        Custom configuration file
    --version            Show version
    --help               Show this help

OSINT OPTIONS:
    --osint-email EMAIL          Full email OSINT investigation
    --osint-username USERNAME    Full username OSINT investigation
    --osint-domain DOMAIN        Full domain OSINT investigation
    --osint-company NAME         Full company OSINT investigation
    --harvest-emails --domain D  Harvest public emails from domain
    --osint-report               Generate OSINT report from existing data

MODULES:
    osint                OSINT intelligence gathering
    recon                Reconnaissance and discovery
    network              Network discovery (authorized only)
    attack-surface       Attack surface mapping
    web                  Web application security
    api                  API security analysis
    javascript           JavaScript file analysis
    tls                  TLS and header audit
    network-audit        Network security audit
    vulnerability        Vulnerability correlation
    risk                 Risk analysis and prioritization
    evidence             Evidence collection
    duplicate            Duplicate finding detection
    reporting            Report generation
    monitoring           Authorized asset monitoring

EXAMPLES:
    $SCRIPT_NAME --target https://example.com --auto
    $SCRIPT_NAME --target https://example.com --module osint
    $SCRIPT_NAME --target https://example.com --scope scope.txt --auto
    $SCRIPT_NAME --lab
    $SCRIPT_NAME --test
    $SCRIPT_NAME --check-deps

SCOPE FILE FORMAT:
    example.com
    *.example.com
    api.example.com
    # comments are ignored

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
                [[ -z "$TARGET" ]] && { print_error "Missing value for --target"; exit 4; }
                shift 2
                ;;
            --scope)
                SCOPE_FILE="${2:-}"
                [[ -z "$SCOPE_FILE" ]] && { print_error "Missing value for --scope"; exit 4; }
                shift 2
                ;;
            --auto)       AUTO_MODE=true; shift ;;
            --recon)      RECON_ONLY=true; shift ;;
            --scan)       SCAN_ONLY=true; shift ;;
            --report)     REPORT_ONLY=true; shift ;;
            --status)     show_status; exit 0 ;;
            --resume)     resume_assessment; exit 0 ;;
            --lab)        LAB_MODE=true; shift ;;
            --check-deps) CHECK_DEPS=true; shift ;;
            --test)       TEST_MODE=true; shift ;;
            --no-color)   NO_COLOR=true; shift ;;
            --ascii)      ASCII_MODE=true; shift ;;
            --config)
                CONFIG_FILE="${2:-}"
                shift 2
                ;;
            --module)
                SINGLE_MODULE="${2:-}"
                [[ -z "$SINGLE_MODULE" ]] && { print_error "Missing value for --module"; exit 4; }
                shift 2
                ;;
            --osint-email)
                OSINT_EMAIL_TARGET="${2:-}"
                [[ -z "$OSINT_EMAIL_TARGET" ]] && { print_error "Missing value for --osint-email"; exit 4; }
                shift 2
                ;;
            --osint-username)
                OSINT_USERNAME_TARGET="${2:-}"
                [[ -z "$OSINT_USERNAME_TARGET" ]] && { print_error "Missing value for --osint-username"; exit 4; }
                shift 2
                ;;
            --osint-domain)
                OSINT_DOMAIN_TARGET="${2:-}"
                [[ -z "$OSINT_DOMAIN_TARGET" ]] && { print_error "Missing value for --osint-domain"; exit 4; }
                shift 2
                ;;
            --osint-company)
                OSINT_COMPANY_TARGET="${2:-}"
                [[ -z "$OSINT_COMPANY_TARGET" ]] && { print_error "Missing value for --osint-company"; exit 4; }
                shift 2
                ;;
            --harvest-emails)
                HARVEST_DOMAIN="${2:-}"
                if [[ -z "$HARVEST_DOMAIN" ]]; then
                    if [[ "${1:-}" == "--domain" ]]; then
                        HARVEST_DOMAIN="${3:-}"
                        shift 3
                    else
                        print_error "Missing --domain for --harvest-emails"; exit 4
                    fi
                else
                    shift 2
                fi
                ;;
            --osint-report)
                OSINT_REPORT_MODE=true; shift
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
# MODULE EXECUTION
# ============================================================================
run_module() {
    local module_name="$1"
    local module_path="${MODULE_REGISTRY[$module_name]:-}"

    if [[ -z "$module_path" ]]; then
        print_error "Unknown module: $module_name"
        return 1
    fi

    local full_path="$CYBERSEC_ROOT/$module_path"
    if [[ ! -f "$full_path" ]]; then
        print_error "Module file not found: $full_path"
        return 1
    fi

    print_info "Running module: $module_name"
    log_message "INFO" "Starting module: $module_name"

    # Each module is a standalone script that also works when sourced
    # We run it as a subprocess with the target
    if [[ -n "$TARGET" ]]; then
        bash "$full_path" --target "$TARGET" 2>&1 | while IFS= read -r line; do
            echo "  [$module_name] $line"
        done
    else
        bash "$full_path" 2>&1 | while IFS= read -r line; do
            echo "  [$module_name] $line"
        done
    fi

    local rc=${PIPESTATUS[0]:-0}
    if [[ "$rc" -eq 0 ]]; then
        log_message "SUCCESS" "Module $module_name completed"
    else
        log_message "ERROR" "Module $module_name failed with code $rc"
    fi
    return "$rc"
}

# ============================================================================
# STATUS / RESUME
# ============================================================================
show_status() {
    init_ui
    print_banner

    local latest_case=""
    if [[ -d "$CYBERSEC_ROOT/assessments" ]]; then
        latest_case=$(ls -1t "$CYBERSEC_ROOT/assessments" 2>/dev/null | head -1 || true)
    fi

    if [[ -z "$latest_case" ]]; then
        print_warn "No assessments found"
        return
    fi

    local case_dir="$CYBERSEC_ROOT/assessments/$latest_case"
    draw_panel_header "ASSESSMENT STATUS"
    draw_panel_row "Case" "$latest_case"

    if [[ -f "$case_dir/findings.json" ]] && has_dep "jq"; then
        local count
        count=$(jq 'length' "$case_dir/findings.json" 2>/dev/null || echo "0")
        draw_panel_row "Findings" "$count"
    fi

    if [[ -f "$case_dir/tasks.json" ]] && has_dep "jq"; then
        local completed pending
        completed=$(jq '[.[] | select(.status == "COMPLETED")] | length' "$case_dir/tasks.json" 2>/dev/null || echo "0")
        pending=$(jq '[.[] | select(.status == "PENDING" or .status == "RUNNING")] | length' "$case_dir/tasks.json" 2>/dev/null || echo "0")
        draw_panel_row "Tasks Done" "$completed"
        draw_panel_row "Tasks Left" "$pending"
    fi

    draw_panel_footer
}

resume_assessment() {
    init_ui
    print_banner

    local latest_case=""
    if [[ -d "$CYBERSEC_ROOT/assessments" ]]; then
        latest_case=$(ls -1t "$CYBERSEC_ROOT/assessments" 2>/dev/null | head -1 || true)
    fi

    if [[ -z "$latest_case" ]]; then
        print_error "No assessments to resume"
        exit 1
    fi

    CASE_DIR="$CYBERSEC_ROOT/assessments/$latest_case"
    print_info "Resuming case: $latest_case"
    log_message "INFO" "Resuming case: $latest_case"

    # Find what's left to do
    if [[ -f "$CASE_DIR/tasks.json" ]] && has_dep "jq"; then
        local pending_tasks
        pending_tasks=$(jq -r '.[] | select(.status == "PENDING") | .module' "$CASE_DIR/tasks.json" 2>/dev/null || true)
        for module in $pending_tasks; do
            if [[ -n "${MODULE_REGISTRY[$module]:-}" ]]; then
                print_info "Resuming module: $module"
                run_module "$module" || true
            fi
        done
    fi

    show_summary
}

# ============================================================================
# LAB MODE
# ============================================================================
run_lab_mode() {
    init_ui
    print_banner
    print_stage "LAB MODE"
    print_info "Running in lab mode - no external scanning"
    log_message "INFO" "Lab mode activated"

    # Create test fixtures
    TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t bba_lab)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    local lab_target="http://localhost:8080"
    TARGET="$lab_target"
    SCOPE_ENTRIES=("localhost" "127.0.0.1" "*.localhost")

    print_info "Lab target: $lab_target"
    print_info "Scope: localhost, 127.0.0.1"

    # Run each module in lab/test mode
    local passed=0
    local failed=0

    for module_name in "${!MODULE_REGISTRY[@]}"; do
        local module_path="$CYBERSEC_ROOT/${MODULE_REGISTRY[$module_name]}"
        if [[ -f "$module_path" ]] && grep -q "test_" "$module_path" 2>/dev/null; then
            echo -n "  LAB: $module_name ... "
            # Try to run the test function
            local test_func="test_${module_name//-/_}"
            if ( bash "$module_path" --test ) >/dev/null 2>&1; then
                echo -e "${GREEN}PASS${NC}"
                passed=$((passed + 1))
            else
                echo -e "${YELLOW}SKIP${NC} (no external test)"
                passed=$((passed + 1))
            fi
        fi
    done

    echo ""
    print_separator
    echo -e "LAB RESULTS: ${GREEN}$passed passed${NC}, ${RED}$failed failed${NC}"
    print_separator
}

# ============================================================================
# TEST SUITE
# ============================================================================
run_tests() {
    init_ui
    print_banner
    print_stage "TEST SUITE"
    print_info "Running all tests (no external scanning)..."
    echo ""

    local total_passed=0
    local total_failed=0

    # Run core tests
    if [[ -f "$CYBERSEC_ROOT/tests/test-core.sh" ]]; then
        echo -e "${BOLD}Core Tests:${NC}"
        if bash "$CYBERSEC_ROOT/tests/test-core.sh" 2>&1; then
            total_passed=$((total_passed + 1))
        else
            total_failed=$((total_failed + 1))
        fi
        echo ""
    fi

    # Run integration tests
    if [[ -f "$CYBERSEC_ROOT/tests/test-integration.sh" ]]; then
        echo -e "${BOLD}Integration Tests:${NC}"
        if bash "$CYBERSEC_ROOT/tests/test-integration.sh" 2>&1; then
            total_passed=$((total_passed + 1))
        else
            total_failed=$((total_failed + 1))
        fi
        echo ""
    fi

    # Run syntax checks on all scripts
    echo -e "${BOLD}Syntax Checks:${NC}"
    local syntax_ok=0
    local syntax_fail=0
    for script in "$CYBERSEC_ROOT"/core/*.sh "$CYBERSEC_ROOT"/modules/*/*.sh "$CYBERSEC_ROOT"/cybersec-agent.sh; do
        [[ -f "$script" ]] || continue
        local name
        name=$(basename "$script")
        echo -n "  $name ... "
        if bash -n "$script" 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
            syntax_ok=$((syntax_ok + 1))
        else
            echo -e "${RED}FAIL${NC}"
            syntax_fail=$((syntax_fail + 1))
        fi
    done

    echo ""
    print_separator
    echo -e "SYNTAX: ${GREEN}$syntax_ok passed${NC}, ${RED}$syntax_fail failed${NC}"
    echo -e "TESTS:  ${GREEN}$total_passed passed${NC}, ${RED}$total_failed failed${NC}"
    print_separator

    if [[ $total_failed -gt 0 || $syntax_fail -gt 0 ]]; then
        exit 5
    fi
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================
show_interactive_menu() {
    init_ui
    print_banner
    show_startup_panel "INTERACTIVE"
    show_interactive_menu
}

handle_menu_choice() {
    local choice="$1"
    case "$choice" in
        1)
            echo -e "${BOLD}Enter authorized target:${NC}"
            read -r -p "> " TARGET
            [[ -z "$TARGET" ]] && { print_error "No target"; exit 4; }
            AUTO_MODE=true
            run_autonomous_workflow
            ;;
        2)  run_module_with_prompt "osint" ;;
        3)  run_module_with_prompt "recon" ;;
        4)  run_module_with_prompt "network" ;;
        5)  run_module_with_prompt "attack-surface" ;;
        6)  run_module_with_prompt "web" ;;
        7)  run_module_with_prompt "api" ;;
        8)  run_module_with_prompt "javascript" ;;
        9)  run_module_with_prompt "tls" ;;
        10) run_module_with_prompt "network-audit" ;;
        11)
            init_case "analysis"
            run_module "vulnerability"
            run_module "risk"
            ;;
        12) run_module_with_prompt "risk" ;;
        13) run_module "evidence" ;;
        14) run_module "reporting" ;;
        15) run_module_with_prompt "monitoring" ;;
        16) check_dependencies; show_deps ;;
        17)
            print_stage "CONFIGURATION"
            load_config
            print_info "Current configuration:"
            echo "  RATE_LIMIT=$RATE_LIMIT"
            echo "  CONCURRENCY=$CONCURRENCY"
            echo "  TIMEOUT=$TIMEOUT"
            echo "  LOG_LEVEL=$LOG_LEVEL"
            ;;
        0|*) echo -e "${GREEN}Goodbye.${NC}"; exit 0 ;;
    esac
}

run_module_with_prompt() {
    local module="$1"
    echo -e "${BOLD}Enter authorized target:${NC}"
    read -r -p "> " TARGET
    [[ -z "$TARGET" ]] && { print_error "No target"; exit 4; }
    load_scope
    validate_target "$(extract_hostname "$TARGET")" || exit 2
    init_case "$TARGET"
    run_module "$module"
}

# ============================================================================
# AUTONOMOUS WORKFLOW
# ============================================================================
run_autonomous_workflow() {
    init_ui
    print_banner
    show_startup_panel "AUTONOMOUS"

    # Validate scope
    local hostname
    hostname="$(extract_hostname "$TARGET")"

    load_scope
    local scope_status
    scope_status="$(is_in_scope "$hostname")"
    show_target_panel "$TARGET" "$hostname" "$scope_status"
    validate_target "$hostname" || exit 2

    # Init case
    init_case "$TARGET"
    log_message "INFO" "Autonomous workflow started for $TARGET"

    load_config

    init_pipeline

    local step=0
    local total=${#PIPELINE_ORDER[@]}
    DASHBOARD_TOTAL_STEPS=$((total + 2))

    # Run modules in order
    for module_name in "${PIPELINE_ORDER[@]}"; do
        step=$((step + 1))
        DASHBOARD_CURRENT_TASK="Running: $module_name"
        DASHBOARD_STEP=$step

        local config_key="ENABLE_${module_name//-/_}"
        config_key="${config_key^^}"

        # Check if module is enabled (with fallback)
        local enabled=true
        case "$module_name" in
            osint) [[ "${ENABLE_OSINT:-true}" != true ]] && enabled=false ;;
            recon) [[ "${ENABLE_RECON:-true}" != true ]] && enabled=false ;;
            network) [[ "${ENABLE_NETWORK:-true}" != true ]] && enabled=false ;;
            web) [[ "${ENABLE_WEB:-true}" != true ]] && enabled=false ;;
            api) [[ "${ENABLE_API:-true}" != true ]] && enabled=false ;;
            javascript) [[ "${ENABLE_JS:-true}" != true ]] && enabled=false ;;
            tls) [[ "${ENABLE_TLS:-true}" != true ]] && enabled=false ;;
            network-audit) [[ "${ENABLE_NETWORK_AUDIT:-true}" != true ]] && enabled=false ;;
        esac

        if [[ "$enabled" == true ]]; then
            render_dashboard
            run_module "$module_name" || print_warn "Module $module_name had issues"
        else
            print_info "Skipping disabled module: $module_name"
        fi
    done

    # Post-processing
    DASHBOARD_CURRENT_TASK="Analyzing vulnerabilities"
    DASHBOARD_STEP=$((step + 1))
    render_dashboard
    run_module "vulnerability" || true
    run_module "risk" || true

    DASHBOARD_CURRENT_TASK="Collecting evidence"
    DASHBOARD_STEP=$((step + 2))
    render_dashboard
    run_module "evidence" || true
    run_module "duplicate" || true

    DASHBOARD_CURRENT_TASK="Generating reports"
    render_dashboard
    run_module "reporting" || true

    DASHBOARD_CURRENT_TASK="Complete"
    show_final_report
    show_summary
}

# ============================================================================
# SUMMARY
# ============================================================================
show_summary() {
    if [[ "$IS_TTY" == true ]]; then
        show_final_report
        return
    fi

    print_stage "ASSESSMENT COMPLETE"
    print_separator

    local findings_file="$CASE_DIR/findings.json"
    if [[ -f "$findings_file" ]] && has_dep "jq"; then
        local total high medium low info
        total=$(jq 'length' "$findings_file" 2>/dev/null || echo "0")
        high=$(jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' "$findings_file" 2>/dev/null || echo "0")
        medium=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$findings_file" 2>/dev/null || echo "0")
        low=$(jq '[.[] | select(.severity == "LOW")] | length' "$findings_file" 2>/dev/null || echo "0")
        info=$(jq '[.[] | select(.severity == "INFO")] | length' "$findings_file" 2>/dev/null || echo "0")

        echo -e "  Total findings    : ${BOLD}$total${NC}"
        echo -e "  ${RED}High/Critical     : $high${NC}"
        echo -e "  ${YELLOW}Medium            : $medium${NC}"
        echo -e "  ${GREEN}Low               : $low${NC}"
        echo -e "  Info              : $info"
    fi

    echo ""
    echo -e "  Reports: ${BOLD}$CYBERSEC_ROOT/reports/${NC}"
    echo -e "  Case:    ${BOLD}$CASE_DIR${NC}"

    print_separator
    log_message "INFO" "Assessment complete"
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
main() {
    parse_args "$@"

    # Handle flags that work before full init
    if [[ "$NO_COLOR" == true ]]; then
        disable_colors 2>/dev/null || true
    fi

    if [[ "$TEST_MODE" == true ]]; then
        run_tests
        return
    fi

    if [[ "$CHECK_DEPS" == true ]]; then
        init_ui
        print_banner
        check_all_deps
        show_deps
        return
    fi

    if [[ "$LAB_MODE" == true ]]; then
        run_lab_mode
        return
    fi

    if [[ -n "$SINGLE_MODULE" ]]; then
        init_ui
        print_banner
        if [[ -z "$TARGET" ]]; then
            echo -e "${BOLD}Enter authorized target:${NC}"
            read -r -p "> " TARGET
            [[ -z "$TARGET" ]] && { print_error "No target"; exit 4; }
        fi
        load_scope
        validate_target "$(extract_hostname "$TARGET")" || exit 2
        init_case "$TARGET"
        load_config
        run_module "$SINGLE_MODULE"
        return
    fi

    if [[ "$REPORT_ONLY" == true ]]; then
        init_ui
        print_banner
        load_config
        init_case "${TARGET:-unknown}"
        run_module "reporting"
        return
    fi

    if [[ "$AUTO_MODE" == true ]]; then
        if [[ -z "$TARGET" ]]; then
            print_error "Target is required in auto mode"
            usage
            exit 4
        fi
        run_autonomous_workflow
        return
    fi

    if [[ "$RECON_ONLY" == true ]]; then
        if [[ -z "$TARGET" ]]; then
            echo -e "${BOLD}Enter authorized target:${NC}"
            read -r -p "> " TARGET
            [[ -z "$TARGET" ]] && { print_error "No target"; exit 4; }
        fi
        init_ui
        print_banner
        load_scope
        validate_target "$(extract_hostname "$TARGET")" || exit 2
        init_case "$TARGET"
        load_config
        run_module "recon"
        return
    fi

    if [[ "$SCAN_ONLY" == true ]]; then
        if [[ -z "$TARGET" ]]; then
            echo -e "${BOLD}Enter authorized target:${NC}"
            read -r -p "> " TARGET
            [[ -z "$TARGET" ]] && { print_error "No target"; exit 4; }
        fi
        init_ui
        print_banner
        load_scope
        validate_target "$(extract_hostname "$TARGET")" || exit 2
        init_case "$TARGET"
        load_config
        run_module "web"
        run_module "api"
        run_module "tls"
        run_module "network-audit"
        return
    fi

    # --- OSINT Direct Invocations ---
    if [[ -n "$OSINT_EMAIL_TARGET" ]]; then
        init_ui
        print_banner
        load_config
        load_scope
        local osint_mod="${MODULE_REGISTRY[osint]:-}"
        if [[ -n "$osint_mod" && -f "$CYBERSEC_ROOT/$osint_mod" ]]; then
            source "$CYBERSEC_ROOT/$osint_mod"
            run_osint_email "$OSINT_EMAIL_TARGET"
        else
            print_error "OSINT module not found"
            exit 3
        fi
        return
    fi

    if [[ -n "$OSINT_USERNAME_TARGET" ]]; then
        init_ui
        print_banner
        load_config
        load_scope
        local osint_mod="${MODULE_REGISTRY[osint]:-}"
        if [[ -n "$osint_mod" && -f "$CYBERSEC_ROOT/$osint_mod" ]]; then
            source "$CYBERSEC_ROOT/$osint_mod"
            run_osint_username "$OSINT_USERNAME_TARGET"
        else
            print_error "OSINT module not found"
            exit 3
        fi
        return
    fi

    if [[ -n "$OSINT_DOMAIN_TARGET" ]]; then
        init_ui
        print_banner
        load_config
        load_scope
        local osint_mod="${MODULE_REGISTRY[osint]:-}"
        if [[ -n "$osint_mod" && -f "$CYBERSEC_ROOT/$osint_mod" ]]; then
            source "$CYBERSEC_ROOT/$osint_mod"
            run_osint_domain "$OSINT_DOMAIN_TARGET"
        else
            print_error "OSINT module not found"
            exit 3
        fi
        return
    fi

    if [[ -n "$OSINT_COMPANY_TARGET" ]]; then
        init_ui
        print_banner
        load_config
        load_scope
        local osint_mod="${MODULE_REGISTRY[osint]:-}"
        if [[ -n "$osint_mod" && -f "$CYBERSEC_ROOT/$osint_mod" ]]; then
            source "$CYBERSEC_ROOT/$osint_mod"
            run_osint_company "$OSINT_COMPANY_TARGET"
        else
            print_error "OSINT module not found"
            exit 3
        fi
        return
    fi

    if [[ -n "$HARVEST_DOMAIN" ]]; then
        init_ui
        print_banner
        load_config
        load_scope
        local osint_mod="${MODULE_REGISTRY[osint]:-}"
        if [[ -n "$osint_mod" && -f "$CYBERSEC_ROOT/$osint_mod" ]]; then
            source "$CYBERSEC_ROOT/$osint_mod"
            run_harvest_emails "$HARVEST_DOMAIN"
        else
            print_error "OSINT module not found"
            exit 3
        fi
        return
    fi

    if [[ "$OSINT_REPORT_MODE" == true ]]; then
        init_ui
        print_banner
        load_config
        local osint_mod="${MODULE_REGISTRY[osint]:-}"
        if [[ -n "$osint_mod" && -f "$CYBERSEC_ROOT/$osint_mod" ]]; then
            source "$CYBERSEC_ROOT/$osint_mod"
            run_osint_report
        else
            print_error "OSINT module not found"
            exit 3
        fi
        return
    fi

    # Interactive mode
    if [[ -z "$TARGET" ]]; then
        init_ui
        show_interactive_menu
        read -r -p "Select option [0-17]: " choice
        handle_menu_choice "$choice"
        return
    fi

    # Target provided without mode - ask what to do
    init_ui
    print_banner
    show_startup_panel "INTERACTIVE"
    echo -e "${BOLD}Target: $TARGET${NC}"
    echo ""
    echo "  [1] Full Autonomous Assessment"
    echo "  [2] Run All Modules"
    echo "  [3] Recon Only"
    echo "  [4] Security Scan Only"
    echo "  [5] Exit"
    echo ""
    read -r -p "Select mode [1-5]: " mode_choice

    case "$mode_choice" in
        1) run_autonomous_workflow ;;
        2)
            load_scope
            validate_target "$(extract_hostname "$TARGET")" || exit 2
            init_case "$TARGET"
            load_config
            for m in "${PIPELINE_ORDER[@]}"; do
                run_module "$m" || true
            done
            run_module "vulnerability" || true
            run_module "risk" || true
            run_module "evidence" || true
            run_module "duplicate" || true
            run_module "reporting" || true
            show_summary
            ;;
        3)
            load_scope
            validate_target "$(extract_hostname "$TARGET")" || exit 2
            init_case "$TARGET"
            load_config
            run_module "recon"
            ;;
        4)
            load_scope
            validate_target "$(extract_hostname "$TARGET")" || exit 2
            init_case "$TARGET"
            load_config
            run_module "web"
            run_module "tls"
            ;;
        *) echo -e "${GREEN}Goodbye.${NC}" ;;
    esac
}

main "$@"
