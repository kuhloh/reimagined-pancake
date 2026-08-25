# Bug Bounty Agent

Autonomous Bug Bounty Reconnaissance and Vulnerability Assessment Agent for Kali Linux.

## Legal Disclaimer

**This tool is for authorized security testing only.** Only use against targets you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

## Installation

```bash
chmod +x bugbounty-agent.sh
```

## Dependencies

### Required

- `curl`
- `wget`
- `dig`
- `host`
- `jq`

### Optional (enhance functionality)

- `nmap` - Port scanning
- `whatweb` - Technology detection
- `httpx` - HTTP probing
- `subfinder` - Subdomain enumeration
- `assetfinder` - Asset discovery
- `dnsx` - DNS toolkit
- `nuclei` - Vulnerability scanner
- `whois` - Domain lookup

Check dependencies:

```bash
./bugbounty-agent.sh --check-deps
```

## Configuration

Edit `config/config.conf` to customize behavior:

```bash
RATE_LIMIT=5
CONCURRENCY=2
TIMEOUT=10
MAX_REDIRECTS=3
USER_AGENT="Authorized-BugBounty-Agent/1.0"
```

## Scope

Define authorized targets in `scope/scope.txt`:

```
example.com
*.example.com
api.example.com
```

The tool **blocks** scanning of out-of-scope or unknown targets.

## Usage

### Autonomous Mode (recommended)

```bash
./bugbounty-agent.sh --target https://authorized-target.example --auto
```

### With Custom Scope

```bash
./bugbounty-agent.sh --target https://example.com --scope scope.txt --auto
```

### Process All Scope Entries

```bash
./bugbounty-agent.sh --scope scope.txt --auto
```

### Reconnaissance Only

```bash
./bugbounty-agent.sh --target https://example.com --recon
```

### Security Scan Only

```bash
./bugbounty-agent.sh --target https://example.com --scan
```

### Check Dependencies

```bash
./bugbounty-agent.sh --check-deps
```

### Run Tests

```bash
./bugbounty-agent.sh --test
```

### Show Version

```bash
./bugbounty-agent.sh --version
```

## Workflow

```
TARGET -> SCOPE VALIDATION -> RECON -> SUBDOMAIN DISCOVERY
-> DNS ENUMERATION -> HTTP/HTTPS DISCOVERY -> TECHNOLOGY DETECTION
-> ENDPOINT DISCOVERY -> SAFE SECURITY TESTING
-> VULNERABILITY CANDIDATES -> VALIDATION -> FALSE-POSITIVE REDUCTION
-> EVIDENCE COLLECTION -> SEVERITY/RISK ANALYSIS -> DEDUPLICATION
-> REPORT GENERATION -> FINAL SUMMARY
```

## Reports

After each scan, reports are generated in:

- `reports/report.md` - Human-readable Markdown report
- `reports/report.json` - Machine-readable JSON report

## Test Mode

Run internal tests without external scanning:

```bash
./bugbounty-agent.sh --test
```

Tests cover:
- Argument parsing
- Scope validation
- URL parsing
- Duplicate detection
- Finding normalization
- Secret redaction
- Report generation
- Dependency detection

## Directory Structure

```
bugbounty-agent/
├── bugbounty-agent.sh
├── config/
│   └── config.conf
├── scope/
│   └── scope.txt
├── results/
│   ├── recon/
│   ├── dns/
│   ├── http/
│   ├── technologies/
│   ├── endpoints/
│   ├── vulnerabilities/
│   └── nuclei/
├── evidence/
├── reports/
├── logs/
├── wordlists/
└── README.md
```

## Limitations

- Non-destructive by design (no exploitation)
- Conservative rate limiting by default
- Passive subdomain enumeration only
- No credential-based testing
- Limited to HTTP/HTTPS services
- Manual verification required for all findings

## Troubleshooting

### Missing Dependencies

Run `--check-deps` to see what is installed. Install missing tools:

```bash
sudo apt install jq curl wget dnsutils
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Permission Denied

```bash
chmod +x bugbounty-agent.sh
```

### No Scope Entries

Ensure your `scope/scope.txt` contains at least one valid domain pattern.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Scope violation |
| 3 | Missing dependencies |
| 4 | Invalid arguments |
| 5 | Test failure |
