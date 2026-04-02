# Red Team Skills - Bug Bounty Recon Agent

A defensive-focused bug bounty reconnaissance agent built for systematic asset discovery and enumeration. All activities are designed for authorized bug bounty programs only.

## What This Is

This repository implements a **two-phase methodology** for bug bounty reconnaissance:

1. **Discovery Phase** - Enumerate all assets before touching anything
   - Scope validation
   - Subdomain enumeration
   - Live host probing
   - Endpoint crawling
   - Technology fingerprinting

2. **Testing Phase** - Automated vulnerability detection on discovered assets
   - Exposed secrets and credentials
   - API authorization flaws (BOLA/IDOR)
   - Privilege escalation (BFLA)
   - Authentication bypass
   - Security misconfigurations

## Mission Statement

**Defensive security only.** This agent is designed for authorized bug bounty programs where security testing is explicitly permitted. Never use these tools on systems you don't have permission to test.

## Repository Structure

```
red-team-skills/
├── CLAUDE.md                     # Agent instructions and protocol
├── README.md                     # This file
├── .gitignore                    # Excludes runs/ directory
├── skills/
│   ├── discovery/               # Phase 1: Discovery skills
│   │   ├── 00_scope.md          # Scope definition & validation
│   │   ├── 01_subdomain_enum.md # Subdomain enumeration
│   │   ├── 02_live_host_probe.md# Live host detection
│   │   ├── 03_endpoint_crawl.md # Endpoint discovery
│   │   └── 04_fingerprint.md    # Tech fingerprinting
│   └── testing/                 # Phase 2: Testing skills
│       ├── 00_run_all_tests.md  # Master workflow
│       ├── 05_bola_idor.md      # API authorization (BOLA/IDOR)
│       ├── 06_bfla_privilege.md # Privilege escalation (BFLA)
│       ├── 07_secret_exposure.md# Exposed credentials/keys
│       ├── 08_auth_bypass.md    # Authentication bypass
│       ├── 09_misconfig.md      # Security misconfigurations
│       └── findings_schema.json # Output template
├── runs/                        # Session outputs (gitignored)
│   └── {target}-{timestamp}/    # One directory per engagement
│       ├── 00_scope.json
│       ├── 01_subdomains.json
│       ├── 02_live_hosts.json
│       ├── 03_endpoints.json
│       ├── 04_fingerprint.json
│       ├── findings.json        # Testing results (phase 2)
│       └── raw/                 # Raw tool outputs
└── wordlists/                   # Curated wordlists
    ├── idor_ids.txt             # IDOR testing IDs
    └── admin_paths.txt          # Admin endpoint patterns
```

## Toolchain Installation

All discovery skills require the following tools. Install them before starting a session.

### Prerequisites

- **Go** (version 1.19+): https://golang.org/doc/install
- **Python 3** (version 3.8+): https://www.python.org/downloads/
- **jq**: JSON processor for bash scripts

```bash
# macOS
brew install go python3 jq

# Linux (Debian/Ubuntu)
sudo apt install golang-go python3 jq

# Linux (RHEL/CentOS)
sudo yum install golang python3 jq
```

### Discovery Tools

Install all tools via `go install`:

```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# DNS resolution
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Endpoint crawling
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Fingerprinting
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Ensure Go binaries are in PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Add to ~/.bashrc or ~/.zshrc for persistence
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
```

### Update Nuclei Templates

After installing nuclei, update its templates:

```bash
nuclei -update-templates
```

### Testing Phase Tools

Install additional tools for vulnerability testing:

```bash
# Secret scanning
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/gitleaks/gitleaks/v8@latest

# JWT testing
pip3 install pyjwt

# Git repository dumping
pip3 install git-dumper

# Python dependencies
pip3 install requests

# Optional: Cloud security (if testing S3 buckets)
pip3 install cloudsplaining
go install github.com/sa7mon/S3Scanner@latest
```

### Verify Installation

```bash
# Discovery tools
subfinder -version
amass -version
dnsx -version
httpx -version
katana -version
gau --version
waybackurls -h
nuclei -version

# Testing tools
trufflehog --version
gitleaks version
python3 -c "import jwt; print('PyJWT installed')"
python3 -c "import requests; print('requests installed')"
```

## How to Start a Session

### 1. Navigate to Repository

```bash
cd /path/to/red-team-skills
```

### 2. Launch Claude Code

```bash
claude-code
# or
claude
```

### 3. Session Start Protocol

The agent will ask you three questions:

1. **What is the target domain?**
   - Provide root domain only (e.g., `example.com`)
   - Do not include `https://`, paths, or ports

2. **Is there a bug bounty program brief or scope doc?**
   - If yes, provide the file path or URL
   - The agent will read it to understand scope boundaries

3. **Does a run directory already exist?**
   - Check `runs/` for existing `{target}-{date}/` directories
   - If resuming, specify which directory to continue from

### 4. Execute Discovery Phase

The agent will load and execute skills sequentially:

1. `@skills/discovery/00_scope.md` - Define scope
2. `@skills/discovery/01_subdomain_enum.md` - Enumerate subdomains (15-40 min)
3. `@skills/discovery/02_live_host_probe.md` - Probe live hosts (3-5 min)
4. `@skills/discovery/03_endpoint_crawl.md` - Crawl endpoints (15-40 min)
5. `@skills/discovery/04_fingerprint.md` - Fingerprint technologies (5-10 min)

**Total estimated time:** 40-90 minutes (depending on target size)

### 5. Execute Testing Phase (Optional)

After discovery phase completes, run vulnerability testing:

```bash
# Run all testing skills (recommended)
bash skills/testing/00_run_all_tests.sh runs/{target}-{timestamp}

# Or run individual skills
python3 skills/testing/07_secret_exposure.py runs/{target}-{timestamp}
python3 skills/testing/05_bola_idor.py runs/{target}-{timestamp}
python3 skills/testing/06_bfla_privilege.py runs/{target}-{timestamp}
python3 skills/testing/08_auth_bypass.py runs/{target}-{timestamp}
python3 skills/testing/09_misconfig.py runs/{target}-{timestamp}
```

**Testing execution order:**
1. `07_secret_exposure.md` - Exposed credentials (CRITICAL, 5-10 min)
2. `05_bola_idor.md` - API authorization flaws (CRITICAL, 15-20 min)
3. `06_bfla_privilege.md` - Privilege escalation (HIGH, 5-15 min)
4. `08_auth_bypass.md` - Authentication bypass (HIGH, 10-15 min)
5. `09_misconfig.md` - Security misconfigurations (MEDIUM, 5-10 min)

**Total testing time:** 40-70 minutes

## Output Files

Each discovery skill produces a structured JSON file in `runs/{target}-{timestamp}/`:

### 00_scope.json
Contains target domain, program details, in-scope/out-of-scope assets.

```json
{
  "target": "example.com",
  "program": "HackerOne: Example Corp",
  "scope": {
    "in_scope": ["*.example.com", "example.com"],
    "out_of_scope": ["mail.example.com"]
  }
}
```

### 01_subdomains.json
All discovered subdomains with resolution data.

```json
{
  "total_subdomains": 1243,
  "resolved_subdomains": 891,
  "data": [
    {
      "subdomain": "api.example.com",
      "sources": ["subfinder", "amass"],
      "resolved": true,
      "ip_addresses": ["203.0.113.42"]
    }
  ]
}
```

### 02_live_hosts.json
Live HTTP/HTTPS services with tech fingerprints.

```json
{
  "total_live_hosts": 234,
  "data": [
    {
      "url": "https://api.example.com",
      "status_code": 200,
      "title": "Example API Gateway",
      "webserver": "nginx/1.21.0",
      "tech": ["Nginx", "Express"]
    }
  ]
}
```

### 03_endpoints.json
All discovered endpoints from active crawling and historical sources.

```json
{
  "total_endpoints": 8472,
  "interesting_endpoints": 47,
  "data": [
    {
      "url": "https://api.example.com/v1/users",
      "source": "katana",
      "interesting": false
    },
    {
      "url": "https://admin.example.com/.git/config",
      "source": "waybackurls",
      "interesting": true,
      "interesting_reason": "exposed .git directory"
    }
  ]
}
```

### 04_fingerprint.json
Technology stack, WAF detection, authentication surfaces, and high-value targets.

```json
{
  "technologies": {
    "web_servers": {"nginx": 142, "Apache": 67},
    "frameworks": {"React": 89, "Laravel": 12}
  },
  "waf_detected": {"Cloudflare": 78, "None": 139},
  "high_value_targets": [
    {
      "url": "https://jenkins.example.com",
      "reason": "Jenkins CI/CD server",
      "priority": "critical"
    }
  ]
}
```

### findings.json (Testing Phase Output)

Comprehensive vulnerability report from testing phase.

```json
{
  "target": "example.com",
  "run_directory": "runs/example.com-20260401-103000/",
  "timestamp": "2026-04-01T13:00:00Z",
  "total_vulnerabilities": 12,
  "severity_breakdown": {
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 0
  },
  "vulnerabilities": [
    {
      "id": "VULN-SECRET-20260401130523",
      "type": "Exposed Secrets",
      "severity": "critical",
      "endpoint": "https://api.example.com/.env",
      "proof_of_concept": {
        "request": "GET https://api.example.com/.env",
        "secrets": [{"type": "aws_access_key", "redacted_value": "AKIA..."}]
      },
      "remediation": "Remove .env file from web root",
      "cvss_score": 9.1
    }
  ],
  "tested_endpoints": 234,
  "execution_time_seconds": 1847
}
```

## Workflow Example

### Complete Discovery Phase

```
$ claude-code

Claude Code> Starting session for target: example.com

1. Reading scope document...
   ✓ Created: runs/example.com-20260401-103000/00_scope.json

2. Enumerating subdomains...
   ✓ Subfinder: 876 subdomains
   ✓ Amass: 1039 subdomains
   ✓ Merged: 1243 unique, 891 resolved
   ✓ Created: runs/example.com-20260401-103000/01_subdomains.json

3. Probing live hosts...
   ✓ httpx: 234 live hosts
   ✓ Created: runs/example.com-20260401-103000/02_live_hosts.json

4. Crawling endpoints...
   ✓ Katana: 4521 endpoints
   ✓ gau: 2834 URLs
   ✓ waybackurls: 3142 URLs
   ✓ Merged: 8104 in-scope, 47 interesting
   ✓ Created: runs/example.com-20260401-103000/03_endpoints.json

5. Fingerprinting technologies...
   ✓ Nuclei: 47 findings
   ✓ Identified: 23 high-value targets
   ✓ Created: runs/example.com-20260401-103000/04_fingerprint.json

Discovery phase complete!

High-value targets:
  [CRITICAL] https://jenkins.example.com - Jenkins CI/CD server
  [HIGH] https://api.example.com - API gateway with swagger docs
  [MEDIUM] https://staging.example.com/.git/config - Exposed .git

6. Running testing phase...
   ✓ Secret exposure: 2 critical findings (AWS keys, .git exposure)
   ✓ BOLA/IDOR: 3 API authorization flaws
   ✓ BFLA: 1 admin endpoint accessible without auth
   ✓ Auth bypass: 2 JWT vulnerabilities
   ✓ Misconfig: 4 CORS/header issues
   ✓ Created: runs/example.com-20260401-103000/findings.json

Testing phase complete!

Vulnerability summary:
  Critical: 3 (AWS keys, .git repo, admin access)
  High: 5 (BOLA, BFLA, JWT)
  Medium: 4 (CORS, headers)
  Total: 12 vulnerabilities across 234 tested endpoints
```

## Key Features

### Scope Safety
- Validates scope before any enumeration
- Filters out-of-scope assets at every step
- Documents boundaries in `00_scope.json`

### Multi-Source Enumeration
- Combines passive sources (subfinder, amass)
- Aggregates historical data (gau, waybackurls)
- Active crawling with JS support (katana)

### Smart Prioritization
- Automatically flags interesting endpoints
- Identifies high-value targets (admin panels, APIs, CI/CD)
- Detects WAF presence for testing planning

### Comprehensive Output
- All data in structured JSON format
- Source attribution (which tool found each result)
- Raw tool outputs preserved in `runs/{target}/raw/`

## Performance Tuning

### Fast Mode (Trade-off: Less Coverage)

**Subdomain enumeration:**
- Skip Amass (slow): Use only subfinder
- Estimated time savings: 15-25 minutes

**Endpoint crawling:**
- Disable JS crawling in katana: Remove `-js-crawl` flag
- Reduce crawl depth: `-depth 2` instead of `-depth 3`
- Estimated time savings: 10-20 minutes

### Stealth Mode (Rate Limiting)

Add rate limits to active scanning tools:

```bash
# httpx: Limit to 10 req/s
httpx -rate-limit 10

# katana: Limit to 10 req/s
katana -rate-limit 10

# nuclei: Limit to 10 req/s
nuclei -rate-limit 10
```

## Safety Notes

### What This Agent Will NOT Do

- ❌ Run exploits or proof-of-concept code (detection only)
- ❌ Perform post-exploitation activities
- ❌ Brute-force credentials aggressively
- ❌ Access systems without authorization
- ❌ Test out-of-scope assets
- ❌ Suggest lateral movement or persistence
- ❌ DoS testing or destructive actions

### What This Agent WILL Do

**Discovery Phase:**
- ✅ Enumerate subdomains passively
- ✅ Identify live services and technologies
- ✅ Crawl public endpoints respectfully
- ✅ Detect exposed configurations
- ✅ Document findings in structured format

**Testing Phase:**
- ✅ Test for API authorization flaws (BOLA/IDOR)
- ✅ Detect exposed secrets and credentials
- ✅ Test privilege escalation (BFLA)
- ✅ Check authentication mechanisms (JWT, SQL injection in login)
- ✅ Identify security misconfigurations (CORS, headers, S3 buckets)
- ✅ Stop at vulnerability confirmation (no exploitation)
- ✅ Respect rate limits and WAF detection

### Rate Limiting Best Practices

- **Default settings:** Moderate speed, good balance
- **Bug bounty programs:** Usually tolerate normal recon traffic
- **Corporate networks:** Consider stealth mode (`-rate-limit 10`)
- **Monitor for 429 errors:** Indicates rate limiting, slow down
- **Respect robots.txt:** Though not required for security testing

## Troubleshooting

### Tools Not Found

```bash
# Verify Go bin directory is in PATH
echo $PATH | grep $(go env GOPATH)/bin

# If not, add to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### Permission Denied Errors

```bash
# Ensure tools are executable
chmod +x $(go env GOPATH)/bin/*
```

### Rate Limiting / 429 Errors

Add rate limits to affected tool (see "Stealth Mode" above).

### DNS Resolution Failures

```bash
# Test connectivity
dig example.com

# Try alternative DNS servers
# Add to dnsx command: -resolver 8.8.8.8,1.1.1.1
```

### Nuclei Templates Outdated

```bash
# Force update templates
nuclei -update-templates -force
```

## Contributing

This repository is designed for authorized security testing only. Contributions that expand defensive capabilities, improve accuracy, or add testing phase skills are welcome.

### Adding Skills

Skills should follow the established format:
- **Purpose**: One-sentence description
- **Inputs**: Required files and environment
- **Outputs**: JSON schema and file path
- **Commands**: Copy-paste ready commands
- **Tool Flags**: Documented and verified
- **Error Handling**: Common issues and fixes
- **Execution Time**: Realistic estimates

## License

This project is for educational and authorized security testing purposes only. Use responsibly and only on systems you have explicit permission to test.

## Support

For issues or questions:
- Check skill files in `skills/discovery/` for detailed usage
- Review `CLAUDE.md` for agent protocol
- Verify tool installation and PATH configuration
- Ensure scope is properly defined in `00_scope.json`

## Credits

Built on top of industry-standard security tools:
- ProjectDiscovery suite (subfinder, httpx, katana, nuclei, dnsx)
- OWASP Amass
- gau (GetAllURLs)
- waybackurls

## Disclaimer

**IMPORTANT:** This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain explicit permission before testing any system. The authors are not responsible for misuse of this tool.