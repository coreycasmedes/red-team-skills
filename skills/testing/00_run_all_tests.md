# 00 - Testing Phase Orchestration

## Purpose
Execute all testing skills in priority order, producing a comprehensive vulnerability report.

## Prerequisites
Before running testing phase:
1. ✅ Discovery phase complete (all 5 JSON files exist)
2. ✅ Tools installed (trufflehog, gitleaks, pyjwt)
3. ✅ Run directory exists with discovery outputs
4. ✅ Scope validated in `00_scope.json`

## Testing Execution Order

**Priority: Critical → High → Medium**

1. **07_secret_exposure.md** (CRITICAL, 5-10 min)
   - Quick wins, minimal target interaction
   - Tests pre-flagged interesting endpoints
   - Git repository dumping if accessible

2. **05_bola_idor.md** (CRITICAL, 15-20 min)
   - API authorization testing
   - Highest impact vulnerability
   - Rate-limited testing

3. **06_bfla_privilege.md** (HIGH, 5-15 min)
   - Admin endpoint access testing
   - Privilege escalation detection
   - Authorization bypass attempts

4. **08_auth_bypass.md** (HIGH, 10-15 min)
   - Authentication mechanism testing
   - JWT vulnerabilities
   - SQL injection in login
   - Default credentials

5. **09_misconfig.md** (MEDIUM, 5-10 min)
   - Security header analysis
   - CORS misconfiguration
   - S3 bucket enumeration
   - Rate limiting checks

**Total Execution Time**: 40-70 minutes

## Commands

### Pre-Flight Checks
```bash
#!/bin/bash
# Pre-flight validation script

RUN_DIR="$1"

if [ -z "$RUN_DIR" ]; then
    echo "Usage: bash 00_run_all_tests.sh <run_directory>"
    exit 1
fi

echo "[*] Pre-flight checks for testing phase"

# Check discovery phase outputs
REQUIRED_FILES=(
    "00_scope.json"
    "01_subdomains.json"
    "02_live_hosts.json"
    "03_endpoints.json"
    "04_fingerprint.json"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$RUN_DIR/$file" ]; then
        echo "[!] Missing required file: $RUN_DIR/$file"
        echo "[!] Run discovery phase first (skills 00-04)"
        exit 1
    fi
    echo "[✓] Found $file"
done

# Check tools
echo ""
echo "[*] Checking required tools..."

command -v python3 >/dev/null 2>&1 || { echo "[!] python3 not found"; exit 1; }
echo "[✓] python3"

command -v trufflehog >/dev/null 2>&1 || echo "[!] Optional: trufflehog not found (install: go install github.com/trufflesecurity/trufflehog/v3@latest)"
command -v gitleaks >/dev/null 2>&1 || echo "[!] Optional: gitleaks not found (install: go install github.com/gitleaks/gitleaks/v8@latest)"

python3 -c "import requests" 2>/dev/null || { echo "[!] Install: pip3 install requests"; exit 1; }
echo "[✓] requests"

python3 -c "import jwt" 2>/dev/null || echo "[!] Optional: pip3 install pyjwt (needed for JWT testing)"

# Check scope
echo ""
echo "[*] Validating scope..."
SCOPE_DOMAIN=$(python3 -c "import json; print(json.load(open('$RUN_DIR/00_scope.json'))['domain'])" 2>/dev/null)
if [ -z "$SCOPE_DOMAIN" ]; then
    echo "[!] Could not read scope domain"
    exit 1
fi
echo "[✓] Target: $SCOPE_DOMAIN"

# Check for WAF detection
WAF_DETECTED=$(python3 -c "import json; data=json.load(open('$RUN_DIR/04_fingerprint.json')); print(any(t.get('waf') and t['waf'] != 'None' for t in data.get('high_value_targets', [])))" 2>/dev/null)
if [ "$WAF_DETECTED" = "True" ]; then
    echo "[!] WARNING: WAF detected on some targets"
    echo "[!] Testing will be rate-limited and may produce fewer results"
fi

# Count high-value targets
HVT_COUNT=$(python3 -c "import json; print(len(json.load(open('$RUN_DIR/04_fingerprint.json')).get('high_value_targets', [])))" 2>/dev/null)
echo "[*] High-value targets: $HVT_COUNT"

ENDPOINT_COUNT=$(python3 -c "import json; print(len(json.load(open('$RUN_DIR/03_endpoints.json')).get('endpoints', [])))" 2>/dev/null)
echo "[*] Total endpoints: $ENDPOINT_COUNT"

INTERESTING_COUNT=$(python3 -c "import json; print(len(json.load(open('$RUN_DIR/03_endpoints.json')).get('interesting_endpoints', [])))" 2>/dev/null)
echo "[*] Interesting endpoints: $INTERESTING_COUNT"

echo ""
echo "[✓] Pre-flight checks passed"
echo "[*] Ready to begin testing phase"
```

### Master Testing Workflow
```bash
#!/bin/bash
# Master testing workflow - executes all testing skills in order

RUN_DIR="$1"
SKILLS_DIR="skills/testing"

if [ -z "$RUN_DIR" ]; then
    echo "Usage: bash run_all_tests.sh <run_directory>"
    echo "Example: bash run_all_tests.sh runs/example.com-20260401-120000"
    exit 1
fi

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Bug Bounty Testing Phase${NC}"
echo -e "${GREEN}[*] Target: $(basename $RUN_DIR)${NC}"
echo -e "${GREEN}[*] Start time: $(date)${NC}"
echo ""

START_TIME=$(date +%s)

# Initialize findings.json
if [ ! -f "$RUN_DIR/findings.json" ]; then
    echo "[*] Initializing findings.json"
    cp "$SKILLS_DIR/findings_schema.json" "$RUN_DIR/findings.json"

    # Update metadata
    python3 << EOF
import json
from pathlib import Path
from datetime import datetime

findings_file = Path("$RUN_DIR/findings.json")
with open(findings_file) as f:
    findings = json.load(f)

findings['target'] = '$(basename $RUN_DIR)'.split('-')[0]
findings['run_directory'] = '$RUN_DIR'
findings['timestamp'] = datetime.utcnow().isoformat() + 'Z'

with open(findings_file, 'w') as f:
    json.dump(findings, f, indent=2)

print("[✓] Findings file initialized")
EOF
fi

# Skill 7: Secret Exposure (CRITICAL - Quick wins)
echo -e "\n${YELLOW}[1/5] Running Secret Exposure Testing...${NC}"
echo "[*] Priority: CRITICAL | Estimated time: 5-10 minutes"

if python3 "$SKILLS_DIR/07_secret_exposure.py" "$RUN_DIR"; then
    echo -e "${GREEN}[✓] Secret exposure testing complete${NC}"
else
    echo -e "${RED}[!] Secret exposure testing failed (continuing anyway)${NC}"
fi

# Skill 5: BOLA/IDOR (CRITICAL - Highest impact)
echo -e "\n${YELLOW}[2/5] Running BOLA/IDOR Testing...${NC}"
echo "[*] Priority: CRITICAL | Estimated time: 15-20 minutes"

if python3 "$SKILLS_DIR/05_bola_idor.py" "$RUN_DIR"; then
    echo -e "${GREEN}[✓] BOLA/IDOR testing complete${NC}"
else
    echo -e "${RED}[!] BOLA/IDOR testing failed (continuing anyway)${NC}"
fi

# Skill 6: BFLA (HIGH - Privilege escalation)
echo -e "\n${YELLOW}[3/5] Running BFLA Testing...${NC}"
echo "[*] Priority: HIGH | Estimated time: 5-15 minutes"

if python3 "$SKILLS_DIR/06_bfla_privilege.py" "$RUN_DIR"; then
    echo -e "${GREEN}[✓] BFLA testing complete${NC}"
else
    echo -e "${RED}[!] BFLA testing failed (continuing anyway)${NC}"
fi

# Skill 8: Authentication Bypass (HIGH)
echo -e "\n${YELLOW}[4/5] Running Authentication Bypass Testing...${NC}"
echo "[*] Priority: HIGH | Estimated time: 10-15 minutes"

if python3 "$SKILLS_DIR/08_auth_bypass.py" "$RUN_DIR"; then
    echo -e "${GREEN}[✓] Authentication bypass testing complete${NC}"
else
    echo -e "${RED}[!] Authentication bypass testing failed (continuing anyway)${NC}"
fi

# Skill 9: Security Misconfiguration (MEDIUM)
echo -e "\n${YELLOW}[5/5] Running Security Misconfiguration Testing...${NC}"
echo "[*] Priority: MEDIUM | Estimated time: 5-10 minutes"

if python3 "$SKILLS_DIR/09_misconfig.py" "$RUN_DIR"; then
    echo -e "${GREEN}[✓] Security misconfiguration testing complete${NC}"
else
    echo -e "${RED}[!] Security misconfiguration testing failed (continuing anyway)${NC}"
fi

# Generate summary report
echo -e "\n${GREEN}[*] Generating summary report...${NC}"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

python3 << EOF
import json
from pathlib import Path
from datetime import datetime

findings_file = Path("$RUN_DIR/findings.json")
with open(findings_file) as f:
    findings = json.load(f)

# Update execution time
findings['execution_time_seconds'] = $DURATION

# Save updated findings
with open(findings_file, 'w') as f:
    json.dump(findings, f, indent=2)

# Print summary
print("\n" + "="*70)
print("                    VULNERABILITY REPORT SUMMARY")
print("="*70)
print(f"Target: {findings['target']}")
print(f"Testing completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"Execution time: {$DURATION // 60} minutes {$DURATION % 60} seconds")
print("-"*70)
print(f"Total vulnerabilities found: {findings['total_vulnerabilities']}")
print("\nSeverity breakdown:")
for severity in ['critical', 'high', 'medium', 'low', 'info']:
    count = findings['severity_breakdown'].get(severity, 0)
    if count > 0:
        print(f"  {severity.upper():8s}: {count}")

print(f"\nEndpoints tested: {findings['tested_endpoints']}")
print("-"*70)

# List critical/high findings
critical_high = [v for v in findings['vulnerabilities'] if v['severity'] in ['critical', 'high']]
if critical_high:
    print(f"\n🚨 CRITICAL/HIGH SEVERITY FINDINGS ({len(critical_high)}):")
    for vuln in critical_high:
        print(f"  [{vuln['severity'].upper()}] {vuln['type']} - {vuln['endpoint'][:80]}")

print("\n" + "="*70)
print(f"Full report: {findings_file}")
print("="*70 + "\n")
EOF

echo -e "${GREEN}[✓] Testing phase complete!${NC}"
echo -e "${GREEN}[*] Results saved to: $RUN_DIR/findings.json${NC}"
```

### Quick Testing (Skip Optional Tests)
```bash
#!/bin/bash
# Quick testing mode - runs only critical vulnerability tests

RUN_DIR="$1"
SKILLS_DIR="skills/testing"

echo "[*] Quick Testing Mode (Critical vulnerabilities only)"
echo "[*] Estimated time: 20-30 minutes"
echo ""

# Secret Exposure
echo "[1/2] Secret Exposure Testing..."
python3 "$SKILLS_DIR/07_secret_exposure.py" "$RUN_DIR"

# BOLA/IDOR
echo "[2/2] BOLA/IDOR Testing..."
python3 "$SKILLS_DIR/05_bola_idor.py" "$RUN_DIR"

echo "[✓] Quick testing complete"
```

## Execution Examples

### Full Testing Phase
```bash
# Run pre-flight checks
bash skills/testing/00_run_all_tests.sh runs/example.com-20260401-120000

# If checks pass, run full testing
cd skills/testing
bash run_all_tests.sh ../../runs/example.com-20260401-120000
```

### Quick Testing (Critical Only)
```bash
bash skills/testing/quick_test.sh runs/example.com-20260401-120000
```

### Individual Skill Testing
```bash
# Test just one skill
python3 skills/testing/07_secret_exposure.py runs/example.com-20260401-120000
```

## Output Structure

After completion, `findings.json` contains:
```json
{
  "target": "example.com",
  "run_directory": "runs/example.com-20260401-120000/",
  "timestamp": "2026-04-01T12:00:00Z",
  "total_vulnerabilities": 12,
  "severity_breakdown": {
    "critical": 3,
    "high": 5,
    "medium": 4,
    "low": 0,
    "info": 0
  },
  "vulnerabilities": [
    {
      "id": "VULN-SECRET-20260401120523",
      "type": "Exposed Secrets",
      "severity": "critical",
      "endpoint": "https://api.example.com/.env",
      "discovered_at": "2026-04-01T12:05:23Z",
      "proof_of_concept": {...},
      "remediation": "...",
      "cvss_score": 9.1
    }
  ],
  "tested_endpoints": 234,
  "execution_time_seconds": 1847
}
```

## Safety Protocol

### WAF-Aware Testing
If WAF detected in `04_fingerprint.json`:
1. **Increase rate limits** (double delay between requests)
2. **Skip WAF-protected targets initially**
3. **Randomize User-Agent headers**
4. **Test non-WAF targets first**

### Rate Limiting Thresholds
- Secret exposure: No rate limiting needed (read-only)
- BOLA testing: 0.5s between requests (2 req/s)
- BFLA testing: 1s between requests (1 req/s)
- Auth bypass: 1-2s between requests (prevent lockout)
- Misconfiguration: 0.5s between hosts

### Detection Mitigation
- Use realistic User-Agent headers
- Limit total requests per skill
- Stop after first critical finding per vulnerability type
- No aggressive fuzzing or brute-force attacks

## Hard Rules

❌ **NEVER**:
- Run exploits (only detect vulnerabilities)
- Perform post-exploitation activities
- Test DoS vulnerabilities
- Test out-of-scope targets
- Continue after severe rate limiting (429 responses)

✅ **ALWAYS**:
- Validate scope before testing
- Respect rate limits
- Stop after confirmation (don't over-test)
- Report critical findings immediately
- Document proof-of-concept clearly

## Troubleshooting

### No vulnerabilities found
- Check if targets have strong security controls
- Review WAF detection (may be blocking tests)
- Verify discovery phase found sufficient attack surface
- Try manual testing on high-priority targets

### Rate limiting errors (429)
- Increase delay in testing scripts
- Reduce number of test cases per endpoint
- Skip WAF-protected targets
- Resume testing after delay

### Script errors
- Verify Python dependencies installed
- Check discovery JSON files are valid
- Review error messages for missing data
- Run individual skills to isolate issue

## Next Steps After Testing

### Critical Findings Protocol
If any critical vulnerabilities found:
1. **Stop testing** (already have reportable findings)
2. **Verify vulnerability** (manual confirmation)
3. **Document impact** (clear proof-of-concept)
4. **Report immediately** to bug bounty program

### Report Generation
```bash
# Generate HTML report (future enhancement)
python3 skills/testing/generate_report.py runs/example.com-20260401-120000

# Export to bug bounty platform format
python3 skills/testing/export_findings.py runs/example.com-20260401-120000 --format hackerone
```

### Continuous Testing
```bash
# Re-run testing on same target (weekly)
bash skills/testing/run_all_tests.sh runs/example.com-20260401-120000

# Compare results with previous run
python3 skills/testing/compare_findings.py \
  runs/example.com-20260401-120000/findings.json \
  runs/example.com-20260408-120000/findings.json
```

## Performance Optimization

### Parallel Testing (Advanced)
For large targets, run skills in parallel:
```bash
# Run critical skills in parallel (requires GNU parallel)
parallel ::: \
  "python3 skills/testing/07_secret_exposure.py $RUN_DIR" \
  "python3 skills/testing/05_bola_idor.py $RUN_DIR"
```

### Incremental Testing
Test only new endpoints:
```bash
# Compare with previous run, test only new endpoints
python3 skills/testing/incremental_test.py \
  --previous runs/example.com-20260401-120000 \
  --current runs/example.com-20260408-120000
```

## Metrics & Reporting

Track testing effectiveness:
- **Vulnerability detection rate**: Vulns found / Endpoints tested
- **Critical finding ratio**: Critical vulns / Total vulns
- **Execution efficiency**: Time per vulnerability found
- **False positive rate**: Invalid findings / Total findings (requires manual review)

## Compliance & Ethics

Before running testing phase:
1. ✅ Confirm active bug bounty program
2. ✅ Verify target is in-scope
3. ✅ Review program rules (rate limits, prohibited tests)
4. ✅ Ensure authorization to test
5. ✅ Have responsible disclosure plan

**Never test without explicit authorization.**
