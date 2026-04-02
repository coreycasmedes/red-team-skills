# 07 - Secret Exposure Detection

## Purpose
Detect exposed credentials, API keys, tokens, and sensitive files in the attack surface identified during discovery.

## Inputs
- `03_endpoints.json` - Interesting endpoints flagged during crawling (.git, .env, backups)
- `04_fingerprint.json` - Technology stack for framework-specific secret paths
- `00_scope.json` - Scope validation

## Testing Strategy

### Phase 1: Test Pre-Flagged Interesting Endpoints
Discovery phase already identified high-risk paths. Test these first:
- `.git/` directories (source code exposure)
- `.env` files (credentials, API keys)
- Backup files (`.bak`, `.old`, `.sql`, `backup.zip`)
- Debug endpoints (`/debug`, `/trace`, `/error`)
- Config files (`web.config`, `config.php`, `settings.py`)

### Phase 2: Git Repository Exploitation
If `.git/` directory is accessible:
1. Dump entire repository using `git-dumper`
2. Scan dumped content with `trufflehog` for secrets
3. Extract `.git/config`, `.git/logs/HEAD`, `.git/index`

### Phase 3: Response Pattern Scanning
Scan all HTTP responses for secret patterns:
- **AWS Keys**: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`
- **API Keys**: `api_key=`, `apiKey:`, `x-api-key:`
- **Tokens**: JWT format (`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+`), OAuth tokens
- **Credentials**: `password:`, `passwd=`, `secret:`, `token:`
- **Database**: Connection strings with credentials

## Commands

### Setup
```bash
# Verify tools installed
command -v trufflehog >/dev/null 2>&1 || echo "Install: go install github.com/trufflesecurity/trufflehog/v3@latest"
command -v gitleaks >/dev/null 2>&1 || echo "Install: go install github.com/gitleaks/gitleaks/v8@latest"
python3 -c "import git" 2>/dev/null || echo "Install: pip3 install gitpython"

# Set run directory
RUN_DIR="runs/$(basename $(pwd))-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR/secrets"
```

### Test Interesting Endpoints
```python
#!/usr/bin/env python3
"""
Secret Exposure Testing - Phase 1: Interesting Endpoints
"""
import json
import re
import requests
from datetime import datetime
from pathlib import Path
import sys

# Secret detection patterns
SECRET_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'aws_secret_access_key[\s]*=[\s]*["\']?([A-Za-z0-9/+=]{40})["\']?',
    'generic_api_key': r'api[_-]?key[\s]*[:=][\s]*["\']?([A-Za-z0-9_\-]{20,})["\']?',
    'jwt_token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    'bearer_token': r'Bearer[\s]+([A-Za-z0-9_\-\.]+)',
    'password': r'password[\s]*[:=][\s]*["\']([^"\']{8,})["\']',
    'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}',
    'github_token': r'ghp_[A-Za-z0-9]{36}',
    'private_key': r'-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----',
    'database_url': r'(mysql|postgresql|mongodb):\/\/[^:]+:[^@]+@[^\/]+',
}

def load_endpoints(run_dir):
    """Load interesting endpoints from 03_endpoints.json"""
    endpoints_file = Path(run_dir) / "03_endpoints.json"
    if not endpoints_file.exists():
        print(f"[!] {endpoints_file} not found. Run discovery phase first.")
        sys.exit(1)

    with open(endpoints_file) as f:
        data = json.load(f)

    # Extract interesting endpoints
    interesting = data.get('interesting_endpoints', [])
    print(f"[*] Loaded {len(interesting)} interesting endpoints")
    return interesting

def scan_for_secrets(content, url):
    """Scan content for secret patterns"""
    findings = []

    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            secret_value = match.group(0)
            # Redact for logging (keep first/last 4 chars)
            if len(secret_value) > 12:
                redacted = secret_value[:4] + "..." + secret_value[-4:]
            else:
                redacted = secret_value[:2] + "..." + secret_value[-2:]

            findings.append({
                'type': secret_type,
                'value': secret_value,  # Full value for reporting
                'redacted': redacted,
                'url': url,
                'context': content[max(0, match.start()-50):min(len(content), match.end()+50)]
            })

    return findings

def test_endpoint(endpoint, timeout=10):
    """Test a single endpoint for secret exposure"""
    url = endpoint['url']
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
    }

    try:
        print(f"[*] Testing: {url}")
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)

        # Check for accessible content
        if response.status_code == 200:
            content = response.text
            secrets = scan_for_secrets(content, url)

            if secrets:
                return {
                    'url': url,
                    'status_code': 200,
                    'secrets_found': secrets,
                    'content_length': len(content),
                    'content_type': response.headers.get('Content-Type', 'unknown')
                }

            # Check for git-specific files
            if '.git/' in url:
                return {
                    'url': url,
                    'status_code': 200,
                    'git_exposed': True,
                    'content_length': len(content),
                    'recommendation': 'Run git-dumper to extract full repository'
                }

        return None

    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing {url}: {e}")
        return None

def create_vulnerability_report(finding, run_dir):
    """Create standardized vulnerability report"""

    # Determine severity
    severity = "critical"
    if finding.get('git_exposed'):
        severity = "critical"
        vuln_type = "Git Repository Exposure"
        impact = "Full source code disclosure, potential credential exposure"
    else:
        secret_types = [s['type'] for s in finding.get('secrets_found', [])]
        vuln_type = "Exposed Secrets"

        if 'aws_access_key' in secret_types or 'private_key' in secret_types:
            severity = "critical"
            impact = "Cloud infrastructure compromise, unauthorized access"
        elif 'api_key' in str(secret_types) or 'password' in secret_types:
            severity = "high"
            impact = "Unauthorized API access, potential data breach"
        else:
            severity = "medium"
            impact = "Information disclosure"

    vuln = {
        'id': f"VULN-SECRET-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'type': vuln_type,
        'severity': severity,
        'endpoint': finding['url'],
        'discovered_at': datetime.utcnow().isoformat() + 'Z',
        'proof_of_concept': {
            'request': f"GET {finding['url']}",
            'status_code': finding['status_code'],
            'content_length': finding.get('content_length', 0),
        },
        'remediation': 'Remove sensitive files from public web root. Use .gitignore to prevent accidental commits.',
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
            'https://cwe.mitre.org/data/definitions/200.html'
        ]
    }

    # Add secret details if found
    if 'secrets_found' in finding:
        vuln['proof_of_concept']['secrets'] = [
            {
                'type': s['type'],
                'redacted_value': s['redacted'],
                'context': s['context'][:100] + '...'  # Truncate context
            }
            for s in finding['secrets_found']
        ]

    # Calculate CVSS score
    if severity == "critical":
        vuln['cvss_score'] = 9.1
    elif severity == "high":
        vuln['cvss_score'] = 7.5
    else:
        vuln['cvss_score'] = 5.3

    return vuln

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 07_secret_exposure.py <run_directory>")
        sys.exit(1)

    run_dir = sys.argv[1]
    print(f"[*] Secret Exposure Testing - Run Directory: {run_dir}")

    # Load endpoints
    interesting = load_endpoints(run_dir)

    if not interesting:
        print("[*] No interesting endpoints flagged. Skipping secret exposure testing.")
        sys.exit(0)

    # Test endpoints
    vulnerabilities = []
    tested_count = 0

    for endpoint in interesting:
        finding = test_endpoint(endpoint)
        tested_count += 1

        if finding:
            vuln = create_vulnerability_report(finding, run_dir)
            vulnerabilities.append(vuln)
            print(f"[+] VULNERABILITY FOUND: {vuln['type']} at {vuln['endpoint']}")
            print(f"    Severity: {vuln['severity'].upper()}")

    # Update findings.json
    findings_file = Path(run_dir) / "findings.json"

    if findings_file.exists():
        with open(findings_file) as f:
            findings = json.load(f)
    else:
        # Initialize from schema
        schema_path = Path(__file__).parent / "findings_schema.json"
        with open(schema_path) as f:
            findings = json.load(f)
        findings['target'] = Path(run_dir).name.split('-')[0]
        findings['run_directory'] = run_dir
        findings['timestamp'] = datetime.utcnow().isoformat() + 'Z'

    # Append vulnerabilities
    findings['vulnerabilities'].extend(vulnerabilities)
    findings['total_vulnerabilities'] = len(findings['vulnerabilities'])
    findings['tested_endpoints'] += tested_count

    # Update severity breakdown
    for vuln in vulnerabilities:
        findings['severity_breakdown'][vuln['severity']] += 1

    # Save findings
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n[*] Testing complete. Found {len(vulnerabilities)} secret exposure vulnerabilities.")
    print(f"[*] Results saved to {findings_file}")

if __name__ == '__main__':
    main()
```

### Git Repository Dumping (if .git/ accessible)
```bash
#!/bin/bash
# Git repository dumper

RUN_DIR="$1"
GIT_URL="$2"  # e.g., https://example.com/.git/

if [ -z "$RUN_DIR" ] || [ -z "$GIT_URL" ]; then
    echo "Usage: bash git_dump.sh <run_directory> <git_url>"
    exit 1
fi

OUTPUT_DIR="$RUN_DIR/secrets/git_dump"
mkdir -p "$OUTPUT_DIR"

echo "[*] Attempting to dump git repository: $GIT_URL"

# Try git-dumper
if command -v git-dumper >/dev/null 2>&1; then
    git-dumper "$GIT_URL" "$OUTPUT_DIR"
else
    # Manual extraction
    echo "[*] git-dumper not found, trying manual extraction"

    # Download key files
    curl -s "${GIT_URL}config" -o "$OUTPUT_DIR/config"
    curl -s "${GIT_URL}HEAD" -o "$OUTPUT_DIR/HEAD"
    curl -s "${GIT_URL}index" -o "$OUTPUT_DIR/index"
    curl -s "${GIT_URL}logs/HEAD" -o "$OUTPUT_DIR/logs_HEAD"
fi

# Scan dumped content for secrets
if [ -d "$OUTPUT_DIR" ]; then
    echo "[*] Running trufflehog on dumped repository"
    trufflehog filesystem "$OUTPUT_DIR" --json > "$RUN_DIR/secrets/trufflehog_results.json"

    echo "[*] Running gitleaks on dumped repository"
    gitleaks detect --source "$OUTPUT_DIR" --report-path "$RUN_DIR/secrets/gitleaks_results.json"
fi

echo "[*] Git dump complete. Results in $RUN_DIR/secrets/"
```

## Expected Output

### Vulnerable Example
```json
{
  "id": "VULN-SECRET-20260401130523",
  "type": "Exposed Secrets",
  "severity": "critical",
  "endpoint": "https://api.example.com/.env",
  "proof_of_concept": {
    "request": "GET https://api.example.com/.env",
    "status_code": 200,
    "content_length": 847,
    "secrets": [
      {
        "type": "aws_access_key",
        "redacted_value": "AKIA...XY9Z",
        "context": "AWS_ACCESS_KEY_ID=AKIA..."
      }
    ]
  },
  "remediation": "Remove .env file from web root. Use .gitignore.",
  "cvss_score": 9.1
}
```

### Safe Example
```
[*] Testing: https://example.com/.git/config
[!] 404 Not Found - .git directory not accessible (SAFE)
```

## Vulnerable vs. Safe

**Vulnerable**:
- `.git/config` returns 200 OK with repository configuration
- `.env` file accessible with `DATABASE_URL=postgres://user:pass@host/db`
- Backup file `config.php.bak` contains database credentials
- Debug endpoint `/debug` shows environment variables

**Safe**:
- All sensitive paths return 404 Not Found or 403 Forbidden
- No secret patterns detected in HTTP responses
- `.gitignore` properly configured to exclude sensitive files
- Debug endpoints disabled in production

## Safety Notes

### Rate Limiting
- Read-only operations (no fuzzing required)
- Minimal requests (only testing pre-flagged endpoints)
- Safe for production environments

### WAF Awareness
- Simple GET requests (unlikely to trigger WAF)
- No payload encoding needed
- Legitimate security research traffic pattern

### Detection Risk
- **Low** - Accessing public endpoints only
- Indistinguishable from regular web browsing
- No authentication bypass attempts

## Execution Time
**Estimated**: 5-10 minutes
- Depends on number of interesting endpoints flagged during discovery
- Git repository dumping adds 2-5 minutes per repository
- Trufflehog/gitleaks scanning adds 1-3 minutes per repository

## Next Step
After secret exposure testing:
- If critical secrets found (AWS keys, private keys): **STOP and report immediately**
- If no secrets found: Proceed to **05_bola_idor.md** (API authorization testing)
- If .git repository dumped: Review source code for hardcoded credentials before proceeding

## Remediation Guidance

### For .git Exposure
```bash
# Add to .gitignore
echo ".git/" >> .gitignore

# Remove from web root (server configuration)
# Apache: Add to .htaccess
<DirectoryMatch "^/.*/\.git/">
    Require all denied
</DirectoryMatch>

# Nginx: Add to server block
location ~ /\.git {
    deny all;
}
```

### For .env Files
```bash
# Never commit .env files
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore

# Move outside web root
mv .env ../  # Above document root
```

### For API Keys in Responses
- Rotate all exposed credentials immediately
- Implement secret scanning in CI/CD pipeline (pre-commit hooks)
- Use secret management tools (AWS Secrets Manager, HashiCorp Vault)
- Never log sensitive data in application logs
