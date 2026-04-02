# 09 - Security Misconfiguration Testing

## Purpose
Detect weak security controls and misconfigurations including CORS, missing security headers, verbose errors, and cloud storage exposure.

## Inputs
- `02_live_hosts.json` - HTTP headers, TLS config, server versions
- `04_fingerprint.json` - WAF detection, technologies
- `01_subdomains.json` - Subdomain names (for cloud bucket enumeration)

## Testing Strategy

### Phase 1: CORS Misconfiguration
Test for Cross-Origin Resource Sharing issues:
- Wildcard `Access-Control-Allow-Origin: *`
- Reflected origin without validation
- `Access-Control-Allow-Credentials: true` with wildcard origin

### Phase 2: Missing Security Headers
Check for absence of:
- `X-Frame-Options` (clickjacking protection)
- `Content-Security-Policy` (XSS protection)
- `Strict-Transport-Security` (HTTPS enforcement)
- `X-Content-Type-Options: nosniff`

### Phase 3: Verbose Error Messages
Test for information disclosure in errors:
- Stack traces with file paths
- Database error messages
- Version information in errors

### Phase 4: Cloud Storage Misconfiguration
Test S3 buckets and Azure Blobs for:
- Public read access
- Public write access (rare but critical)
- Directory listing enabled

### Phase 5: Rate Limiting
Test authentication endpoints for:
- Missing rate limiting
- Weak throttling thresholds

## Commands

### Setup
```bash
RUN_DIR="runs/$(basename $(pwd))-$(date +%Y%m%d-%H%M%S)"

# Optional: Install cloud tools
command -v aws >/dev/null 2>&1 || echo "Optional: Install AWS CLI"
pip3 install s3scanner 2>/dev/null || echo "Optional: Install s3scanner"
```

### Security Misconfiguration Testing Script
```python
#!/usr/bin/env python3
"""
Security Misconfiguration Testing
"""
import json
import requests
import time
from datetime import datetime
from pathlib import Path
import sys
import re
from urllib.parse import urlparse

# Security headers that should be present
SECURITY_HEADERS = {
    'X-Frame-Options': 'Clickjacking protection',
    'X-Content-Type-Options': 'MIME-sniffing protection',
    'Strict-Transport-Security': 'HTTPS enforcement',
    'Content-Security-Policy': 'XSS/injection protection',
    'X-XSS-Protection': 'Legacy XSS protection',
    'Referrer-Policy': 'Referrer information control',
    'Permissions-Policy': 'Feature policy control'
}

def load_live_hosts(run_dir):
    """Load live hosts from discovery phase"""
    hosts_file = Path(run_dir) / "02_live_hosts.json"
    if not hosts_file.exists():
        print(f"[!] {hosts_file} not found. Run discovery phase first.")
        sys.exit(1)

    with open(hosts_file) as f:
        data = json.load(f)

    hosts = data.get('live_hosts', [])
    print(f"[*] Loaded {len(hosts)} live hosts")
    return hosts

def test_cors_misconfiguration(url):
    """Test for CORS misconfiguration"""
    vulnerabilities = []

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Origin': 'https://evil.com'  # Test with attacker origin
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        # Check for wildcard with credentials (critical)
        if acao == '*' and acac.lower() == 'true':
            vulnerabilities.append({
                'type': 'CORS Misconfiguration',
                'severity': 'high',
                'url': url,
                'issue': 'Wildcard origin with credentials',
                'headers': {
                    'Access-Control-Allow-Origin': acao,
                    'Access-Control-Allow-Credentials': acac
                },
                'impact': 'Credential theft via malicious site'
            })
            print(f"[+] CRITICAL CORS: Wildcard with credentials at {url}")

        # Check for reflected origin without validation
        elif acao == 'https://evil.com':
            vulnerabilities.append({
                'type': 'CORS Misconfiguration',
                'severity': 'high',
                'url': url,
                'issue': 'Reflected origin without validation',
                'headers': {
                    'Access-Control-Allow-Origin': acao
                },
                'impact': 'Cross-origin data theft'
            })
            print(f"[+] CORS: Reflected origin at {url}")

        # Check for wildcard (lower severity without credentials)
        elif acao == '*':
            vulnerabilities.append({
                'type': 'CORS Misconfiguration',
                'severity': 'medium',
                'url': url,
                'issue': 'Wildcard origin (credentials not allowed)',
                'headers': {
                    'Access-Control-Allow-Origin': acao
                },
                'impact': 'Public API data accessible cross-origin'
            })
            print(f"[*] CORS: Wildcard origin at {url}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing CORS for {url}: {e}")

    return vulnerabilities

def test_security_headers(url, response_headers):
    """Test for missing security headers"""
    vulnerabilities = []

    missing_headers = []

    for header, description in SECURITY_HEADERS.items():
        if header not in response_headers:
            missing_headers.append({
                'header': header,
                'description': description
            })

    if missing_headers:
        # Determine severity based on most critical missing header
        if 'Content-Security-Policy' in [h['header'] for h in missing_headers]:
            severity = 'medium'
        elif 'X-Frame-Options' in [h['header'] for h in missing_headers]:
            severity = 'medium'
        else:
            severity = 'low'

        vulnerabilities.append({
            'type': 'Missing Security Headers',
            'severity': severity,
            'url': url,
            'missing_headers': missing_headers,
            'impact': 'Reduced defense against various attacks (XSS, clickjacking, etc.)'
        })
        print(f"[*] Missing {len(missing_headers)} security headers at {url}")

    return vulnerabilities

def test_verbose_errors(url):
    """Test for verbose error messages"""
    vulnerabilities = []

    # Trigger errors with malformed requests
    error_triggers = [
        {'path': '/nonexistent-page-12345', 'expected': '404'},
        {'path': '/?id=\'"><script>alert(1)</script>', 'expected': 'error'},
        {'path': '/../../../etc/passwd', 'expected': 'error'},
    ]

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}

    for trigger in error_triggers[:1]:  # Limit to first trigger
        test_url = url.rstrip('/') + trigger['path']

        try:
            response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)
            response_text = response.text.lower()

            # Check for stack traces
            stack_trace_indicators = [
                'traceback', 'stack trace', 'exception',
                'at line', 'in file', '.py:', '.php:',
                'syntaxerror', 'nameerror', 'typeerror',
                'mysql', 'postgresql', 'ora-', 'sql syntax'
            ]

            found_indicators = [ind for ind in stack_trace_indicators if ind in response_text]

            if found_indicators:
                vulnerabilities.append({
                    'type': 'Verbose Error Messages',
                    'severity': 'low',
                    'url': test_url,
                    'issue': 'Stack trace or detailed error information disclosed',
                    'indicators': found_indicators,
                    'impact': 'Information disclosure aids further attacks'
                })
                print(f"[*] Verbose errors at {url}: {', '.join(found_indicators)}")
                break  # Found one, no need to test more

        except requests.exceptions.RequestException:
            continue

    return vulnerabilities

def enumerate_s3_buckets(subdomains):
    """Enumerate potential S3 buckets from subdomain names"""
    potential_buckets = []

    # Extract bucket name patterns from subdomains
    for subdomain in subdomains[:50]:  # Limit to first 50
        # Pattern: s3.amazonaws.com/bucket or bucket.s3.amazonaws.com
        if 's3.amazonaws.com' in subdomain or 's3-' in subdomain:
            potential_buckets.append(subdomain)
            continue

        # Extract just the subdomain part (potential bucket name)
        parts = subdomain.split('.')
        if len(parts) >= 2:
            bucket_name = parts[0]
            # Skip common prefixes that aren't likely buckets
            if bucket_name not in ['www', 'mail', 'smtp', 'ftp', 'api']:
                potential_buckets.append(bucket_name)

    return list(set(potential_buckets))

def test_s3_bucket_permissions(bucket_name):
    """Test S3 bucket for public access"""
    vulnerabilities = []

    # Try different S3 URL formats
    urls_to_test = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}

    for url in urls_to_test:
        try:
            response = requests.get(url, headers=headers, timeout=10)

            # Check for accessible bucket
            if response.status_code == 200:
                # Check if it's an XML listing (bucket contents)
                if '<?xml' in response.text and '<ListBucketResult' in response.text:
                    vulnerabilities.append({
                        'type': 'S3 Bucket Publicly Readable',
                        'severity': 'high',
                        'url': url,
                        'bucket_name': bucket_name,
                        'issue': 'S3 bucket allows public listing and read access',
                        'impact': 'Unauthorized access to stored files'
                    })
                    print(f"[+] PUBLIC S3 BUCKET: {url}")
                    break

            # Check for public write (try to upload)
            # Note: We don't actually upload, just test OPTIONS/HEAD
            options_response = requests.options(url, headers=headers, timeout=10)
            if 'PUT' in options_response.headers.get('Allow', ''):
                vulnerabilities.append({
                    'type': 'S3 Bucket Publicly Writable',
                    'severity': 'critical',
                    'url': url,
                    'bucket_name': bucket_name,
                    'issue': 'S3 bucket allows public write access',
                    'impact': 'Attacker can upload malicious files'
                })
                print(f"[+] PUBLIC WRITE S3 BUCKET: {url}")
                break

        except requests.exceptions.RequestException:
            continue

    return vulnerabilities

def test_rate_limiting(url):
    """Test for missing rate limiting on sensitive endpoint"""
    vulnerabilities = []

    # Only test if it looks like an auth endpoint
    if not any(pattern in url.lower() for pattern in ['/login', '/auth', '/signin', '/api/token']):
        return vulnerabilities

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}

    print(f"[*] Testing rate limiting on: {url}")

    # Send 20 rapid requests
    responses = []
    start_time = time.time()

    for i in range(20):
        try:
            response = requests.get(url, headers=headers, timeout=5)
            responses.append(response.status_code)
        except:
            break

    elapsed = time.time() - start_time

    # Check if any 429 (Too Many Requests) received
    if 429 not in responses:
        vulnerabilities.append({
            'type': 'Missing Rate Limiting',
            'severity': 'medium',
            'url': url,
            'issue': 'No rate limiting detected on authentication endpoint',
            'evidence': f'{len(responses)} requests in {elapsed:.2f}s without throttling',
            'impact': 'Credential brute-force attacks feasible'
        })
        print(f"[*] No rate limiting detected at {url}")

    return vulnerabilities

def create_vulnerability_report(finding, run_dir):
    """Create standardized vulnerability report"""

    vuln = {
        'id': f"VULN-MISCONFIG-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'type': finding.get('type', 'Security Misconfiguration'),
        'severity': finding.get('severity', 'medium'),
        'endpoint': finding.get('url', ''),
        'discovered_at': datetime.utcnow().isoformat() + 'Z',
        'proof_of_concept': {
            'issue': finding.get('issue', ''),
            'impact': finding.get('impact', ''),
        }
    }

    # Add type-specific details
    if 'headers' in finding:
        vuln['proof_of_concept']['headers'] = finding['headers']

    if 'missing_headers' in finding:
        vuln['proof_of_concept']['missing_headers'] = [h['header'] for h in finding['missing_headers']]

    if 'bucket_name' in finding:
        vuln['proof_of_concept']['bucket_name'] = finding['bucket_name']

    if 'evidence' in finding:
        vuln['proof_of_concept']['evidence'] = finding['evidence']

    # Set CVSS score
    severity_scores = {
        'critical': 9.1,
        'high': 7.5,
        'medium': 5.3,
        'low': 3.1
    }
    vuln['cvss_score'] = severity_scores.get(finding.get('severity', 'medium'), 5.0)

    # Set remediation
    vuln_type = finding.get('type', '')
    if 'CORS' in vuln_type:
        vuln['remediation'] = 'Implement strict CORS policy. Validate origins against whitelist. Avoid wildcard with credentials.'
    elif 'Security Headers' in vuln_type:
        vuln['remediation'] = 'Add missing security headers: X-Frame-Options, CSP, HSTS, X-Content-Type-Options.'
    elif 'S3 Bucket' in vuln_type:
        vuln['remediation'] = 'Configure S3 bucket ACLs to private. Use bucket policies to restrict access.'
    elif 'Rate Limiting' in vuln_type:
        vuln['remediation'] = 'Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute).'
    else:
        vuln['remediation'] = 'Follow security best practices. Review configuration for security weaknesses.'

    vuln['references'] = [
        'https://owasp.org/www-project-top-ten/',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
    ]

    return vuln

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 09_misconfig.py <run_directory>")
        sys.exit(1)

    run_dir = sys.argv[1]
    print(f"[*] Security Misconfiguration Testing - Run Directory: {run_dir}")

    # Load live hosts
    live_hosts = load_live_hosts(run_dir)

    if not live_hosts:
        print("[*] No live hosts found. Skipping misconfiguration testing.")
        sys.exit(0)

    all_vulnerabilities = []
    tested_count = 0

    # Test each live host
    for host in live_hosts[:30]:  # Limit to first 30
        url = host.get('url', '')
        status_code = host.get('status_code', 0)

        if status_code not in [200, 201, 301, 302]:
            continue

        print(f"\n[*] Testing: {url}")

        vulnerabilities = []

        # Test CORS
        cors_vulns = test_cors_misconfiguration(url)
        vulnerabilities.extend(cors_vulns)

        # Test security headers (use cached headers from discovery if available)
        if 'headers' in host:
            header_vulns = test_security_headers(url, host['headers'])
            vulnerabilities.extend(header_vulns)

        # Test verbose errors
        error_vulns = test_verbose_errors(url)
        vulnerabilities.extend(error_vulns)

        # Test rate limiting (only for auth endpoints)
        # rate_vulns = test_rate_limiting(url)  # Commented out - too aggressive
        # vulnerabilities.extend(rate_vulns)

        tested_count += 1

        # Create reports
        for vuln_finding in vulnerabilities:
            vuln = create_vulnerability_report(vuln_finding, run_dir)
            all_vulnerabilities.append(vuln)
            print(f"[+] MISCONFIGURATION: {vuln['type']} - {vuln['severity'].upper()}")

        time.sleep(0.5)  # Rate limiting between hosts

    # Test S3 buckets (if subdomains available)
    subdomains_file = Path(run_dir) / "01_subdomains.json"
    if subdomains_file.exists():
        print(f"\n[*] Testing for public S3 buckets...")
        with open(subdomains_file) as f:
            subdomain_data = json.load(f)
            subdomains = subdomain_data.get('subdomains', [])

        bucket_names = enumerate_s3_buckets(subdomains)
        print(f"[*] Testing {len(bucket_names)} potential S3 buckets")

        for bucket in bucket_names[:20]:  # Limit to 20
            s3_vulns = test_s3_bucket_permissions(bucket)
            for vuln_finding in s3_vulns:
                vuln = create_vulnerability_report(vuln_finding, run_dir)
                all_vulnerabilities.append(vuln)
                print(f"[+] S3 VULNERABILITY: {vuln['type']}")

            time.sleep(0.5)

    # Update findings.json
    findings_file = Path(run_dir) / "findings.json"

    if findings_file.exists():
        with open(findings_file) as f:
            findings = json.load(f)
    else:
        schema_path = Path(__file__).parent / "findings_schema.json"
        with open(schema_path) as f:
            findings = json.load(f)
        findings['target'] = Path(run_dir).name.split('-')[0]
        findings['run_directory'] = run_dir
        findings['timestamp'] = datetime.utcnow().isoformat() + 'Z'

    # Append vulnerabilities
    findings['vulnerabilities'].extend(all_vulnerabilities)
    findings['total_vulnerabilities'] = len(findings['vulnerabilities'])
    findings['tested_endpoints'] += tested_count

    # Update severity breakdown
    for vuln in all_vulnerabilities:
        findings['severity_breakdown'][vuln['severity']] += 1

    # Save findings
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n[*] Testing complete. Found {len(all_vulnerabilities)} misconfiguration issues.")
    print(f"[*] Results saved to {findings_file}")

if __name__ == '__main__':
    main()
```

## Expected Output

### Vulnerable - CORS Misconfiguration
```json
{
  "type": "CORS Misconfiguration",
  "severity": "high",
  "proof_of_concept": {
    "issue": "Wildcard origin with credentials",
    "headers": {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": "true"
    },
    "impact": "Credential theft via malicious site"
  }
}
```

### Vulnerable - Public S3 Bucket
```json
{
  "type": "S3 Bucket Publicly Readable",
  "severity": "high",
  "proof_of_concept": {
    "bucket_name": "company-backups",
    "issue": "S3 bucket allows public listing",
    "impact": "Unauthorized access to stored files"
  }
}
```

## Safety Notes

### Rate Limiting
- 0.5s between host tests
- Rate limiting test commented out by default (too aggressive)
- S3 tests: 0.5s between buckets

### Detection Risk
- **Low** - Legitimate security testing traffic
- CORS tests use single Origin header
- Error testing uses common 404 patterns

## Execution Time
**Estimated**: 5-10 minutes
- 30 hosts × 3 tests × 0.5s = ~45s
- S3 testing: 20 buckets × 0.5s = 10s
- Overhead for analysis: 5 minutes

## Next Step
After misconfiguration testing:
- Review all findings in `findings.json`
- Generate summary report
- Prioritize critical/high severity findings for immediate reporting
