# 06 - BFLA Testing (Broken Function Level Authorization)

## Purpose
Detect unauthorized access to privileged functions - OWASP API #5 vulnerability.

## Inputs
- `04_fingerprint.json` - High-value targets (admin panels, management APIs)
- `03_endpoints.json` - All endpoints for privilege escalation testing
- `02_live_hosts.json` - Authentication surfaces for token generation

## Testing Strategy

### Phase 1: Identify Privileged Endpoints
From `04_fingerprint.json` high_value_targets and path patterns:
- Admin panels: `/admin`, `/dashboard`, `/management`
- Privileged APIs: `/api/admin`, `/api/users/delete`, `/api/config`
- Management functions: `/manage`, `/settings`, `/control`

### Phase 2: Test Authorization Levels
For each privileged endpoint, test with:
1. **No authentication** (anonymous access)
2. **Low-privilege token** (regular user credentials)
3. **Different user's token** (horizontal privilege escalation)

### Phase 3: Vulnerability Detection
- **200 OK with privileged data** = BFLA vulnerability
- **403 Forbidden** = proper authorization (safe)
- **401 Unauthorized** = authentication required (safe)
- **302 redirect to login** = proper access control (safe)

## Commands

### Setup
```bash
RUN_DIR="runs/$(basename $(pwd))-$(date +%Y%m%d-%H%M%S)"

# Verify Python dependencies
python3 -c "import requests" 2>/dev/null || pip3 install requests
```

### BFLA Testing Script
```python
#!/usr/bin/env python3
"""
BFLA Testing - Broken Function Level Authorization
"""
import json
import requests
import time
from datetime import datetime
from pathlib import Path
import sys

# Privileged path patterns
PRIVILEGED_PATTERNS = [
    '/admin', '/administrator', '/dashboard', '/manage', '/management',
    '/panel', '/control', '/config', '/settings', '/system',
    '/api/admin', '/api/management', '/api/users/delete', '/api/users/update',
    '/v1/admin', '/v2/admin', '/debug', '/console'
]

def load_high_value_targets(run_dir):
    """Load high-value targets from fingerprinting phase"""
    fingerprint_file = Path(run_dir) / "04_fingerprint.json"
    if not fingerprint_file.exists():
        print(f"[!] {fingerprint_file} not found. Run discovery phase first.")
        sys.exit(1)

    with open(fingerprint_file) as f:
        data = json.load(f)

    targets = data.get('high_value_targets', [])
    print(f"[*] Loaded {len(targets)} high-value targets")
    return targets

def load_all_endpoints(run_dir):
    """Load all endpoints from crawling phase"""
    endpoints_file = Path(run_dir) / "03_endpoints.json"
    if not endpoints_file.exists():
        return []

    with open(endpoints_file) as f:
        data = json.load(f)

    return data.get('endpoints', [])

def identify_privileged_endpoints(targets, all_endpoints):
    """Identify endpoints that likely require privileged access"""
    privileged = []

    # Add high-value targets
    for target in targets:
        if target.get('priority') in ['critical', 'high']:
            privileged.append({
                'url': target['url'],
                'reason': target.get('reason', 'High-value target'),
                'priority': target['priority']
            })

    # Search all endpoints for privileged patterns
    for endpoint in all_endpoints:
        url = endpoint.get('url', '')
        for pattern in PRIVILEGED_PATTERNS:
            if pattern in url.lower():
                privileged.append({
                    'url': url,
                    'reason': f'Contains privileged path pattern: {pattern}',
                    'priority': 'medium'
                })
                break

    # Deduplicate
    seen_urls = set()
    unique_privileged = []
    for item in privileged:
        if item['url'] not in seen_urls:
            seen_urls.add(item['url'])
            unique_privileged.append(item)

    print(f"[*] Identified {len(unique_privileged)} privileged endpoints")
    return unique_privileged

def test_endpoint_authorization(url, rate_limit=1.0):
    """Test endpoint with different authorization levels"""
    results = {
        'url': url,
        'tests': []
    }

    headers_base = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept': 'application/json, text/html, */*'
    }

    # Test 1: Anonymous access (no authentication)
    print(f"[*] Testing anonymous access: {url}")
    try:
        response = requests.get(url, headers=headers_base, timeout=10, allow_redirects=False)
        results['tests'].append({
            'type': 'anonymous',
            'status_code': response.status_code,
            'content_length': len(response.text),
            'redirected': response.status_code in [301, 302, 303, 307, 308],
            'location': response.headers.get('Location', '')
        })

        # Check for vulnerability
        if response.status_code == 200:
            # Check if response contains privileged data
            if is_privileged_content(response.text):
                print(f"[+] POTENTIAL BFLA: Anonymous access returned privileged content")
                results['vulnerable'] = True
                results['vulnerability_type'] = 'Anonymous access to privileged function'

    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing anonymous access: {e}")
        results['tests'].append({'type': 'anonymous', 'error': str(e)})

    time.sleep(rate_limit)

    # Test 2: Low-privilege token (simulated - in real testing, get actual user token)
    # Note: This is a placeholder. In actual testing, you would:
    # 1. Create a low-privilege user account
    # 2. Authenticate and obtain a valid token
    # 3. Test privileged endpoints with that token

    print(f"[*] Note: Low-privilege token testing requires valid user credentials")
    print(f"[*] To implement: Create regular user account, authenticate, test with token")

    # Test 3: Common authentication bypass attempts
    bypass_tests = [
        {'header': 'X-Original-URL', 'value': url.split('/', 3)[-1]},  # X-Original-URL bypass
        {'header': 'X-Rewrite-URL', 'value': url.split('/', 3)[-1]},   # X-Rewrite-URL bypass
        {'header': 'X-Forwarded-For', 'value': '127.0.0.1'},           # Localhost bypass
    ]

    for bypass in bypass_tests:
        headers_bypass = headers_base.copy()
        headers_bypass[bypass['header']] = bypass['value']

        try:
            response = requests.get(url, headers=headers_bypass, timeout=10, allow_redirects=False)
            if response.status_code == 200 and is_privileged_content(response.text):
                print(f"[+] BFLA BYPASS: {bypass['header']} header bypass successful")
                results['vulnerable'] = True
                results['vulnerability_type'] = f"Authorization bypass via {bypass['header']} header"
                results['tests'].append({
                    'type': 'bypass',
                    'method': bypass['header'],
                    'status_code': response.status_code,
                    'success': True
                })
        except requests.exceptions.RequestException:
            pass

        time.sleep(rate_limit)

    return results

def is_privileged_content(content):
    """Check if response contains privileged data/functionality"""
    # Convert to lowercase for case-insensitive matching
    content_lower = content.lower()

    # Indicators of privileged content
    privileged_indicators = [
        'admin panel', 'dashboard', 'user management', 'delete user',
        'configuration', 'system settings', 'all users', 'user list',
        'create user', 'update user', 'delete account', 'manage',
        'control panel', 'administrative', 'privilege'
    ]

    # HTML form actions that suggest privileged operations
    privileged_actions = [
        'delete', 'remove', 'ban', 'suspend', 'promote', 'grant',
        'revoke', 'configure', 'modify'
    ]

    # Check for privileged indicators
    for indicator in privileged_indicators:
        if indicator in content_lower:
            return True

    # Check for privileged form actions
    if '<form' in content_lower:
        for action in privileged_actions:
            if action in content_lower:
                return True

    # Check for admin/privileged API responses
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            # Look for user lists or admin data
            if 'users' in data and isinstance(data['users'], list) and len(data['users']) > 1:
                return True
            if any(key in data for key in ['admin', 'privileges', 'permissions', 'roles']):
                return True
    except json.JSONDecodeError:
        pass

    return False

def create_vulnerability_report(test_result, run_dir):
    """Create standardized BFLA vulnerability report"""

    # Determine severity
    if test_result.get('vulnerability_type') == 'Anonymous access to privileged function':
        severity = 'critical'
        impact = 'Unauthenticated access to administrative functions'
    else:
        severity = 'high'
        impact = 'Unauthorized access to privileged operations'

    # Get successful test
    successful_test = None
    for test in test_result['tests']:
        if test.get('type') == 'anonymous' and test.get('status_code') == 200:
            successful_test = test
            break
        elif test.get('type') == 'bypass' and test.get('success'):
            successful_test = test
            break

    vuln = {
        'id': f"VULN-BFLA-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'type': 'BFLA',
        'severity': severity,
        'endpoint': test_result['url'],
        'discovered_at': datetime.utcnow().isoformat() + 'Z',
        'proof_of_concept': {
            'privileged_endpoint': test_result['url'],
            'access_method': test_result.get('vulnerability_type', 'Anonymous access'),
            'status_code': successful_test.get('status_code', 200) if successful_test else 200,
            'impact': impact
        },
        'remediation': 'Implement function-level authorization checks. Verify user has required privileges before executing privileged operations.',
        'references': [
            'https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/',
            'https://cwe.mitre.org/data/definitions/285.html'
        ],
        'cvss_score': 8.8 if severity == 'critical' else 7.5
    }

    # Add bypass-specific details
    if successful_test and successful_test.get('type') == 'bypass':
        vuln['proof_of_concept']['bypass_header'] = successful_test.get('method', '')

    return vuln

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 06_bfla_privilege.py <run_directory>")
        sys.exit(1)

    run_dir = sys.argv[1]
    print(f"[*] BFLA Testing - Run Directory: {run_dir}")

    # Load targets
    high_value_targets = load_high_value_targets(run_dir)
    all_endpoints = load_all_endpoints(run_dir)

    # Identify privileged endpoints
    privileged_endpoints = identify_privileged_endpoints(high_value_targets, all_endpoints)

    if not privileged_endpoints:
        print("[*] No privileged endpoints identified. Skipping BFLA testing.")
        sys.exit(0)

    # Test endpoints
    vulnerabilities = []
    tested_count = 0

    for endpoint in privileged_endpoints[:30]:  # Limit to first 30 for safety
        url = endpoint['url']

        test_result = test_endpoint_authorization(url, rate_limit=1.0)
        tested_count += 1

        if test_result.get('vulnerable'):
            vuln = create_vulnerability_report(test_result, run_dir)
            vulnerabilities.append(vuln)
            print(f"[+] BFLA VULNERABILITY CONFIRMED: {url}")
            print(f"    Type: {test_result.get('vulnerability_type')}")
            print(f"    Severity: {vuln['severity'].upper()}")

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
    findings['vulnerabilities'].extend(vulnerabilities)
    findings['total_vulnerabilities'] = len(findings['vulnerabilities'])
    findings['tested_endpoints'] += tested_count

    # Update severity breakdown
    for vuln in vulnerabilities:
        findings['severity_breakdown'][vuln['severity']] += 1

    # Save findings
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n[*] Testing complete. Found {len(vulnerabilities)} BFLA vulnerabilities.")
    print(f"[*] Results saved to {findings_file}")

if __name__ == '__main__':
    main()
```

## Expected Output

### Vulnerable Example
```json
{
  "id": "VULN-BFLA-20260401131045",
  "type": "BFLA",
  "severity": "critical",
  "endpoint": "https://admin.example.com/api/users/delete",
  "proof_of_concept": {
    "privileged_endpoint": "https://admin.example.com/api/users/delete",
    "access_method": "Anonymous access",
    "status_code": 200,
    "impact": "Unauthenticated access to administrative functions"
  },
  "remediation": "Implement function-level authorization checks",
  "cvss_score": 8.8
}
```

### Safe Example
```
[*] Testing anonymous access: https://admin.example.com/dashboard
[-] 401 Unauthorized - Authentication required (SAFE)
```

## Vulnerable vs. Safe

**Vulnerable**:
```
GET /api/admin/users HTTP/1.1
Host: example.com
[No authentication]

HTTP/1.1 200 OK
{"users": [...]}  ← Admin endpoint accessible without auth
```

**Safe**:
```
GET /api/admin/users HTTP/1.1
Host: example.com
[No authentication]

HTTP/1.1 403 Forbidden
{"error": "Insufficient privileges"}
```

## Safety Notes

### Rate Limiting
- **Default**: 1 second between requests
- Conservative to avoid detection
- Increase if 429 responses received

### WAF Awareness
- Simple GET requests (low risk)
- Header manipulation tests (may trigger WAF)
- If WAF detected, skip bypass attempts

### Detection Risk
- **Medium** - Accessing admin endpoints is logged
- Limit to 30 endpoints maximum
- Use realistic User-Agent

## Execution Time
**Estimated**: 5-15 minutes
- Depends on number of privileged endpoints
- Rate limit: 1s per request
- 30 endpoints × 4 tests = 120 requests = ~2 minutes + overhead

## Next Step
After BFLA testing:
- If critical BFLA found: **Report immediately**
- Proceed to **08_auth_bypass.md** (authentication mechanism testing)
