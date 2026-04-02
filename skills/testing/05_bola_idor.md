# 05 - BOLA/IDOR Testing (Broken Object Level Authorization)

## Purpose
Detect unauthorized access to objects via ID manipulation - the #1 API vulnerability in OWASP API Top 10.

## Inputs
- `03_endpoints.json` - API endpoints with numeric/UUID parameters
- `04_fingerprint.json` - High-value API targets
- `00_scope.json` - Scope validation

## Testing Strategy

### Phase 1: Identify Testable Endpoints
Extract API endpoints with ID-like parameters:
- **Numeric IDs**: `/api/user/123`, `/v1/order/456`
- **UUIDs**: `/api/resource/550e8400-e29b-41d4-a716-446655440000`
- **Common parameter names**: `id`, `user_id`, `account_id`, `order_id`, `resource_id`, `uuid`

### Phase 2: Generate Test Cases
For each endpoint with ID parameter:
1. **Baseline request**: Capture original response (if authenticated)
2. **Sequential IDs**: Test id+1, id+10, id+100 (numeric only)
3. **Common IDs**: Test 1, 2, 100, 1000, 9999 from wordlist
4. **Edge cases**: 0, -1, MAX_INT (depending on API behavior)

### Phase 3: Vulnerability Detection
Compare responses to identify BOLA:
- **Different data + same status code** = BOLA vulnerability (accessing other user's data)
- **403/401 error** = proper authorization (not vulnerable)
- **404 error** = object doesn't exist (expected behavior)
- **500 error** = potential input validation issue (investigate)

### Algorithm
```
For each endpoint with ID parameter:
    original_id = extract_id(endpoint)
    original_response = GET(endpoint, original_id)

    for test_id in [original_id+1, original_id+10, 1, 2, 100, 1000]:
        test_response = GET(endpoint, test_id)

        if test_response.status == 200 AND test_response.data != original_response.data:
            if different_user_data(test_response, original_response):
                REPORT BOLA VULNERABILITY
```

## Commands

### Setup
```bash
# Set run directory
RUN_DIR="runs/$(basename $(pwd))-$(date +%Y%m%d-%H%M%S)"

# Verify tools
python3 --version || echo "Install Python 3"
command -v ffuf >/dev/null 2>&1 || echo "Optional: Install ffuf for fuzzing"
```

### BOLA Testing Script
```python
#!/usr/bin/env python3
"""
BOLA/IDOR Testing - Broken Object Level Authorization
"""
import json
import re
import requests
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import sys

# ID parameter patterns
ID_PATTERNS = {
    'numeric': r'\/(\d+)(?:\/|$|\?)',  # /api/user/123
    'uuid': r'\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\/|$|\?)',
    'param': r'[?&](id|user_id|account_id|order_id|resource_id|object_id)=([^&]+)'
}

def load_endpoints(run_dir):
    """Load API endpoints from discovery phase"""
    endpoints_file = Path(run_dir) / "03_endpoints.json"
    if not endpoints_file.exists():
        print(f"[!] {endpoints_file} not found. Run discovery phase first.")
        sys.exit(1)

    with open(endpoints_file) as f:
        data = json.load(f)

    # Extract API endpoints
    all_endpoints = data.get('endpoints', [])
    print(f"[*] Loaded {len(all_endpoints)} total endpoints")
    return all_endpoints

def extract_id_from_endpoint(url):
    """Extract ID parameter and type from URL"""
    # Check for numeric ID in path
    match = re.search(ID_PATTERNS['numeric'], url)
    if match:
        return {
            'type': 'numeric',
            'value': int(match.group(1)),
            'url_template': re.sub(r'\/\d+', '/{id}', url, count=1)
        }

    # Check for UUID in path
    match = re.search(ID_PATTERNS['uuid'], url, re.IGNORECASE)
    if match:
        return {
            'type': 'uuid',
            'value': match.group(1),
            'url_template': re.sub(ID_PATTERNS['uuid'], '/{id}', url, count=1)
        }

    # Check for ID in query parameters
    match = re.search(ID_PATTERNS['param'], url)
    if match:
        param_name = match.group(1)
        param_value = match.group(2)

        # Determine if numeric or string
        try:
            numeric_val = int(param_value)
            return {
                'type': 'numeric',
                'value': numeric_val,
                'param_name': param_name,
                'url_template': re.sub(f'{param_name}=[^&]+', f'{param_name}={{id}}', url)
            }
        except ValueError:
            return {
                'type': 'string',
                'value': param_value,
                'param_name': param_name,
                'url_template': re.sub(f'{param_name}=[^&]+', f'{param_name}={{id}}', url)
            }

    return None

def generate_test_ids(original_id, id_type, wordlist_path=None):
    """Generate test IDs based on original ID type"""
    test_ids = []

    if id_type == 'numeric':
        original_val = int(original_id)
        # Sequential tests
        test_ids.extend([
            original_val + 1,
            original_val + 10,
            original_val - 1,
            original_val + 100,
        ])
        # Common IDs
        test_ids.extend([1, 2, 3, 10, 100, 1000, 9999])

        # Load wordlist if provided
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path) as f:
                wordlist_ids = [line.strip() for line in f if line.strip().isdigit()]
                test_ids.extend([int(x) for x in wordlist_ids])

    elif id_type == 'uuid':
        # UUID testing is limited (can't generate valid UUIDs easily)
        # Try common patterns
        test_ids = [
            '00000000-0000-0000-0000-000000000000',
            '00000000-0000-0000-0000-000000000001',
            '11111111-1111-1111-1111-111111111111',
        ]

    # Remove duplicates, preserve order
    seen = set()
    unique_ids = []
    for tid in test_ids:
        if tid not in seen and tid != original_id:
            seen.add(tid)
            unique_ids.append(tid)

    return unique_ids[:20]  # Limit to 20 tests per endpoint

def test_endpoint_for_bola(url, original_id, id_info, rate_limit=0.5):
    """Test a single endpoint for BOLA vulnerability"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Accept': 'application/json, text/html, */*'
    }

    try:
        # Get baseline response
        print(f"[*] Testing: {url}")
        baseline_response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)

        if baseline_response.status_code not in [200, 201]:
            print(f"[-] Baseline request failed with status {baseline_response.status_code}")
            return None

        baseline_data = baseline_response.text
        baseline_length = len(baseline_data)

        # Generate test IDs
        test_ids = generate_test_ids(
            original_id['value'],
            original_id['type'],
            wordlist_path='wordlists/idor_ids.txt'
        )

        vulnerabilities = []

        for test_id in test_ids:
            # Build test URL
            test_url = original_id['url_template'].replace('{id}', str(test_id))

            # Rate limiting
            time.sleep(rate_limit)

            try:
                test_response = requests.get(test_url, headers=headers, timeout=10, allow_redirects=False)

                # Check for BOLA vulnerability
                if test_response.status_code == 200:
                    test_data = test_response.text
                    test_length = len(test_data)

                    # Compare responses
                    if test_data != baseline_data:
                        # Different data returned = potential BOLA
                        # Additional validation: check if it's meaningful data
                        if is_meaningful_difference(baseline_data, test_data, test_length):
                            vulnerabilities.append({
                                'original_id': original_id['value'],
                                'test_id': test_id,
                                'test_url': test_url,
                                'baseline_length': baseline_length,
                                'test_length': test_length,
                                'status_code': test_response.status_code
                            })
                            print(f"[+] POTENTIAL BOLA: {test_url}")
                            break  # Found vulnerability, no need to test more IDs

            except requests.exceptions.RequestException as e:
                print(f"[!] Error testing {test_url}: {e}")
                continue

        return vulnerabilities if vulnerabilities else None

    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing baseline {url}: {e}")
        return None

def is_meaningful_difference(baseline, test_data, test_length):
    """Check if response difference indicates BOLA (not just timestamp/session differences)"""

    # If response is JSON, compare structure
    try:
        baseline_json = json.loads(baseline)
        test_json = json.loads(test_data)

        # Extract key fields that indicate user data
        user_fields = ['email', 'username', 'name', 'phone', 'address', 'account_id', 'user_id']

        for field in user_fields:
            baseline_val = extract_nested_value(baseline_json, field)
            test_val = extract_nested_value(test_json, field)

            if baseline_val and test_val and baseline_val != test_val:
                return True  # Different user data

    except json.JSONDecodeError:
        # Not JSON, compare content length
        # Significant size difference suggests different data
        if abs(len(baseline) - test_length) > 50:  # More than 50 bytes difference
            return True

    return False

def extract_nested_value(data, key):
    """Recursively extract value from nested dict"""
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for v in data.values():
            result = extract_nested_value(v, key)
            if result:
                return result
    elif isinstance(data, list):
        for item in data:
            result = extract_nested_value(item, key)
            if result:
                return result
    return None

def create_vulnerability_report(url, bola_findings, run_dir):
    """Create standardized BOLA vulnerability report"""

    finding = bola_findings[0]  # First confirmed BOLA

    vuln = {
        'id': f"VULN-BOLA-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'type': 'BOLA/IDOR',
        'severity': 'critical',
        'endpoint': url,
        'vulnerable_parameter': 'id',
        'discovered_at': datetime.utcnow().isoformat() + 'Z',
        'proof_of_concept': {
            'original_request': f"GET {url}",
            'original_id': str(finding['original_id']),
            'modified_request': f"GET {finding['test_url']}",
            'modified_id': str(finding['test_id']),
            'status_code': finding['status_code'],
            'impact': 'Unauthorized access to other users\' resources',
            'evidence': f"Response length changed from {finding['baseline_length']} to {finding['test_length']} bytes"
        },
        'remediation': 'Implement object-level authorization checks. Verify user owns the requested resource before returning data.',
        'references': [
            'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/',
            'https://cwe.mitre.org/data/definitions/639.html'
        ],
        'cvss_score': 9.1
    }

    return vuln

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 05_bola_idor.py <run_directory>")
        sys.exit(1)

    run_dir = sys.argv[1]
    print(f"[*] BOLA/IDOR Testing - Run Directory: {run_dir}")

    # Load endpoints
    endpoints = load_endpoints(run_dir)

    # Filter API endpoints with IDs
    testable_endpoints = []
    for endpoint in endpoints:
        url = endpoint.get('url', '')
        id_info = extract_id_from_endpoint(url)

        if id_info:
            testable_endpoints.append({
                'url': url,
                'id_info': id_info
            })

    print(f"[*] Found {len(testable_endpoints)} endpoints with ID parameters")

    if not testable_endpoints:
        print("[*] No testable endpoints found. Skipping BOLA testing.")
        sys.exit(0)

    # Test endpoints
    vulnerabilities = []
    tested_count = 0

    for endpoint_data in testable_endpoints[:50]:  # Limit to first 50 for safety
        url = endpoint_data['url']
        id_info = endpoint_data['id_info']

        bola_findings = test_endpoint_for_bola(url, id_info, id_info, rate_limit=0.5)
        tested_count += 1

        if bola_findings:
            vuln = create_vulnerability_report(url, bola_findings, run_dir)
            vulnerabilities.append(vuln)
            print(f"[+] BOLA VULNERABILITY CONFIRMED: {url}")
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

    print(f"\n[*] Testing complete. Found {len(vulnerabilities)} BOLA vulnerabilities.")
    print(f"[*] Results saved to {findings_file}")

if __name__ == '__main__':
    main()
```

### Alternative: ffuf-based BOLA Fuzzing
```bash
#!/bin/bash
# Fast BOLA testing with ffuf

RUN_DIR="$1"
TARGET_URL="$2"  # e.g., https://api.example.com/v1/user/FUZZ

if [ -z "$RUN_DIR" ] || [ -z "$TARGET_URL" ]; then
    echo "Usage: bash bola_ffuf.sh <run_directory> <target_url_with_FUZZ>"
    echo "Example: bash bola_ffuf.sh runs/example.com-20260401 'https://api.example.com/v1/user/FUZZ'"
    exit 1
fi

echo "[*] Running ffuf BOLA fuzzing: $TARGET_URL"

# Fuzz with ID wordlist
ffuf -u "$TARGET_URL" \
     -w wordlists/idor_ids.txt \
     -mc 200 \
     -t 10 \
     -rate 10 \
     -o "$RUN_DIR/bola_ffuf_results.json" \
     -of json

echo "[*] Results saved to $RUN_DIR/bola_ffuf_results.json"
echo "[*] Review results manually to confirm BOLA vulnerabilities"
```

## Expected Output

### Vulnerable Example
```json
{
  "id": "VULN-BOLA-20260401130523",
  "type": "BOLA/IDOR",
  "severity": "critical",
  "endpoint": "https://api.example.com/v1/user/123",
  "proof_of_concept": {
    "original_request": "GET /v1/user/123",
    "original_id": "123",
    "modified_request": "GET /v1/user/124",
    "modified_id": "124",
    "status_code": 200,
    "impact": "Unauthorized access to other users' resources",
    "evidence": "Response returned different user data (email: bob@example.com vs alice@example.com)"
  },
  "remediation": "Implement object-level authorization checks",
  "cvss_score": 9.1
}
```

### Safe Example
```
[*] Testing: https://api.example.com/v1/user/123
[*] Testing ID: 124
[-] 403 Forbidden - Authorization enforced correctly (SAFE)
```

## Vulnerable vs. Safe

**Vulnerable**:
```
GET /api/user/123 → {"email": "alice@example.com", "account_id": "123"}
GET /api/user/124 → {"email": "bob@example.com", "account_id": "124"}
```
User 123 can access user 124's data = BOLA vulnerability

**Safe**:
```
GET /api/user/123 → 200 OK {"email": "alice@example.com"}
GET /api/user/124 → 403 Forbidden {"error": "Unauthorized"}
```
Proper authorization check prevents access to other user's data

## Safety Notes

### Rate Limiting
- **Default**: 0.5 seconds between requests (2 req/s)
- **Maximum**: 10 req/s with ffuf (use `-rate 10` flag)
- Prevents API rate limiting and detection

### WAF Awareness
- Simple GET requests (low WAF trigger risk)
- Sequential ID testing (legitimate-looking traffic)
- If 429 received: Increase delay to 1-2 seconds

### Detection Risk
- **Medium** - Sequential ID testing is detectable
- Limit to 20 test IDs per endpoint
- Use realistic User-Agent headers

### Scope Validation
Always verify endpoint is in-scope before testing:
```python
# Check against 00_scope.json
with open(f"{run_dir}/00_scope.json") as f:
    scope = json.load(f)
    in_scope_domains = scope['in_scope']

parsed_url = urlparse(test_url)
if not any(domain in parsed_url.netloc for domain in in_scope_domains):
    print(f"[!] {test_url} is OUT OF SCOPE. Skipping.")
    continue
```

## Execution Time
**Estimated**: 15-20 minutes
- Depends on number of API endpoints with ID parameters
- Rate limiting: 0.5s per request = ~120 requests/minute
- 50 endpoints × 20 test IDs = 1000 requests = ~8-10 minutes
- Add overhead for response analysis: 5-10 minutes

## Next Step
After BOLA testing:
- If critical BOLA found: **Report immediately** (high impact vulnerability)
- If no BOLA found: Proceed to **06_bfla_privilege.md** (admin endpoint testing)
- Review findings.json for severity breakdown

## Real-World Examples

### Example 1: User Profile IDOR
```
Vulnerable endpoint: https://app.example.com/api/profile?user_id=5432
Attack: Change user_id=5433
Result: Access to another user's profile data
Impact: Privacy violation, data breach
```

### Example 2: Order Details BOLA
```
Vulnerable endpoint: https://shop.example.com/api/orders/98765
Attack: Increment to /api/orders/98766
Result: View another customer's order details
Impact: PII disclosure, transaction history exposure
```

### Example 3: File Download IDOR
```
Vulnerable endpoint: https://storage.example.com/download/file/abc123
Attack: Change to file/abc124
Result: Download another user's private files
Impact: Data breach, confidential document exposure
```
