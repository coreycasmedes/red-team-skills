# Technology Fingerprinting & Target Prioritization

## Purpose
Identify technologies, frameworks, WAF presence, authentication surfaces, and high-value targets across the discovered attack surface.

## Inputs
**Required files:**
- `runs/{target}-{timestamp}/02_live_hosts.json` (live hosts)
- `runs/{target}-{timestamp}/03_endpoints.json` (discovered endpoints)

**Optional:**
- Custom nuclei template directory
- Custom nuclei tags

## Outputs
**File:** `runs/{target}-{timestamp}/04_fingerprint.json`

**Schema:**
```json
{
  "target": "example.com",
  "timestamp": "2026-04-01T12:30:00Z",
  "tools_used": ["nuclei", "httpx"],
  "execution_time_seconds": 421,
  "total_hosts_analyzed": 234,
  "technologies": {
    "web_servers": {
      "nginx": 142,
      "Apache": 67,
      "IIS": 18,
      "Cloudflare": 7
    },
    "frameworks": {
      "React": 89,
      "WordPress": 34,
      "Laravel": 12,
      "Django": 8
    },
    "languages": {
      "PHP": 67,
      "JavaScript": 234,
      "Python": 23,
      "Ruby": 5
    },
    "cms": {
      "WordPress": 34,
      "Drupal": 3,
      "Joomla": 1
    }
  },
  "waf_detected": {
    "Cloudflare": 78,
    "AWS WAF": 12,
    "ModSecurity": 5,
    "None": 139
  },
  "authentication_surfaces": [
    {
      "url": "https://admin.example.com/login",
      "type": "form-based",
      "framework": "custom",
      "mfa_detected": false
    },
    {
      "url": "https://api.example.com/oauth/authorize",
      "type": "OAuth2",
      "framework": "standard",
      "mfa_detected": true
    }
  ],
  "high_value_targets": [
    {
      "url": "https://jenkins.example.com",
      "reason": "Jenkins CI/CD server",
      "priority": "critical",
      "tech": ["Jenkins 2.387"],
      "findings": ["unauthenticated access", "exposed build logs"]
    },
    {
      "url": "https://api.example.com",
      "reason": "API gateway with swagger docs",
      "priority": "high",
      "tech": ["Swagger UI", "Express"],
      "findings": ["API documentation exposed"]
    }
  ],
  "nuclei_findings": [
    {
      "template": "exposed-panels/jenkins-panel.yaml",
      "matched_at": "https://jenkins.example.com",
      "severity": "info",
      "name": "Jenkins Login Panel",
      "tags": ["panel", "jenkins"]
    }
  ]
}
```

## Pre-flight Checklist
- [ ] Live host probing complete (`02_live_hosts.json` exists)
- [ ] Endpoint crawling complete (`03_endpoints.json` exists)
- [ ] `nuclei` installed (verify: `nuclei -version`)
- [ ] Nuclei templates updated (run: `nuclei -update-templates`)

## Commands

### 1. Extract Live Hosts and Interesting Endpoints
```bash
# Read run directory
SCOPE_FILE=$(ls -t runs/*/00_scope.json | head -1)
RUN_DIR=$(jq -r '.run_directory' "$SCOPE_FILE")
LIVE_HOSTS_FILE="$RUN_DIR/02_live_hosts.json"
ENDPOINTS_FILE="$RUN_DIR/03_endpoints.json"

# Extract all unique hosts
jq -r '.data[] | .url' "$LIVE_HOSTS_FILE" \
  > "$RUN_DIR/raw/hosts_for_nuclei.txt"

# Extract interesting endpoints
jq -r '.data[] | select(.interesting == true) | .url' "$ENDPOINTS_FILE" \
  >> "$RUN_DIR/raw/hosts_for_nuclei.txt"

# Deduplicate
sort -u "$RUN_DIR/raw/hosts_for_nuclei.txt" -o "$RUN_DIR/raw/hosts_for_nuclei.txt"

HOST_COUNT=$(wc -l < "$RUN_DIR/raw/hosts_for_nuclei.txt")
echo "✓ Prepared $HOST_COUNT targets for fingerprinting"
```

### 2. Run Nuclei with Relevant Templates
```bash
# Run nuclei with tech detection, WAF detection, panel detection, and misconfiguration tags
nuclei -list "$RUN_DIR/raw/hosts_for_nuclei.txt" \
  -tags tech-detect,waf,panel,exposure,misconfig \
  -severity info,low,medium,high,critical \
  -silent \
  -json \
  -o "$RUN_DIR/raw/nuclei.json"

NUCLEI_COUNT=$(wc -l < "$RUN_DIR/raw/nuclei.json" 2>/dev/null || echo "0")
echo "✓ Nuclei scan complete: $NUCLEI_COUNT findings"
```

**Tool flags:**
- `-list`: File containing target URLs
- `-tags`: Comma-separated template tags to run
  - `tech-detect`: Technology fingerprinting
  - `waf`: WAF detection
  - `panel`: Admin panel detection
  - `exposure`: Exposed services/configs
  - `misconfig`: Common misconfigurations
- `-severity`: Filter by severity levels
- `-silent`: Suppress banner and progress
- `-json`: Output in JSON format

**Note:** Nuclei scan time depends on target count and enabled templates (typically 5-10 minutes).

### 3. Aggregate Technology Data
```bash
# Python script to aggregate tech stack
python3 << 'EOF'
import json
from collections import defaultdict

# Read live hosts (already has tech detection from httpx)
with open("$LIVE_HOSTS_FILE") as f:
    live_hosts = json.load(f)

# Aggregate technologies
tech_categories = {
    "web_servers": defaultdict(int),
    "frameworks": defaultdict(int),
    "languages": defaultdict(int),
    "cms": defaultdict(int)
}

# Known categorization (expand as needed)
WEB_SERVERS = {"nginx", "apache", "iis", "cloudflare", "lighttpd", "caddy"}
CMS = {"wordpress", "drupal", "joomla", "magento", "shopify"}
FRAMEWORKS = {"react", "vue", "angular", "laravel", "django", "express", "rails", "flask"}
LANGUAGES = {"php", "python", "ruby", "java", "javascript", "go", "rust"}

def categorize_tech(tech_name):
    tech_lower = tech_name.lower()

    if any(ws in tech_lower for ws in WEB_SERVERS):
        return "web_servers"
    elif any(cms in tech_lower for cms in CMS):
        return "cms"
    elif any(fw in tech_lower for fw in FRAMEWORKS):
        return "frameworks"
    elif any(lang in tech_lower for lang in LANGUAGES):
        return "languages"
    else:
        return "frameworks"  # Default to frameworks

# Process live hosts
for host_data in live_hosts["data"]:
    tech_list = host_data.get("tech", [])
    webserver = host_data.get("webserver", "")

    if webserver:
        tech_categories["web_servers"][webserver.split("/")[0]] += 1

    for tech in tech_list:
        category = categorize_tech(tech)
        tech_categories[category][tech] += 1

# Convert defaultdict to regular dict for JSON serialization
technologies = {
    category: dict(techs)
    for category, techs in tech_categories.items()
}

# Write intermediate result
with open("$RUN_DIR/raw/tech_aggregate.json", "w") as f:
    json.dump(technologies, f, indent=2)

print("✓ Technology aggregation complete")
EOF
```

### 4. Detect WAF Presence
```bash
# Python script to identify WAF from nuclei + httpx data
python3 << 'EOF'
import json
from collections import defaultdict

# Read live hosts for CDN/WAF detection
with open("$LIVE_HOSTS_FILE") as f:
    live_hosts = json.load(f)

# Count WAF/CDN detections
waf_counts = defaultdict(int)

for host_data in live_hosts["data"]:
    cdn = host_data.get("cdn", "")

    if cdn:
        waf_counts[cdn] += 1
    else:
        waf_counts["None"] += 1

# Read nuclei results for additional WAF detection
try:
    with open("$RUN_DIR/raw/nuclei.json") as f:
        for line in f:
            finding = json.loads(line)
            if "waf" in finding.get("info", {}).get("tags", []):
                waf_name = finding.get("info", {}).get("name", "Unknown WAF")
                waf_counts[waf_name] += 1
except FileNotFoundError:
    pass

# Write result
with open("$RUN_DIR/raw/waf_detection.json", "w") as f:
    json.dump(dict(waf_counts), f, indent=2)

print("✓ WAF detection complete")
EOF
```

### 5. Identify Authentication Surfaces
```bash
# Python script to find login/auth endpoints
python3 << 'EOF'
import json
import re

# Read endpoints
with open("$ENDPOINTS_FILE") as f:
    endpoints = json.load(f)

# Authentication patterns
AUTH_PATTERNS = {
    "form-based": [r"/login", r"/signin", r"/auth/login", r"/user/login"],
    "OAuth2": [r"/oauth/authorize", r"/oauth2/authorize", r"/connect/authorize"],
    "SAML": [r"/saml/sso", r"/saml2/acs"],
    "API-key": [r"/api/authenticate", r"/api/login"],
    "Basic-Auth": []  # Detected via 401 status with WWW-Authenticate header
}

auth_surfaces = []

for endpoint_data in endpoints["data"]:
    url = endpoint_data["url"]
    path = endpoint_data["path"]

    for auth_type, patterns in AUTH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path, re.IGNORECASE):
                auth_surfaces.append({
                    "url": url,
                    "type": auth_type,
                    "framework": "detected from path",
                    "mfa_detected": False  # TODO: Detect via nuclei or manual
                })
                break

# Deduplicate by URL
auth_surfaces = list({a["url"]: a for a in auth_surfaces}.values())

# Write result
with open("$RUN_DIR/raw/auth_surfaces.json", "w") as f:
    json.dump(auth_surfaces, f, indent=2)

print(f"✓ Identified {len(auth_surfaces)} authentication surfaces")
EOF
```

### 6. Identify High-Value Targets
```bash
# Python script to prioritize targets
python3 << 'EOF'
import json
import re

# High-value patterns and priorities
HIGH_VALUE_PATTERNS = {
    "critical": {
        r"jenkins": "Jenkins CI/CD server",
        r"gitlab": "GitLab instance",
        r"jira": "Atlassian Jira",
        r"confluence": "Atlassian Confluence",
        r"sonarqube": "SonarQube code analysis",
        r"grafana": "Grafana monitoring",
        r"kibana": "Kibana dashboard",
        r"portainer": "Portainer Docker management"
    },
    "high": {
        r"/admin": "Admin panel",
        r"/api": "API gateway",
        r"swagger": "API documentation",
        r"graphql": "GraphQL endpoint",
        r"phpmyadmin": "phpMyAdmin database interface",
        r"adminer": "Adminer database tool"
    },
    "medium": {
        r"/backup": "Backup directory",
        r"/debug": "Debug endpoint",
        r"/test": "Test environment",
        r"/staging": "Staging environment",
        r"\.git": "Exposed git repository"
    }
}

# Read live hosts and endpoints
with open("$LIVE_HOSTS_FILE") as f:
    live_hosts = json.load(f)

with open("$ENDPOINTS_FILE") as f:
    endpoints = json.load(f)

# Read nuclei findings
nuclei_findings_by_url = {}
try:
    with open("$RUN_DIR/raw/nuclei.json") as f:
        for line in f:
            finding = json.loads(line)
            url = finding.get("matched-at", "")
            if url not in nuclei_findings_by_url:
                nuclei_findings_by_url[url] = []
            nuclei_findings_by_url[url].append(finding.get("info", {}).get("name", ""))
except FileNotFoundError:
    pass

# Identify high-value targets
high_value_targets = []

def check_patterns(url, title, tech):
    """Check if URL matches high-value patterns"""
    combined = f"{url} {title} {' '.join(tech)}".lower()

    for priority in ["critical", "high", "medium"]:
        for pattern, reason in HIGH_VALUE_PATTERNS[priority].items():
            if re.search(pattern, combined, re.IGNORECASE):
                return priority, reason
    return None, None

# Check live hosts
for host_data in live_hosts["data"]:
    url = host_data["url"]
    title = host_data.get("title", "")
    tech = host_data.get("tech", [])

    priority, reason = check_patterns(url, title, tech)

    if priority:
        findings = nuclei_findings_by_url.get(url, [])

        high_value_targets.append({
            "url": url,
            "reason": reason,
            "priority": priority,
            "tech": tech,
            "findings": findings
        })

# Check interesting endpoints
for endpoint_data in endpoints["data"]:
    if endpoint_data.get("interesting"):
        url = endpoint_data["url"]
        reason = endpoint_data.get("interesting_reason", "")

        # Skip if already added from live hosts
        if any(t["url"] == url for t in high_value_targets):
            continue

        findings = nuclei_findings_by_url.get(url, [])

        high_value_targets.append({
            "url": url,
            "reason": reason,
            "priority": "medium",
            "tech": [],
            "findings": findings
        })

# Sort by priority (critical > high > medium)
priority_order = {"critical": 0, "high": 1, "medium": 2}
high_value_targets.sort(key=lambda x: priority_order.get(x["priority"], 3))

# Write result
with open("$RUN_DIR/raw/high_value_targets.json", "w") as f:
    json.dump(high_value_targets, f, indent=2)

print(f"✓ Identified {len(high_value_targets)} high-value targets")
EOF
```

### 7. Build Final JSON Output
```bash
# Combine all fingerprinting data
python3 << 'EOF'
import json
from datetime import datetime, timezone
import os.path

# Read scope
with open("$SCOPE_FILE") as f:
    scope = json.load(f)

with open("$LIVE_HOSTS_FILE") as f:
    live_hosts = json.load(f)

# Load aggregated data
with open("$RUN_DIR/raw/tech_aggregate.json") as f:
    technologies = json.load(f)

with open("$RUN_DIR/raw/waf_detection.json") as f:
    waf_detected = json.load(f)

with open("$RUN_DIR/raw/auth_surfaces.json") as f:
    auth_surfaces = json.load(f)

with open("$RUN_DIR/raw/high_value_targets.json") as f:
    high_value_targets = json.load(f)

# Load nuclei findings
nuclei_findings = []
if os.path.exists("$RUN_DIR/raw/nuclei.json"):
    with open("$RUN_DIR/raw/nuclei.json") as f:
        for line in f:
            finding = json.loads(line)
            nuclei_findings.append({
                "template": finding.get("template-id", ""),
                "matched_at": finding.get("matched-at", ""),
                "severity": finding.get("info", {}).get("severity", ""),
                "name": finding.get("info", {}).get("name", ""),
                "tags": finding.get("info", {}).get("tags", [])
            })

# Build final output
output = {
    "target": scope["target"],
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "tools_used": ["nuclei", "httpx"],
    "execution_time_seconds": 0,
    "total_hosts_analyzed": live_hosts["total_live_hosts"],
    "technologies": technologies,
    "waf_detected": waf_detected,
    "authentication_surfaces": auth_surfaces,
    "high_value_targets": high_value_targets,
    "nuclei_findings": nuclei_findings
}

# Write final output
with open("$RUN_DIR/04_fingerprint.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"✓ Fingerprinting complete: {len(high_value_targets)} high-value targets identified")
EOF

echo "✓ Created: $RUN_DIR/04_fingerprint.json"
```

### 8. Verify Output and Display High-Value Targets
```bash
# Display summary
echo "=== FINGERPRINTING SUMMARY ==="
jq '{target, total_hosts_analyzed, high_value_target_count: (.high_value_targets | length)}' \
  "$RUN_DIR/04_fingerprint.json"

# Display technology breakdown
echo ""
echo "Top web servers:"
jq -r '.technologies.web_servers | to_entries | sort_by(-.value) | .[] | "\(.key): \(.value)"' \
  "$RUN_DIR/04_fingerprint.json"

# Display high-value targets
echo ""
echo "=== HIGH-VALUE TARGETS ==="
jq -r '.high_value_targets[] | "[\(.priority | ascii_upcase)] \(.url)\n  Reason: \(.reason)\n  Tech: \(.tech | join(", "))\n"' \
  "$RUN_DIR/04_fingerprint.json"
```

## Expected Output

**Good Result:**
```
✓ Prepared 281 targets for fingerprinting
✓ Nuclei scan complete: 47 findings
✓ Technology aggregation complete
✓ WAF detection complete
✓ Identified 12 authentication surfaces
✓ Identified 23 high-value targets
✓ Fingerprinting complete: 23 high-value targets identified
✓ Created: runs/example.com-20260401-103000/04_fingerprint.json

=== HIGH-VALUE TARGETS ===
[CRITICAL] https://jenkins.example.com
  Reason: Jenkins CI/CD server
  Tech: Jenkins 2.387

[HIGH] https://api.example.com
  Reason: API gateway
  Tech: Swagger UI, Express

[MEDIUM] https://staging.example.com/.git/config
  Reason: Exposed git repository
  Tech:
```

## Error Handling

**Issue:** Nuclei not found
```bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Ensure $GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**Issue:** Nuclei templates outdated
```bash
# Update templates
nuclei -update-templates

# Force update
nuclei -update-templates -force
```

**Issue:** Nuclei scan too slow
```bash
# Reduce scope to only interesting endpoints
jq -r '.data[] | select(.interesting == true) | .url' "$ENDPOINTS_FILE" \
  > "$RUN_DIR/raw/hosts_for_nuclei.txt"

# Or use specific tags only
nuclei -list "$RUN_DIR/raw/hosts_for_nuclei.txt" \
  -tags panel,exposure \
  -silent -json \
  -o "$RUN_DIR/raw/nuclei.json"
```

## Execution Time
- **Nuclei scan:** 5-15 minutes (depends on target count and templates)
- **Data aggregation:** 1-2 minutes
- **Total:** 5-20 minutes

## Rate Limiting Considerations
- **Nuclei:** Active scanning, configurable rate
  - Default: ~150 req/s per template
  - Stealth mode: Add `-rate-limit 10`
  - Use `-concurrency 5` to reduce parallel connections

## Vulnerable vs. Safe

**Vulnerable Approach:**
- Running all nuclei templates including exploits (risk of service disruption)
- No WAF detection (may trigger blocks)
- Aggressive scanning with no rate limits

**Safe Approach:**
- Info/low-severity templates only for discovery phase
- WAF-aware scanning with rate limits
- Prioritization for manual review (not automated exploitation)

## Next Steps

**Discovery phase complete!** You now have:
1. ✅ Scope validation (`00_scope.json`)
2. ✅ Subdomain enumeration (`01_subdomains.json`)
3. ✅ Live host identification (`02_live_hosts.json`)
4. ✅ Endpoint discovery (`03_endpoints.json`)
5. ✅ Technology fingerprinting (`04_fingerprint.json`)

**Recommended next actions:**
1. **Review high-value targets** manually
2. **Prioritize testing** based on:
   - Critical priority targets first
   - Authentication surfaces for auth bypass testing
   - Exposed configs/backups for sensitive data
   - API endpoints for authorization issues
3. **Create `findings.json`** as you test (phase 2)
4. **Load testing skills** from `skills/testing/` (when available)

## Report-Worthy Findings

If you identified any of the following during fingerprinting, **flag for immediate reporting**:
- ✅ Exposed `.git` directories with accessible files
- ✅ Unauthenticated admin panels (Jenkins, GitLab, etc.)
- ✅ Exposed credentials/API keys in URLs
- ✅ Backup files containing source code or config
- ✅ Unauthenticated API documentation exposing sensitive endpoints

## Verification Checklist
Discovery phase complete when:
- [ ] `runs/{target}-{timestamp}/04_fingerprint.json` exists
- [ ] High-value targets identified and prioritized
- [ ] Technology stack documented for each host
- [ ] WAF presence noted for testing planning
- [ ] Authentication surfaces cataloged
- [ ] All 5 discovery JSON files exist in run directory
