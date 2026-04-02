# Live Host Probing

## Purpose
Identify live HTTP/HTTPS services from resolved subdomains and capture technology fingerprints.

## Inputs
**Required files:**
- `runs/{target}-{timestamp}/01_subdomains.json` (from previous step)

**Optional:**
- Custom port list (default: 80, 443, 8080, 8443)

## Outputs
**File:** `runs/{target}-{timestamp}/02_live_hosts.json`

**Schema:**
```json
{
  "target": "example.com",
  "timestamp": "2026-04-01T11:15:00Z",
  "tools_used": ["httpx"],
  "execution_time_seconds": 287,
  "ports_probed": [80, 443, 8080, 8443],
  "total_hosts_probed": 891,
  "total_live_hosts": 234,
  "data": [
    {
      "url": "https://api.example.com",
      "host": "api.example.com",
      "port": 443,
      "scheme": "https",
      "status_code": 200,
      "content_length": 1234,
      "title": "Example API Gateway",
      "webserver": "nginx/1.21.0",
      "tech": ["Nginx", "Express"],
      "cdn": "Cloudflare",
      "tls": {
        "version": "TLSv1.3",
        "cipher": "TLS_AES_128_GCM_SHA256"
      },
      "response_time_ms": 142
    }
  ]
}
```

## Pre-flight Checklist
- [ ] Subdomain enumeration complete (`01_subdomains.json` exists)
- [ ] `httpx` installed (verify: `httpx -version`)
- [ ] At least some resolved subdomains exist
- [ ] Network connectivity to target is stable

## Commands

### 1. Extract Resolved Subdomains
```bash
# Read run directory and resolved subdomains
SCOPE_FILE=$(ls -t runs/*/00_scope.json | head -1)
RUN_DIR=$(jq -r '.run_directory' "$SCOPE_FILE")
SUBDOMAIN_FILE="$RUN_DIR/01_subdomains.json"

# Extract only resolved subdomains
jq -r '.data[] | select(.resolved == true) | .subdomain' "$SUBDOMAIN_FILE" \
  > "$RUN_DIR/raw/resolved_hosts.txt"

RESOLVED_COUNT=$(wc -l < "$RUN_DIR/raw/resolved_hosts.txt")
echo "✓ Extracted $RESOLVED_COUNT resolved subdomains"
```

### 2. Run httpx for Live Host Detection
```bash
# Probe common web ports with httpx
cat "$RUN_DIR/raw/resolved_hosts.txt" \
  | httpx -silent \
    -ports 80,443,8080,8443 \
    -status-code \
    -content-length \
    -title \
    -tech-detect \
    -web-server \
    -cdn \
    -response-time \
    -tls-probe \
    -json \
    -o "$RUN_DIR/raw/httpx.json"

LIVE_COUNT=$(wc -l < "$RUN_DIR/raw/httpx.json")
echo "✓ httpx complete: $LIVE_COUNT live hosts found"
```

**Tool flags:**
- `-silent`: Suppress banner and progress
- `-ports`: Comma-separated port list
- `-status-code`: Include HTTP status code
- `-content-length`: Include response size
- `-title`: Extract HTML title tag
- `-tech-detect`: Detect technologies (Wappalyzer database)
- `-web-server`: Extract Server header
- `-cdn`: Detect CDN provider
- `-response-time`: Measure response latency
- `-tls-probe`: Extract TLS version and cipher
- `-json`: Output in JSON format

### 3. Build Final JSON Output
```bash
# Python script to structure httpx output
python3 << 'EOF'
import json
from datetime import datetime, timezone

# Read scope and subdomain files
with open("$SCOPE_FILE") as f:
    scope = json.load(f)

with open("$SUBDOMAIN_FILE") as f:
    subdomains = json.load(f)

# Read httpx output
data = []
try:
    with open("$RUN_DIR/raw/httpx.json") as f:
        for line in f:
            entry = json.loads(line)

            # Parse URL components
            url = entry.get("url", "")
            host = entry.get("host", "")
            port = entry.get("port", 0)
            scheme = entry.get("scheme", "")

            # Extract technology data
            tech = entry.get("tech", [])
            if isinstance(tech, str):
                tech = [tech]

            # Build structured entry
            data.append({
                "url": url,
                "host": host,
                "port": port,
                "scheme": scheme,
                "status_code": entry.get("status_code", 0),
                "content_length": entry.get("content_length", 0),
                "title": entry.get("title", ""),
                "webserver": entry.get("webserver", ""),
                "tech": tech,
                "cdn": entry.get("cdn", ""),
                "tls": {
                    "version": entry.get("tls_version", ""),
                    "cipher": entry.get("tls_cipher", "")
                } if entry.get("tls_version") else None,
                "response_time_ms": entry.get("response_time", 0)
            })
except FileNotFoundError:
    pass

# Build final output
output = {
    "target": scope["target"],
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "tools_used": ["httpx"],
    "execution_time_seconds": 0,  # TODO: track if needed
    "ports_probed": [80, 443, 8080, 8443],
    "total_hosts_probed": subdomains["resolved_subdomains"],
    "total_live_hosts": len(data),
    "data": data
}

# Write output
with open("$RUN_DIR/02_live_hosts.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"✓ Final output: {len(data)} live hosts")
EOF

echo "✓ Created: $RUN_DIR/02_live_hosts.json"
```

### 4. Verify Output
```bash
# Display summary statistics
echo "=== LIVE HOST PROBE SUMMARY ==="
jq '{target, total_hosts_probed, total_live_hosts, ports_probed}' "$RUN_DIR/02_live_hosts.json"

# Show breakdown by status code
echo ""
echo "Status code distribution:"
jq -r '.data[] | .status_code' "$RUN_DIR/02_live_hosts.json" \
  | sort | uniq -c | sort -rn

# Show technology summary
echo ""
echo "Top technologies detected:"
jq -r '.data[] | .tech[]?' "$RUN_DIR/02_live_hosts.json" \
  | sort | uniq -c | sort -rn | head -10
```

## Expected Output

**Good Result:**
```
✓ Extracted 891 resolved subdomains
✓ httpx complete: 234 live hosts found
✓ Final output: 234 live hosts
✓ Created: runs/example.com-20260401-103000/02_live_hosts.json

=== LIVE HOST PROBE SUMMARY ===
{
  "target": "example.com",
  "total_hosts_probed": 891,
  "total_live_hosts": 234,
  "ports_probed": [80, 443, 8080, 8443]
}

Status code distribution:
    156 200
     42 301
     18 403
     12 401
      6 500
```

**Bad Result:**
```
✓ Extracted 891 resolved subdomains
✓ httpx complete: 0 live hosts found

WARNING: No live hosts found. Possible causes:
- Network connectivity issues
- Target hosts are down
- Firewall blocking probes
```

## Error Handling

**Issue:** httpx not found
```bash
# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Ensure $GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**Issue:** Rate limiting or connection timeouts
```bash
# Add rate limiting and timeout controls
cat "$RUN_DIR/raw/resolved_hosts.txt" \
  | httpx -silent \
    -ports 80,443,8080,8443 \
    -rate-limit 50 \
    -timeout 10 \
    -retries 2 \
    -status-code -content-length -title \
    -tech-detect -web-server -cdn \
    -response-time -tls-probe \
    -json \
    -o "$RUN_DIR/raw/httpx.json"
```

**Tool flags for rate limiting:**
- `-rate-limit 50`: Limit to 50 requests/second
- `-timeout 10`: 10-second timeout per request
- `-retries 2`: Retry failed requests 2 times

**Issue:** Too many connection errors
```bash
# Check for network issues
echo "Testing connectivity to a known host..."
echo "google.com" | httpx -silent

# If this fails, network/DNS issues exist
```

**Issue:** TLS certificate errors
```bash
# Ignore TLS certificate validation (for testing only)
# Add flag: -tls-skip-verify
# WARNING: Only use for bug bounty recon, not production
```

## Execution Time
- **Small target** (~100 resolved hosts): 1-2 minutes
- **Medium target** (~500 resolved hosts): 3-5 minutes
- **Large target** (~2000 resolved hosts): 10-15 minutes

Time varies based on network latency and target responsiveness.

## Rate Limiting Considerations
- Default httpx rate: ~1000 req/s (aggressive)
- Recommended rate for stealth: 10-50 req/s
- Add `-rate-limit 10` for low-profile scanning
- Monitor for 429 (Too Many Requests) responses

## Vulnerable vs. Safe

**Vulnerable Approach:**
- Aggressive scanning with no rate limits (triggers WAF/IDS)
- Probing all 65535 ports (noisy, unnecessary)
- No timeout handling (resource exhaustion)

**Safe Approach:**
- Rate-limited probing (respectful of target resources)
- Common web ports only (80, 443, 8080, 8443)
- Timeout and retry logic (handles transient failures)
- Technology fingerprinting for follow-up prioritization

## High-Value Indicators

**Prioritize hosts with:**
- Status 200 with login/admin keywords in title
- Technologies: Jenkins, GitLab, Jira, Confluence
- Status 401/403 (authentication required = something to protect)
- Custom webserver headers (potential custom apps)
- Old software versions in Server header

**Examples:**
```bash
# Find admin panels
jq -r '.data[] | select(.title | test("admin|login|dashboard"; "i")) | .url' \
  "$RUN_DIR/02_live_hosts.json"

# Find outdated servers
jq -r '.data[] | select(.webserver | test("Apache/2\\.(2|4)|nginx/1\\.1")) | {url, webserver}' \
  "$RUN_DIR/02_live_hosts.json"
```

## Next Step
**After live host probing:**
Load and execute `skills/discovery/03_endpoint_crawl.md` to discover endpoints and paths on live hosts.

## Verification Checklist
Before proceeding to endpoint crawling:
- [ ] `runs/{target}-{timestamp}/02_live_hosts.json` exists
- [ ] JSON file contains `data` array with URL objects
- [ ] At least some hosts have status_code 200
- [ ] Technology detection captured (tech array not empty for most hosts)
- [ ] No excessive connection errors or timeouts
