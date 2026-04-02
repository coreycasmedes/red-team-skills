# Endpoint Discovery & Crawling

## Purpose
Discover all accessible endpoints, paths, and parameters across live hosts using active crawling and passive historical data.

## Inputs
**Required files:**
- `runs/{target}-{timestamp}/00_scope.json` (scope validation)
- `runs/{target}-{timestamp}/02_live_hosts.json` (live hosts to crawl)

**Optional:**
- Custom crawl depth (default: 3)
- Custom timeout (default: 5 seconds per request)

## Outputs
**File:** `runs/{target}-{timestamp}/03_endpoints.json`

**Schema:**
```json
{
  "target": "example.com",
  "timestamp": "2026-04-01T11:45:00Z",
  "tools_used": ["katana", "gau", "waybackurls"],
  "execution_time_seconds": 1823,
  "total_live_hosts": 234,
  "total_endpoints": 8472,
  "unique_paths": 3201,
  "interesting_endpoints": 47,
  "data": [
    {
      "url": "https://api.example.com/v1/users",
      "host": "api.example.com",
      "path": "/v1/users",
      "method": "GET",
      "status_code": 200,
      "source": "katana",
      "params": ["id", "limit"],
      "interesting": false,
      "interesting_reason": null
    },
    {
      "url": "https://admin.example.com/.git/config",
      "host": "admin.example.com",
      "path": "/.git/config",
      "method": "GET",
      "status_code": 200,
      "source": "waybackurls",
      "params": [],
      "interesting": true,
      "interesting_reason": "exposed .git directory"
    }
  ]
}
```

## Pre-flight Checklist
- [ ] Live host probing complete (`02_live_hosts.json` exists)
- [ ] `katana` installed (verify: `katana -version`)
- [ ] `gau` installed (verify: `gau --version`)
- [ ] `waybackurls` installed (verify: `waybackurls -h`)
- [ ] Sufficient disk space (estimate: 50-500 MB for large targets)

## Commands

### 1. Extract Live Host URLs
```bash
# Read run directory
SCOPE_FILE=$(ls -t runs/*/00_scope.json | head -1)
RUN_DIR=$(jq -r '.run_directory' "$SCOPE_FILE")
TARGET=$(jq -r '.target' "$SCOPE_FILE")
LIVE_HOSTS_FILE="$RUN_DIR/02_live_hosts.json"

# Extract live host URLs
jq -r '.data[] | .url' "$LIVE_HOSTS_FILE" \
  > "$RUN_DIR/raw/live_urls.txt"

URL_COUNT=$(wc -l < "$RUN_DIR/raw/live_urls.txt")
echo "✓ Extracted $URL_COUNT live host URLs"
```

### 2. Active Crawling with Katana
```bash
# Crawl live hosts with JavaScript rendering
cat "$RUN_DIR/raw/live_urls.txt" \
  | katana -silent \
    -depth 3 \
    -js-crawl \
    -known-files all \
    -automatic-form-fill \
    -field-scope fqdn \
    -timeout 5 \
    -concurrency 10 \
    -rate-limit 50 \
    -o "$RUN_DIR/raw/katana.txt"

KATANA_COUNT=$(wc -l < "$RUN_DIR/raw/katana.txt")
echo "✓ Katana crawl complete: $KATANA_COUNT endpoints found"
```

**Tool flags:**
- `-silent`: Suppress banner and progress
- `-depth 3`: Maximum crawl depth (links from links from links)
- `-js-crawl`: Parse and execute JavaScript to find dynamic endpoints
- `-known-files all`: Look for known files (robots.txt, sitemap.xml, etc.)
- `-automatic-form-fill`: Auto-fill forms to discover POST endpoints
- `-field-scope fqdn`: Stay within same FQDN (don't follow external links)
- `-timeout 5`: 5-second timeout per request
- `-concurrency 10`: 10 concurrent connections
- `-rate-limit 50`: 50 requests/second max

**Note:** Katana with `-js-crawl` can take 10-30 minutes depending on site complexity.

### 3. Historical Data with gau (GetAllURLs)
```bash
# Fetch URLs from AlienVault OTX, Wayback Machine, Common Crawl, URLScan
echo "$TARGET" \
  | gau --threads 5 \
    --subs \
    --o "$RUN_DIR/raw/gau.txt"

GAU_COUNT=$(wc -l < "$RUN_DIR/raw/gau.txt")
echo "✓ gau complete: $GAU_COUNT historical URLs found"
```

**Tool flags:**
- `--threads 5`: Use 5 concurrent threads
- `--subs`: Include subdomains of target domain
- `--o`: Output file

### 4. Historical Data with waybackurls
```bash
# Fetch URLs from Wayback Machine
echo "$TARGET" \
  | waybackurls \
  > "$RUN_DIR/raw/waybackurls.txt"

WAYBACK_COUNT=$(wc -l < "$RUN_DIR/raw/waybackurls.txt")
echo "✓ waybackurls complete: $WAYBACK_COUNT historical URLs found"
```

### 5. Merge, Deduplicate, and Filter Scope
```bash
# Combine all sources
cat "$RUN_DIR/raw/katana.txt" \
    "$RUN_DIR/raw/gau.txt" \
    "$RUN_DIR/raw/waybackurls.txt" \
  | sort -u \
  > "$RUN_DIR/raw/all_endpoints_raw.txt"

TOTAL_RAW=$(wc -l < "$RUN_DIR/raw/all_endpoints_raw.txt")
echo "✓ Merged: $TOTAL_RAW unique URLs before filtering"

# Filter to in-scope only (based on scope file)
# Python script to validate scope
python3 << 'EOF'
import json
import re
from urllib.parse import urlparse

# Read scope
with open("$SCOPE_FILE") as f:
    scope = json.load(f)

in_scope = scope["scope"]["in_scope"]
out_of_scope = scope["scope"].get("out_of_scope", [])

def matches_pattern(host, patterns):
    """Check if host matches any wildcard pattern"""
    for pattern in patterns:
        # Convert wildcard to regex
        regex_pattern = pattern.replace(".", r"\.").replace("*", r"[^.]*")
        if re.match(f"^{regex_pattern}$", host):
            return True
    return False

# Read all URLs
in_scope_urls = []
with open("$RUN_DIR/raw/all_endpoints_raw.txt") as f:
    for line in f:
        url = line.strip()
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0]  # Remove port

            # Check if in scope
            if matches_pattern(host, in_scope) and not matches_pattern(host, out_of_scope):
                in_scope_urls.append(url)
        except:
            continue

# Write filtered URLs
with open("$RUN_DIR/raw/all_endpoints_filtered.txt", "w") as f:
    for url in in_scope_urls:
        f.write(url + "\n")

print(f"✓ Filtered to {len(in_scope_urls)} in-scope URLs")
EOF
```

### 6. Identify Interesting Endpoints
```bash
# Flag endpoints with high-value patterns
python3 << 'EOF'
import re

# Interesting patterns
INTERESTING_PATTERNS = {
    r"\.(git|svn|env|config|db|sql|bak|backup|old|swp)(/|$)": "exposed sensitive file",
    r"/(admin|dashboard|panel|phpmyadmin|wp-admin|login)": "admin/login panel",
    r"/(api|v1|v2|v3|graphql|swagger|openapi)": "API endpoint",
    r"\.(json|xml|yaml|yml|conf|ini)$": "config file",
    r"[?&](api_?key|token|secret|password|passwd|pwd)=": "potential credential in URL",
    r"/(backup|backups|old|test|dev|staging|uat)": "non-production environment",
    r"\.(log|txt|md|readme)$": "documentation/log file",
    r"/(upload|uploads|files|downloads|assets)": "file upload/storage endpoint",
    r"/(debug|trace|error|errors)": "debug/error endpoint"
}

# Read filtered URLs
interesting = []
all_urls = []

with open("$RUN_DIR/raw/all_endpoints_filtered.txt") as f:
    all_urls = [line.strip() for line in f]

for url in all_urls:
    url_lower = url.lower()
    for pattern, reason in INTERESTING_PATTERNS.items():
        if re.search(pattern, url_lower):
            interesting.append((url, reason))
            break

# Write interesting endpoints
with open("$RUN_DIR/raw/interesting_endpoints.txt", "w") as f:
    for url, reason in interesting:
        f.write(f"{url}\t{reason}\n")

print(f"✓ Identified {len(interesting)} interesting endpoints")
EOF
```

### 7. Build Final JSON Output
```bash
# Python script to structure all data
python3 << 'EOF'
import json
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
import os.path

# Read scope file
with open("$SCOPE_FILE") as f:
    scope = json.load(f)

with open("$LIVE_HOSTS_FILE") as f:
    live_hosts = json.load(f)

# Load sources (which tool found each URL)
sources = {}

def load_source(filename, source_name):
    if os.path.exists(filename):
        with open(filename) as f:
            for line in f:
                url = line.strip()
                if url not in sources:
                    sources[url] = source_name

load_source("$RUN_DIR/raw/katana.txt", "katana")
load_source("$RUN_DIR/raw/gau.txt", "gau")
load_source("$RUN_DIR/raw/waybackurls.txt", "waybackurls")

# Load interesting endpoints
interesting_map = {}
if os.path.exists("$RUN_DIR/raw/interesting_endpoints.txt"):
    with open("$RUN_DIR/raw/interesting_endpoints.txt") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) == 2:
                interesting_map[parts[0]] = parts[1]

# Build data array
data = []
with open("$RUN_DIR/raw/all_endpoints_filtered.txt") as f:
    for line in f:
        url = line.strip()
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
        params = list(parse_qs(parsed.query).keys())

        is_interesting = url in interesting_map
        interesting_reason = interesting_map.get(url, None)

        data.append({
            "url": url,
            "host": host,
            "path": parsed.path or "/",
            "method": "GET",  # Default, actual method unknown from URL
            "status_code": None,  # Historical data may not have status
            "source": sources.get(url, "unknown"),
            "params": params,
            "interesting": is_interesting,
            "interesting_reason": interesting_reason
        })

# Calculate unique paths
unique_paths = len(set(d["path"] for d in data))
interesting_count = sum(1 for d in data if d["interesting"])

# Build output
output = {
    "target": scope["target"],
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "tools_used": ["katana", "gau", "waybackurls"],
    "execution_time_seconds": 0,  # TODO: track if needed
    "total_live_hosts": live_hosts["total_live_hosts"],
    "total_endpoints": len(data),
    "unique_paths": unique_paths,
    "interesting_endpoints": interesting_count,
    "data": data
}

# Write output
with open("$RUN_DIR/03_endpoints.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"✓ Final output: {len(data)} endpoints, {interesting_count} interesting")
EOF

echo "✓ Created: $RUN_DIR/03_endpoints.json"
```

### 8. Verify Output
```bash
# Display summary
echo "=== ENDPOINT CRAWL SUMMARY ==="
jq '{target, total_endpoints, unique_paths, interesting_endpoints}' "$RUN_DIR/03_endpoints.json"

# Show interesting endpoints
echo ""
echo "Interesting endpoints found:"
jq -r '.data[] | select(.interesting == true) | "\(.url) - \(.interesting_reason)"' \
  "$RUN_DIR/03_endpoints.json" | head -20
```

## Expected Output

**Good Result:**
```
✓ Extracted 234 live host URLs
✓ Katana crawl complete: 4521 endpoints found
✓ gau complete: 2834 historical URLs found
✓ waybackurls complete: 3142 historical URLs found
✓ Merged: 8472 unique URLs before filtering
✓ Filtered to 8104 in-scope URLs
✓ Identified 47 interesting endpoints
✓ Final output: 8104 endpoints, 47 interesting
✓ Created: runs/example.com-20260401-103000/03_endpoints.json
```

**Interesting endpoints found:**
```
https://admin.example.com/.git/config - exposed sensitive file
https://api.example.com/v1/users?api_key=test - potential credential in URL
https://staging.example.com/backup/ - non-production environment
```

## Error Handling

**Issue:** Tool not found
```bash
# Install katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Install waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Ensure $GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**Issue:** Katana too slow
```bash
# Reduce crawl depth and disable JS crawling
cat "$RUN_DIR/raw/live_urls.txt" \
  | katana -silent \
    -depth 2 \
    -field-scope fqdn \
    -timeout 5 \
    -concurrency 10 \
    -o "$RUN_DIR/raw/katana.txt"
# Removes -js-crawl flag for faster execution
```

**Issue:** Rate limiting or 429 errors
```bash
# Reduce katana rate limit
# Add to katana command: -rate-limit 10
# Reduces from 50 req/s to 10 req/s
```

**Issue:** Historical data sources timing out
```bash
# Skip gau/waybackurls if too slow
# Comment out those steps and only use katana
# Trade-off: Less coverage, faster execution
```

## Execution Time
- **Katana (with JS):** 10-30 minutes (depends on site size/complexity)
- **Katana (no JS):** 5-10 minutes
- **gau:** 5-10 minutes
- **waybackurls:** 5-10 minutes
- **Filtering/processing:** 1-2 minutes
- **Total:** 15-40 minutes (medium target)

## Rate Limiting Considerations
- **Katana:** Active crawling, directly hits target
  - Default: 50 req/s (moderate)
  - Stealth mode: Use `-rate-limit 10`
  - Monitor for 429 or blocks
- **gau/waybackurls:** Passive sources, no target interaction
  - Safe to run aggressively

## Vulnerable vs. Safe

**Vulnerable Approach:**
- No scope filtering (test out-of-scope assets)
- Aggressive crawling with no rate limits (triggers WAF)
- Following all external links (leaks recon to 3rd parties)

**Safe Approach:**
- Strict scope filtering at every step
- Rate-limited crawling (respectful of target resources)
- Field scope limited to target FQDN
- Combination of active + passive sources for stealth

## High-Value Findings

**Immediately investigate:**
- Exposed version control: `.git`, `.svn`, `.hg`
- Config files: `.env`, `web.config`, `config.php`
- Admin panels: `/admin`, `/phpmyadmin`, `/wp-admin`
- API endpoints with credentials in URL
- Backup files: `.bak`, `.old`, `.backup`, `.sql`

**Flag for further testing:**
- API endpoints (`/api/`, `/v1/`, `/graphql`)
- File upload paths (`/upload`, `/files`)
- Non-production environments (`/staging`, `/dev`, `/test`)
- Debug/error pages (`/debug`, `/trace`)

## Next Step
**After endpoint crawling:**
Load and execute `skills/discovery/04_fingerprint.md` to fingerprint technologies and identify high-value targets.

## Verification Checklist
Before proceeding to fingerprinting:
- [ ] `runs/{target}-{timestamp}/03_endpoints.json` exists
- [ ] JSON file contains `data` array with URL objects
- [ ] `interesting_endpoints` count > 0 (if not, may need deeper crawl)
- [ ] All URLs are in-scope (manual spot check recommended)
- [ ] No excessive errors or timeouts during crawling
