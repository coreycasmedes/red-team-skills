# Subdomain Enumeration

## Purpose
Passively enumerate all subdomains for the target using multiple sources, then resolve to IPs.

## Inputs
**Required files:**
- `runs/{target}-{timestamp}/00_scope.json` (from previous step)

**Environment variables:**
- `CHAOS_KEY` (optional, for ProjectDiscovery Chaos dataset)
- `GITHUB_TOKEN` (optional, for GitHub subdomain search)

## Outputs
**File:** `runs/{target}-{timestamp}/01_subdomains.json`

**Schema:**
```json
{
  "target": "example.com",
  "timestamp": "2026-04-01T10:45:00Z",
  "tools_used": ["subfinder", "amass", "dnsx"],
  "execution_time_seconds": 1847,
  "total_subdomains": 1243,
  "resolved_subdomains": 891,
  "data": [
    {
      "subdomain": "api.example.com",
      "sources": ["subfinder", "amass"],
      "resolved": true,
      "ip_addresses": ["203.0.113.42", "203.0.113.43"],
      "cname": null
    },
    {
      "subdomain": "stale.example.com",
      "sources": ["amass"],
      "resolved": false,
      "ip_addresses": [],
      "cname": null
    }
  ]
}
```

## Pre-flight Checklist
- [ ] Scope file exists and is validated
- [ ] `subfinder` installed (verify: `subfinder -version`)
- [ ] `amass` installed (verify: `amass -version`)
- [ ] `dnsx` installed (verify: `dnsx -version`)
- [ ] Sufficient disk space for output files (estimate: 5-50 MB)

## Commands

### 1. Extract Target from Scope File
```bash
# Read target and run directory from scope file
SCOPE_FILE=$(ls -t runs/*/00_scope.json | head -1)
TARGET=$(jq -r '.target' "$SCOPE_FILE")
RUN_DIR=$(jq -r '.run_directory' "$SCOPE_FILE")

echo "Target: $TARGET"
echo "Run directory: $RUN_DIR"
```

### 2. Run Subfinder (Passive Enumeration)
```bash
# Create output directory for raw tool outputs
mkdir -p "$RUN_DIR/raw"

# Run subfinder with all passive sources
subfinder -d "$TARGET" \
  -all \
  -recursive \
  -o "$RUN_DIR/raw/subfinder.txt"

echo "✓ Subfinder complete: $(wc -l < "$RUN_DIR/raw/subfinder.txt") subdomains found"
```

**Tool flags:**
- `-d`: Target domain
- `-all`: Use all available passive sources (crt.sh, VirusTotal, SecurityTrails, etc.)
- `-recursive`: Recursively enumerate subdomains of found subdomains
- `-o`: Output file

### 3. Run Amass (Passive Enumeration)
```bash
# Run amass in passive mode (no active DNS brute-forcing)
amass enum -passive \
  -d "$TARGET" \
  -o "$RUN_DIR/raw/amass.txt"

echo "✓ Amass complete: $(wc -l < "$RUN_DIR/raw/amass.txt") subdomains found"
```

**Tool flags:**
- `enum`: Enumeration subcommand
- `-passive`: Only use passive OSINT sources (no active DNS)
- `-d`: Target domain
- `-o`: Output file

**Note:** Amass passive mode can take 10-30 minutes depending on target size.

### 4. Merge and Deduplicate
```bash
# Combine all sources and deduplicate
cat "$RUN_DIR/raw/subfinder.txt" "$RUN_DIR/raw/amass.txt" \
  | sort -u \
  > "$RUN_DIR/raw/all_subdomains.txt"

TOTAL=$(wc -l < "$RUN_DIR/raw/all_subdomains.txt")
echo "✓ Merged and deduplicated: $TOTAL unique subdomains"
```

### 5. Resolve Subdomains with dnsx
```bash
# Resolve all subdomains to IPs and CNAMEs
cat "$RUN_DIR/raw/all_subdomains.txt" \
  | dnsx -silent \
    -a \
    -cname \
    -resp \
    -json \
    -o "$RUN_DIR/raw/dnsx.json"

echo "✓ DNS resolution complete"
```

**Tool flags:**
- `-silent`: Suppress banner and progress
- `-a`: Query A records (IPv4)
- `-cname`: Query CNAME records
- `-resp`: Include full response data
- `-json`: Output in JSON format

### 6. Build Final JSON Output
```bash
# Python script to build structured JSON
python3 << 'EOF'
import json
from datetime import datetime, timezone
from collections import defaultdict

# Read scope file
with open("$SCOPE_FILE") as f:
    scope = json.load(f)

# Read raw subdomain list
with open("$RUN_DIR/raw/all_subdomains.txt") as f:
    all_subs = set(line.strip() for line in f)

# Read subfinder output for source attribution
with open("$RUN_DIR/raw/subfinder.txt") as f:
    subfinder_subs = set(line.strip() for line in f)

# Read amass output for source attribution
with open("$RUN_DIR/raw/amass.txt") as f:
    amass_subs = set(line.strip() for line in f)

# Read dnsx resolution data
dnsx_data = {}
try:
    with open("$RUN_DIR/raw/dnsx.json") as f:
        for line in f:
            entry = json.loads(line)
            host = entry.get("host", "")
            dnsx_data[host] = {
                "resolved": True,
                "ip_addresses": entry.get("a", []),
                "cname": entry.get("cname", None)
            }
except FileNotFoundError:
    pass

# Build output data
data = []
for sub in sorted(all_subs):
    sources = []
    if sub in subfinder_subs:
        sources.append("subfinder")
    if sub in amass_subs:
        sources.append("amass")

    resolution = dnsx_data.get(sub, {
        "resolved": False,
        "ip_addresses": [],
        "cname": None
    })

    data.append({
        "subdomain": sub,
        "sources": sources,
        "resolved": resolution["resolved"],
        "ip_addresses": resolution["ip_addresses"],
        "cname": resolution["cname"]
    })

# Calculate stats
resolved_count = sum(1 for d in data if d["resolved"])

# Build final output
output = {
    "target": scope["target"],
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "tools_used": ["subfinder", "amass", "dnsx"],
    "execution_time_seconds": 0,  # TODO: track this if needed
    "total_subdomains": len(data),
    "resolved_subdomains": resolved_count,
    "data": data
}

# Write output file
with open("$RUN_DIR/01_subdomains.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"✓ Final output: {len(data)} total, {resolved_count} resolved")
EOF

echo "✓ Created: $RUN_DIR/01_subdomains.json"
```

### 7. Verify Output
```bash
# Display summary statistics
echo "=== SUBDOMAIN ENUMERATION SUMMARY ==="
jq '{target, total_subdomains, resolved_subdomains, tools_used}' "$RUN_DIR/01_subdomains.json"

# Show sample of results
echo ""
echo "Sample of resolved subdomains:"
jq -r '.data[] | select(.resolved == true) | .subdomain' "$RUN_DIR/01_subdomains.json" | head -10
```

## Expected Output

**Good Result:**
```
Target: example.com
Run directory: runs/example.com-20260401-103000/
✓ Subfinder complete: 876 subdomains found
✓ Amass complete: 1039 subdomains found
✓ Merged and deduplicated: 1243 unique subdomains
✓ DNS resolution complete
✓ Final output: 1243 total, 891 resolved
✓ Created: runs/example.com-20260401-103000/01_subdomains.json
```

**Bad Result:**
```
ERROR: subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Error Handling

**Issue:** Tool not found
```bash
# Install missing tools
# subfinder:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# amass:
go install -v github.com/owasp-amass/amass/v4/...@master

# dnsx:
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Ensure $GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**Issue:** Amass taking too long
```bash
# Option 1: Skip amass and use only subfinder
# (Remove amass.txt from merge step)

# Option 2: Use amass with timeout
timeout 1800 amass enum -passive -d "$TARGET" -o "$RUN_DIR/raw/amass.txt"
# 1800 seconds = 30 minutes
```

**Issue:** DNS resolution rate limiting
```bash
# Use dnsx with rate limiting
cat "$RUN_DIR/raw/all_subdomains.txt" \
  | dnsx -silent -a -cname -resp -json \
    -rate-limit 50 \
    -o "$RUN_DIR/raw/dnsx.json"
# Limits to 50 requests/second
```

**Issue:** Python not available
```bash
# Install Python 3
# macOS:
brew install python3

# Linux (Debian/Ubuntu):
sudo apt install python3

# Linux (RHEL/CentOS):
sudo yum install python3
```

## Execution Time
- **Subfinder:** 2-5 minutes
- **Amass:** 10-30 minutes (passive mode)
- **DNS resolution:** 2-5 minutes
- **Total:** 15-40 minutes (medium target with ~500-1000 subdomains)

## Rate Limiting Considerations
- **Subfinder/Amass:** Passive sources, no direct target interaction
- **dnsx:** Active DNS queries, use `-rate-limit` flag if needed
- Default dnsx rate: 1000 req/s (usually fine for public DNS)
- For stealth: Add `-rate-limit 10` to dnsx command

## Vulnerable vs. Safe

**Vulnerable Approach:**
- Active DNS brute-forcing (alerts target)
- No deduplication (wasted effort on duplicates)
- No source attribution (can't verify findings)

**Safe Approach:**
- Passive enumeration only (no target alerts)
- Multi-source aggregation for maximum coverage
- DNS resolution to filter out stale records
- Source tracking for reproducibility

## Next Step
**After subdomain enumeration:**
Load and execute `skills/discovery/02_live_host_probe.md` to identify live HTTP/HTTPS services.

## Verification Checklist
Before proceeding to live host probing:
- [ ] `runs/{target}-{timestamp}/01_subdomains.json` exists
- [ ] JSON file contains `data` array with subdomain objects
- [ ] At least some subdomains are marked as `resolved: true`
- [ ] Total subdomain count is reasonable (not 0, not millions)
- [ ] No errors in tool execution
