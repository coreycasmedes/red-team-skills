# Scope Definition & Validation

## Purpose
Define target scope and create run directory before any enumeration begins.

## Inputs
**User must provide:**
- Target root domain (e.g., `example.com`)
- Bug bounty program name (optional, e.g., "HackerOne: Example Corp")
- Scope rules (wildcards, exclusions, IP ranges)

**Optional:**
- Program brief or scope document URL/file

## Outputs
**File:** `runs/{target}-{timestamp}/00_scope.json`

**Schema:**
```json
{
  "target": "example.com",
  "program": "HackerOne: Example Corp",
  "timestamp": "2026-04-01T10:30:00Z",
  "run_directory": "runs/example.com-20260401-103000/",
  "scope": {
    "in_scope": [
      "*.example.com",
      "example.com",
      "api.example.com"
    ],
    "out_of_scope": [
      "mail.example.com",
      "*.internal.example.com",
      "192.168.0.0/16"
    ],
    "notes": "Do not test payment processing endpoints"
  },
  "validated": true,
  "validation_timestamp": "2026-04-01T10:30:05Z"
}
```

## Pre-flight Checklist
- [ ] Target domain is a valid FQDN (no protocols, paths, or ports)
- [ ] Bug bounty program explicitly allows security testing
- [ ] Out-of-scope assets are clearly documented
- [ ] Rate limiting guidance is understood
- [ ] No existing run directory for this target today (or resuming intentionally)

## Commands

### 1. Validate Domain Format
```bash
# Target domain (user provides this)
TARGET="example.com"

# Validate domain format (must be FQDN, no http://, no paths)
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
  echo "ERROR: Invalid domain format. Provide root domain only (e.g., example.com)"
  exit 1
fi

echo "✓ Domain format valid: $TARGET"
```

### 2. Create Run Directory
```bash
# Generate timestamp
TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
RUN_DIR="runs/${TARGET}-${TIMESTAMP}"

# Create directory
mkdir -p "$RUN_DIR"
echo "✓ Created run directory: $RUN_DIR"
```

### 3. Create Scope File (Interactive)
```bash
# Prompt user for scope details
echo "Enter bug bounty program name (or press Enter to skip):"
read PROGRAM

echo "Enter in-scope wildcards/domains (one per line, Ctrl+D when done):"
IN_SCOPE=$(cat)

echo "Enter out-of-scope assets (one per line, Ctrl+D when done):"
OUT_OF_SCOPE=$(cat)

echo "Enter any special notes/restrictions (or press Enter to skip):"
read NOTES

# Create JSON (using jq if available, else manual)
cat > "$RUN_DIR/00_scope.json" <<EOF
{
  "target": "$TARGET",
  "program": "$PROGRAM",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "run_directory": "$RUN_DIR/",
  "scope": {
    "in_scope": [
      $(echo "$IN_SCOPE" | jq -R -s -c 'split("\n") | map(select(length > 0))')
    ],
    "out_of_scope": [
      $(echo "$OUT_OF_SCOPE" | jq -R -s -c 'split("\n") | map(select(length > 0))')
    ],
    "notes": "$NOTES"
  },
  "validated": true,
  "validation_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

echo "✓ Scope file created: $RUN_DIR/00_scope.json"
```

### 4. Verify Scope File
```bash
# Display scope for user confirmation
echo "=== SCOPE CONFIRMATION ==="
cat "$RUN_DIR/00_scope.json" | jq .

echo ""
echo "Does this scope look correct? (yes/no)"
read CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
  echo "ERROR: Scope not confirmed. Edit $RUN_DIR/00_scope.json manually and re-run."
  exit 1
fi

echo "✓ Scope validated and confirmed"
```

## Tool Flags
- **jq**: JSON processor for scope file creation
  - `-R`: Read raw strings
  - `-s`: Slurp entire input
  - `-c`: Compact output

## Expected Output

**Good Result:**
```
✓ Domain format valid: example.com
✓ Created run directory: runs/example.com-20260401-103000
✓ Scope file created: runs/example.com-20260401-103000/00_scope.json
✓ Scope validated and confirmed
```

**Bad Result:**
```
ERROR: Invalid domain format. Provide root domain only (e.g., example.com)
```

## Error Handling

**Issue:** Domain includes protocol
```bash
# User provides: https://example.com
# Fix: Strip protocol manually
TARGET=$(echo "https://example.com" | sed 's|https\?://||')
```

**Issue:** Run directory already exists
```bash
# Check before creating
if [[ -d "$RUN_DIR" ]]; then
  echo "WARNING: Run directory already exists: $RUN_DIR"
  echo "Resume existing run? (yes/no)"
  read RESUME
  if [[ "$RESUME" != "yes" ]]; then
    TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
    RUN_DIR="runs/${TARGET}-${TIMESTAMP}"
    mkdir -p "$RUN_DIR"
  fi
fi
```

**Issue:** jq not installed
```bash
# Install jq
# macOS:
brew install jq

# Linux (Debian/Ubuntu):
sudo apt install jq

# Linux (RHEL/CentOS):
sudo yum install jq
```

## Execution Time
**1-2 minutes** (mostly user input)

## Vulnerable vs. Safe

**Vulnerable Approach:**
- Skipping scope validation
- Testing out-of-scope assets
- No documentation of boundaries

**Safe Approach:**
- Explicit in-scope/out-of-scope lists
- Scope confirmation before proceeding
- Written scope artifact for reference

## Next Step
**After scope validation:**
Load and execute `skills/discovery/01_subdomain_enum.md` to begin subdomain enumeration.

## Verification Checklist
Before proceeding to subdomain enumeration:
- [ ] `runs/{target}-{timestamp}/00_scope.json` exists
- [ ] Scope file contains in_scope and out_of_scope arrays
- [ ] User confirmed scope is correct
- [ ] Run directory path is stored for subsequent steps
