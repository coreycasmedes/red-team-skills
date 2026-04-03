---
name: scope-check
description: Validate that a target host or IP is in scope for the current engagement before scanning
disable-model-invocation: true
argument-hint: <host-or-ip>
---

# Scope Validation

Validates whether a target host or IP address is in scope for the current bug bounty engagement.

## Usage

```
/scope-check example.com
/scope-check subdomain.example.com
/scope-check 203.0.113.10
```

## Workflow

### Step 1: Find Scope File

```bash
TARGET_HOST=$ARGUMENTS

# Look for scope files in targets/ directory
SCOPE_FILES=$(find targets/ -name "scope.txt" 2>/dev/null)

if [ -z "$SCOPE_FILES" ]; then
  echo "[!] No scope files found in targets/ directory"
  echo "[!] Please create a scope file at: targets/<engagement>/scope.txt"
  echo ""
  echo "Scope file format:"
  echo "  # In-scope"
  echo "  *.example.com"
  echo "  example.com"
  echo "  203.0.113.0/24"
  echo ""
  echo "  # Out-of-scope (prefix with !)"
  echo "  !mail.example.com"
  echo "  !internal.example.com"
  exit 1
fi
```

### Step 2: Run Scope Validation Script

```bash
# Use the first scope file found (or user can specify which engagement)
SCOPE_FILE=$(echo "$SCOPE_FILES" | head -1)

echo "[*] Checking scope against: $SCOPE_FILE"

# Run Python validation script
python3 .claude/skills/scope-check/scripts/parse-scope.py "$SCOPE_FILE" "$TARGET_HOST"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo ""
  echo "[✓] $TARGET_HOST is IN SCOPE"
  echo "[✓] Safe to proceed with scanning"
  exit 0
else
  echo ""
  echo "[✗] $TARGET_HOST is OUT OF SCOPE"
  echo "[✗] Do NOT scan this target"
  exit 1
fi
```

## Scope File Format

Create a scope file at `targets/<engagement>/scope.txt`:

```
# In-scope assets (wildcards supported)
*.example.com
example.com
203.0.113.0/24
10.0.1.0/24

# Out-of-scope assets (prefix with !)
!mail.example.com
!internal.example.com
!10.0.1.5
```

### Rules

1. **Wildcard domains**: `*.example.com` matches any subdomain
2. **Exact domains**: `example.com` matches only the root domain
3. **CIDR ranges**: `203.0.113.0/24` matches IPs in range
4. **Exclusions**: Prefix with `!` to explicitly exclude
5. **Comments**: Lines starting with `#` are ignored
6. **Blank lines**: Ignored

### Precedence

1. Explicit exclusions (`!target`) override all inclusions
2. More specific rules override less specific (exact domain > wildcard)
3. If no match found, target is OUT OF SCOPE by default

## Examples

### Example 1: Subdomain of Wildcard

```bash
Scope file:
  *.example.com

Check: api.example.com
Result: IN SCOPE (matches wildcard)

Check: example.com
Result: OUT OF SCOPE (not in wildcard)
```

### Example 2: Explicit Exclusion

```bash
Scope file:
  *.example.com
  !mail.example.com

Check: api.example.com
Result: IN SCOPE

Check: mail.example.com
Result: OUT OF SCOPE (explicit exclusion)
```

### Example 3: CIDR Range

```bash
Scope file:
  203.0.113.0/24

Check: 203.0.113.50
Result: IN SCOPE (within CIDR)

Check: 203.0.114.50
Result: OUT OF SCOPE (outside CIDR)
```

### Example 4: Mixed Rules

```bash
Scope file:
  *.example.com
  example.com
  203.0.113.0/24
  !internal.example.com
  !203.0.113.100

Check: app.example.com
Result: IN SCOPE

Check: internal.example.com
Result: OUT OF SCOPE (excluded)

Check: 203.0.113.50
Result: IN SCOPE

Check: 203.0.113.100
Result: OUT OF SCOPE (excluded IP)
```

## Integration with Agents

The `port-scanner` agent automatically uses `validate-scope.sh` hook to check all targets before scanning. Other agents can call this skill manually:

```
/scope-check $TARGET_HOST
```

## Error Handling

### No Scope File Found

```
[!] No scope files found in targets/ directory
[!] Please create a scope file at: targets/<engagement>/scope.txt
```

**Action**: Create a scope file before starting reconnaissance.

### Invalid Scope File Format

```
[!] Scope file parse error: Invalid CIDR notation
```

**Action**: Review scope file for syntax errors.

### Multiple Scope Files

If multiple scope files exist:

```
[*] Multiple scope files found:
  - targets/engagement1/scope.txt
  - targets/engagement2/scope.txt

[*] Using: targets/engagement1/scope.txt
```

**Action**: Specify which engagement you're working on, or remove old scope files.

## Safety Note

**Always validate scope before active scanning!**

This skill is a safeguard, but you should:
1. Manually review scope files before starting
2. Confirm with the user if uncertain
3. Never scan out-of-scope assets, even if tools permit it

Unauthorized scanning can:
- Violate bug bounty program rules
- Get you banned from platforms
- Lead to legal consequences
- Harm your reputation

**When in doubt, ask the user to confirm scope.**
