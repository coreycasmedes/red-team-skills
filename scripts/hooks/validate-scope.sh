#!/bin/bash
#
# validate-scope.sh - Pre-execution scope validation hook for Claude Code
#
# This hook reads the tool input from stdin (JSON format from Claude Code),
# extracts any bash commands, scans for target hosts/IPs, and validates
# them against scope files in targets/ directory.
#
# Exit codes:
#   0 - Allow execution (in scope or non-network command)
#   2 - Block execution (out of scope target detected)
#

# Read JSON input from stdin
INPUT=$(cat)

# Extract the bash command from JSON using jq
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

if [ -z "$COMMAND" ]; then
  # No command found, allow (might be different tool)
  exit 0
fi

# List of network tools that require scope validation
NETWORK_TOOLS=(
  "nmap"
  "masscan"
  "ffuf"
  "nuclei"
  "httpx"
  "curl"
  "wget"
  "nikto"
  "sqlmap"
  "wpscan"
  "subfinder"
  "amass"
  "katana"
  "arjun"
  "subjack"
)

# Check if command contains any network tools
IS_NETWORK_COMMAND=false
for tool in "${NETWORK_TOOLS[@]}"; do
  if echo "$COMMAND" | grep -qw "$tool"; then
    IS_NETWORK_COMMAND=true
    break
  fi
done

# If not a network command, allow without scope check
if [ "$IS_NETWORK_COMMAND" = false ]; then
  exit 0
fi

# Extract potential targets from command
# Look for:
# - Domain patterns (example.com, subdomain.example.com)
# - IP addresses (203.0.113.1)
# - CIDR ranges (203.0.113.0/24)

# Extract domains (basic pattern)
DOMAINS=$(echo "$COMMAND" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+' | sort -u)

# Extract IP addresses
IPS=$(echo "$COMMAND" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

# Combine all potential targets
TARGETS=$(echo -e "$DOMAINS\n$IPS" | grep -v '^$')

# If no targets found, it's likely a safe command (setup, config, etc.)
if [ -z "$TARGETS" ]; then
  exit 0
fi

# Check if any scope files exist
SCOPE_FILES=$(find targets/ -name "scope.txt" 2>/dev/null)

if [ -z "$SCOPE_FILES" ]; then
  # No scope files found - warn but allow (don't block setup commands)
  # This is expected during initial setup
  exit 0
fi

# Get the first scope file (or could iterate through all)
SCOPE_FILE=$(echo "$SCOPE_FILES" | head -1)

# Validate each target
BLOCKED_TARGETS=()

while IFS= read -r target; do
  if [ -z "$target" ]; then
    continue
  fi

  # Run scope validation script
  python3 .claude/skills/scope-check/scripts/parse-scope.py "$SCOPE_FILE" "$target" >/dev/null 2>&1
  EXIT_CODE=$?

  if [ $EXIT_CODE -ne 0 ]; then
    # Target is out of scope
    BLOCKED_TARGETS+=("$target")
  fi
done <<< "$TARGETS"

# If any targets are blocked, prevent execution
if [ ${#BLOCKED_TARGETS[@]} -gt 0 ]; then
  echo "========================================" >&2
  echo "❌ SCOPE VALIDATION FAILED" >&2
  echo "========================================" >&2
  echo "" >&2
  echo "The following targets are OUT OF SCOPE:" >&2
  for blocked in "${BLOCKED_TARGETS[@]}"; do
    echo "  - $blocked" >&2
  done
  echo "" >&2
  echo "Blocked command:" >&2
  echo "  $COMMAND" | cut -c1-150 >&2
  echo "" >&2
  echo "Scope file: $SCOPE_FILE" >&2
  echo "" >&2
  echo "Action required:" >&2
  echo "  1. Verify the target is actually in scope" >&2
  echo "  2. Update the scope file if needed" >&2
  echo "  3. Use /scope-check <target> to manually validate" >&2
  echo "" >&2
  echo "⚠️  Never scan out-of-scope targets!" >&2
  echo "========================================" >&2

  # Exit with code 2 to block the command
  exit 2
fi

# All targets are in scope, allow execution
exit 0
