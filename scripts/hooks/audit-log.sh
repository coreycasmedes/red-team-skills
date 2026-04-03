#!/bin/bash
#
# audit-log.sh - Command audit logging hook for Claude Code
#
# This hook logs all bash commands executed during reconnaissance
# to findings/audit.log for accountability and review.
#
# Exit code: Always 0 (never blocks execution, audit only)
#

# Read JSON input from stdin
INPUT=$(cat)

# Extract the bash command from JSON using jq
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

if [ -z "$COMMAND" ]; then
  # No command found, nothing to log
  exit 0
fi

# Ensure findings directory exists
mkdir -p findings/

# Log file path
LOG_FILE="findings/audit.log"

# Get ISO 8601 timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Truncate command if too long (keep first 200 chars)
TRUNCATED_COMMAND=$(echo "$COMMAND" | head -c 200)
if [ ${#COMMAND} -gt 200 ]; then
  TRUNCATED_COMMAND="${TRUNCATED_COMMAND}..."
fi

# Log entry format: [timestamp] TOOL: <command>
echo "[$TIMESTAMP] TOOL: $TRUNCATED_COMMAND" >> "$LOG_FILE"

# Always exit 0 - this is audit only, never block
exit 0
