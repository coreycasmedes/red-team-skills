---
name: recon-report
description: Generate a formatted bug bounty recon report from findings in the findings/ directory
disable-model-invocation: true
argument-hint: <target-domain>
---

# Reconnaissance Report Generator

Generates or regenerates a comprehensive bug bounty report from existing findings.

## Usage

```
/recon-report example.com
```

## Workflow

### Step 1: Validate Findings Directory

```bash
TARGET=$ARGUMENTS
FINDINGS_DIR="findings/$TARGET"

if [ ! -d "$FINDINGS_DIR" ]; then
  echo "[!] Findings directory not found: $FINDINGS_DIR"
  echo "[!] Run /full-recon $TARGET first to generate findings"
  exit 1
fi
```

### Step 2: Check for Findings Files

```bash
REQUIRED_FILES=(
  "osint.md"
  "dns.md"
  "ports.md"
  "web.md"
  "cloud.md"
  "code-leaks.md"
)

MISSING_FILES=()

for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$FINDINGS_DIR/$file" ]; then
    MISSING_FILES+=("$file")
  fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
  echo "[!] Missing findings files:"
  for file in "${MISSING_FILES[@]}"; do
    echo "  - $file"
  done
  echo ""
  echo "[*] Run the corresponding agents to generate missing files:"
  echo "  - osint.md: @passive-osint"
  echo "  - dns.md: @dns-recon"
  echo "  - ports.md: @port-scanner"
  echo "  - web.md: @web-mapper"
  echo "  - cloud.md: @cloud-recon"
  echo "  - code-leaks.md: @code-leak"
  echo ""
  echo "[*] Or run /full-recon $TARGET to execute the complete pipeline"
  exit 1
fi
```

### Step 3: Invoke Report Writer Agent

```
Invoke: @report-writer
Target: $TARGET
Duration: ~5-10 minutes
```

**What it does**: Synthesizes all findings into a prioritized bug bounty report

**Input**: Reads all 6 findings files from `findings/$TARGET/`

**Output**: `findings/$TARGET/report.md`

### Step 4: Display Report Summary

```bash
echo ""
echo "[✓] Report generated successfully"
echo ""
echo "Report location: findings/$TARGET/report.md"
echo ""

# Extract key statistics
CRITICAL=$(grep -c "CRITICAL" findings/$TARGET/report.md 2>/dev/null || echo "0")
HIGH=$(grep -c "HIGH" findings/$TARGET/report.md 2>/dev/null || echo "0")
SECRETS=$(grep -c "Verified" findings/$TARGET/report.md 2>/dev/null || echo "0")

echo "Report Summary:"
echo "  Critical findings: $CRITICAL"
echo "  High findings: $HIGH"
echo "  Verified secrets: $SECRETS"
echo ""

# Show top 5 high-value targets
echo "Top 5 High-Value Targets:"
grep "^### [0-9]\. " findings/$TARGET/report.md | head -5
echo ""

echo "Next steps:"
echo "  1. Review findings/$TARGET/report.md"
echo "  2. Report critical findings immediately"
echo "  3. Begin exploitation phase on high-value targets"
echo "  4. Test API endpoints for IDOR/BFLA"
echo "  5. Attempt subdomain takeovers"
```

## Report Template

The report-writer agent uses a structured template with these sections:

1. **Executive Summary** - High-level overview
2. **Scope Reviewed** - In-scope and out-of-scope assets
3. **Attack Surface Map** - Network, web, cloud infrastructure
4. **Top 5 High-Value Targets** - Prioritized by exploitability
5. **Credentials & Secrets Found** - Verified secrets (redacted)
6. **Subdomain Takeover Candidates** - Quick wins
7. **Cloud Misconfigurations** - S3, Azure, GCP issues
8. **API Endpoints for Testing** - IDOR/BFLA targets
9. **Vulnerable Dependencies** - CVEs in discovered code
10. **Recommended Next Steps** - Exploitation phase guidance
11. **Appendix** - Raw data sources and scan statistics

## Use Cases

### Regenerate Report After New Findings

If you discover new findings and want to regenerate the report:

```bash
# Add new findings to existing files
echo "New subdomain: new.example.com" >> findings/example.com/dns.md

# Regenerate report
/recon-report example.com
```

### Generate Report from Partial Findings

If only some recon agents completed:

```bash
# The report-writer will note missing data sources
# and work with available findings
/recon-report example.com
```

The report will include a note like:
```
[!] Warning: Some findings files are missing
[!] This report is based on partial data
```

### Export Report for Bug Bounty Submission

```bash
# Generate report
/recon-report example.com

# Report is in Markdown format - can be submitted directly
# Or convert to PDF for formal submission
```

## Troubleshooting

### No Findings Directory

```
[!] Findings directory not found: findings/example.com
[!] Run /full-recon example.com first to generate findings
```

**Action**: Execute the full recon pipeline first.

### Missing Findings Files

```
[!] Missing findings files:
  - osint.md
  - dns.md
```

**Action**: Run the specific agents to generate missing files.

### Empty or Incomplete Findings

If findings files exist but are empty:

```
[!] Warning: findings/example.com/osint.md appears empty
```

The report-writer will document this and proceed with available data.

## Report Quality

The quality of the final report depends on:

1. **Completeness**: All 6 recon agents completed
2. **Accuracy**: Findings were verified and not false positives
3. **Prioritization**: High-value targets were correctly identified
4. **Context**: Agent memory provided historical context

## Notifications

After report generation, you'll see:

```
[✓] Report generated successfully

Report location: findings/example.com/report.md

Report Summary:
  Critical findings: 3
  High findings: 5
  Verified secrets: 2

Top 5 High-Value Targets:
### 1. Jenkins CI/CD Server (CRITICAL)
### 2. AWS Credentials in Public GitHub Repository (CRITICAL)
### 3. Public S3 Bucket with Production Database Backup (CRITICAL)
### 4. Subdomain Takeover Candidates (HIGH)
### 5. Elasticsearch Cluster Exposed to Internet (HIGH)

Next steps:
  1. Review findings/example.com/report.md
  2. Report critical findings immediately
  3. Begin exploitation phase on high-value targets
```

## Integration

This skill is automatically called at the end of `/full-recon`, but can also be invoked separately to:

- Regenerate reports after updates
- Create reports from manually edited findings
- Generate reports from partial recon data
