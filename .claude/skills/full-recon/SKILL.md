---
name: full-recon
description: Full recon pipeline for a bug bounty target. Orchestrates all recon agents in sequence. Takes a target domain as argument.
disable-model-invocation: true
argument-hint: <target-domain>
---

# Full Reconnaissance Pipeline

Executes the complete bug bounty reconnaissance workflow against the target domain provided as an argument.

## Usage

```
/full-recon example.com
```

## Workflow

This skill orchestrates all 6 recon agents in the optimal sequence:

### Step 1: Create Findings Directory

```bash
TARGET=$ARGUMENTS
mkdir -p findings/$TARGET/raw/
echo "[*] Created findings directory: findings/$TARGET/"
```

### Step 2: Passive OSINT (No Target Contact)

```
Invoke: @passive-osint
Target: $TARGET
Duration: ~10-15 minutes
```

**What it does**: Gathers intel from third-party sources (Shodan, theHarvester, Wayback, GitHub) without touching the target.

**Output**: `findings/$TARGET/osint.md`

**Wait for completion before proceeding.**

**Summary**: Review findings - note subdomains discovered, employees, technology hints.

---

### Step 3: DNS Reconnaissance

```
Invoke: @dns-recon
Target: $TARGET
Duration: ~15-25 minutes
```

**What it does**: Expands subdomain surface via cert transparency, DNS brute force, and zone transfers.

**Input**: Uses subdomains from passive-osint as seeds

**Output**: `findings/$TARGET/dns.md`

**Wait for completion before proceeding.**

**Summary**: Review resolved subdomains, cloud assets, takeover candidates.

---

### Step 4 & 5: Parallel Scanning

Run these two agents in parallel (background):

#### Port Scanner (Background)

```
Invoke: @port-scanner (background)
Target: Resolved hosts from dns-recon
Duration: ~20-40 minutes
```

**What it does**: Staged nmap/masscan to map open ports and services.

**Input**: Reads `findings/$TARGET/resolved-subdomains.txt` from dns-recon

**Output**: `findings/$TARGET/ports.md`

#### Cloud Recon (Background)

```
Invoke: @cloud-recon (background)
Target: $TARGET
Duration: ~15-25 minutes
```

**What it does**: Enumerates S3 buckets, Azure blobs, GCS, subdomain takeovers.

**Input**: Uses subdomains from dns-recon

**Output**: `findings/$TARGET/cloud.md`

**Note**: Both agents run in parallel. Monitor progress and wait for both to complete.

**Summary**: Review open ports, exposed services, public cloud storage.

---

### Step 6: Web Mapping

```
Invoke: @web-mapper
Target: HTTP/HTTPS services from port-scanner
Duration: ~25-45 minutes
```

**What it does**: Maps web attack surface - endpoints, params, JS secrets, tech stack.

**Input**: Reads `findings/$TARGET/ports.md` for web services

**Output**: `findings/$TARGET/web.md`

**Wait for completion before proceeding.**

**Summary**: Review interesting endpoints, API specs, secrets in JS, admin panels.

---

### Step 7: Code Leak Detection (Background)

```
Invoke: @code-leak (background)
Target: $TARGET
Duration: ~20-30 minutes
```

**What it does**: Searches GitHub/GitLab for leaked source code, credentials, internal info.

**Input**: Reads target domain, employee emails, internal hostnames from previous phases

**Output**: `findings/$TARGET/code-leaks.md`

**Note**: Can run in background during web-mapper. Wait for completion before final report.

**Summary**: Review verified secrets, leaked credentials, vulnerable dependencies.

---

### Step 8: Report Synthesis

```
Invoke: @report-writer
Target: $TARGET
Duration: ~5-10 minutes
```

**What it does**: Reads all findings and produces prioritized bug bounty report.

**Input**: Reads all 6 findings files (osint, dns, ports, web, cloud, code-leaks)

**Output**: `findings/$TARGET/report.md`

**Summary**: Review top 5 high-value targets, credentials found, recommended next steps.

---

## Total Execution Time

**Estimated**: 90-180 minutes (1.5-3 hours) depending on target size

- Passive OSINT: 10-15 min
- DNS Recon: 15-25 min
- Port Scanning + Cloud Recon (parallel): 20-40 min
- Web Mapping: 25-45 min
- Code Leak Detection: 20-30 min
- Report Writing: 5-10 min

## Success Criteria

At the end of the pipeline, you should have:

- [x] 6 findings markdown files (osint, dns, ports, web, cloud, code-leaks)
- [x] 1 comprehensive report (report.md)
- [x] High-value targets identified and prioritized
- [x] Credentials/secrets documented (if found)
- [x] Attack surface mapped
- [x] Next exploitation steps recommended

## After Completion

Review the final report:

```bash
cat findings/$TARGET/report.md
```

Key sections to check:
- **Top 5 High-Value Targets**: Prioritized by exploitability
- **Credentials & Secrets Found**: Report immediately if critical
- **Subdomain Takeover Candidates**: Quick wins for bounty
- **Recommended Next Steps**: Exploitation phase planning

## Troubleshooting

### Missing Prerequisites

If any recon agent fails due to missing tools:
- Note which tools are missing in the findings
- Continue with available tools
- Document gaps in final report

### Rate Limiting

If you encounter rate limiting (429 errors):
- Pause and resume after delay
- Reduce scan rates in agent configurations
- Document in findings

### Scope Validation Failures

If validate-scope.sh blocks commands:
- Verify `targets/$TARGET/scope.txt` exists and is correct
- Ensure target is actually in scope
- Ask user to confirm scope before proceeding

## Notes

- All agents respect rate limits and stealth settings
- Passive-osint makes NO direct contact with target
- Active scanning (port-scanner, web-mapper) requires scope validation
- Cloud-recon is read-only (never modifies cloud resources)
- Code-leak never commits secrets to this repo

## Notification

After pipeline completes, notify the user:

```
[✓] Full reconnaissance complete for $TARGET

Findings saved to: findings/$TARGET/
Final report: findings/$TARGET/report.md

Critical findings: [X] (report immediately)
High-value targets: [Y]
Secrets found: [Z]

Next steps:
1. Review report.md for prioritized targets
2. Report any critical findings (AWS keys, open admin panels, etc.)
3. Begin exploitation phase on high-value targets
4. Test API endpoints for IDOR/BFLA
5. Attempt subdomain takeovers

Run /recon-report $TARGET to regenerate the final report.
```
