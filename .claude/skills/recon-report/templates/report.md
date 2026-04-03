# Bug Bounty Reconnaissance Report

**Target**: {target}
**Date**: {date}
**Reconnaissance Duration**: {start_time} to {end_time}
**Agent**: Claude Code (red-team-skills)

---

## Executive Summary

{2-3 sentences summarizing the target's attack surface and most critical findings}

**Key Statistics**:
- Subdomains discovered: {subdomain_count}
- Live web services: {web_service_count}
- Open ports: {open_port_count}
- Critical findings: {critical_count}
- High-priority targets: {high_priority_count}

**Overall Security Posture**: {Strong/Moderate/Weak - with justification}

---

## Scope Reviewed

**In-Scope Assets**:
{list_of_in_scope_assets}

**Out-of-Scope Assets**:
{list_of_out_of_scope_assets}

**Scope Source**: targets/{target}/scope.txt

---

## Attack Surface Map

### Summary by Category

| Category | Count | Notable |
|----------|-------|---------|
| Subdomains | {count} | {notable_items} |
| Web Services | {count} | {notable_items} |
| Open Ports | {count} | {notable_items} |
| Cloud Assets | {count} | {notable_items} |
| Code Repositories | {count} | {notable_items} |
| API Endpoints | {count} | {notable_items} |

### Network Infrastructure

| Host | IP | Services | Priority | Notes |
|------|----|----|----------|-------|
{host_table_rows}

### Web Attack Surface

**Main Applications**:
{list_of_main_apps}

**Interesting Endpoints**:
{list_of_interesting_endpoints}

**Technology Stack**:
{technology_summary}

---

## Top 5 High-Value Targets

### 1. {Target Name} ({SEVERITY})

**URL/Location**: {url_or_location}

**Finding**: {brief_description}

**Impact**:
{bullet_list_of_impacts}

**Confidence**: {High/Medium/Low} (with reasoning)

**Proof of Concept**:
```bash
{commands_or_steps}
```

**Recommended Exploitation Steps**:
{numbered_list_of_steps}

**Estimated Severity**: {severity} (CVSS {score} - {description})

---

{Repeat for targets 2-5}

---

## Credentials & Secrets Found

⚠️ **Actual secret values NOT included in this report** ⚠️

### Critical Secrets (Report Immediately)

| Type | Location | Status | Impact |
|------|----------|--------|--------|
{secret_table_rows}

### High Secrets

| Type | Location | Status | Impact |
|------|----------|--------|--------|
{secret_table_rows}

### Internal Credentials (Testing Required)

| Type | Location | Notes |
|------|----------|-------|
{credential_table_rows}

---

## Subdomain Takeover Candidates

| Subdomain | Provider | Status | Verified | Risk |
|-----------|----------|--------|----------|------|
{takeover_table_rows}

**Total**: {count} confirmed takeover candidates

---

## Cloud Misconfigurations

### AWS

**S3 Buckets**:
{s3_summary}

**CloudFront**:
{cloudfront_summary}

**Other Services**:
{aws_other_summary}

### Azure

**Storage Accounts**:
{azure_storage_summary}

**App Services**:
{azure_apps_summary}

### Google Cloud

**Storage**:
{gcs_summary}

---

## API Endpoints for Testing

### High-Priority Endpoints (IDOR/BFLA Testing)

| Endpoint | Parameters | Method | Attack Vector |
|----------|------------|--------|---------------|
{api_endpoint_rows}

### GraphQL APIs

{graphql_summary}

### Swagger/OpenAPI Specs

{swagger_summary}

---

## Vulnerable Dependencies

### Critical CVEs (Immediate Patching Required)

| Package | Version | CVE | CVSS | Repository | Impact |
|---------|---------|-----|------|------------|--------|
{critical_cve_rows}

### High CVEs

{high_cve_summary}

---

## Recommended Next Steps (Exploitation Phase)

### Immediate Actions (Report Now)

{numbered_list_of_immediate_actions}

### High-Priority Testing

{numbered_list_of_high_priority_tests}

### Medium-Priority Testing

{numbered_list_of_medium_priority_tests}

### Low-Priority (Research)

{numbered_list_of_research_items}

---

## Appendix: Data Sources

### Raw Tool Outputs

All raw scan outputs are available in:
- `findings/{target}/raw/` directory

### Agent Reports

Individual agent findings:
- `findings/{target}/osint.md` (passive OSINT)
- `findings/{target}/dns.md` (DNS recon)
- `findings/{target}/ports.md` (port scanning)
- `findings/{target}/web.md` (web mapping)
- `findings/{target}/cloud.md` (cloud recon)
- `findings/{target}/code-leaks.md` (source code analysis)

### Scan Statistics

- Total recon time: {duration}
- Passive collection: {passive_time}
- Active scanning: {active_time}
- Data processed: {data_size}
- API calls made: {api_call_count}

---

## Report Confidence Assessment

**Overall Confidence**: {High/Medium/Low}

**Verified Findings**: {percentage}% (direct testing)
**Likely Findings**: {percentage}% (pattern matching)
**Unverified**: {percentage}% (requires manual testing)

**Methodology**: This report was generated using the red-team-skills Claude Code agent framework with 6 specialized reconnaissance agents (passive-osint, dns-recon, port-scanner, web-mapper, cloud-recon, code-leak).

---

**Report Generated**: {timestamp}
**Report Version**: 1.0
**Next Update**: After exploitation phase
