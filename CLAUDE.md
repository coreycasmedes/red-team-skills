# red-team-skills

Bug bounty recon and testing agent. All targets are in-scope under an active
bug bounty program. Never act on out-of-scope assets.

## Mission
Two-phase methodology only:
1. **Discovery** — enumerate all assets before touching anything
2. **Testing** — probe discovered assets systematically

Do not skip ahead to testing. Discovery must produce a complete run directory
before any testing skill is invoked.

## Repo Structure
```
red-team-skills/
  CLAUDE.md                  ← you are here
  skills/
    discovery/               ← Phase 1 (reconnaissance)
      00_scope.md
      01_subdomain_enum.md
      02_live_host_probe.md
      03_endpoint_crawl.md
      04_fingerprint.md
    testing/                 ← Phase 2 (vulnerability detection)
      00_run_all_tests.md    ← Master workflow
      05_bola_idor.md        ← CRITICAL: API authorization
      06_bfla_privilege.md   ← HIGH: Admin access
      07_secret_exposure.md  ← CRITICAL: Exposed credentials
      08_auth_bypass.md      ← HIGH: Authentication flaws
      09_misconfig.md        ← MEDIUM: Security config
      findings_schema.json   ← Output template
  runs/                      ← gitignored, one dir per session
  wordlists/                 ← curated lists (idor_ids.txt, admin_paths.txt)
```

## Session Start Protocol
Before anything else, ask:
1. What is the target domain?
2. Is there a bug bounty program brief or scope doc? If yes, read it first.
3. Does a `runs/{target}-{date}/` directory already exist? If yes, resume from there.

## Run Directory Convention
All output goes to `runs/{target}-{timestamp}/` using this schema:
```
00_scope.json        ← domain, program, in-scope/out-of-scope
01_subdomains.json   ← raw enumeration output, deduplicated
02_live_hosts.json   ← httpx-filtered live hosts with status + tech
03_endpoints.json    ← katana + gau + waybackurls merged
04_fingerprint.json  ← tech stack, WAF, auth surfaces, high-value targets
findings.json        ← testing results (phase 2)
```
Never overwrite an existing step — append or create a new timestamped run.

## Invoking Skills
Load a skill by reading it before executing.

### Discovery Phase (Phase 1)
- `@skills/discovery/00_scope.md` — define and validate scope
- `@skills/discovery/01_subdomain_enum.md` — subdomain enumeration
- `@skills/discovery/02_live_host_probe.md` — live host filtering
- `@skills/discovery/03_endpoint_crawl.md` — endpoint crawling
- `@skills/discovery/04_fingerprint.md` — fingerprinting

### Testing Phase (Phase 2)
**Prerequisites**: All discovery outputs (00-04) must exist before testing.

- `@skills/testing/00_run_all_tests.md` — orchestration workflow (runs all tests)
- `@skills/testing/07_secret_exposure.md` — exposed credentials/keys (run first)
- `@skills/testing/05_bola_idor.md` — API authorization flaws (OWASP API #1)
- `@skills/testing/06_bfla_privilege.md` — privilege escalation (OWASP API #5)
- `@skills/testing/08_auth_bypass.md` — authentication bypass (JWT, SQLi, defaults)
- `@skills/testing/09_misconfig.md` — security misconfigurations (CORS, headers, S3)

**Execution Order**: Critical (07, 05) → High (06, 08) → Medium (09)

Read the skill file fully before running any commands from it.

## Output Format (all responses)
- **Objective** — what this step accomplishes
- **Commands** — runnable, copy-paste bash/python
- **Expected Output** — what a good result looks like
- **Vulnerable vs. Safe** — concrete diff where relevant
- **Next Step** — what skill or action follows

## Preferred Toolchain

### Discovery Tools
subfinder, amass, dnsx, httpx, katana, gau, waybackurls, nuclei, nmap

### Testing Tools
- **Secret scanning**: trufflehog, gitleaks, git-dumper
- **JWT testing**: pyjwt, jwt_tool
- **API fuzzing**: ffuf (optional, Python scripts primary)
- **Cloud security**: awscli, cloudsplaining, s3scanner

Always verify flag syntax before running. If uncertain, say so.

## Hard Rules

### Discovery Phase
- Confirm scope in `00_scope.json` before any active enumeration
- Never run testing skills before all discovery outputs exist (00-04 JSON files)
- Passive reconnaissance only until scope confirmed

### Testing Phase
- **Prerequisites**: All 5 discovery JSON files must exist
- **No exploitation**: Only detect vulnerabilities, never exploit them
- **No post-exploitation**: Stop at vulnerability confirmation
- **Respect rate limits**: Follow skill-specific thresholds (0.5-2s between requests)
- **WAF awareness**: Skip or delay testing on WAF-protected targets
- **Stop on critical**: Report immediately if critical vulnerability found

### Universal Rules
- Never suggest post-exploitation, lateral movement, or persistence
- Flag rate limiting and stealth risks proactively
- If a finding is report-worthy, say so and frame the impact clearly
- Only test in-scope targets (validate against 00_scope.json)
- Document all findings with clear proof-of-concept
