---
name: rate-limits
description: Reference knowledge for safe scanning rates in bug bounty programs to avoid triggering WAFs, rate limits, or violating program rules. Automatically loaded when running active scans.
user-invocable: false
---

# Rate Limiting Guidelines for Bug Bounty Reconnaissance

This is a reference guide for safe scanning rates to use during bug bounty reconnaissance. Following these guidelines helps avoid detection, WAF blocks, and program rule violations.

## General Principles

1. **Respect the target**: Bug bounties authorize security testing, not DoS attacks
2. **Start conservative**: Begin with slower rates, increase if no issues
3. **Monitor responses**: Watch for 429 errors, connection resets, blocks
4. **Read program rules**: Some programs specify rate limits explicitly
5. **Back off immediately**: If you get rate limited, reduce your rate

## Rate Limiting by Program Type

### Public Bug Bounty Programs

**Definition**: Open programs on HackerOne, Bugcrowd, etc. Anyone can participate.

**Recommended Rates**:

| Tool | Parameter | Rate | Notes |
|------|-----------|------|-------|
| masscan | `--rate` | 1000 | 1,000 packets/sec |
| nmap | `-T` | 3 (Normal) | Balanced timing |
| httpx | `--rate-limit` | 10 | 10 req/sec |
| ffuf | `--rate` | 10 | 10 req/sec |
| katana | `-rate-limit` | 10 | 10 req/sec |
| nuclei | `-rate-limit` | 10 | 10 req/sec |
| subfinder | (default) | N/A | Passive only |
| amass | `-max-dns-queries` | 100 | 100 queries/sec |

**Delays Between Tools**:
```bash
# Add 2-5 second delays between major tool runs
sleep 5
```

**Rationale**: Public programs expect security testing but want to avoid service disruption. Conservative rates show professionalism.

---

### Private Bug Bounty Programs

**Definition**: Invite-only programs. You received a direct invitation.

**Recommended Rates**:

| Tool | Parameter | Rate | Notes |
|------|-----------|------|-------|
| masscan | `--rate` | 5000 | 5,000 packets/sec |
| nmap | `-T` | 4 (Aggressive) | Faster timing |
| httpx | `--rate-limit` | 50 | 50 req/sec |
| ffuf | `--rate` | 50 | 50 req/sec |
| katana | `-rate-limit` | 50 | 50 req/sec |
| nuclei | `-rate-limit` | 50 | 50 req/sec |
| amass | `-max-dns-queries` | 500 | 500 queries/sec |

**Delays Between Tools**:
```bash
# 2 second delays acceptable
sleep 2
```

**Rationale**: Private invitations indicate higher trust and often larger scope. Moderate rates are acceptable.

---

### VDP (Vulnerability Disclosure Programs)

**Definition**: No bounty offered, just coordinated disclosure.

**Recommended Rates**: Same as **Public Bug Bounty Programs** (conservative)

**Rationale**: No monetary incentive means extra care to avoid disrupting free services.

---

### Your Own Infrastructure / Lab

**Definition**: Testing your own systems or authorized lab environments.

**Recommended Rates**: **Unrestricted**

You can use maximum speed settings:
```bash
masscan --rate 10000
nmap -T5
ffuf --rate 1000
```

---

## Rate Limiting by Tool

### masscan (Port Scanning)

**Conservative** (Public Programs):
```bash
masscan -iL targets.txt -p1-65535 --rate 1000
```

**Moderate** (Private Programs):
```bash
masscan -iL targets.txt -p1-65535 --rate 5000
```

**Aggressive** (Own Infrastructure):
```bash
masscan -iL targets.txt -p1-65535 --rate 10000
```

**Never Use**:
- `--rate > 10000` on production targets
- Can cause network congestion and service disruption

---

### nmap (Service Detection)

**Conservative** (Public Programs):
```bash
nmap -iL targets.txt -sV -sC -T3
```
- `-T3`: Normal timing template
- Includes retries and reasonable timeouts

**Moderate** (Private Programs):
```bash
nmap -iL targets.txt -sV -sC -T4
```
- `-T4`: Aggressive timing
- Faster but more noticeable

**Aggressive** (Own Infrastructure):
```bash
nmap -iL targets.txt -sV -sC -T5 --min-rate 1000
```
- `-T5`: Insane timing
- `--min-rate`: Force minimum packet rate

**Never Use**:
- `-T5` on production targets (bug bounties)
- Can overwhelm firewalls and IDS systems

---

### httpx (HTTP Probing)

**Conservative**:
```bash
httpx -l targets.txt -rate-limit 10 -threads 10
```

**Moderate**:
```bash
httpx -l targets.txt -rate-limit 50 -threads 25
```

**Aggressive**:
```bash
httpx -l targets.txt -rate-limit 150 -threads 50
```

---

### ffuf (Directory/File Fuzzing)

**Conservative**:
```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 10 -t 10
```
- `-rate 10`: 10 req/sec
- `-t 10`: 10 threads

**Moderate**:
```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 50 -t 25
```

**Aggressive**:
```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 200 -t 50
```

**Add Delays** (if needed):
```bash
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 10 -p 0.5
```
- `-p 0.5`: 500ms delay between requests

---

### katana (Web Crawling)

**Conservative**:
```bash
katana -u https://example.com -rate-limit 10 -delay 1000
```
- `-rate-limit 10`: 10 req/sec
- `-delay 1000`: 1 second delay

**Moderate**:
```bash
katana -u https://example.com -rate-limit 50 -delay 500
```

**Aggressive**:
```bash
katana -u https://example.com -rate-limit 150
```

---

### nuclei (Vulnerability Scanning)

**Conservative**:
```bash
nuclei -l targets.txt -rate-limit 10 -bulk-size 10
```

**Moderate**:
```bash
nuclei -l targets.txt -rate-limit 50 -bulk-size 25
```

**Aggressive**:
```bash
nuclei -l targets.txt -rate-limit 150 -bulk-size 50
```

**Important**: Nuclei can be very noisy. Always use rate limiting.

---

### amass (DNS Enumeration)

**Conservative**:
```bash
amass enum -d example.com -max-dns-queries 100
```

**Moderate**:
```bash
amass enum -d example.com -max-dns-queries 500
```

**Aggressive**:
```bash
amass enum -d example.com -max-dns-queries 2000
```

---

## Detection and Response

### Signs You're Rate Limited

**429 Too Many Requests**:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```
**Action**: Stop immediately. Wait for `Retry-After` duration. Reduce rate by 50%.

**Connection Resets**:
```
curl: (56) Recv failure: Connection reset by peer
```
**Action**: WAF or firewall blocking you. Reduce rate by 75% and add delays.

**503 Service Unavailable** (repeated):
```
HTTP/1.1 503 Service Unavailable
```
**Action**: You may be overwhelming the service. Stop and wait 5 minutes.

**Cloudflare Challenge**:
```
<title>Just a moment...</title>
```
**Action**: Cloudflare detected automated traffic. Slow down significantly.

### Response Strategy

1. **Stop immediately** when rate limited
2. **Wait** for cooldown period (30-60 seconds minimum)
3. **Reduce rate** by 50-75%
4. **Add delays** between requests (0.5-2 seconds)
5. **Monitor closely** for continued blocking

### Example Response Script

```bash
# If you get a 429
echo "[!] 429 Rate Limit detected. Stopping."
sleep 60  # Wait 1 minute

# Retry with reduced rate
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 5  # Reduced from 10
```

---

## WAF-Specific Considerations

### Cloudflare

**Detection**: Look for `cf-ray` header or `cloudflare` in response

**Recommended Rates**:
- Initial scan: 5-10 req/sec
- If no issues: Increase to 20 req/sec
- If challenged: Drop to 2-5 req/sec

**Tips**:
- Randomize User-Agent headers
- Add realistic delays (0.5-1 second)
- Avoid burst patterns

### AWS WAF

**Detection**: Look for `x-amzn-requestid` header

**Recommended Rates**:
- Start at 10 req/sec
- AWS WAF is generally permissive for scanning

### Akamai

**Detection**: Look for `akamai` in headers or HTML comments

**Recommended Rates**:
- Very sensitive, start at 5 req/sec
- Increase slowly if no blocking

---

## Program-Specific Rules

### HackerOne

**General Guidance**:
- "Don't DoS the target"
- No specific rate limits usually
- Use conservative rates (10 req/sec)

**Check**: Always read the program's policy page

### Bugcrowd

**General Guidance**:
- "Avoid disruption to services"
- Some programs specify limits in scope
- Use conservative rates

### Intigriti

**General Guidance**:
- Similar to HackerOne
- Conservative approach recommended

### YesWeHack

**General Guidance**:
- Some European targets are more sensitive
- Start with 5 req/sec, increase if allowed

---

## Best Practices Summary

1. **Always read program rules first** - Some programs specify exact limits
2. **Start conservative** - You can always speed up
3. **Monitor responses** - Watch for 429, connection resets, blocks
4. **Add delays between tools** - Don't run multiple aggressive tools simultaneously
5. **Test during off-peak hours** - Reduces impact on legitimate users
6. **Document your scanning** - Note rates used in findings for transparency
7. **Respect rate limits** - Never deliberately try to bypass them

---

## Tools Comparison

| Tool | Purpose | Safe Rate (Public) | Safe Rate (Private) |
|------|---------|-------------------|---------------------|
| masscan | Port scanning | 1000 pkt/s | 5000 pkt/s |
| nmap | Service detection | -T3 | -T4 |
| httpx | HTTP probing | 10 req/s | 50 req/s |
| ffuf | Directory fuzzing | 10 req/s | 50 req/s |
| katana | Web crawling | 10 req/s | 50 req/s |
| nuclei | Vuln scanning | 10 req/s | 50 req/s |
| amass | DNS enum | 100 queries/s | 500 queries/s |

---

## Example Scan Configurations

### Conservative Full Scan

```bash
# Port scan
masscan -iL targets.txt -p1-65535 --rate 1000

sleep 5

# Service detection
nmap -iL targets.txt -sV -sC -T3

sleep 5

# HTTP probing
httpx -l targets.txt -rate-limit 10

sleep 5

# Directory fuzzing (limited wordlist)
ffuf -u https://example.com/FUZZ -w small-wordlist.txt -rate 10
```

### Moderate Scan (Private Program)

```bash
# Port scan
masscan -iL targets.txt -p1-65535 --rate 5000

sleep 2

# Service detection
nmap -iL targets.txt -sV -sC -T4

sleep 2

# HTTP probing
httpx -l targets.txt -rate-limit 50

# Directory fuzzing (can run in parallel)
ffuf -u https://example.com/FUZZ -w medium-wordlist.txt -rate 50
```

---

## Integration

This skill is automatically referenced by agents when performing:
- Port scanning (port-scanner)
- Web fuzzing (web-mapper)
- Directory brute forcing (web-mapper)
- Service detection (port-scanner)

Agents will apply appropriate rate limits based on the target context and program type.

---

## Legal Note

Rate limiting is not just about avoiding detection - it's about:
1. **Respecting the target's infrastructure**
2. **Following bug bounty program rules**
3. **Maintaining professional reputation**
4. **Avoiding service disruption**

**Always err on the side of being too conservative.**
