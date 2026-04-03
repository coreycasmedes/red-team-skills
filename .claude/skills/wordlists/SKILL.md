---
name: wordlists
description: Reference knowledge for which wordlists to use for different fuzzing tasks in bug bounty recon. Automatically loaded when doing directory fuzzing, parameter discovery, or subdomain brute forcing.
user-invocable: false
---

# Wordlist Reference Guide

This is a reference guide for selecting appropriate wordlists for various bug bounty reconnaissance tasks. It assumes SecLists is installed at `/usr/share/seclists`.

## Installation

If SecLists is not installed:

```bash
# Clone SecLists repository
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists

# Or on Kali Linux (pre-installed)
sudo apt update && sudo apt install seclists
```

## Wordlist Selection by Task

### Subdomain Enumeration (Brute Force)

**Task**: Brute-forcing subdomains via DNS

**Recommended Wordlists**:

1. **Quick scan** (5-10 minutes):
   ```
   /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
   ```
   - 5,000 most common subdomains
   - Fast, low noise

2. **Standard scan** (15-30 minutes):
   ```
   /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
   ```
   - 20,000 common subdomains
   - Good balance of coverage and speed

3. **Comprehensive scan** (1-2 hours):
   ```
   /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
   ```
   - 110,000 subdomains
   - Maximum coverage, slow

4. **Alternative** (focused on bug bounty):
   ```
   /usr/share/seclists/Discovery/DNS/best-dns-wordlist.txt
   ```
   - Curated for security testing
   - ~10,000 entries

**Usage Example**:
```bash
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt example.com
```

---

### Directory Fuzzing

**Task**: Discovering hidden directories and paths

**Recommended Wordlists**:

1. **Quick scan** (5-10 minutes per host):
   ```
   /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
   ```
   - ~17,000 entries
   - Common web paths

2. **Standard scan** (15-30 minutes per host):
   ```
   /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
   ```
   - ~30,000 entries
   - Recommended for bug bounties

3. **Comprehensive scan** (1+ hour per host):
   ```
   /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
   ```
   - ~62,000 entries
   - Thorough coverage

4. **Common paths** (2-5 minutes per host):
   ```
   /usr/share/seclists/Discovery/Web-Content/common.txt
   ```
   - ~4,700 entries
   - Very common paths only

**Usage Example**:
```bash
ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

---

### File Fuzzing

**Task**: Discovering files with specific extensions

**Recommended Wordlists**:

1. **Standard file fuzzing**:
   ```
   /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
   ```
   - ~17,000 files
   - Common file names

2. **Small file list**:
   ```
   /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
   ```
   - ~11,000 files
   - Quick scan

3. **Backup file patterns**:
   ```
   /usr/share/seclists/Discovery/Web-Content/backup-files.txt
   ```
   - Backup extensions (.bak, .old, .backup)

**Usage Example**:
```bash
ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

---

### API Endpoint Discovery

**Task**: Finding API endpoints and objects

**Recommended Wordlists**:

1. **API objects**:
   ```
   /usr/share/seclists/Discovery/Web-Content/api/objects.txt
   ```
   - Common REST API object names (users, posts, products)

2. **API actions**:
   ```
   /usr/share/seclists/Discovery/Web-Content/api/actions.txt
   ```
   - Common API actions (get, create, update, delete)

3. **API endpoints**:
   ```
   /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
   ```
   - Full API endpoint patterns

**Usage Example**:
```bash
ffuf -u https://api.example.com/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
```

---

### Parameter Discovery

**Task**: Finding hidden parameters in requests

**Recommended Wordlists**:

1. **Burp parameter names** (most common):
   ```
   /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
   ```
   - ~6,000 parameter names
   - From Burp Suite research

2. **Common parameters**:
   ```
   /usr/share/seclists/Discovery/Web-Content/common-params.txt
   ```
   - Smaller list (~1,000 entries)

**Usage Example** (with Arjun):
```bash
arjun -u https://example.com/search -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

### Cloud Storage Enumeration

**Task**: Finding S3 buckets, Azure blobs, GCS buckets

**Recommended Wordlists**:

1. **AWS S3 buckets**:
   ```
   /usr/share/seclists/Discovery/Cloud/aws-s3.txt
   ```
   - Common S3 bucket naming patterns

2. **Azure storage**:
   ```
   /usr/share/seclists/Discovery/Cloud/azure-storage-accounts.txt
   ```
   - Azure storage account patterns

**Usage Example**:
```bash
s3scanner scan --buckets-file /usr/share/seclists/Discovery/Cloud/aws-s3.txt
```

---

### Username Enumeration

**Task**: Enumerating valid usernames

**Recommended Wordlists**:

1. **Common usernames**:
   ```
   /usr/share/seclists/Usernames/Names/names.txt
   ```
   - ~10,000 real names

2. **Top usernames**:
   ```
   /usr/share/seclists/Usernames/top-usernames-shortlist.txt
   ```
   - ~17 very common usernames

**Usage Example**:
```bash
ffuf -u https://example.com/user/FUZZ -w /usr/share/seclists/Usernames/Names/names.txt -mc 200,301
```

---

### Password Testing (Last Resort, Authorized Only)

**Task**: Testing for weak/default passwords

**⚠️ WARNING**: Only use on authorized targets with explicit permission.

**Recommended Wordlists**:

1. **Common passwords**:
   ```
   /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt
   ```
   - Top 10,000 most common passwords

2. **Default credentials**:
   ```
   /usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt
   ```
   - Default creds for various services

3. **Top 100 passwords** (very targeted):
   ```
   /usr/share/seclists/Passwords/Common-Credentials/top-100.txt
   ```
   - Top 100 only (for rate-limited testing)

**Usage Example**:
```bash
# Test default credentials only
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://example.com
```

---

## Custom Wordlist Generation

For target-specific wordlists:

### CeWL (Custom Word List generator)

```bash
# Generate wordlist from target website
cewl https://example.com -d 2 -m 5 -w custom-wordlist.txt
```

### Combining Wordlists

```bash
# Merge multiple wordlists and deduplicate
cat wordlist1.txt wordlist2.txt | sort -u > combined-wordlist.txt
```

### Adding Target-Specific Terms

```bash
# Add organization name, product names, etc.
cat > target-specific.txt << EOF
example
examplecorp
example-corp
exampleapp
example-api
EOF

cat target-specific.txt /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | sort -u > custom-subdomain-list.txt
```

---

## Wordlist Size Guidelines

| List Size | Use Case | Scan Time (estimate) |
|-----------|----------|---------------------|
| < 1,000 | Quick verification, rate-limited targets | 1-5 min |
| 1,000-10,000 | Standard recon, balanced approach | 5-30 min |
| 10,000-50,000 | Comprehensive scan, patient approach | 30 min - 2 hours |
| 50,000+ | Exhaustive scan, overnight jobs | 2+ hours |

**Trade-off**: Larger wordlists find more, but:
- Take longer
- Generate more traffic (rate limiting risk)
- Increase chance of WAF detection
- May violate bug bounty program rules

**Recommendation**: Start with medium-sized lists, expand only if needed.

---

## SecLists Directory Structure Reference

```
/usr/share/seclists/
├── Discovery/
│   ├── DNS/              # Subdomain lists
│   ├── Web-Content/      # Directories, files, parameters
│   │   ├── api/          # API-specific lists
│   │   └── ...
│   └── Cloud/            # Cloud storage patterns
├── Usernames/            # Username lists
├── Passwords/            # Password lists (use carefully!)
│   ├── Common-Credentials/
│   └── Default-Credentials/
├── Fuzzing/              # Fuzzing payloads (for vulnerability testing)
└── ...
```

---

## Best Practices

1. **Start small**: Begin with small wordlists to test rate limits
2. **Target-specific**: Add organization-specific terms to generic lists
3. **Monitor for blocking**: Watch for 429 responses or connection resets
4. **Respect scope**: Only fuzz in-scope targets
5. **Read program rules**: Some bug bounties prohibit brute forcing

---

## Troubleshooting

### Wordlist Not Found

```bash
# Check if SecLists is installed
ls /usr/share/seclists/

# If not, install:
sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

### Rate Limiting Issues

```bash
# Reduce request rate
ffuf -u https://example.com/FUZZ -w wordlist.txt -rate 10  # 10 req/sec max

# Add delays
ffuf -u https://example.com/FUZZ -w wordlist.txt -p 0.5  # 500ms delay
```

### WAF Blocking

```bash
# Use smaller wordlist
# Add randomized delays
# Rotate User-Agent headers
```

---

## Integration

This skill is automatically referenced by agents when performing:
- Subdomain brute forcing (dns-recon)
- Directory fuzzing (web-mapper)
- Parameter discovery (web-mapper)
- Cloud storage enumeration (cloud-recon)

Agents will suggest appropriate wordlists based on the task and target characteristics.
