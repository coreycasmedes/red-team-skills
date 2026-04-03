#!/usr/bin/env python3
"""
Scope Validation Script for Bug Bounty Reconnaissance

Parses a scope.txt file and validates whether a target host/IP is in scope.

Usage:
    python3 parse-scope.py <scope_file> <target>

Returns:
    Exit 0: Target is IN SCOPE
    Exit 1: Target is OUT OF SCOPE

Scope file format:
    # In-scope
    *.example.com
    example.com
    203.0.113.0/24

    # Out-of-scope (prefix with !)
    !mail.example.com
    !10.0.1.5
"""

import sys
import ipaddress
import re


def parse_scope_file(scope_file_path):
    """Parse scope file into in-scope and out-of-scope lists."""
    in_scope = []
    out_of_scope = []

    try:
        with open(scope_file_path, 'r') as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Check if it's an exclusion
                if line.startswith('!'):
                    out_of_scope.append(line[1:].strip())
                else:
                    in_scope.append(line)

        return in_scope, out_of_scope

    except FileNotFoundError:
        print(f"[!] Scope file not found: {scope_file_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading scope file: {e}", file=sys.stderr)
        sys.exit(1)


def is_ip_address(target):
    """Check if target is an IP address."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_cidr_range(pattern):
    """Check if pattern is a CIDR range."""
    try:
        ipaddress.ip_network(pattern, strict=False)
        return True
    except ValueError:
        return False


def ip_in_cidr(ip, cidr):
    """Check if IP is within CIDR range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(cidr, strict=False)
        return ip_obj in network_obj
    except ValueError:
        return False


def matches_domain_pattern(target, pattern):
    """
    Check if target domain matches pattern.

    Patterns:
    - exact match: example.com
    - wildcard: *.example.com (matches any subdomain)
    """
    target = target.lower()
    pattern = pattern.lower()

    # Exact match
    if target == pattern:
        return True

    # Wildcard match
    if pattern.startswith('*.'):
        base_domain = pattern[2:]  # Remove '*.'

        # Check if target is a subdomain of base_domain
        if target.endswith('.' + base_domain):
            return True

        # Also match the base domain itself for wildcard patterns
        if target == base_domain:
            return True

    return False


def is_in_scope(target, in_scope_list, out_of_scope_list):
    """
    Determine if target is in scope.

    Precedence:
    1. Explicit exclusions (out_of_scope_list) override everything
    2. Must match at least one in_scope_list item
    3. If no match, target is OUT OF SCOPE
    """

    # Check explicit exclusions first
    for exclusion in out_of_scope_list:
        if is_ip_address(target) and is_cidr_range(exclusion):
            if ip_in_cidr(target, exclusion):
                return False, f"Excluded by CIDR: {exclusion}"
        elif is_ip_address(target) and target == exclusion:
            return False, f"Explicitly excluded IP: {exclusion}"
        elif matches_domain_pattern(target, exclusion):
            return False, f"Excluded by pattern: {exclusion}"

    # Check if matches any in-scope item
    matched = False
    match_reason = None

    for scope_item in in_scope_list:
        # IP address matching
        if is_ip_address(target):
            if is_cidr_range(scope_item):
                if ip_in_cidr(target, scope_item):
                    matched = True
                    match_reason = f"Matched CIDR: {scope_item}"
                    break
            elif target == scope_item:
                matched = True
                match_reason = f"Exact IP match: {scope_item}"
                break
        # Domain matching
        else:
            if matches_domain_pattern(target, scope_item):
                matched = True
                match_reason = f"Matched pattern: {scope_item}"
                break

    if matched:
        return True, match_reason
    else:
        return False, "No matching scope rule found"


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 parse-scope.py <scope_file> <target>", file=sys.stderr)
        sys.exit(1)

    scope_file = sys.argv[1]
    target = sys.argv[2]

    # Parse scope file
    in_scope_list, out_of_scope_list = parse_scope_file(scope_file)

    # Validate target
    in_scope, reason = is_in_scope(target, in_scope_list, out_of_scope_list)

    if in_scope:
        print(f"IN SCOPE: {target}")
        print(f"Reason: {reason}")
        sys.exit(0)
    else:
        print(f"OUT OF SCOPE: {target}")
        print(f"Reason: {reason}")
        sys.exit(1)


if __name__ == "__main__":
    main()
