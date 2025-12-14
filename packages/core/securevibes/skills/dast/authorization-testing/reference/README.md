# Authorization Testing Reference Implementations

These files are examples to read and adapt — not runnable drop-in scripts.

## Files

### auth_patterns.py
Reusable authentication helper functions for common auth mechanisms:
- **session_based_auth()**: Session cookie authentication (Flask, Express, Django)
- **jwt_bearer_auth()**: JWT Bearer token authentication (REST APIs)
- **api_key_auth()**: API key header authentication
- **oauth2_token_auth()**: OAuth2 access token authentication
- **basic_auth()**: HTTP Basic authentication
- **auto_auth()**: Automatic authentication detection

Usage:
```python
from auth_patterns import jwt_bearer_auth

headers = jwt_bearer_auth("http://localhost:5000", "user1", "pass123")
response = requests.get(f"{target_url}/api/resource", headers=headers)
```

### validate_idor.py
Complete authorization testing pattern illustrating:
- Authentication and session management
- Baseline vs. test request execution
- Response redaction for sensitive fields
- Response truncation and hashing
- Classification logic (VALIDATED/FALSE_POSITIVE/UNVALIDATED)

Usage:
```bash
python validate_idor.py --endpoint "http://target.com/api/user/{id}" \
  --user1-token "jwt_token_here" --user1-id "123" --user2-id "456" \
  --output results.json
```

### bypass_403.py
403/401 bypass testing using path manipulation, header injection, and HTTP method overrides.

**Features:**
- Path manipulation bypasses (URL encoding, semicolon injection, case variation)
- Header injection bypasses (X-Original-URL, X-Forwarded-For, etc.)
- HTTP method override testing
- Comprehensive JSON output with all bypass attempts

Usage:
```bash
# Basic usage
python bypass_403.py --url "http://target.com/admin" --output results.json

# With authentication
python bypass_403.py --url "http://target.com/admin" \
  --cookie "session=abc123" --output results.json

# With custom header
python bypass_403.py --url "http://target.com/admin" \
  -H "Authorization: Bearer token" --output results.json
```

**Output:**
```json
{
  "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
  "baseline": {"url": "...", "status": 403},
  "bypasses": [...],
  "successful_bypasses": [...],
  "evidence": "Found 2 bypass(es) for /admin"
}
```

### cors_testing.py
CORS misconfiguration detection and PoC generation.

**Features:**
- Origin reflection testing
- Null origin bypass detection
- Subdomain/wildcard misconfiguration checks
- Credential mode analysis (Access-Control-Allow-Credentials)
- Automatic PoC HTML generation

Usage:
```bash
# Basic usage
python cors_testing.py --url "http://target.com/api/user" --output results.json

# With authentication and PoC generation
python cors_testing.py --url "http://target.com/api/user" \
  --cookie "session=abc123" --poc --output results.json
```

**Output:**
```json
{
  "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
  "baseline": {"url": "...", "cors_headers": {...}},
  "tests": [...],
  "vulnerabilities": [
    {
      "vulnerability": "CORS_ORIGIN_REFLECTION_WITH_CREDENTIALS",
      "severity": "HIGH",
      "origin_tested": "https://evil.com"
    }
  ],
  "evidence": "CRITICAL: Found 1 high-severity CORS misconfiguration"
}
```

### csrf_testing.py
CSRF vulnerability testing including token validation bypass techniques.

**Features:**
- No-token test (missing CSRF protection)
- Empty/null token bypass
- Invalid token value testing
- Content-Type manipulation bypass
- PoC HTML generation

Usage:
```bash
# Test password change endpoint
python csrf_testing.py --url "http://target.com/api/password/change" \
  --method POST --data '{"new_password":"test123"}' \
  --cookie "session=abc123" --output results.json

# With PoC generation
python csrf_testing.py --url "http://target.com/api/transfer" \
  --method POST --data '{"amount":1000,"to":"attacker"}' \
  --cookie "session=abc123" --poc --output results.json
```

**Output:**
```json
{
  "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
  "csrf_token_found": {"name": "csrf_token", "value": "...", "location": "form_field"},
  "tests": [...],
  "successful_bypasses": [...],
  "evidence": "CSRF vulnerability: Action performed without any CSRF token"
}
```

### mass_assignment.py
Mass assignment / object injection privilege escalation testing.

**Features:**
- Automatic injection of privilege-related parameters
- Before/after response comparison
- Privilege escalation detection
- Support for user registration and profile update endpoints

Usage:
```bash
# Test user registration
python mass_assignment.py --url "http://target.com/api/register" \
  --method POST --data '{"username":"test","password":"test123"}' \
  --output results.json

# Test profile update with authentication
python mass_assignment.py --url "http://target.com/api/user/update" \
  --method PUT --data '{"name":"Test User"}' \
  --cookie "session=abc123" --output results.json
```

**Output:**
```json
{
  "status": "VALIDATED|FALSE_POSITIVE|PARTIAL|UNVALIDATED",
  "baseline": {"url": "...", "status": 201, "response_snippet": "..."},
  "tests": [...],
  "escalations": [
    {
      "injected_params": {"role": "admin"},
      "escalation_detected": true,
      "severity": "HIGH",
      "indicators": ["Injected parameter 'role' reflected in response with value 'admin'"]
    }
  ],
  "evidence": "CRITICAL: Mass assignment vulnerability - 1 privilege escalation(s) detected"
}
```

## Payload Files

The `../payloads/` directory contains wordlists used by these scripts:

| File | Description | Used By |
|------|-------------|---------|
| `403_bypass.txt` | Path manipulation payloads | bypass_403.py |
| `403_bypass_headers.txt` | Header injection payloads | bypass_403.py |
| `cors_origins.txt` | CORS origin bypass values | cors_testing.py |
| `csrf_tokens.txt` | CSRF token bypass values | csrf_testing.py |
| `mass_assignment_params.txt` | Privilege escalation parameters | mass_assignment.py |
| `referer_bypass.txt` | Referer header bypass payloads | Manual testing |
| `backup_extensions.txt` | Backup file extensions | Manual testing |

## CLI Alternatives

These scripts provide CLI alternatives to GUI-based security tools:

| Script | Replaces |
|--------|----------|
| bypass_403.py | Burp Suite 403 Bypasser, byp4xx |
| cors_testing.py | Corsy |
| csrf_testing.py | Burp Suite CSRF PoC Generator |
| mass_assignment.py | Param Miner (partial) |

## Important

Do not run these files unchanged; each application requires tailored logic. These are reference implementations to guide your testing approach.

### Adapting Scripts

1. **Review authentication**: Modify auth mechanisms to match your target
2. **Update endpoints**: Replace placeholder URLs with actual target endpoints
3. **Customize payloads**: Add application-specific parameters or headers
4. **Handle edge cases**: Add error handling for your specific environment
5. **Review output**: Validate classification logic for your use case
