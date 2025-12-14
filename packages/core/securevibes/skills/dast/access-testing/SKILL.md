---
name: access-testing
description: Validate cross-site attacks, session protection, and information disclosure vulnerabilities. Test CSRF token validation, CORS policies, cache controls, and sensitive data exposure. Use when testing CWE-352 (CSRF), CWE-942 (CORS), CWE-293 (Referer Bypass), CWE-548 (Directory Listing), CWE-530 (Backup Exposure), CWE-798 (Hardcoded Credentials), CWE-525 (Browser Cache/History), CWE-615 (Developer Comments), or CWE-1108 (Broken Links) findings.
allowed-tools: Read, Write, Bash
---

# Access Testing Skill

## Purpose
Validate cross-site attacks, session protection mechanisms, and information disclosure vulnerabilities by testing:
- **Cross-site request forgery (CSRF)** protection
- **Cross-origin resource sharing (CORS)** policies
- **Browser caching** and history controls
- **Sensitive data exposure** via backups, comments, and credentials

## Vulnerability Types Covered

### 1. Cross-Site Request Forgery - CSRF (CWE-352)
Perform unauthorized state-changing actions on behalf of authenticated users.

**Test Pattern:** Send state-changing request without/with invalid CSRF token
**Expected:** 403 Forbidden | **Actual if vulnerable:** 200 OK, action performed
**CLI Test:**
```bash
# Test without CSRF token
curl -X POST "$TARGET/api/password/change" -H "Cookie: $SESSION" \
  -H "Content-Type: application/json" -d '{"new_password":"hacked123"}'

# Test with empty CSRF token
curl -X POST "$TARGET/api/password/change" -H "Cookie: $SESSION" \
  -H "X-CSRF-Token: " -d '{"new_password":"hacked123"}'
```
**Reference:** See `reference/csrf_testing.py` and `payloads/csrf_tokens.txt`

### 2. CSRF Token Bruteforce / Weak Entropy (CWE-330)
Predict or guess CSRF tokens through statistical analysis or weak randomness.

**Test Pattern:** Analyze CSRF token entropy level using statistical analysis
**Expected:** Token entropy >= 64 bits, length >= 16 bytes | **Actual if vulnerable:** Predictable tokens
**CLI Test:**
```bash
# Collect multiple CSRF tokens
for i in {1..100}; do
  curl -s "$TARGET/api/csrf-token" -H "Cookie: $SESSION" | jq -r '.token' >> tokens.txt
done

# Analyze for patterns (manual review)
sort tokens.txt | uniq -c | sort -rn | head
```
**Indicators of Weak Tokens:**
- Tokens shorter than 16 characters
- Sequential or predictable patterns
- Timestamp-based generation
- Low character diversity
- Duplicate tokens across requests

### 3. CORS Misconfiguration (CWE-942)
Bypass same-origin policy via misconfigured CORS headers allowing cross-origin data theft.

**Test Pattern:** Send request with malicious Origin header, check if reflected with credentials
**Expected:** Origin not reflected or strict whitelist | **Actual if vulnerable:** Origin reflected with `Access-Control-Allow-Credentials: true`
**CLI Test:**
```bash
# Test origin reflection
curl -I "$TARGET/api/user" -H "Origin: https://evil.com" -H "Cookie: $SESSION" \
  | grep -i "access-control"

# Test null origin bypass
curl -I "$TARGET/api/user" -H "Origin: null" -H "Cookie: $SESSION" \
  | grep -i "access-control"

# Test subdomain bypass
curl -I "$TARGET/api/user" -H "Origin: https://evil.target.com" -H "Cookie: $SESSION" \
  | grep -i "access-control"
```
**Reference:** See `reference/cors_testing.py` and `payloads/cors_origins.txt`

### 4. Referer-based Access Control Bypass (CWE-293)
Bypass access controls that rely on Referer header validation.

**Test Pattern:** Manipulate Referer header to bypass restrictions
**Expected:** Access denied | **Actual if vulnerable:** Access granted with spoofed Referer
**CLI Test:**
```bash
# Test with spoofed referer
curl "$TARGET/admin/action" -H "Referer: https://target.com/admin"
curl "$TARGET/admin/action" -H "Referer: https://evil.com?.target.com"
curl "$TARGET/admin/action" -H "Referer: https://evil.com#target.com"
```
**Reference:** See `payloads/referer_bypass.txt`

### 5. Directory Listing (CWE-548)
Enumerate directory contents when index file is missing.

**Test Pattern:** Access directories directly to check for directory listing
**Expected:** 403 Forbidden or index page | **Actual if vulnerable:** Directory listing with file names
**CLI Test:**
```bash
curl "$TARGET/uploads/"
curl "$TARGET/backup/"
curl "$TARGET/admin/"
curl "$TARGET/assets/"
curl "$TARGET/static/"
```

### 6. Backup File Exposure (CWE-530)
Access backup copies of sensitive files that may contain credentials or source code.

**Test Pattern:** Append backup extensions to known file paths
**Expected:** 404 Not Found | **Actual if vulnerable:** 200 OK with backup file contents
**CLI Test:**
```bash
curl "$TARGET/config.php.bak"
curl "$TARGET/wp-config.php~"
curl "$TARGET/database.sql.gz"
curl "$TARGET/.env.backup"
curl "$TARGET/web.config.old"
```
**Reference:** See `payloads/backup_extensions.txt`

### 7. Hardcoded Credentials (CWE-798)
Find hardcoded credentials in responses, comments, or JavaScript files.

**Test Pattern:** Search responses for credential patterns
**Expected:** No credentials exposed | **Actual if vulnerable:** Passwords, API keys, or tokens visible
**Search Patterns:**
```
password|api_key|apikey|secret|token|private_key|access_key|credentials|
aws_secret|jwt_secret|encryption_key|db_password|admin_password
```
**CLI Test:**
```bash
# Search in JavaScript files
curl -s "$TARGET/static/js/app.js" | grep -iE "password|api_key|secret|token"

# Search in HTML comments
curl -s "$TARGET/" | grep -o '<!--.*-->' | grep -iE "password|secret|todo|fixme"

# Check debug endpoints
curl "$TARGET/api/debug/config"
curl "$TARGET/api/admin/config"
```

### 8. Browser History Weakness (CWE-525)
Sensitive information stored in browser history via GET parameters or URLs.

**Test Pattern:** Check if sensitive data appears in URLs (GET params instead of POST body)
**Expected:** Sensitive data in POST body | **Actual if vulnerable:** Sensitive data in GET parameters
**Vulnerable Patterns:**
```
GET /login?username=admin&password=secret123
GET /api/transfer?amount=1000&account=1234567890
GET /search?ssn=123-45-6789
GET /reset?token=abc123&newpassword=secret
```
**CLI Test:**
```bash
# Check login form method
curl -s "$TARGET/login" | grep -i "method="

# Check if sensitive forms use GET
curl -s "$TARGET/" | grep -iE '<form.*method="get"' | grep -iE 'password|credit|ssn'
```
**Mitigation Check:**
- Verify sensitive operations use POST/PUT methods
- Check for `Cache-Control: must-revalidate` header on sensitive pages

### 9. Browser Cache Weakness (CWE-525)
Sensitive data leakage through browser cache or improper cache headers.

**Test Pattern:** Check cache control headers on sensitive pages
**Expected:** `Cache-Control: no-cache, no-store` | **Actual if vulnerable:** Missing or permissive cache headers
**CLI Test:**
```bash
# Check cache headers on sensitive endpoints
curl -I "$TARGET/api/user/profile" -H "Cookie: $SESSION" | grep -iE "cache-control|pragma|expires"
curl -I "$TARGET/api/account/balance" -H "Cookie: $SESSION" | grep -iE "cache-control"
curl -I "$TARGET/dashboard" -H "Cookie: $SESSION" | grep -iE "cache-control"
```
**Secure Headers Expected:**
```
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```
**Vulnerable Response:**
```
Cache-Control: max-age=3600  # Cached for 1 hour!
# or no Cache-Control header at all
```

### 10. Developer Comments (CWE-615)
Sensitive information exposed in HTML/JavaScript comments.

**Test Pattern:** Search for comments containing sensitive data or TODOs
**Expected:** No sensitive comments | **Actual if vulnerable:** Credentials, TODOs, or internal info in comments
**CLI Test:**
```bash
# Extract HTML comments
curl -s "$TARGET/" | grep -oE '<!--.*?-->'

# Search JavaScript for comments
curl -s "$TARGET/static/js/app.js" | grep -E '//.*|/\*.*\*/'

# Look for sensitive patterns
curl -s "$TARGET/" | grep -iE 'TODO|FIXME|HACK|XXX|password|secret|admin'
```
**Patterns to Find:**
- `<!-- TODO: Remove hardcoded password -->`
- `// FIXME: Disable auth bypass before production`
- `/* Admin credentials: admin/admin123 */`
- `<!-- Debug: user_id=1, role=admin -->`

### 11. Broken Links (CWE-1108)
External links that could be hijacked to serve malicious content.

**Test Pattern:** Find broken external links that attackers could register
**Expected:** All links resolve correctly | **Actual if vulnerable:** Dead links to unregistered domains
**CLI Test:**
```bash
# Extract all links from page
curl -s "$TARGET/" | grep -oE 'href="https?://[^"]+' | cut -d'"' -f2 > links.txt

# Check each link (simplified)
while read url; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
  if [ "$status" = "000" ] || [ "$status" = "404" ]; then
    echo "BROKEN: $url ($status)"
  fi
done < links.txt
```
**Risk:** Attackers can register expired/available domains linked from your site to serve malicious content.

## Prerequisites
- Target application running and reachable
- Test accounts for authenticated testing (CSRF, CORS with credentials)
- VULNERABILITIES.json with suspected cross-site or disclosure vulnerabilities

## Testing Methodology

### Phase 1: Identify Test Scenarios

Map vulnerabilities to test types:

| CWE | Vulnerability | Test Type | Auth Required |
|-----|---------------|-----------|---------------|
| CWE-352 | CSRF on `/api/password/change` | Token validation | Yes |
| CWE-330 | Weak CSRF tokens | Entropy analysis | Yes |
| CWE-942 | CORS on `/api/user` | Origin reflection | Yes |
| CWE-293 | Referer bypass on `/admin/action` | Header manipulation | Optional |
| CWE-548 | Directory listing on `/uploads/` | Direct access | No |
| CWE-530 | Backup files | Extension fuzzing | No |
| CWE-798 | Hardcoded credentials | Pattern search | No |
| CWE-525 | Browser cache/history | Header inspection | Yes |
| CWE-615 | Developer comments | Comment extraction | No |
| CWE-1108 | Broken links | Link validation | No |

### Phase 2: Execute Tests

**CSRF Test:**
```python
# Test without token
response = requests.post(f"{target}/api/action",
    cookies=session_cookies,
    json={"action": "dangerous"})

if response.status_code == 200:
    return "VALIDATED"  # CSRF protection missing!
elif response.status_code in [401, 403]:
    return "FALSE_POSITIVE"  # CSRF protection working
```

**CORS Test:**
```python
response = requests.get(f"{target}/api/sensitive",
    headers={"Origin": "https://evil.com"},
    cookies=session_cookies)

cors_origin = response.headers.get("Access-Control-Allow-Origin")
cors_creds = response.headers.get("Access-Control-Allow-Credentials")

if cors_origin == "https://evil.com" and cors_creds == "true":
    return "VALIDATED"  # CORS misconfiguration!
```

**Cache Header Test:**
```python
response = requests.get(f"{target}/api/user/profile",
    cookies=session_cookies)

cache_control = response.headers.get("Cache-Control", "")

if "no-store" not in cache_control and "no-cache" not in cache_control:
    return "VALIDATED"  # Missing cache protection!
```

### Phase 3: Capture Evidence

```json
{
  "status": "VALIDATED|FALSE_POSITIVE|UNVALIDATED",
  "test": {
    "url": "http://target.com/api/user",
    "method": "GET",
    "headers": {"Origin": "https://evil.com"},
    "status": 200,
    "response_headers": {
      "Access-Control-Allow-Origin": "https://evil.com",
      "Access-Control-Allow-Credentials": "true"
    }
  },
  "evidence": "CORS reflects arbitrary origin with credentials enabled"
}
```

### Phase 4: Classification Logic

```python
# CSRF Classification
if response.status_code == 200 and action_performed:
    return "VALIDATED"  # CSRF bypass!
elif response.status_code in [401, 403]:
    return "FALSE_POSITIVE"  # Protection working

# CORS Classification
if origin_reflected and credentials_allowed:
    return "VALIDATED"  # CORS misconfiguration!
elif not origin_reflected or origin_in_whitelist:
    return "FALSE_POSITIVE"  # CORS properly configured

# Cache Classification
if sensitive_endpoint and no_cache_headers:
    return "VALIDATED"  # Cache weakness!
elif proper_cache_headers:
    return "FALSE_POSITIVE"  # Cache controls present
```

## Output Guidelines

**CRITICAL: Keep responses concise (1-4 sentences)**

**Format for VALIDATED:**
```
[Vulnerability type] on [endpoint] - [specific finding]. [Impact]. Evidence: [file_path]
```

**Examples:**

**CSRF:**
```
CSRF vulnerability on /api/password/change - request accepted without token (200 OK). Account takeover risk.
```

**CORS:**
```
CORS misconfiguration on /api/user - reflects evil.com origin with credentials enabled. Cross-origin data theft possible.
```

**Cache:**
```
Browser cache weakness on /api/account/balance - missing Cache-Control headers. Sensitive data may persist in browser cache.
```

**Backup Exposure:**
```
Backup file exposed at /config.php.bak - contains database credentials in plaintext. Full database access possible.
```

## CWE Mapping

This skill validates:
- **CWE-352:** Cross-Site Request Forgery (CSRF)
- **CWE-330:** Use of Insufficiently Random Values (Weak CSRF Tokens)
- **CWE-942:** Permissive Cross-domain Policy with Untrusted Domains (CORS)
- **CWE-293:** Using Referer Field for Authentication
- **CWE-548:** Exposure of Information Through Directory Listing
- **CWE-530:** Exposure of Backup File to an Unauthorized Control Sphere
- **CWE-798:** Use of Hard-coded Credentials
- **CWE-525:** Use of Web Browser Cache Containing Sensitive Information
- **CWE-615:** Inclusion of Sensitive Information in Source Code Comments
- **CWE-1108:** Excessive Reliance on Unconditional External Links

## Safety Rules

**Skill Responsibilities:**
- ONLY test against --target-url provided by user
- STOP immediately if unexpected damage occurs
- NO exfiltration of real user data (capture evidence, not actual credentials)
- Redact sensitive data from all evidence
- Log all test actions (optional: `.securevibes/dast_audit.log`)

**Scanner Responsibilities (handled at infrastructure level):**
- Production URL detection
- User confirmation prompts
- Target reachability checks
- `--allow-production` flag requirement

## Error Handling
- Target unreachable → Mark all UNVALIDATED
- Authentication fails → Test only unauthenticated endpoints
- Timeout exceeded → UNVALIDATED with timeout reason
- Unexpected error → Log error, continue with next vulnerability

## Examples

For comprehensive vulnerability-specific examples with code and evidence, see `examples.md`:
- **CSRF**: Token bypass, Content-Type manipulation, PoC generation
- **CORS Misconfiguration**: Origin reflection, null origin bypass, credential mode
- **Cache Weakness**: Missing headers, sensitive data caching
- **Backup Exposure**: Extension fuzzing, credential extraction
- **Hardcoded Credentials**: Comment mining, debug endpoint discovery

## Reference Implementations

See `reference/` directory for implementation examples:
- **`cors_testing.py`**: CORS misconfiguration detection and PoC generation
- **`csrf_testing.py`**: CSRF token validation testing and bypass techniques
- **`README.md`**: Usage guidance and adaptation notes

## Payload Files

See `payloads/` directory for test wordlists:
- **`cors_origins.txt`**: CORS origin bypass test values
- **`csrf_tokens.txt`**: CSRF token bypass values
- **`referer_bypass.txt`**: Referer header manipulation payloads
- **`backup_extensions.txt`**: Backup file extension wordlist

### Additional Resources

- [Agent Skills Guide](../../../docs/references/AGENT_SKILLS_GUIDE.md) - Comprehensive skill development guide
- [DAST Guide](../../../docs/DAST_GUIDE.md) - DAST validation workflow
