# Access Testing Reference Implementations

This directory contains reference implementations for cross-site attacks, session protection, and information disclosure testing.

## Scripts

### cors_testing.py
**Purpose:** Test for CORS misconfigurations

**Features:**
- Origin reflection detection
- Null origin bypass testing
- Subdomain/prefix/suffix bypass checks
- Credential mode analysis
- Automatic CORS header extraction
- PoC HTML generation

**Usage:**
```bash
python cors_testing.py --url "http://target.com/api/user" --cookie "session=abc123" --output cors_results.json
```

**CLI Options:**
- `--url`: Target URL to test
- `--cookie`: Session cookie for authenticated testing
- `--output`: Output file path (JSON)
- `--poc`: Generate HTML PoC file

### csrf_testing.py
**Purpose:** Test CSRF token validation

**Features:**
- CSRF token detection (headers, form fields, meta tags)
- No-token bypass testing
- Empty/null token bypass
- Invalid token value testing
- Content-Type manipulation bypass
- PoC HTML generation

**Usage:**
```bash
python csrf_testing.py --url "http://target.com/api/password/change" --method POST \
  --data '{"new_password":"test"}' --cookie "session=abc123" --output csrf_results.json
```

**CLI Options:**
- `--url`: Target URL to test
- `--method`: HTTP method (POST, PUT, DELETE)
- `--data`: Request body (JSON)
- `--cookie`: Session cookie
- `--output`: Output file path (JSON)
- `--poc`: Generate HTML PoC file

## Payload Files

Located in `../payloads/`:

| File | Count | Purpose |
|------|-------|---------|
| `cors_origins.txt` | 84 | CORS origin bypass test values |
| `csrf_tokens.txt` | Variable | CSRF token bypass values |
| `referer_bypass.txt` | 76 | Referer header manipulation payloads |
| `backup_extensions.txt` | 135 | Backup file extension wordlist |

## Adapting Reference Scripts

These scripts are templates - adapt them for your target:

1. **Authentication**: Modify cookie/header handling for your auth mechanism
2. **Endpoints**: Update URL patterns for your API structure
3. **Evidence Capture**: Adjust response parsing for your application
4. **Classification**: Tune success/failure detection for your context

## Example Workflow

```bash
# 1. Test CORS on sensitive endpoints
python cors_testing.py --url "http://target.com/api/user/profile" \
  --cookie "session=$SESSION" --output cors.json

# 2. Test CSRF on state-changing endpoints
python csrf_testing.py --url "http://target.com/api/password/change" \
  --method POST --data '{"new_password":"test123"}' \
  --cookie "session=$SESSION" --output csrf.json --poc

# 3. Check results
cat cors.json | jq '.status'
cat csrf.json | jq '.status'
```

## Integration with SecureVibes

These scripts are designed to be called by the DAST agent during validation. The agent will:

1. Read vulnerability from VULNERABILITIES.json
2. Identify matching skill (access-testing)
3. Adapt reference script for specific endpoint
4. Execute test and capture evidence
5. Write results to DAST_VALIDATION.json

## Safety Notes

- Only test against authorized targets
- Use test accounts, not production credentials
- Redact sensitive data in evidence
- Stop testing if unexpected errors occur
