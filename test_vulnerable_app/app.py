#!/usr/bin/env python3
"""
Comprehensive vulnerable Flask application for testing DAST authorization-testing
and access-testing skills.

Vulnerabilities included:
1. IDOR (CWE-639) - /api/users/<id>, /api/documents/<id>
2. Vertical Privilege Escalation (CWE-269) - /api/admin/users, /update_role
3. Missing Authorization (CWE-862) - /api/admin/config
4. Forced Browsing (CWE-425) - /admin/dashboard, /admin/settings
5. Mass Assignment (CWE-915) - /api/register, /api/users/<id>/update
6. CSRF (CWE-352) - /api/password/change, /api/transfer
7. CORS Misconfiguration (CWE-942) - Reflects any Origin header
8. 403 Bypass - /restricted with various bypass techniques
9. Directory Listing (CWE-548) - /uploads/
10. Backup File Exposure (CWE-530) - /config.php.bak
11. Hardcoded Credentials (CWE-798) - API key in response
12. Referer-based Access Control (CWE-293) - /admin/action

Authentication:
- POST /login - Login with username/password, returns session cookie
- GET /login - Login page with HTML form
- POST /logout - Invalidate session
- Two roles: admin, user
"""

from flask import Flask, jsonify, request, make_response, send_from_directory, abort, redirect, url_for
import os
import hashlib
import secrets
import time

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # For session management

# ============================================
# SIMULATED DATABASE
# ============================================

USERS = {
    "1": {"id": "1", "username": "alice", "name": "Alice", "email": "alice@example.com",
          "role": "user", "ssn": "123-45-6789", "password": "alice123"},
    "2": {"id": "2", "username": "bob", "name": "Bob", "email": "bob@example.com",
          "role": "user", "ssn": "987-65-4321", "password": "bob456"},
    "3": {"id": "3", "username": "admin", "name": "Admin", "email": "admin@example.com",
          "role": "admin", "ssn": "111-22-3333", "password": "admin789"},
}

DOCUMENTS = {
    "doc-001": {"id": "doc-001", "title": "Alice's Secret Doc", "owner_id": "1",
                "content": "Alice's confidential information"},
    "doc-002": {"id": "doc-002", "title": "Bob's Private Doc", "owner_id": "2",
                "content": "Bob's private data"},
    "doc-003": {"id": "doc-003", "title": "Admin Report", "owner_id": "3",
                "content": "Admin confidential report"},
}

# Dynamic sessions - populated on login
SESSIONS = {}

# Pre-seeded sessions for backward compatibility (can be removed for strict testing)
SESSIONS_PRESET = {
    "alice_session": {"user_id": "1", "role": "user", "username": "alice"},
    "bob_session": {"user_id": "2", "role": "user", "username": "bob"},
    "admin_session": {"user_id": "3", "role": "admin", "username": "admin"},
}

TRANSFERS = []

# Hardcoded API key (CWE-798)
API_KEY = "sk_live_51234567890abcdefghijklmnop"
DB_PASSWORD = "super_secret_db_password_123"

# ============================================
# HELPER FUNCTIONS
# ============================================

def get_current_user():
    """Get current user from session cookie"""
    session_id = request.cookies.get('session')
    if session_id:
        # Check dynamic sessions first, then preset sessions
        session = SESSIONS.get(session_id) or SESSIONS_PRESET.get(session_id)
        if session:
            user_id = session["user_id"]
            return USERS.get(user_id)
    return None

def get_current_session():
    """Get current session"""
    session_id = request.cookies.get('session')
    return SESSIONS.get(session_id) or SESSIONS_PRESET.get(session_id)

def find_user_by_username(username):
    """Find user by username"""
    for user_id, user in USERS.items():
        if user['username'] == username:
            return user
    return None

def add_cors_headers(response):
    """Add CORS headers - VULNERABLE: reflects any origin"""
    origin = request.headers.get('Origin')
    if origin:
        # VULNERABLE (CWE-942): Reflects ANY origin with credentials
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-CSRF-Token'
    return response

@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    return add_cors_headers(response)

# ============================================
# HOME & HEALTH ENDPOINTS
# ============================================

@app.route('/')
def index():
    """Home page with API documentation"""
    return jsonify({
        "message": "Vulnerable Test API - Authorization & Access Testing Lab",
        "version": "3.0",
        "authentication": {
            "login_page": "GET /login",
            "login_api": "POST /login (JSON: username, password)",
            "logout": "POST /logout",
            "status": "GET /api/auth/status",
            "test_accounts": {
                "alice (user)": {"username": "alice", "password": "alice123"},
                "bob (user)": {"username": "bob", "password": "bob456"},
                "admin": {"username": "admin", "password": "admin789"}
            },
            "legacy_sessions": {
                "alice": "Cookie: session=alice_session",
                "bob": "Cookie: session=bob_session",
                "admin": "Cookie: session=admin_session"
            }
        },
        "vulnerabilities": [
            "IDOR", "Vertical Privilege Escalation", "Missing Authorization",
            "Forced Browsing", "Mass Assignment", "CSRF", "CORS Misconfiguration",
            "403 Bypass", "Directory Listing", "Backup File Exposure",
            "Hardcoded Credentials", "Referer-based Access Control"
        ],
        "endpoints": {
            "IDOR": ["GET /api/users/<id>", "GET /api/documents/<id>"],
            "Vertical Escalation": ["GET /api/admin/users", "POST /update_role"],
            "Missing Auth": ["GET /api/admin/config"],
            "Forced Browsing": ["GET /admin/dashboard", "GET /admin/settings"],
            "Mass Assignment": ["POST /api/register", "PUT /api/users/<id>/update"],
            "CSRF": ["POST /api/password/change", "POST /api/transfer"],
            "CORS": ["Any endpoint with Origin header"],
            "403 Bypass": ["GET /restricted"],
            "Directory Listing": ["GET /uploads/"],
            "Backup Exposure": ["GET /config.php.bak"],
            "Hardcoded Creds": ["GET /api/debug/config"],
            "Referer Bypass": ["GET /admin/action"]
        }
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "version": "2.0"})

# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

@app.route('/login', methods=['GET'])
def login_page():
    """Login page with HTML form"""
    return '''<!DOCTYPE html>
<html>
<head>
    <title>Login - Vulnerable Test App</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; margin-bottom: 15px; }
        .info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 20px; }
        .info h4 { margin-top: 0; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h2>Login</h2>
    <form method="POST" action="/login">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit">Login</button>
    </form>
    <div class="info">
        <h4>Test Accounts:</h4>
        <p><strong>User:</strong> <code>alice</code> / <code>alice123</code></p>
        <p><strong>User:</strong> <code>bob</code> / <code>bob456</code></p>
        <p><strong>Admin:</strong> <code>admin</code> / <code>admin789</code></p>
    </div>
</body>
</html>''', 200, {'Content-Type': 'text/html'}

@app.route('/login', methods=['POST'])
def login():
    """
    Login endpoint - authenticates user and creates session.
    Accepts form data or JSON.
    """
    # Get credentials from form or JSON
    if request.is_json:
        data = request.json or {}
        username = data.get('username', '')
        password = data.get('password', '')
    else:
        username = request.form.get('username', '')
        password = request.form.get('password', '')

    if not username or not password:
        if request.is_json:
            return jsonify({"error": "Username and password required"}), 400
        return '''<html><body><h2>Error</h2><p>Username and password required</p>
            <a href="/login">Back to login</a></body></html>''', 400, {'Content-Type': 'text/html'}

    # Find user by username
    user = find_user_by_username(username)

    if not user or user['password'] != password:
        if request.is_json:
            return jsonify({"error": "Invalid credentials"}), 401
        return '''<html><body><h2>Error</h2><p>Invalid username or password</p>
            <a href="/login">Back to login</a></body></html>''', 401, {'Content-Type': 'text/html'}

    # Create session token
    session_token = secrets.token_hex(32)
    SESSIONS[session_token] = {
        "user_id": user['id'],
        "role": user['role'],
        "username": user['username'],
        "created_at": time.time()
    }

    # Create response with session cookie
    if request.is_json:
        response = make_response(jsonify({
            "success": True,
            "message": "Login successful",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "role": user['role']
            },
            "session_token": session_token
        }))
    else:
        response = make_response(redirect('/'))

    # Set session cookie
    response.set_cookie('session', session_token, httponly=True, samesite='Lax')
    return response

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    """Logout endpoint - invalidates session"""
    session_id = request.cookies.get('session')

    # Remove session if exists
    if session_id and session_id in SESSIONS:
        del SESSIONS[session_id]

    if request.is_json or request.method == 'POST':
        response = make_response(jsonify({"success": True, "message": "Logged out"}))
    else:
        response = make_response(redirect('/login'))

    # Clear session cookie
    response.set_cookie('session', '', expires=0)
    return response

@app.route('/api/auth/status')
def auth_status():
    """Check current authentication status"""
    current_user = get_current_user()
    if current_user:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": current_user['id'],
                "username": current_user['username'],
                "role": current_user['role']
            }
        })
    return jsonify({"authenticated": False}), 401

# ============================================
# 1. IDOR VULNERABILITIES (CWE-639)
# ============================================

@app.route('/api/users/<user_id>')
def get_user(user_id):
    """
    VULNERABLE (CWE-639): IDOR - No authorization check.
    Any authenticated user can access any other user's data.
    """
    user = USERS.get(user_id)
    if user:
        # Return user data without checking if requester is authorized
        return jsonify({k: v for k, v in user.items() if k != 'password'})
    return jsonify({"error": "User not found"}), 404

@app.route('/api/documents/<doc_id>')
def get_document(doc_id):
    """
    VULNERABLE (CWE-639): IDOR - No ownership check.
    Any user can access any document by ID.
    """
    doc = DOCUMENTS.get(doc_id)
    if doc:
        return jsonify(doc)
    return jsonify({"error": "Document not found"}), 404

@app.route('/api/documents/<doc_id>', methods=['PUT'])
def update_document(doc_id):
    """
    SECURE for comparison: Checks ownership before allowing update.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    # Ownership check
    if doc['owner_id'] != current_user['id']:
        return jsonify({"error": "Not authorized to modify this document"}), 403

    # Update document
    data = request.json or {}
    if 'title' in data:
        doc['title'] = data['title']
    if 'content' in data:
        doc['content'] = data['content']

    return jsonify({"success": True, "document": doc})

@app.route('/api/documents/<doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    """
    SECURE for comparison: Checks ownership before allowing delete.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404

    if doc['owner_id'] != current_user['id']:
        return jsonify({"error": "Not authorized to delete this document"}), 403

    return jsonify({"success": True, "message": "Document deleted"})

# ============================================
# 2. VERTICAL PRIVILEGE ESCALATION (CWE-269)
# ============================================

@app.route('/api/admin/users')
def admin_list_users():
    """
    VULNERABLE (CWE-269): No admin check - any authenticated user can access.
    Should only be accessible by admins.
    """
    # VULNERABLE: Only checks authentication, not authorization (admin role)
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    # Missing: if current_user['role'] != 'admin': return 403
    return jsonify({"users": list(USERS.values())})

@app.route('/update_role', methods=['POST'])
def update_role():
    """
    VULNERABLE (CWE-269): Allows any user to change any user's role.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    data = request.json or {}
    user_id = data.get('user_id')
    new_role = data.get('role')

    if not user_id or not new_role:
        return jsonify({"error": "user_id and role required"}), 400

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULNERABLE: No check if requester has permission to change roles
    user['role'] = new_role
    return jsonify({"success": True, "user": {k: v for k, v in user.items() if k != 'password'}})

# ============================================
# 3. MISSING AUTHORIZATION (CWE-862)
# ============================================

@app.route('/api/admin/config')
def admin_config():
    """
    VULNERABLE (CWE-862): No authentication or authorization at all.
    Exposes sensitive configuration including API keys.
    """
    # VULNERABLE: No authentication check whatsoever
    return jsonify({
        "database": {
            "host": "db.internal.example.com",
            "port": 5432,
            "password": DB_PASSWORD  # CWE-798: Hardcoded credential
        },
        "api_key": API_KEY,  # CWE-798: Hardcoded credential
        "debug_mode": True,
        "secret_key": "flask_secret_key_12345"
    })

# ============================================
# 4. FORCED BROWSING (CWE-425)
# ============================================

@app.route('/admin/dashboard')
def admin_dashboard():
    """
    VULNERABLE (CWE-425): Direct URL access without authorization.
    Relies on UI hiding the link, not server-side check.
    """
    # VULNERABLE: No authorization check
    return jsonify({
        "dashboard": "Admin Dashboard",
        "stats": {
            "total_users": len(USERS),
            "total_documents": len(DOCUMENTS),
            "active_sessions": len(SESSIONS)
        },
        "recent_activity": [
            {"action": "user_login", "user": "alice", "timestamp": "2024-01-15T10:30:00Z"},
            {"action": "document_created", "user": "bob", "timestamp": "2024-01-15T09:15:00Z"}
        ]
    })

@app.route('/admin/settings')
def admin_settings():
    """
    VULNERABLE (CWE-425): Direct URL access to admin settings.
    """
    return jsonify({
        "settings": {
            "smtp_server": "smtp.internal.example.com",
            "smtp_password": "smtp_password_123",
            "backup_location": "/var/backups/app/",
            "log_level": "DEBUG"
        }
    })

# ============================================
# 5. MASS ASSIGNMENT (CWE-915)
# ============================================

@app.route('/api/register', methods=['POST'])
def register():
    """
    VULNERABLE (CWE-915): Mass assignment - accepts role parameter.
    Attacker can register as admin by including role in request.
    """
    data = request.json or {}

    # VULNERABLE: Directly uses all input data including 'role'
    new_id = str(len(USERS) + 1)
    new_user = {
        "id": new_id,
        "username": data.get("username", ""),
        "name": data.get("name", ""),
        "email": data.get("email", ""),
        "password": data.get("password", ""),
        "role": data.get("role", "user"),  # VULNERABLE: Should not accept from input
        "ssn": data.get("ssn", ""),
    }

    # Add any extra fields from input (mass assignment)
    for key, value in data.items():
        if key not in new_user:
            new_user[key] = value

    USERS[new_id] = new_user

    return jsonify({
        "success": True,
        "user": {k: v for k, v in new_user.items() if k != 'password'}
    }), 201

@app.route('/api/users/<user_id>/update', methods=['PUT'])
def update_user(user_id):
    """
    VULNERABLE (CWE-915): Mass assignment on update.
    User can escalate privileges by including role in update.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.json or {}

    # VULNERABLE: Updates any field provided, including 'role'
    for key, value in data.items():
        if key != 'id':  # Don't allow changing ID
            user[key] = value

    return jsonify({
        "success": True,
        "user": {k: v for k, v in user.items() if k != 'password'}
    })

# ============================================
# 6. CSRF (CWE-352)
# ============================================

@app.route('/api/password/change', methods=['POST'])
def change_password():
    """
    VULNERABLE (CWE-352): No CSRF token validation.
    Attacker can change victim's password via malicious page.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    data = request.json or {}
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({"error": "new_password required"}), 400

    # VULNERABLE: No CSRF token validation
    current_user['password'] = new_password
    return jsonify({"success": True, "message": "Password changed"})

@app.route('/api/transfer', methods=['POST'])
def transfer_funds():
    """
    VULNERABLE (CWE-352): No CSRF protection on sensitive action.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    # Check for CSRF token but accept empty value (BUG)
    csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')

    # VULNERABLE: Accepts if token is present (even if empty)
    if csrf_token is None:
        # Still processes without token - vulnerable!
        pass

    data = request.json or {}
    to_account = data.get('to_account')
    amount = data.get('amount')

    if not to_account or not amount:
        return jsonify({"error": "to_account and amount required"}), 400

    transfer = {
        "id": f"txn_{len(TRANSFERS) + 1}",
        "from_user": current_user['id'],
        "to_account": to_account,
        "amount": amount
    }
    TRANSFERS.append(transfer)

    return jsonify({"success": True, "transfer_id": transfer['id']})

# ============================================
# 7. CORS MISCONFIGURATION (CWE-942)
# ============================================
# Handled in after_request decorator above

@app.route('/api/user/profile')
def user_profile():
    """
    Endpoint to test CORS - returns user profile.
    VULNERABLE: CORS headers reflect any origin with credentials.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    return jsonify({
        "profile": {k: v for k, v in current_user.items() if k != 'password'},
        "sensitive_data": "This is sensitive user data"
    })

@app.route('/api/sensitive/data')
def sensitive_data():
    """
    Another endpoint for CORS testing with null origin.
    """
    return jsonify({
        "data": "Sensitive information",
        "api_secret": "secret_12345"
    })

# ============================================
# 8. 403 BYPASS TECHNIQUES
# ============================================

@app.route('/restricted')
def restricted_direct():
    """
    VULNERABLE: 403 but can be bypassed.
    Returns 403 for direct access but allows various bypass techniques.
    """
    # Check for bypass techniques
    x_original_url = request.headers.get('X-Original-URL')
    x_rewrite_url = request.headers.get('X-Rewrite-URL')
    x_forwarded_for = request.headers.get('X-Forwarded-For')

    # VULNERABLE: Trusts X-Original-URL header
    if x_original_url == '/restricted' or x_rewrite_url == '/restricted':
        return jsonify({"data": "Restricted data accessed via header bypass!"})

    # VULNERABLE: IP-based bypass
    if x_forwarded_for and ('127.0.0.1' in x_forwarded_for or 'localhost' in x_forwarded_for):
        return jsonify({"data": "Restricted data accessed via IP bypass!"})

    # Check for method override
    method_override = request.headers.get('X-HTTP-Method-Override') or \
                      request.headers.get('X-Method-Override') or \
                      request.headers.get('X-HTTP-Method')

    if request.method == 'POST' and method_override == 'GET':
        return jsonify({"data": "Restricted data accessed via method override!"})

    # Default: return 403
    return jsonify({"error": "Forbidden"}), 403

@app.route('/restricted', methods=['POST'])
def restricted_post():
    """Handle POST to restricted for method override testing"""
    return restricted_direct()

# Path-based bypass endpoints
@app.route('/%2e/restricted')
@app.route('/./restricted')
@app.route('//restricted')
@app.route('/restricted/')
@app.route('/restricted/..')
@app.route('/RESTRICTED')
def restricted_bypass():
    """
    VULNERABLE: Path manipulation bypasses return 200.
    """
    return jsonify({"data": "Restricted data accessed via path bypass!"})

# ============================================
# 9. DIRECTORY LISTING (CWE-548)
# ============================================

@app.route('/uploads/')
@app.route('/uploads')
def uploads_listing():
    """
    VULNERABLE (CWE-548): Returns directory listing.
    """
    return jsonify({
        "directory": "/uploads/",
        "files": [
            {"name": "report_2024.pdf", "size": "2.4MB"},
            {"name": "backup_db.sql", "size": "15MB"},
            {"name": "users_export.csv", "size": "500KB"},
            {"name": "config_backup.tar.gz", "size": "1.2MB"},
            {"name": ".env.backup", "size": "2KB"}
        ]
    })

@app.route('/backup/')
def backup_listing():
    """Another directory listing vulnerability"""
    return jsonify({
        "directory": "/backup/",
        "files": [
            {"name": "db_dump_20240115.sql", "size": "50MB"},
            {"name": "app_backup.zip", "size": "100MB"}
        ]
    })

# ============================================
# 10. BACKUP FILE EXPOSURE (CWE-530)
# ============================================

@app.route('/config.php.bak')
@app.route('/config.php~')
@app.route('/config.php.old')
def backup_config():
    """
    VULNERABLE (CWE-530): Backup file accessible.
    """
    return """<?php
// Database configuration - BACKUP FILE
$db_host = 'localhost';
$db_user = 'root';
$db_pass = 'super_secret_password_123';
$db_name = 'production_db';

// API Keys
$api_key = 'sk_live_abcdef123456';
$stripe_secret = 'sk_test_51234567890';
?>
""", 200, {'Content-Type': 'text/plain'}

@app.route('/wp-config.php.bak')
def wp_config_backup():
    """Another backup file vulnerability"""
    return """<?php
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'wordpress_db_pass_123');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'put your unique phrase here');
?>
""", 200, {'Content-Type': 'text/plain'}

# ============================================
# 11. HARDCODED CREDENTIALS (CWE-798)
# ============================================

@app.route('/api/debug/config')
def debug_config():
    """
    VULNERABLE (CWE-798): Exposes hardcoded credentials in response.
    """
    return jsonify({
        "debug": True,
        "database_url": f"postgresql://admin:{DB_PASSWORD}@db.example.com/prod",
        "api_key": API_KEY,
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "jwt_secret": "my-256-bit-secret",
        "encryption_key": "aes_encryption_key_12345"
    })

@app.route('/api/debug/info')
def debug_info():
    """Another endpoint exposing secrets"""
    return f"""
    <!-- Debug info -->
    <!-- API_KEY: {API_KEY} -->
    <!-- DB_PASS: {DB_PASSWORD} -->
    <!-- Admin password: admin789 -->
    <html><body>Debug mode enabled</body></html>
    """, 200, {'Content-Type': 'text/html'}

# ============================================
# 12. REFERER-BASED ACCESS CONTROL (CWE-293)
# ============================================

@app.route('/admin/action')
def admin_action():
    """
    VULNERABLE (CWE-293): Uses Referer header for access control.
    """
    referer = request.headers.get('Referer', '')

    # VULNERABLE: Weak Referer validation
    if 'admin' in referer.lower() or 'localhost' in referer or '127.0.0.1' in referer:
        return jsonify({
            "action": "admin_action_performed",
            "result": "Success - action completed"
        })

    # Also vulnerable to various bypass patterns
    if any(bypass in referer for bypass in ['.example.com', 'example.com']):
        return jsonify({
            "action": "admin_action_performed",
            "result": "Success via domain bypass"
        })

    return jsonify({"error": "Access denied - invalid referer"}), 403

# ============================================
# SECURE ENDPOINTS FOR COMPARISON
# ============================================

@app.route('/api/secure/profile')
def secure_profile():
    """
    SECURE: Proper authorization - only returns current user's data.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    return jsonify({
        "profile": {k: v for k, v in current_user.items() if k not in ['password', 'ssn']}
    })

@app.route('/api/secure/admin/users')
def secure_admin_users():
    """
    SECURE: Proper admin check before returning user list.
    """
    current_user = get_current_user()
    if not current_user:
        return jsonify({"error": "Authentication required"}), 401

    if current_user['role'] != 'admin':
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({"users": list(USERS.values())})

# ============================================
# MAIN
# ============================================

if __name__ == '__main__':
    print("=" * 60)
    print("VULNERABLE TEST APPLICATION - Authorization & Access Testing")
    print("=" * 60)
    print("\nAuthentication:")
    print("  - Login Page: GET /login")
    print("  - Login API:  POST /login (JSON: username, password)")
    print("  - Logout:     POST /logout")
    print("  - Status:     GET /api/auth/status")
    print("\nTest Accounts:")
    print("  - alice / alice123 (user role)")
    print("  - bob / bob456     (user role)")
    print("  - admin / admin789 (admin role)")
    print("\nLegacy Sessions (backward compatible):")
    print("  - Alice (user):  session=alice_session")
    print("  - Bob (user):    session=bob_session")
    print("  - Admin:         session=admin_session")
    print("\nVulnerabilities:")
    print("  1. IDOR: GET /api/users/<id>, GET /api/documents/<id>")
    print("  2. Vertical Escalation: GET /api/admin/users, POST /update_role")
    print("  3. Missing Auth: GET /api/admin/config")
    print("  4. Forced Browsing: GET /admin/dashboard, /admin/settings")
    print("  5. Mass Assignment: POST /api/register, PUT /api/users/<id>/update")
    print("  6. CSRF: POST /api/password/change, POST /api/transfer")
    print("  7. CORS: Any endpoint with Origin header")
    print("  8. 403 Bypass: GET /restricted (with headers/path manipulation)")
    print("  9. Directory Listing: GET /uploads/")
    print("  10. Backup Exposure: GET /config.php.bak")
    print("  11. Hardcoded Creds: GET /api/debug/config")
    print("  12. Referer Bypass: GET /admin/action")
    print("\n" + "=" * 60)

    app.run(host='0.0.0.0', port=5001, debug=False)
