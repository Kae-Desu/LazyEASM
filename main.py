import jwt
import datetime
import threading
import secrets
import time
import logging
import hashlib
import uuid
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env
from utils.env_manager import set_env_key, delete_env_key, get_env_key, get_config_for_ui, EDITABLE_KEYS, KEY_DEFAULTS
from utils.db_utils import get_all_assets_for_display, get_db_connection, set_vulnerability_status, set_finding_status, get_changes, VULN_STATUSES
from utils.parsing import parse_input
from utils.queue_manager import task_queue
from utils.pipeline import enqueue_input_discovery, enqueue_assets_for_phase1, enqueue_single_asset_for_phase1
from utils.asset_repository import AssetQueryError, get_asset_detail, list_assets
from modules.Notify import test_webhook, send_message as discord_send_message
from modules.AskAI import send_message
from utils import auth
from utils.scan_settings import get_schedule, get_cve_min_cvss

logger = logging.getLogger(__name__)

app = Flask(__name__)
flask_secret = get_env('FLASK_SECRET_KEY')
jwt_secret = get_env('JWT_SECRET')

if not flask_secret:
    flask_secret = secrets.token_hex(32)
    set_env_key('FLASK_SECRET_KEY', flask_secret)
if not jwt_secret:
    jwt_secret = secrets.token_hex(32)
    set_env_key('JWT_SECRET', jwt_secret)

app.secret_key = flask_secret
JWT_SECRET = jwt_secret


def env_flag(name: str) -> bool:
    return (get_env(name) or '').strip().lower() in ('1', 'true', 'yes', 'on')


# HTTPS is decided separately from debug mode. FORCE_HTTPS marks cookies Secure
# and sends HSTS even when TLS is terminated by a proxy we cannot see.
# FLASK_ENV=production keeps its old meaning (HTTPS-only) for existing installs.
FORCE_HTTPS = env_flag('FORCE_HTTPS') or get_env('FLASK_ENV', '') == 'production'

# Behind a reverse proxy, trust X-Forwarded-For/-Proto/-Host so request.is_secure
# and the client IP used for login rate limiting are correct.
if env_flag('TRUST_PROXY'):
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def is_https_request() -> bool:
    return FORCE_HTTPS or request.is_secure

SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https:; connect-src 'self'"
}


@app.after_request
def add_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    
    # Prevent caching authenticated pages (but allow static assets)
    if not request.path.startswith('/static') and request.path not in ['/login', '/health']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    if is_https_request():
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

KEY_NAMES = {
    'DISCORD_WEBHOOK_URL': 'Discord Webhook',
    'DISCORD_USER_ID': 'Discord User ID',
    'SECURITYTRAILS_API_KEY': 'SecurityTrails Key',
    'NVD_API_KEY': 'NVD API Key',
    'AI_PROVIDER': 'AI Provider',
    'AI_MODEL': 'AI Model',
    'AI_BASE_URL': 'AI Base URL',
    'GEMINI_API_KEY': 'Gemini Key',
    'OPENAI_API_KEY': 'OpenAI Key',
    'ANTHROPIC_API_KEY': 'Anthropic Key',
    'SLACK_WEBHOOK_URL': 'Slack Webhook',
    'NOTIFY_WEBHOOK_URL': 'Webhook URL',
    'NOTIFY_WEBHOOK_SECRET': 'Webhook Secret',
    'SMTP_HOST': 'SMTP Host',
    'SMTP_PORT': 'SMTP Port',
    'SMTP_SECURITY': 'SMTP Security',
    'SMTP_USERNAME': 'SMTP Username',
    'SMTP_PASSWORD': 'SMTP Password',
    'SMTP_FROM': 'SMTP From',
    'SMTP_TO': 'SMTP Recipients',
    'OTX_API_KEY': 'OTX Key',
    'DNS_BRUTEFORCE': 'DNS Brute Force'
}

ACCESS_TOKEN_LIFETIME = datetime.timedelta(minutes=15)
REFRESH_TOKEN_LIFETIME = datetime.timedelta(days=7)

login_attempts = {}
login_lock = threading.Lock()
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_DURATION = 60


def is_rate_limited(ip: str) -> tuple:
    blocked, attempts, remaining = False, 0, 0
    current_time = time.time()
    
    with login_lock:
        if ip in login_attempts:
            attempts = login_attempts[ip]['count']
            first_attempt = login_attempts[ip]['first_attempt']
            
            if attempts >= MAX_LOGIN_ATTEMPTS:
                elapsed = current_time - first_attempt
                if elapsed < LOGIN_BLOCK_DURATION:
                    blocked = True
                    remaining = int(LOGIN_BLOCK_DURATION - elapsed)
                else:
                    del login_attempts[ip]
    
    return blocked, attempts, remaining


def record_failed_login(ip: str, username: str):
    current_time = time.time()
    
    with login_lock:
        if ip not in login_attempts:
            login_attempts[ip] = {'count': 1, 'first_attempt': current_time}
        else:
            login_attempts[ip]['count'] += 1
    
    logger.warning(f"Failed login attempt - IP: {ip}, Username: {username}, Attempts: {login_attempts[ip]['count']}")


def reset_failed_login(ip: str):
    with login_lock:
        if ip in login_attempts:
            del login_attempts[ip]


def get_secure_cookie_kwargs():
    # Secure cookies are only sent back over HTTPS, so they are set whenever the
    # request arrived over HTTPS (or FORCE_HTTPS says TLS ends at a proxy)
    return {
        'httponly': True,
        'secure': is_https_request(),
        'samesite': 'Lax'
    }


def generate_csrf_token(session_token: str) -> str:
    if not session_token:
        return secrets.token_hex(16)
    return hashlib.sha256(f"{session_token}{flask_secret}".encode()).hexdigest()[:32]


def validate_csrf_token(session_token: str, provided_token: str) -> bool:
    if not session_token or not provided_token:
        return False
    expected_token = generate_csrf_token(session_token)
    return secrets.compare_digest(expected_token, provided_token)


def csrf_protected(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_token = request.cookies.get('access_token') or ''
        csrf_token = request.form.get('csrf_token') or (request.get_json(silent=True) or {}).get('csrf_token')
        
        if not csrf_token:
            return jsonify({'success': False, 'error': 'CSRF token required'}), 403
        
        if not validate_csrf_token(session_token, csrf_token):
            return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
        
        return f(*args, **kwargs)
    return decorated

assets_data = [
    {
        "id": 1,
        "name": "192.168.1.15",
        "type": "ip",
        "status": "Critical",
        "last_scanned": "12:39",
        "findings": [
            {"port": "102/TCP", "service": "S7Comm", "version": "Siemens S7-PLC"},
            {"port": "502/TCP", "service": "Modbus", "version": "Schneider Electric"}
        ],
        "cves": [
            {
                "id": "CVE-2023-35078",
                "cvss": "10.0",
                "title": "Remote Unauthenticated API Access",
                "ai_reco": "Isolasi port industri segera."
            },
            {
                "id": "CVE-2021-44228",
                "cvss": "10.0",
                "title": "Log4Shell Vulnerability",
                "ai_reco": "Update Java runtime dan patch library log4j ke versi terbaru."
            }
        ]
    },
    {
        "id": 2,
        "name": "internal.dev.local",
        "type": "hostname",
        "status": "Medium Risk",
        "last_scanned": "14:20",
        "directories": [
            {"path": "/admin", "status": "403", "size": "0B"},
            {"path": "/.env", "status": "200", "size": "1.2KB"}
        ],
        "cves": [
            {
                "id": "CVE-2023-35078, CVE-2023-35078, CVE-2023-35078",
                "cvss": "10.0",
                "title": "Remote Unauthenticated API Access",
                "ai_reco": "Isolasi port industri segera."
            }
        ]
    }
]


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            if payload.get('type') != 'access':
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Invalid token type'}), 401
                return redirect(url_for('login'))

            if not token_is_current(payload):
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Session revoked'}), 401
                flash("Session ended. Please login again.", "error")
                return redirect(url_for('login'))
            
        except jwt.ExpiredSignatureError:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Token expired'}), 401
            flash("Session expired. Please login again.", "error")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Invalid token'}), 401
            flash("Invalid session. Please login again.", "error")
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated


def issue_session(resp, user: str, token_version: int):
    """Set a new access + refresh token pair carrying the account's token version."""
    now = datetime.datetime.utcnow()
    for kind, lifetime in (('access', ACCESS_TOKEN_LIFETIME), ('refresh', REFRESH_TOKEN_LIFETIME)):
        token = jwt.encode({
            'user': user,
            'type': kind,
            'pv': token_version,
            'jti': str(uuid.uuid4()),
            'exp': now + lifetime
        }, JWT_SECRET, algorithm="HS256")
        resp.set_cookie(f'{kind}_token', token, **get_secure_cookie_kwargs())
    return resp


def token_is_current(payload: dict) -> bool:
    """False for tokens issued before the last password change or session revocation."""
    version = auth.current_token_version()
    return version is not None and payload.get('pv') == version


@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr or 'unknown'
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        blocked, attempts, remaining = is_rate_limited(client_ip)
        if blocked:
            flash(f"Terlalu banyak percobaan login. Coba lagi dalam {remaining} detik.", "error")
            return redirect(url_for('login'))
        
        if auth.get_admin() is None:
            flash("Password admin belum diatur. Tambahkan ADMIN_PASS=... di file .env lalu restart LazyEASM.", "error")
            return redirect(url_for('login'))
        
        admin = auth.verify_login(username, password)
        if admin:
            reset_failed_login(client_ip)
            resp = make_response(redirect(url_for('dashboard')))
            return issue_session(resp, admin['username'], admin['token_version'])
        
        record_failed_login(client_ip, username)
        flash("Username atau Password salah!", "error")
        return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    from utils.db_utils import blacklist_token
    
    refresh_token = request.cookies.get('refresh_token')
    
    if refresh_token:
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=["HS256"])
            if payload.get('type') == 'refresh':
                jti = payload.get('jti')
                user = payload.get('user')
                exp = payload.get('exp')
                expires_at = datetime.datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')
                blacklist_token(jti, user, expires_at)
        except:
            pass
    
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('access_token', '', expires=0, **get_secure_cookie_kwargs())
    resp.set_cookie('refresh_token', '', expires=0, **get_secure_cookie_kwargs())
    flash("Berhasil logout.", "success")
    return resp


@app.route('/refresh-token', methods=['POST'])
def refresh_token():
    """
    Exchange refresh token for new access + refresh tokens.
    
    Implements refresh token rotation:
    - Validates current refresh token
    - Checks blacklist (reuse detection)
    - Issues new token pair
    - Blacklists old refresh token
    """
    from utils.db_utils import blacklist_token, is_token_blacklisted, blacklist_all_user_tokens
    
    old_refresh = request.cookies.get('refresh_token')
    
    if not old_refresh:
        return jsonify({'success': False, 'error': 'No refresh token'}), 401
    
    try:
        payload = jwt.decode(old_refresh, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        resp = jsonify({'success': False, 'error': 'Refresh token expired'})
        resp = make_response(resp, 401)
        resp.set_cookie('access_token', '', expires=0, **get_secure_cookie_kwargs())
        resp.set_cookie('refresh_token', '', expires=0, **get_secure_cookie_kwargs())
        return resp
    except jwt.InvalidTokenError:
        return jsonify({'success': False, 'error': 'Invalid refresh token'}), 401
    
    if payload.get('type') != 'refresh':
        return jsonify({'success': False, 'error': 'Invalid token type'}), 401

    if not token_is_current(payload):
        resp = make_response(jsonify({'success': False, 'error': 'Session revoked'}), 401)
        resp.set_cookie('access_token', '', expires=0, **get_secure_cookie_kwargs())
        resp.set_cookie('refresh_token', '', expires=0, **get_secure_cookie_kwargs())
        return resp
    
    jti = payload.get('jti')
    user = payload.get('user')
    
    # Check if token is blacklisted (REUSE DETECTION)
    if is_token_blacklisted(jti):
        # Token was already used - possible theft
        # Revoke ALL tokens for this user
        blacklist_all_user_tokens(user)
        auth.revoke_all_sessions()
        logger.warning(f"Refresh token reuse detected for user: {user}; all sessions revoked")
        
        resp = jsonify({'success': False, 'error': 'Token reuse detected. Please login again.'})
        resp = make_response(resp, 401)
        resp.set_cookie('access_token', '', expires=0, **get_secure_cookie_kwargs())
        resp.set_cookie('refresh_token', '', expires=0, **get_secure_cookie_kwargs())
        return resp
    
    # Blacklist old refresh token
    exp = payload.get('exp')
    expires_at = datetime.datetime.fromtimestamp(exp).strftime('%Y-%m-%d %H:%M:%S')
    blacklist_token(jti, user, expires_at)
    
    # Generate new token pair
    return issue_session(jsonify({'success': True}), user, payload['pv'])


@app.route('/health')
def health():
    """
    Health check endpoint for Docker/monitoring.
    
    No auth required for localhost, auth required for external.
    
    Returns:
        {
            'status': 'healthy' | 'unhealthy',
            'checks': {
                'database': 'ok' | 'error: ...',
                'worker': 'ok' | 'error: ...',
                'phase0_worker' / 'discovery_worker' / 'phase1_worker' /
                'phase2_worker' / 'phase3_worker': 'ok' | 'error: ...',
                'phase1_queue': 'ok' | 'error: ...'
            }
        }
    """
    from flask import request
    from utils.worker_runtime import get_worker_status
    
    # Check if request is from localhost (no auth required)
    client_ip = request.remote_addr
    is_localhost = client_ip in ['127.0.0.1', '::1', 'localhost']
    
    # If not localhost, require auth (cookie only)
    if not is_localhost:
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({'status': 'unhealthy', 'error': 'Authentication required'}), 401
        
        try:
            if not token_is_current(jwt.decode(token, JWT_SECRET, algorithms=['HS256'])):
                return jsonify({'status': 'unhealthy', 'error': 'Session revoked'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 'unhealthy', 'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 'unhealthy', 'error': 'Invalid token'}), 401
    
    checks = {}
    all_healthy = True
    
    # 1. Database check
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {str(e)[:50]}'
        all_healthy = False
    
    # 2. Background worker (separate process): heartbeat freshness + components
    try:
        worker = get_worker_status()
        if not worker['alive']:
            age = worker['age_seconds']
            checks['worker'] = 'error: no heartbeat' if age is None else f'error: last heartbeat {age:.0f}s ago'
            all_healthy = False
        else:
            checks['worker'] = 'ok'
        for name in ('phase0', 'discovery', 'phase1', 'phase2', 'phase3'):
            if worker['alive'] and worker['components'].get(name):
                checks[f'{name}_worker'] = 'ok'
            else:
                checks[f'{name}_worker'] = 'error: not running'
                all_healthy = False
    except Exception as e:
        checks['worker'] = f'error: {str(e)[:50]}'
        all_healthy = False

    # 3. Phase 1 queue readable
    try:
        task_queue.get_status()
        checks['phase1_queue'] = 'ok'
    except Exception as e:
        checks['phase1_queue'] = f'error: {str(e)[:50]}'
        all_healthy = False

    status_code = 200 if all_healthy else 503
    return jsonify({
        'status': 'healthy' if all_healthy else 'unhealthy',
        'checks': checks
    }), status_code


@app.context_processor
def inject_csrf_token():
    session_token = request.cookies.get('access_token') or ''
    csrf_token = generate_csrf_token(session_token)
    return dict(csrf_token=csrf_token)


@app.route('/')
@token_required
def dashboard():
    config = get_config_for_ui()
    assets = get_all_assets_for_display()
    queue_status = task_queue.get_status()
    queue_active = task_queue.is_active()
    
    # Get Phase 2 queue items
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT queue_id, scan_type, target, target_id, target_type, status, 
               queued_at, started_at, completed_at, ports_found, dirs_found, error_message
        FROM scan_queue
        WHERE scan_type = 'phase2_deep_scan'
        ORDER BY queued_at DESC
        LIMIT 20
    ''')
    phase2_queue = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('dashboard.html', assets=assets, config=config, queue_status=queue_status, queue_active=queue_active, phase2_queue=phase2_queue,
                           changes=get_changes(limit=RECENT_CHANGES_LIMIT),
                           schedule=get_schedule(), cve_min_cvss=get_cve_min_cvss())


@app.route('/api/assets', methods=['GET'])
@token_required
def api_assets():
    """Return a searchable, paginated page of lightweight asset summaries."""
    raw_types = []
    for value in request.args.getlist('type') + request.args.getlist('types'):
        raw_types.extend(part.strip() for part in value.split(',') if part.strip())

    try:
        result = list_assets(
            page=request.args.get('page', 1),
            page_size=request.args.get('page_size', 25),
            query=request.args.get('q'),
            asset_types=raw_types,
            status=request.args.get('status'),
            root_domain=request.args.get('root_domain'),
            technology=request.args.get('technology'),
            port=request.args.get('port'),
            min_cvss=request.args.get('min_cvss'),
            kev_only=request.args.get('kev', ''),
            cert_state=request.args.get('cert_state'),
            scan_state=request.args.get('scan_state'),
            sort=request.args.get('sort', 'name'),
            order=request.args.get('order', 'asc'),
        )
    except AssetQueryError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    return jsonify({'success': True, **result})


@app.route('/api/assets/<asset_type>/<int:asset_id>', methods=['GET'])
@token_required
def api_asset_detail(asset_type, asset_id):
    """Return expensive collections for one asset on demand."""
    try:
        asset = get_asset_detail(asset_type, asset_id)
    except AssetQueryError as exc:
        return jsonify({'success': False, 'error': str(exc)}), 400

    if not asset:
        return jsonify({'success': False, 'error': 'Asset not found'}), 404

    return jsonify({'success': True, 'asset': asset})


@app.route('/delete_asset/<asset_type>/<int:asset_id>', methods=['DELETE'])
@token_required
def delete_asset(asset_type, asset_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if asset_type == 'domain':
            cursor.execute('DELETE FROM domain_asset WHERE dom_id = ?', (asset_id,))
            cursor.execute('DELETE FROM domain_ip WHERE dom_id = ?', (asset_id,))
        elif asset_type == 'subdomain':
            cursor.execute('DELETE FROM subdomain_asset WHERE sub_id = ?', (asset_id,))
            cursor.execute('DELETE FROM subdomain_ip WHERE sub_id = ?', (asset_id,))
        elif asset_type == 'ip':
            cursor.execute('DELETE FROM ip_asset WHERE ip_id = ?', (asset_id,))
            cursor.execute('DELETE FROM domain_ip WHERE ip_id = ?', (asset_id,))
            cursor.execute('DELETE FROM subdomain_ip WHERE ip_id = ?', (asset_id,))
        else:
            return jsonify({'success': False, 'error': 'Invalid asset type'}), 400
        
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/save_scanning_settings', methods=['POST'])
@token_required
@csrf_protected
def save_scanning_settings_route():
    """Check intervals and minimum CVSS; the worker picks them up without a restart."""
    from utils.scan_settings import save_scanning_settings

    errors, changed = save_scanning_settings(request.form)
    if errors:
        flash(f"Scanning settings not saved: {'; '.join(errors)}", "error")
    elif changed:
        flash(f"Scanning settings updated: {', '.join(changed)}", "success")
    else:
        flash("No changes submitted.", "warning")
    return redirect(url_for('dashboard'))


@app.route('/change_password', methods=['POST'])
@token_required
@csrf_protected
def change_password():
    """Change the admin password; every other session is signed out."""
    client_ip = request.remote_addr or 'unknown'
    blocked, _, remaining = is_rate_limited(client_ip)
    if blocked:
        flash(f"Too many failed attempts. Try again in {remaining} seconds.", "error")
        return redirect(url_for('dashboard'))

    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    admin = auth.get_admin()

    if not admin or not auth.verify_login(admin['username'], current):
        record_failed_login(client_ip, admin['username'] if admin else '')
        flash("Current password is incorrect.", "error")
        return redirect(url_for('dashboard'))
    if new != confirm:
        flash("New passwords do not match.", "error")
        return redirect(url_for('dashboard'))
    if new == current:
        flash("New password must be different from the current one.", "error")
        return redirect(url_for('dashboard'))
    error = auth.validate_new_password(new, admin['username'])
    if error:
        flash(f"{error}.", "error")
        return redirect(url_for('dashboard'))

    reset_failed_login(client_ip)
    version = auth.set_admin_password(admin['username'], new)
    logger.info("Admin password changed; all other sessions revoked")
    flash("Password changed. Other sessions have been signed out.", "success")
    return issue_session(make_response(redirect(url_for('dashboard'))), admin['username'], version)


@app.route('/save_config', methods=['POST'])
@token_required
@csrf_protected
def save_config():
    errors = []
    saved_keys = []
    deleted_keys = []
    
    for key in EDITABLE_KEYS:
        clear_flag = request.form.get(f'CLEAR_{key}', '0')
        
        if clear_flag == '1':
            success = delete_env_key(key)
            if success:
                deleted_keys.append(key)
            continue
        
        value = request.form.get(key, '').strip()
        
        if not value or value == (get_env_key(key) or KEY_DEFAULTS.get(key, '')):
            continue
        
        success, error = set_env_key(key, value)
        
        if success:
            saved_keys.append(key)
        elif error:
            errors.append(f"{key}: {error}")
    
    if errors:
        flash(f"Configuration errors: {'; '.join(errors)}", "error")
    elif saved_keys and deleted_keys:
        saved_names = [KEY_NAMES.get(k) or k for k in saved_keys]
        deleted_names = [KEY_NAMES.get(k) or k for k in deleted_keys]
        flash(f"Updated: {', '.join(saved_names)} | Cleared: {', '.join(deleted_names)}", "success")
    elif saved_keys:
        saved_names = [KEY_NAMES.get(k) or k for k in saved_keys]
        flash(f"Configuration updated: {', '.join(saved_names)}", "success")
    elif deleted_keys:
        deleted_names = [KEY_NAMES.get(k) or k for k in deleted_keys]
        flash(f"Configuration cleared: {', '.join(deleted_names)}", "success")
    else:
        flash("No changes submitted.", "warning")
    
    return redirect(url_for('dashboard'))


@app.route('/test_webhook', methods=['POST'])
@token_required
def test_webhook_endpoint():
    success, message = test_webhook()
    
    if success:
        flash(f"✓ {message}", "success")
    else:
        flash(f"✗ {message}", "error")
    
    return redirect(url_for('dashboard'))


RECENT_CHANGES_LIMIT = 30


@app.route('/update_changes')
@token_required
def update_changes():
    return render_template('changes_partial.html', changes=get_changes(limit=RECENT_CHANGES_LIMIT))


@app.route('/api/changes', methods=['GET'])
@token_required
def api_changes():
    """
    Change history, newest first.

    Query params: host, type, since ('YYYY-MM-DD[ HH:MM:SS]'), limit (max 500), offset
    """
    try:
        limit = min(max(int(request.args.get('limit', 100)), 1), 500)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({'success': False, 'error': 'limit and offset must be integers'}), 400
    changes = get_changes(host=request.args.get('host') or None, change_type=request.args.get('type') or None,
                          since=request.args.get('since') or None, limit=limit, offset=offset)
    return jsonify({'success': True, 'changes': changes, 'limit': limit, 'offset': offset})


@app.route('/api/export/<dataset>.<fmt>', methods=['GET'])
@token_required
def export_data(dataset, fmt):
    """
    Download assets or findings as CSV or JSON.
    
    /api/export/assets.csv, /api/export/assets.json
    /api/export/findings.csv, /api/export/findings.json  (?status=open|fixed|accepted|false_positive)
    """
    from utils import export
    from utils.db_utils import get_findings_for_export
    from utils.asset_repository import export_assets
    
    if fmt not in ('csv', 'json') or dataset not in ('assets', 'findings'):
        return jsonify({'success': False, 'error': 'Use /api/export/<assets|findings>.<csv|json>'}), 404
    
    if dataset == 'assets':
        rows, columns = [export.flatten_asset(a) for a in export_assets()], export.ASSET_COLUMNS
    else:
        status = request.args.get('status') or None
        if status and status not in VULN_STATUSES:
            return jsonify({'success': False, 'error': f"status must be one of: {', '.join(VULN_STATUSES)}"}), 400
        rows, columns = get_findings_for_export(status), export.FINDING_COLUMNS
    
    body = export.to_csv(rows, columns) if fmt == 'csv' else export.to_json(rows, columns)
    filename = f"lazyeasm-{dataset}-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.{fmt}"
    response = make_response(body)
    response.headers['Content-Type'] = 'text/csv; charset=utf-8' if fmt == 'csv' else 'application/json'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


@app.route('/update_table')
@token_required
def update_table():
    assets = get_all_assets_for_display()
    return render_template('table_partial.html', assets=assets)


@app.route('/update_queue')
@token_required
def update_queue():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT queue_id, target, target_id, target_type, status, 
               queued_at, started_at, completed_at, ports_found, dirs_found, error_message
        FROM scan_queue
        WHERE scan_type = 'phase2_deep_scan'
        ORDER BY queued_at DESC
        LIMIT 50
    ''')
    
    phase2_queue = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('queue_partial.html', phase2_queue=phase2_queue)


@app.route('/queue/status')
@token_required
def queue_status():
    """API endpoint for queue status polling."""
    return jsonify(task_queue.get_status())


@app.route('/phase_status')
def phase_status():
    """
    Get current phase status for dashboard.
    
    Returns:
        JSON with phase, progress, ETA, next run time
    """
    from utils.phase_lock import get_phase2_progress, get_current_phase, PHASE_NONE, get_next_phase2_time
    
    current_phase = get_current_phase()
    
    if current_phase == PHASE_NONE:
        return jsonify({
            'phase': 0,
            'phase_name': 'none',
            'message': 'No phase running',
            'next_run': get_next_phase2_time()
        })
    
    progress = get_phase2_progress()
    
    phase_names = {
        1: 'phase0',
        2: 'phase1',
        3: 'phase2'
    }
    
    return jsonify({
        'phase': current_phase,
        'phase_name': phase_names.get(current_phase, 'unknown'),
        'total': progress['total'],
        'processed': progress['processed'],
        'eta_minutes': progress['eta_minutes'],
        'next_run': get_next_phase2_time()
    })


@app.route('/generate_ai', methods=['POST'])
@token_required
def generate_ai():
    data = request.get_json()
    vuln_id = data.get('vuln_id')
    
    if not vuln_id:
        return jsonify({'error': 'vuln_id required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            SELECT v.vuln_id, v.cve_id, v.cve_score, v.description,
                   t.tech_name, t.tech_version, t.tech_id,
                   h.host, h.port_num, h.is_https, h.http_id
            FROM vulnerabilities v
            INNER JOIN technologies t ON t.tech_id = v.tech_id
            INNER JOIN http_services h ON h.http_id = t.http_id
            WHERE v.vuln_id = ?
        ''', (vuln_id,))
        
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'CVE not found'}), 404
        
        cve_id = row['cve_id']
        cve_score = row['cve_score']
        description = row['description'] or ''
        tech_name = row['tech_name'] or 'Unknown'
        tech_version = row['tech_version'] or ''
        tech_id = row['tech_id']
        asset_name = row['host']
        port = row['port_num']
        is_https = row['is_https']
        http_id = row['http_id']
        
        # Get other technologies on the same http_service
        cursor.execute('''
            SELECT tech_name, tech_version
            FROM technologies
            WHERE http_id = ? AND tech_id != ? AND removed_at IS NULL
        ''', (http_id, tech_id))
        tech_stack = [(r['tech_name'], r['tech_version']) for r in cursor.fetchall()]
        
        if not description:
            return jsonify({'error': 'CVE lacks description'}), 400
        
        recommendation, ai_error = send_message(
            cve_id=cve_id,
            cve_score=cve_score,
            cve_description=description,
            tech_name=tech_name,
            tech_version=tech_version,
            asset_name=asset_name,
            port=port,
            is_https=is_https,
            tech_stack=tech_stack
        )
        
        if not recommendation:
            error_text = f"AI generation failed: {ai_error}" if ai_error else "AI generation failed. Check the AI provider settings."
            return jsonify({'error': error_text}), 500
        
        cursor.execute('''
            UPDATE vulnerabilities 
            SET recommendation = ?
            WHERE vuln_id = ?
        ''', (recommendation, vuln_id))
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'vuln_id': vuln_id,
            'recommendation': recommendation
        })
    except Exception as e:
        logger.error(f"Error in /generate_ai: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/vulnerabilities/<int:vuln_id>/status', methods=['POST'])
@token_required
@csrf_protected
def update_vulnerability_status(vuln_id):
    data = request.get_json(silent=True) or {}
    status = data.get('status')
    note = (data.get('note') or '').strip()[:500] or None
    
    if status not in VULN_STATUSES:
        return jsonify({'success': False, 'error': f"status must be one of: {', '.join(VULN_STATUSES)}"}), 400
    
    try:
        updated = set_vulnerability_status(vuln_id, status, note)
    except Exception as e:
        logger.error(f"Error updating vulnerability {vuln_id} status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to update status'}), 500
    
    if not updated:
        return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404
    
    return jsonify({'success': True, 'vuln_id': vuln_id, 'status': status, 'updated': updated})


@app.route('/api/findings/<int:finding_id>/status', methods=['POST'])
@token_required
@csrf_protected
def update_finding_status(finding_id):
    data = request.get_json(silent=True) or {}
    status = data.get('status')
    note = (data.get('note') or '').strip()[:500] or None

    if status not in VULN_STATUSES:
        return jsonify({'success': False, 'error': f"status must be one of: {', '.join(VULN_STATUSES)}"}), 400

    try:
        updated = set_finding_status(finding_id, status, note)
    except Exception as e:
        logger.error(f"Error updating finding {finding_id} status: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to update status'}), 500

    if not updated:
        return jsonify({'success': False, 'error': 'Finding not found'}), 404

    return jsonify({'success': True, 'finding_id': finding_id, 'status': status})


@app.route('/process_assets', methods=['POST'])
@token_required
@csrf_protected
def process_assets():
    """
    Process user input and run Phase 1 in background.
    
    Returns immediately with "Asset accepted" message.
    Sends Discord notification when complete.
    """
    from utils.phase_lock import is_phase2_running, get_phase2_progress
    
    # Check if Phase 2 is running
    if is_phase2_running():
        progress = get_phase2_progress()
        flash(
            f"Deep Scan is currently running ({progress['processed']}/{progress['total']} assets). "
            f"Please wait for it to complete. New assets will be scanned in the next Deep Scan cycle.",
            'warning'
        )
        return redirect(url_for('dashboard'))
    
    input_text = request.form.get('asset_input', '')
    
    if not input_text or not input_text.strip():
        flash('No assets provided. Please enter domains, IPs, or CIDRs.', 'error')
        return redirect(url_for('dashboard'))
    
    # Parse input
    targets = parse_input(input_text)
    invalid = targets.get('invalid', [])
    invalid_note = ''
    if invalid:
        shown = ', '.join(invalid[:5]) + (f' (+{len(invalid) - 5} more)' if len(invalid) > 5 else '')
        invalid_note = f' Skipped {len(invalid)} invalid or oversized (larger than /20) entries: {shown}.'

    if not any(v for k, v in targets.items() if k != 'invalid'):
        flash('No valid assets found. Please check your input format.' + invalid_note, 'error')
        return redirect(url_for('dashboard'))
    
    # Log counts
    counts = {k: len(v) for k, v in targets.items()}
    print(f"[Phase 1] Assets received: {counts}")
    
    # Discovery runs in the worker process
    enqueue_input_discovery(targets)
    
    flash('Asset accepted. Processing may take up to 10 minutes. Initialization will start automatically after parsing.' + invalid_note, 'success')
    return redirect(url_for('dashboard'))


# ============================================
# Phase 2 API Endpoints
# ============================================

@app.route('/api/phase2/scan', methods=['POST'])
@token_required
def queue_phase2_scan():
    """
    Queue a Phase 2 deep scan for an asset.
    
    Request body:
        asset_id: int
        asset_type: 'domain' | 'subdomain'
        asset_name: str
    """
    # Get data from form or JSON
    if request.is_json:
        data = request.get_json()
        asset_id = data.get('asset_id')
        asset_type = data.get('asset_type')
        asset_name = data.get('asset_name')
    else:
        asset_id = request.form.get('asset_id')
        asset_type = request.form.get('asset_type')
        asset_name = request.form.get('asset_name')
    
    if not asset_id or not asset_type or not asset_name:
        return jsonify({'success': False, 'error': f'Missing parameters. Got: asset_id={asset_id}, asset_type={asset_type}, asset_name={asset_name}'}), 400
    
    try:
        asset_id = int(asset_id)
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'asset_id must be an integer'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if already queued or processing
    cursor.execute('''
        SELECT queue_id, status FROM scan_queue 
        WHERE target = ? AND scan_type = 'phase2_deep_scan' 
          AND status IN ('pending', 'processing')
    ''', (asset_name,))
    
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return jsonify({
            'success': False, 
            'error': f'Asset already in queue with status: {existing["status"]}'
        }), 400
    
    # Add to queue
    cursor.execute('''
        INSERT INTO scan_queue (scan_type, cycle, target, target_id, target_type, status, queued_at)
        VALUES (?, 'phase2', ?, ?, ?, 'pending', datetime('now'))
    ''', ('phase2_deep_scan', asset_name, asset_id, asset_type))
    
    queue_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Send Discord notification
    try:
        from modules.Notify import send_message
        send_message(
            f"**Deep Scan Queued**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Asset: {asset_name}\n"
            f"Type: {asset_type}\n"
            f"Queue ID: {queue_id}"
        )
    except Exception as e:
        print(f"[Phase2] Discord notification failed: {e}")
    
    return jsonify({
        'success': True, 
        'message': f'Deep scan queued for {asset_name}',
        'queue_id': queue_id
    })


@app.route('/api/phase2/cancel', methods=['POST'])
@token_required
def cancel_phase2_scan():
    """
    Cancel a pending Phase 2 scan.
    
    Request body:
        asset_name: str
    """
    if request.is_json:
        asset_name = request.json.get('asset_name')
    else:
        asset_name = request.form.get('asset_name')
    
    if not asset_name:
        return jsonify({'success': False, 'error': 'Missing asset_name'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find pending scan
    cursor.execute('''
        SELECT queue_id, status FROM scan_queue 
        WHERE target = ? AND scan_type = 'phase2_deep_scan' 
          AND status = 'pending'
    ''', (asset_name,))
    
    scan = cursor.fetchone()
    
    if not scan:
        conn.close()
        return jsonify({'success': False, 'error': 'No pending scan found for this asset'}), 404
    
    if scan['status'] != 'pending':
        conn.close()
        return jsonify({'success': False, 'error': f'Cannot cancel scan with status: {scan["status"]}'}), 400
    
    # Delete from queue
    cursor.execute('DELETE FROM scan_queue WHERE queue_id = ?', (scan['queue_id'],))
    conn.commit()
    conn.close()
    
    # Send Discord notification
    try:
        from modules.Notify import send_message
        send_message(
            f"**Deep Scan Cancelled**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"Asset: {asset_name}"
        )
    except Exception as e:
        print(f"[Phase2] Discord notification failed: {e}")
    
    return jsonify({
        'success': True, 
        'message': f'Scan cancelled for {asset_name}'
    })


@app.route('/api/phase2/queue', methods=['GET'])
@token_required
def get_phase2_queue():
    """Get all Phase 2 scans in queue."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT queue_id, target, target_id, target_type, status, 
               queued_at, started_at, completed_at, ports_found, dirs_found, error_message
        FROM scan_queue
        WHERE scan_type = 'phase2_deep_scan'
        ORDER BY queued_at DESC
        LIMIT 50
    ''')
    
    queue_items = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        'success': True,
        'queue': queue_items
    })


# ============================================
# PHASE 3: CONTINUOUS MONITORING ENDPOINTS
# ============================================

@app.route('/api/phase3/status', methods=['GET'])
@token_required
def phase3_status():
    """Get Phase 3 monitoring status."""
    from utils.phase3_worker import get_phase3_status
    from utils.liveness_checker import get_liveness_summary
    from utils.ct_monitor import get_cert_expiry_summary
    
    status = get_phase3_status()
    liveness = get_liveness_summary()
    certs = get_cert_expiry_summary()
    
    return jsonify({
        'success': True,
        'running': status['running'],
        'enabled': status['enabled'],
        'last_liveness_check': status['last_liveness_check'],
        'last_ctlogs_check': status['last_ctlogs_check'],
        'last_wappalyzer_check': status['last_wappalyzer_check'],
        'last_takeover_check': status['last_takeover_check'],
        'last_intel_check': status['last_intel_check'],
        'last_misconfig_check': status['last_misconfig_check'],
        'last_discovery_check': status['last_discovery_check'],
        'liveness_interval_min': status['liveness_interval_min'],
        'ctlogs_interval_hr': status['ctlogs_interval_hr'],
        'wappalyzer_interval_hr': status['wappalyzer_interval_hr'],
        'takeover_interval_hr': status['takeover_interval_hr'],
        'intel_interval_hr': status['intel_interval_hr'],
        'misconfig_interval_hr': status['misconfig_interval_hr'],
        'discovery_interval_hr': status['discovery_interval_hr'],
        'assets': {
            'total': liveness['total'],
            'up': liveness['up'],
            'down': liveness['down']
        },
        'certificates': {
            'total_certs': certs['total_certs'],
            'expired': certs['expired'],
            'expiring_3_days': certs['expiring_3_days'],
            'expiring_7_days': certs['expiring_7_days'],
            'expiring_30_days': certs['expiring_30_days']
        }
    })


@app.route('/api/phase3/toggle', methods=['POST'])
@token_required
def phase3_toggle():
    """Enable or disable Phase 3 monitoring."""
    from utils.db_utils import set_setting
    from utils.phase3_worker import get_phase3_status
    
    data = request.get_json() or {}
    enabled = data.get('enabled', True)
    
    # The worker process re-reads this flag every few seconds
    set_setting('phase3_enabled', '1' if enabled else '0')
    
    status = get_phase3_status()
    
    return jsonify({
        'success': True,
        'enabled': status['enabled'],
        'running': status['running'],
        'message': f"Phase 3 monitoring {'enabled' if enabled else 'disabled'}"
    })


@app.route('/api/phase3/<name>/check', methods=['POST'])
@token_required
def phase3_manual_check(name):
    """
    Queue a Phase 3 check to run now in the worker process.

    name: liveness, ctlogs, wappalyzer, takeover, intel, misconfig, discovery, maintenance
    Returns 202 with a job_id; poll GET /api/jobs/<job_id> for the outcome.
    """
    from utils.phase3_worker import MONITORS
    from utils.pipeline import enqueue_monitor_run

    if name not in MONITORS:
        return jsonify({'success': False, 'error': f"Unknown check. Use one of: {', '.join(MONITORS)}"}), 404

    job_id, created = enqueue_monitor_run(name)
    return jsonify({
        'success': True,
        'queued': created,
        'job_id': job_id,
        'message': f"{name} check queued" if created else f"{name} check already queued"
    }), 202


@app.route('/api/jobs/<int:job_id>', methods=['GET'])
@token_required
def job_status(job_id):
    """Status of a queued input discovery or manual check job."""
    from utils.pipeline import get_job

    job = get_job(job_id)
    if not job:
        return jsonify({'success': False, 'error': 'Job not found'}), 404
    return jsonify({'success': True, 'job': job})


def serve_web():
    """Serve the app with waitress (production WSGI server), or Flask's debug server if FLASK_DEBUG."""
    host = get_env('HOST', '0.0.0.0')
    port = int(get_env('PORT', '10001'))
    if env_flag('FLASK_DEBUG'):
        # Debug mode exposes the Werkzeug debugger; it is opt-in only. The
        # reloader stays off because it runs this module twice.
        app.run(debug=True, use_reloader=False, host=host, port=port)
        return
    from waitress import serve
    logger.info(f"Serving LazyEASM on http://{host}:{port}")
    serve(app, host=host, port=port, threads=int(get_env('WEB_THREADS', '8')))


if __name__ == '__main__':
    # LAZYEASM_ROLE=web serves only the web app (run.py starts worker.py
    # separately). The default "all" also runs the background workers in this
    # process, for local development with a single `python main.py`.
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    from modules.InitDB import init_db
    init_db()
    auth.bootstrap_admin_from_env()

    if get_env('LAZYEASM_ROLE', 'all') != 'web':
        from utils.worker_runtime import start_background_workers
        start_background_workers()

    serve_web()
