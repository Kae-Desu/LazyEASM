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
from utils.env_manager import set_env_key, delete_env_key, get_config_for_ui, EDITABLE_KEYS
from utils.db_utils import get_all_assets_for_display, get_db_connection
from utils.parsing import parse_input
from utils.queue_manager import task_queue
from modules.Notify import test_webhook, send_message as discord_send_message
from modules.AskAI import send_message

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
    
    if get_env('FLASK_ENV', 'production') == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

KEY_NAMES = {
    'DISCORD_WEBHOOK_URL': 'Discord Webhook',
    'DISCORD_USER_ID': 'Discord User ID',
    'SECURITYTRAILS_API_KEY': 'SecurityTrails Key',
    'VULNERS_API_KEY': 'Vulners Key',
    'GEMINI_API_KEY': 'Gemini Key'
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
    # Check if running on localhost (dev mode)
    # secure=True only works over HTTPS, so disable for localhost
    is_localhost = request.remote_addr in ['127.0.0.1', '::1', 'localhost'] if request else True
    
    return {
        'httponly': True,
        'secure': get_env('FLASK_ENV', 'production') == 'production' and not is_localhost,
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
        csrf_token = request.form.get('csrf_token') or (request.get_json() or {}).get('csrf_token')
        
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
        
        if username == get_env('ADMIN_USER', 'admin') and password == get_env('ADMIN_PASS', 'changeme'):
            reset_failed_login(client_ip)
            
            now = datetime.datetime.utcnow()
            
            access_payload = {
                'user': username,
                'type': 'access',
                'jti': str(uuid.uuid4()),
                'exp': now + ACCESS_TOKEN_LIFETIME
            }
            access_token = jwt.encode(access_payload, JWT_SECRET, algorithm="HS256")
            
            refresh_payload = {
                'user': username,
                'type': 'refresh',
                'jti': str(uuid.uuid4()),
                'exp': now + REFRESH_TOKEN_LIFETIME
            }
            refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm="HS256")
            
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('access_token', access_token, **get_secure_cookie_kwargs())
            resp.set_cookie('refresh_token', refresh_token, **get_secure_cookie_kwargs())
            return resp
        
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
    
    jti = payload.get('jti')
    user = payload.get('user')
    
    # Check if token is blacklisted (REUSE DETECTION)
    if is_token_blacklisted(jti):
        # Token was already used - possible theft
        # Revoke ALL tokens for this user
        blacklist_all_user_tokens(user)
        logger.warning(f"Refresh token reuse detected for user: {user}")
        
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
    now = datetime.datetime.utcnow()
    
    access_payload = {
        'user': user,
        'type': 'access',
        'jti': str(uuid.uuid4()),
        'exp': now + ACCESS_TOKEN_LIFETIME
    }
    new_access = jwt.encode(access_payload, JWT_SECRET, algorithm="HS256")
    
    refresh_payload = {
        'user': user,
        'type': 'refresh',
        'jti': str(uuid.uuid4()),
        'exp': now + REFRESH_TOKEN_LIFETIME
    }
    new_refresh = jwt.encode(refresh_payload, JWT_SECRET, algorithm="HS256")
    
    resp = jsonify({'success': True})
    resp.set_cookie('access_token', new_access, **get_secure_cookie_kwargs())
    resp.set_cookie('refresh_token', new_refresh, **get_secure_cookie_kwargs())
    return resp


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
                'phase0_worker': 'ok' | 'error: ...',
                'phase1_queue': 'ok' | 'error: ...',
                'phase2_worker': 'ok' | 'error: ...',
                'phase3_liveness': 'ok' | 'error: ...',
                'phase3_ctlogs': 'ok' | 'error: ...'
            }
        }
    """
    from flask import request
    from utils.phase0_worker import get_phase0_status
    from utils.phase2_worker import get_phase2_status
    from utils.phase3_worker import get_phase3_status
    
    # Check if request is from localhost (no auth required)
    client_ip = request.remote_addr
    is_localhost = client_ip in ['127.0.0.1', '::1', 'localhost']
    
    # If not localhost, require auth (cookie only)
    if not is_localhost:
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({'status': 'unhealthy', 'error': 'Authentication required'}), 401
        
        try:
            jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
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
    
    # 2. Phase 0 worker check
    try:
        phase0_status = get_phase0_status()
        if phase0_status.get('thread_alive'):
            checks['phase0_worker'] = 'ok'
        else:
            checks['phase0_worker'] = 'error: thread not running'
            all_healthy = False
    except Exception as e:
        checks['phase0_worker'] = f'error: {str(e)[:50]}'
        all_healthy = False
    
    # 3. Phase 1 queue check (ThreadPoolExecutor creates threads on demand)
    try:
        queue_status = task_queue.get_status()
        workers_status = task_queue.get_workers_status()
        # Consider healthy if queue exists and process is running
        checks['phase1_queue'] = 'ok'
    except Exception as e:
        checks['phase1_queue'] = f'error: {str(e)[:50]}'
        all_healthy = False
    
    # 4. Phase 2 worker check
    try:
        phase2_status = get_phase2_status()
        if phase2_status.get('thread_alive'):
            checks['phase2_worker'] = 'ok'
        else:
            checks['phase2_worker'] = 'error: thread not running'
            all_healthy = False
    except Exception as e:
        checks['phase2_worker'] = f'error: {str(e)[:50]}'
        all_healthy = False
    
    # 5. Phase 3 workers check
    try:
        phase3_status = get_phase3_status()
        
        if phase3_status.get('running'):
            checks['phase3_workers'] = 'ok'
        else:
            checks['phase3_workers'] = 'error: workers not running'
            all_healthy = False
    except Exception as e:
        checks['phase3_workers'] = f'error: {str(e)[:50]}'
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
    
    return render_template('dashboard.html', assets=assets, config=config, queue_status=queue_status, queue_active=queue_active, phase2_queue=phase2_queue)


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
        
        if not value:
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
            SELECT v.vuln_id, v.cve_id, v.description, t.tech_name, t.tech_version, h.host
            FROM vulnerabilities v
            INNER JOIN technologies t ON t.tech_id = v.tech_id
            INNER JOIN http_services h ON h.http_id = t.http_id
            WHERE v.vuln_id = ?
        ''', (vuln_id,))
        
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'CVE not found'}), 404
        
        cve_id = row['cve_id']
        description = row['description'] or ''
        tech_name = row['tech_name'] or 'Unknown'
        tech_version = row['tech_version'] or 'Unknown'
        asset_name = row['host']
        
        if not description:
            return jsonify({'error': 'CVE lacks description'}), 400
        
        recommendation = send_message(
            cve_id=cve_id,
            tech_version=f"{tech_name} {tech_version}" if tech_version else tech_name,
            cve_description=description,
            asset_name=asset_name
        )
        
        if not recommendation:
            return jsonify({'error': 'AI generation failed. Check GEMINI_API_KEY.'}), 500
        
        cursor.execute('''
            UPDATE vulnerabilities 
            SET recommendation = ?, last_seen = ?
            WHERE vuln_id = ?
        ''', (recommendation, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), vuln_id))
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'vuln_id': vuln_id,
            'recommendation': recommendation
        })
    except Exception as e:
        print(f"Error in /generate_ai: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


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
            f"Phase 2 is currently running ({progress['processed']}/{progress['total']} assets). "
            f"Please wait for it to complete. New assets will be scanned in the next Phase 2 cycle.",
            'warning'
        )
        return redirect(url_for('dashboard'))
    
    input_text = request.form.get('asset_input', '')
    
    if not input_text or not input_text.strip():
        flash('No assets provided. Please enter domains, IPs, or CIDRs.', 'error')
        return redirect(url_for('dashboard'))
    
    # Parse input
    targets = parse_input(input_text)
    
    if not any(targets.values()):
        flash('No valid assets found. Please check your input format.', 'error')
        return redirect(url_for('dashboard'))
    
    # Log counts
    counts = {k: len(v) for k, v in targets.items()}
    print(f"[Phase 1] Assets received: {counts}")
    
    # Start background thread for Phase 1
    thread = threading.Thread(target=run_phase1_background, args=(targets,))
    thread.daemon = True
    thread.start()
    
    flash(f'Asset accepted. Processing may take up to 10 minutes. Phase 1 will start automatically after discovery.', 'success')
    return redirect(url_for('dashboard'))


def run_phase1_background(targets: dict):
    """
    Background worker for Phase 0 (Asset Discovery).
    
    After Phase 0 completes, enqueues assets for Phase 1 processing.
    Sends Discord notification on completion or error.
    """
    import importlib
    
    try:
        # Import module (filename starts with number, use importlib)
        phase1_module = importlib.import_module('modules.03-asset-expansion')
        
        # Initialize expander
        expander = phase1_module.Phase1Expander()
        
        # Run Phase 0 (Asset Discovery)
        stats = expander.run_phase1(targets)
        
        # Send success notification for Phase 0
        message = (
            f"✅ **Phase 0 Complete**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"**Domains added:** {stats['domains_added']}\n"
            f"**Subdomains discovered:** {stats['subdomains_discovered']}\n"
            f"**New subdomains:** {stats['subdomains_new']}\n"
            f"**IPs resolved:** {stats['ips_resolved']}\n"
            f"**Time:** {stats['time_elapsed']:.1f}s"
        )
        
        if stats['errors']:
            message += f"\n**Errors:** {len(stats['errors'])}"
        
        discord_send_message(message)
        print(f"[Phase 0] Complete: {stats}")
        
        # After Phase 0, enqueue assets for Phase 1
        if stats['domains_added'] > 0 or stats['subdomains_new'] > 0 or stats['ips_resolved'] > 0:
            enqueue_assets_for_phase1()
            discord_send_message(f"📋 **Phase 1 Queued**: Processing assets...")
        
    except Exception as e:
        # Send error notification
        import traceback
        error_msg = f"❌ **Phase 0 Failed**\nError: {str(e)}"
        discord_send_message(error_msg)
        print(f"[Phase 0] Error: {e}")
        traceback.print_exc()


def enqueue_assets_for_phase1():
    """
    Enqueue all discovered assets from database for Phase 1 processing.
    
    Only enqueues assets that haven't been scanned yet (last_scanned IS NULL).
    Queries domain_asset, subdomain_asset, and ip_asset tables
    for assets with status='up'.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Enqueue domains that haven't been scanned
        cursor.execute('''
            SELECT dom_id, domain_name FROM domain_asset 
            WHERE status='up' AND last_scanned IS NULL
        ''')
        for row in cursor.fetchall():
            task_queue.enqueue(row['dom_id'], 'domain', row['domain_name'])
        
        # Enqueue subdomains that haven't been scanned
        cursor.execute('''
            SELECT sub_id, subdomain_name FROM subdomain_asset 
            WHERE status='up' AND last_scanned IS NULL
        ''')
        for row in cursor.fetchall():
            task_queue.enqueue(row['sub_id'], 'subdomain', row['subdomain_name'])
        
        # Enqueue IPs (standalone, not linked to domain/subdomain) that haven't been scanned
        cursor.execute('''
            SELECT ip_id, ip_value FROM ip_asset 
            WHERE status='up' AND last_scanned IS NULL
              AND ip_id NOT IN (SELECT ip_id FROM domain_ip UNION SELECT ip_id FROM subdomain_ip)
        ''')
        for row in cursor.fetchall():
            task_queue.enqueue(row['ip_id'], 'ip', row['ip_value'])
        
        conn.close()
        
        print(f"[Queue] Enqueued assets for Phase 1")
        
    except Exception as e:
        print(f"[Queue] Error enqueueing assets: {e}")


def enqueue_single_asset_for_phase1(asset_name: str, asset_type: str):
    """
    Enqueue a single asset for Phase 1 processing.
    
    Uses INSERT OR IGNORE to prevent duplicates.
    Called by Phase 0 worker after processing each subdomain.
    
    Args:
        asset_name: Domain, subdomain, or IP name
        asset_type: 'domain', 'subdomain', or 'ip'
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Get asset ID based on type
        asset_id = None
        if asset_type == 'domain':
            cursor.execute('SELECT dom_id FROM domain_asset WHERE domain_name = ?', (asset_name,))
            row = cursor.fetchone()
            asset_id = row['dom_id'] if row else None
        elif asset_type == 'subdomain':
            cursor.execute('SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?', (asset_name,))
            row = cursor.fetchone()
            asset_id = row['sub_id'] if row else None
        
        # Insert into queue
        cursor.execute('''
            INSERT OR IGNORE INTO scan_queue (scan_type, cycle, target, target_id, target_type, status, queued_at)
            VALUES ('phase1', 'standard', ?, ?, ?, 'pending', ?)
        ''', (asset_name, asset_id, asset_type, now))
        
        conn.commit()
        conn.close()
        
        print(f"[Phase0] Enqueued {asset_name} for Phase 1")
        
    except Exception as e:
        print(f"[Phase0] Error enqueueing {asset_name}: {e}")


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
            f"**Phase 2 Deep Scan Queued**\n"
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
    asset_name = request.form.get('asset_name') or request.json.get('asset_name') if request.is_json else None
    
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
            f"**Phase 2 Scan Cancelled**\n"
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
        'liveness_interval_min': status['liveness_interval_min'],
        'ctlogs_interval_hr': status['ctlogs_interval_hr'],
        'assets': {
            'total': liveness['total'],
            'up': liveness['up'],
            'down': liveness['down']
        },
        'certificates': {
            'total': certs['total_certs'],
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
    from utils.phase3_worker import start_phase3_workers, stop_phase3_workers, get_phase3_status
    
    data = request.get_json() or {}
    enabled = data.get('enabled', True)
    
    # Update setting
    set_setting('phase3_enabled', '1' if enabled else '0')
    
    # Start or stop workers
    if enabled:
        start_phase3_workers()
    else:
        stop_phase3_workers()
    
    status = get_phase3_status()
    
    return jsonify({
        'success': True,
        'enabled': status['enabled'],
        'running': status['running'],
        'message': f"Phase 3 monitoring {'enabled' if enabled else 'disabled'}"
    })


@app.route('/api/phase3/liveness/check', methods=['POST'])
@token_required
def phase3_liveness_check():
    """Manually trigger a liveness check."""
    from utils.liveness_checker import check_all_liveness
    from utils.phase3_worker import send_liveness_notification
    
    result = check_all_liveness()
    
    # Send notification if any changes
    if result['down'] or result['recovered']:
        send_liveness_notification(result)
    
    return jsonify({
        'success': True,
        'result': result
    })


@app.route('/api/phase3/ctlogs/check', methods=['POST'])
@token_required
def phase3_ctlogs_check():
    """Manually trigger a CT logs check."""
    from utils.ct_monitor import poll_all_domains
    from utils.phase3_worker import send_ctlogs_notification
    
    result = poll_all_domains()
    
    # Send notification if any discoveries
    if result['new_subdomains'] or result['cert_expiring']:
        send_ctlogs_notification(result)
    
    return jsonify({
        'success': True,
        'result': result
    })


if __name__ == '__main__':
    # Start Phase 2 worker in background thread
    from utils.phase2_worker import phase2_worker_loop, _phase2_thread as phase2_thread_ref
    import utils.phase2_worker
    
    worker_thread = threading.Thread(
        target=phase2_worker_loop,
        args=(5,),
        daemon=True
    )
    worker_thread.start()
    
    # Store thread reference for health check
    utils.phase2_worker._phase2_thread = worker_thread
    print("[Phase2] Worker thread started")
    
    # Start Phase 0 worker in background thread
    from utils.phase0_worker import start_phase0_worker
    start_phase0_worker()
    print("[Phase0] Discovery worker started")
    
    # Start Phase 3 workers in background
    from utils.phase3_worker import start_phase3_workers
    start_phase3_workers()
    print("[Phase3] Monitoring workers started")
    
    debug_mode = get_env('FLASK_ENV', 'development') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=10001)