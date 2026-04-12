import jwt
import datetime
import threading
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, make_response, jsonify
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env
from utils.env_manager import set_env_key, delete_env_key, get_config_for_ui, EDITABLE_KEYS
from utils.db_utils import get_all_assets_for_display, get_db_connection
from utils.parsing import parse_input
from modules.Notify import test_webhook, send_message as discord_send_message
from modules.AskAI import send_message

app = Flask(__name__)
app.secret_key = get_env('FLASK_SECRET_KEY', 'default-secret-change-in-production')
JWT_SECRET = get_env('JWT_SECRET', 'default-jwt-secret-change-in-production')

KEY_NAMES = {
    'DISCORD_WEBHOOK_URL': 'Discord Webhook',
    'DISCORD_USER_ID': 'Discord User ID',
    'SECURITYTRAILS_API_KEY': 'SecurityTrails Key',
    'VULNERS_API_KEY': 'Vulners Key',
    'GEMINI_API_KEY': 'Gemini Key'
}

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
        token = request.cookies.get('session_token')
        
        if not token:
            return redirect(url_for('login_page'))
        
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except:
            return redirect(url_for('login_page'))
            
        return f(*args, **kwargs)
    return decorated


@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_action():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == "admin" and password == "password":
        payload = {
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('session_token', token, httponly=True)
        return resp
    
    flash("Username atau Password salah!", "error")
    return redirect(url_for('login_page'))


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login_page')))
    resp.set_cookie('session_token', '', expires=0)
    flash("Berhasil logout.", "success")
    return resp


@app.route('/')
@token_required
def dashboard():
    config = get_config_for_ui()
    assets = get_all_assets_for_display()
    return render_template('dashboard.html', assets=assets, config=config)


@app.route('/save_config', methods=['POST'])
@token_required
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
def process_assets():
    """
    Process user input and run Phase 1 in background.
    
    Returns immediately with "Asset accepted" message.
    Sends Discord notification when complete.
    """
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
    
    flash(f'Asset accepted. Processing may take up to 10 minutes. You will be notified on Discord when complete.', 'success')
    return redirect(url_for('dashboard'))


def run_phase1_background(targets: dict):
    """
    Background worker for Phase 1.
    
    Called from process_assets route.
    Sends Discord notification on completion or error.
    """
    import importlib
    
    try:
        # Import module (filename starts with number, use importlib)
        phase1_module = importlib.import_module('modules.03-asset-expansion')
        
        # Initialize expander
        expander = phase1_module.Phase1Expander()
        
        # Run Phase 1
        stats = expander.run_phase1(targets)
        
        # Send success notification
        message = (
            f"✅ **Phase 1 Complete**\n"
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
        print(f"[Phase 1] Complete: {stats}")
        
    except Exception as e:
        # Send error notification
        import traceback
        error_msg = f"❌ **Phase 1 Failed**\nError: {str(e)}"
        discord_send_message(error_msg)
        print(f"[Phase 1] Error: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)