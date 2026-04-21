import jwt
import datetime
import threading
import secrets
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
            return redirect(url_for('login'))
        
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except:
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == get_env('ADMIN_USER', 'admin') and password == get_env('ADMIN_PASS', 'changeme'):
            payload = {
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_token', token, httponly=True)
            return resp
        
        flash("Username atau Password salah!", "error")
        return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('session_token', '', expires=0)
    flash("Berhasil logout.", "success")
    return resp


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
    
    Queries domain_asset, subdomain_asset, and ip_asset tables
    for assets with status='up'.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Enqueue domains
        cursor.execute("SELECT dom_id, domain_name FROM domain_asset WHERE status='up'")
        for row in cursor.fetchall():
            task_queue.enqueue(row['dom_id'], 'domain', row['domain_name'])
        
        # Enqueue subdomains
        cursor.execute("SELECT sub_id, subdomain_name FROM subdomain_asset WHERE status='up'")
        for row in cursor.fetchall():
            task_queue.enqueue(row['sub_id'], 'subdomain', row['subdomain_name'])
        
        # Enqueue IPs (standalone, not linked to domain/subdomain)
        cursor.execute('''
            SELECT ip_id, ip_value FROM ip_asset 
            WHERE status='up'
              AND ip_id NOT IN (SELECT ip_id FROM domain_ip UNION SELECT ip_id FROM subdomain_ip)
        ''')
        for row in cursor.fetchall():
            task_queue.enqueue(row['ip_id'], 'ip', row['ip_value'])
        
        conn.close()
        
        print(f"[Queue] Enqueued assets for Phase 1")
        
    except Exception as e:
        print(f"[Queue] Error enqueueing assets: {e}")


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


if __name__ == '__main__':
    # Start Phase 2 worker in background thread
    from utils.phase2_worker import phase2_worker_loop
    
    worker_thread = threading.Thread(
        target=phase2_worker_loop,
        args=(5,),
        daemon=True
    )
    worker_thread.start()
    print("[Phase2] Worker thread started")
    
    app.run(debug=True, host='0.0.0.0', port=10001)