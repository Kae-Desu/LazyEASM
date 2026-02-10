import jwt
import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, make_response

app = Flask(__name__)
app.secret_key = "very-secure-approx-128-characters-secret"
JWT_SECRET = "very-secure-approx-128-characters-jwt-secret"

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

config_data = {
    "discord_webhook": "987987",
    "discord_uid": "89089",
    "vulners_key": "kjbjkb",
    "gemini_key": "78g87g8"
}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        
        if not token:
            return redirect(url_for('login_page'))
        
        try:
            # Decode tanpa ribet, kalau expired atau salah dia otomatis lempar ke 'except'
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

    # Hardcoded dulu buat ngetes
    if username == "admin" and password == "password":
        payload = {
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24) # Berlaku 1 hari
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        resp = make_response(redirect(url_for('dashboard')))
        # Simpan di cookie agar aman
        resp.set_cookie('session_token', token, httponly=True)
        return resp
    
    flash("Username atau Password salah!", "error")
    return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login_page')))
    # Hapus cookie dengan cara menimpa nilainya dan set expired ke 0
    resp.set_cookie('session_token', '', expires=0)
    flash("Berhasil logout.", "success")
    return resp

@app.route('/')
@token_required
def dashboard():
    return render_template('dashboard.html', assets=assets_data, config=config_data)

@app.route('/save_config', methods=['POST'])
@token_required
def save_config():
    # Logika simpan config ke DB/File
    flash("Configuration updated successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/update_table')
@token_required
def update_table():
    # Di sini nanti kamu ambil data terbaru dari database
    # assets = Asset.query.order_by(Asset.id.desc()).all()
    return render_template('table_partial.html', assets=assets_data)

if __name__ == '__main__':
    app.run(debug=True, port=5000)