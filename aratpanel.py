#!/usr/bin/env python3
# AratPanel - custom lightweight WireGuard panel (kernel WG) - stdlib only + qrencode binary
import http.server, socketserver, subprocess, json, urllib.parse, base64, os, time, threading, hashlib, html, re

PORT = 51821
WG_IF = 'wg0'
CONF = '/etc/wireguard/wg0.conf'
EP = '13.60.83.207:51820'
PW_FILE = os.path.expanduser('~/.aratpanel.hash')
sessions = {}
lock = threading.Lock()

def set_password(pw):
    h = hashlib.sha256(pw.encode()).hexdigest()
    open(PW_FILE, 'w').write(h)

if not os.path.exists(PW_FILE):
    set_password('Arat2026')

def checkpw(pw):
    try: return open(PW_FILE).read().strip() == hashlib.sha256(pw.encode()).hexdigest()
    except: return False

def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout, r.returncode

def wg_dump():
    out, _ = sh(f'sudo wg show {WG_IF} dump')
    peers = {}
    lines = out.strip().split('\n')
    for ln in lines[1:]:  # first line = interface
        p = ln.split('\t')
        if len(p) >= 8:
            peers[p[0]] = {'pub': p[0], 'preshared': p[1], 'endpoint': p[2], 'ip': p[3] if p[3] != '(none)' else '',
                           'rx': int(p[5]), 'tx': int(p[6]), 'handshake': int(p[4]) if p[4] != '0' else 0}
    return peers

def conf_peers():
    # parse wg0.conf: [Peer] blocks with # name comment support: "# client: <name>|<GB>|<expiry_ts>"
    txt = open(CONF).read() if os.path.exists(CONF) else ''
    blocks = re.split(r'(?=\[Peer\])', txt)
    res = {}
    for b in blocks:
        if '[Peer]' not in b: continue
        pub = re.search(r'PublicKey\s*=\s*(\S+)', b)
        if not pub: continue
        meta = {'name': '?', 'totalGB': 0, 'expiry': 0}
        m = re.search(r'#\s*client:\s*(.+)', b)
        if m:
            parts = m.group(1).split('|')
            if len(parts) >= 1: meta['name'] = parts[0].strip()
            if len(parts) >= 2:
                try: meta['totalGB'] = int(parts[1])
                except: pass
            if len(parts) >= 3:
                try: meta['expiry'] = int(parts[2])
                except: pass
        ip = re.search(r'AllowedIPs\s*=\s*(\S+)', b)
        meta['allowedIPs'] = ip.group(1) if ip else ''
        res[pub.group(1)] = meta
    return res

def get_ip_usage():
    # next free 10.0.0.X
    used = set()
    for p in conf_peers().values():
        aip = p.get('allowedIPs', '')
        m = re.match(r'10\.0\.0\.(\d+)', aip)
        if m: used.add(int(m.group(1)))
    i = 2
    while i in used: i += 1
    if i > 254: return None
    return f'10.0.0.{i}'

def add_client(name, total_gb, days):
    priv, _ = sh('wg genkey')
    priv = priv.strip()
    pub, _ = sh(f'echo {priv} | wg pubkey')
    pub = pub.strip()
    psk, _ = sh('wg genpsk'); psk = psk.strip()
    ip = get_ip_usage()
    if not ip: return None, 'no free IPs'
    expiry = int(time.time()) + days * 86400 if days else 0
    priv_path = '/tmp/_psk.tmp'
    open(priv_path, 'w').write(psk)
    os.chmod(priv_path, 0o600)
    cmd = f'sudo wg set {WG_IF} peer {pub} allowed-ips {ip}/32 preshared-key {priv_path}'
    if expiry:
        cmd += f' && (echo "sudo wg set {WG_IF} peer {pub} remove" | at now + {days} days 2>/dev/null || true)'
    sh('which at >/dev/null || true')
    out, rc = sh(cmd)
    os.remove(priv_path)
    if rc != 0: return None, out
    with open(CONF, 'a') as f:
        f.write(f'\n[Peer]\n# client: {name} | {total_gb} | {expiry}\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n')
    conf_text = f'''[Interface]
PrivateKey = {priv}
Address = {ip}/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = {server_pub()[0]}
PresharedKey = {psk}
Endpoint = {EP}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
'''
    with open(f'/home/ubuntu/clients/{name}.conf', 'w') as f:
        os.makedirs('/home/ubuntu/clients', exist_ok=True)
        f.write(conf_text)
    qr_png(pub)
    return {'pub': pub, 'ip': ip, 'conf': conf_text, 'qr': '/qr/' + pub + '.png'}, ''

def qr_png(pub):
    out, rc = sh(f'qrencode -t PNG -o /home/ubuntu/clients/{pub}.png -s 8 /home/ubuntu/clients/{re.sub(r"[^A-Za-z0-9+/=]", "_", pub)}.conf 2>/dev/null || true')
    return rc

def server_pub():
    out, _ = sh(f'sudo wg show {WG_IF} public-key')
    return out.strip(), 0

def remove_client(pub):
    sh(f'sudo wg set {WG_IF} peer {pub} remove')
    txt = open(CONF).read()
    blocks = re.split(r'(?=\[Peer\])', txt)
    keep = [b for b in blocks if not (('[Peer]' in b) and (f'PublicKey = {pub}' in b))]
    open(CONF, 'w').write(''.join(keep))

def usage_thread():
    # check limits every 5 min
    while True:
        try:
            peers = wg_dump(); metas = conf_peers()
            for pub, meta in metas.items():
                if pub not in peers: continue
                used_gb = (peers[pub]['rx'] + peers[pub]['tx']) / 1024**3
                expired = meta['expiry'] and time.time() > meta['expiry']
                over = meta['totalGB'] and used_gb > meta['totalGB']
                cl = sh(f'sudo iptables -C FORWARD -s 10.0.0.0/24 -j DROP 2>/dev/null')[1]
                if expired or over:
                    sh(f'sudo wg set {WG_IF} peer {pub} remove')
                # else keep
        except Exception as e:
            pass
        time.sleep(300)

threading.Thread(target=usage_thread, daemon=True).start()

def status():
    peers = wg_dump(); metas = conf_peers()
    rows = []
    for pub, meta in metas.items():
        p = peers.get(pub, {'rx': 0, 'tx': 0, 'handshake': 0})
        used = round((p['rx'] + p['tx']) / 1024**3, 2)
        lim = meta['totalGB'] or 0
        exp = time.strftime('%Y-%m-%d', time.localtime(meta['expiry'])) if meta['expiry'] else '-'
        online = p['handshake'] and (time.time() - p['handshake'] < 180)
        rows.append({'name': meta['name'], 'ip': meta['allowedIPs'], 'usedGB': used, 'limitGB': lim,
                     'expiry': exp, 'online': bool(online), 'pub': pub})
    return rows

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _hdr(self, code=200, ct='text/html'):
        self.send_response(code); self.send_header('Content-Type', ct); self.end_headers()
    def _page(self, body, code=200):
        self._hdr(code); self.wfile.write(body.encode())
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == '/qrcheck':
            self._page('ok'); return
        if u.path.startswith('/static/menu'):
            self._page('noop'); return
        if u.path == '/login' or u.path == '/':
            self._page(LOGIN_PAGE); return
        ck = self.headers.get('Cookie', '')
        tok = dict(p.split('=') for p in ck.split('; ') if '=' in p).get('t', '')
        if tok not in sessions:
            self._page(LOGIN_PAGE); return
        if u.path.startswith('/qr/'):
            pub = u.path[4:].replace('.png', '')
            safe = re.sub(r'[^A-Za-z0-9+/=]', '_', pub)
            path = f'/home/ubuntu/clients/{safe}.png'
            if os.path.exists(path):
                self._hdr(200, 'image/png')
                self.wfile.write(open(path, 'rb').read())
            else:
                self._page('no qr', 404)
            return
        if u.path == '/api/status':
            self._hdr(200, 'application/json'); self.wfile.write(json.dumps({'rows': status()}).encode()); return
        # dashboard
        rows = status()
        cells = ''
        for r in rows:
            c = 'سبز' if r['online'] else 'قرمز'
            cells += f"<tr><td>{html.escape(r['name'])}</td><td>{r['ip']}</td><td>{r['usedGB']} / {r['limitGB'] or '∞'}</td><td>{r['expiry']}</td><td>{'🟢' if r['online'] else '🔴'}</td><td><a href=\"/qr/{r['pub']}.png\">QR</a> | <form style=display:inline method=post action=/del><input type=hidden name=pub value='{r['pub']}'><button>حذف</button></form></td></tr>"
        self._page(DASH_PAGE.replace('{rows}', cells))
    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        ln = int(self.headers.get('Content-Length', 0))
        form = urllib.parse.parse_qs(self.rfile.read(ln).decode())
        if u.path == '/login':
            if checkpw(form.get('pw', [''])[0]):
                tok = base64.b64encode(os.urandom(24)).decode()
                sessions[tok] = time.time()
                self.send_response(303); self.send_header('Set-Cookie', f't={tok}; Path=/'); self.send_header('Location', '/'); self.end_headers()
            else:
                self._page(LOGIN_PAGE.replace('{err}', 'پسورد غلطه'))
            return
        ck = self.headers.get('Cookie', '')
        tok = dict(p.split('=') for p in ck.split('; ') if '=' in p).get('t', '')
        if tok not in sessions:
            self._page(LOGIN_PAGE); return
        if u.path == '/add':
            name = form.get('name', ['client'])[0][:24]
            gb = int(form.get('gb', ['0'])[0] or 0)
            days = int(form.get('days', ['0'])[0] or 0)
            res, err = add_client(name, gb, days)
            self._hdr(303); self.send_header('Location', '/'); self.end_headers()
        elif u.path == '/del':
            remove_client(form.get('pub', [''])[0])
            self._hdr(303); self.send_header('Location', '/'); self.end_headers()

LOGIN_PAGE = '''<!doctype html><html dir=rtl><meta charset=utf-8><title>AratPanel</title>
<style>body{font-family:sans-serif;background:#111;color:#eee;display:grid;place-items:center;height:100vh}
form{background:#1c1c1c;padding:2rem;border-radius:12px}input{display:block;margin:8px 0;padding:8px;border-radius:6px;border:1px solid #444;background:#222;color:#eee}
button{padding:8px 16px;background:#0a84ff;color:#fff;border:0;border-radius:6px}</style>
<form method=post action=/login><h2>🔐 AratPanel</h2>{err}<input name=pw type=password placeholder=پسورد><button>ورود</button></form>'''

DASH_PAGE = '''<!doctype html><html dir=rtl><meta charset=utf-8><title>AratPanel</title><meta http-equiv=refresh content=60>
<style>body{font-family:sans-serif;background:#111;color:#eee;padding:1rem}table{border-collapse:collapse;width:100%}
td,th{padding:8px;border-bottom:1px solid #333;text-align:right}button{background:#e33;color:#fff;border:0;border-radius:4px;padding:2px 8px}
form.add{background:#1c1c1c;padding:1rem;border-radius:10px;margin:1rem 0}input{padding:6px;border-radius:5px;border:1px solid #444;background:#222;color:#eee;margin-inline-end:6px}
.add button{background:#0a84ff;padding:8px 14px}</style>
<h2>WireGuard</h2>
<form class=add method=post action=/add>اسم: <input name=name required> حجم (GB، خالی=نامحدود): <input name=gb type=number min=0> روز (خالی=بی‌نهایت): <input name=days type=number min=0> <button>＋ ساخت کلاینت</button></form>
<table><tr><th>اسم</th><th>IP</th><th>مصرف (GB)</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr>{rows}</table>
<p style=opacity:.6>توجه: سقف مصرف تا کلاینتِ جدید اعمال می‌شه؛ حذف خودکار بعد از عبور از سقف طبق چکر ۵ دقیقه‌ای.</p>'''

socketserver.ThreadingTCPServer.allow_reuse_address = True
class Srv(socketserver.ThreadingTCPServer):
    daemon_threads = True
print('AratPanel running on http://0.0.0.0:', PORT, flush=True)
Srv(('0.0.0.0', PORT), H).serve_forever()
