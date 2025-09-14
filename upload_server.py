#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# PoC webserver voor TL-WR841N eindopdracht.
# Implementeert geselecteerde endpoints zoals aangetroffen in de firmware-UI:
# - /web/login/LoginRpm.htm  (en alias /web/userRpm/LoginRpm.htm)  → login pass-the-
# hash / geen CSRF
# - /web/login/encrypt.js            → placeholder voor client-side "hashing"
# - /web/userRpm/SoftwareUpgradeRpm.htm                              → insecure file upload (firmware zonder validatie)
# - /web/userRpm/BakNRestoreRpm.htm                                       → restore multipart (CSRF/config injection)
# - /web/userRpm/DiagnosticRpm.htm                                            → command injection via ping_addr
# - /web/userRpm/WlanAdvRpm.htm                                                → stored XSS via ssid

from http.server import HTTPServer, BaseHTTPRequestHandler
import os, traceback, cgi, urllib.parse, subprocess

# ---------- Config ----------
UPLOAD_DIR = "uploads"
SSID_STORE_PATH = os.path.join(UPLOAD_DIR, "ssid.txt")

ROUTE_LOGIN_USERRPM = "/web/userRpm/LoginRpm.htm"
ROUTE_LOGIN_LOGIN   = "/web/login/LoginRpm.htm"
ROUTE_ENCRYPT_JS    = "/web/login/encrypt.js"

ROUTE_FW_UPGRADE    = "/web/userRpm/SoftwareUpgradeRpm.htm"
ROUTE_RESTORE       = "/web/userRpm/BakNRestoreRpm.htm"
ROUTE_DIAG          = "/web/userRpm/DiagnosticRpm.htm"
ROUTE_WLAN_ADV      = "/web/userRpm/WlanAdvRpm.htm"

# ---------- Helper mixin ----------
class SimpleHandler(BaseHTTPRequestHandler):
    def _send(self, code:int, body:bytes, ctype:str="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_urlencoded(self):
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length).decode(errors="replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(data, keep_blank_values=True).items()}

    def _parse_multipart(self):
        env = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE":   self.headers.get("Content-Type"),
            "CONTENT_LENGTH": self.headers.get("Content-Length"),
        }
        
        return cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env)

    def _ensure_upload_dir(self):
        os.makedirs(UPLOAD_DIR, exist_ok=True)

    def log_message(self, fmt, *args):
        # iets stiller; comment uit als je alles wilt zien
        return

# ---------- Hoofdhandler ----------
class Handler(SimpleHandler):

    # ---------------- GET ----------------
    def do_GET(self):
        try:
            if self.path == "/":
                self._send(200, b"OK\n"); return

            # Login UI (beide paden, voor compat met testplan/firmware)
            if self.path in (ROUTE_LOGIN_LOGIN, ROUTE_LOGIN_USERRPM):
                html = f"""<!doctype html><meta charset="utf-8"><title>LoginRpm PoC</title>
<h1>LoginRpm PoC</h1>
<form method="POST" action="{self.path}">
  <label>User:</label><input name="username" value="admin"><br>
  <label>Password:</label><input name="password" value=""><br>
  <label>Hash:</label><input name="hash" value=""><br>
  <button type="submit">Login</button>
</form>
<p><em>Deze PoC accepteert een "hash" zonder nonce/CSRF (pass-the-hash, geen bescherming).</em></p>
<script src="/web/login/encrypt.js"></script>
""".encode()
                self._send(200, html, "text/html; charset=utf-8"); return

            # encrypt.js placeholder (client-side hashing façade)
            if self.path == ROUTE_ENCRYPT_JS:
                js = (
                    "// PoC encrypt.js (placeholder): zou normaal client-side hashing doen\n"
                    "function encrypt(p){ return 'md5('+p+')'; }\n"
                ).encode()
                self._send(200, js, "application/javascript"); return

            # Diagnostic test UI
            if self.path == ROUTE_DIAG:
                html = f"""<!doctype html><meta charset="utf-8"><title>DiagnosticRpm PoC</title>
<h1>DiagnosticRpm PoC</h1>
<form method="POST" action="{ROUTE_DIAG}">
  <label>Host/IP:</label>
  <input name="ping_addr" value="8.8.8.8">
  <button type="submit">Ping</button>
</form>
<p>Voorbeeld payload: <code>8.8.8.8; cat /etc/passwd</code></p>
""".encode()
                self._send(200, html, "text/html; charset=utf-8"); return

            # WLAN-advanced UI (stored XSS)
            if self.path == ROUTE_WLAN_ADV:
                current_ssid = self._read_ssid()
                html = f"""<!doctype html><meta charset="utf-8"><title>WlanAdvRpm PoC</title>
<h1>Wlan Advanced (SSID)</h1>
<form method="POST" action="{ROUTE_WLAN_ADV}">
  <label>SSID:</label>
  <input name="ssid" value="{current_ssid}">
  <button type="submit">Save</button>
</form>
<p>Current SSID: <strong>{current_ssid}</strong></p>
<p><em>Let op: geen sanitization/encoding → stored XSS demonstratie.</em></p>
""".encode()
                self._send(200, html, "text/html; charset=utf-8"); return

            # Firmware upgrade UI (optioneel, handig voor screenshots)
            if self.path == ROUTE_FW_UPGRADE:
                html = f"""<!doctype html><meta charset="utf-8"><title>SoftwareUpgradeRpm PoC</title>
<h1>Firmware Upgrade</h1>
<form method="POST" action="{ROUTE_FW_UPGRADE}" enctype="multipart/form-data">
  <input type="file" name="firmware">
  <button type="submit">Upload</button>
</form>
<p><em>Geen type/size/signature-validatie (PoC insecure upload).</em></p>
""".encode()
                self._send(200, html, "text/html; charset=utf-8"); return

            self.send_error(404, "Not Found")
        except Exception as e:
            try: self._send(500, b"Internal Server Error\n")
            finally: print(("GET error:\n%s\n\n%s" % (e, traceback.format_exc())))

    # ---------------- POST ----------------
    def do_POST(self):
        try:
            if self.path in (ROUTE_LOGIN_LOGIN, ROUTE_LOGIN_USERRPM):
                self.handle_login(); return
            if self.path == ROUTE_FW_UPGRADE:
                self.handle_fw_upgrade(); return
            if self.path == ROUTE_RESTORE:
                self.handle_restore(); return
            if self.path == ROUTE_DIAG:
                self.handle_diagnostic(); return
            if self.path == ROUTE_WLAN_ADV:
                self.handle_wlan_adv(); return
            self.send_error(404, "Not Found")
        except Exception as e:
            try: self._send(500, b"Internal Server Error\n")
            finally: print(("POST error:\n%s\n\n%s" % (e, traceback.format_exc())))

    # ---------- Specifieke handlers ----------
    # LoginRpm – pass-the-hash / geen CSRF / geen nonce
    def handle_login(self):
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("multipart/form-data"):
            form = self._parse_multipart()
            username = form["username"].value if "username" in form else ""
            password = form["password"].value if "password" in form else ""
            hsh      = form["hash"].value      if "hash" in form else ""
        else:
            fields = self._parse_urlencoded()
            username = fields.get("username", "")
            password = fields.get("password", "")
            hsh      = fields.get("hash", "")

       
        # - accepteert 'hash' zonder nonce/CSRF
        # - als er een 'hash' present is, beschouwt PoC dit als geldig (pass-the-hash)
        # - geen rate limiting / lockout
        if hsh:
            body = f"Login OK (hash accepted without nonce): user={username}, hash={hsh}\n".encode()
            self._send(200, body); return

        # fallback: accepteer elk wachtwoord 'admin' of leeg (illustratief)
        if username == "admin" and (password == "admin" or password == ""):
            self._send(200, b"Login OK (weak password accepted)\n"); return

        self._send(401, b"Login failed\n")

    # SoftwareUpgradeRpm – insecure firmware upload (geen validatie)
    def handle_fw_upgrade(self):
        self._ensure_upload_dir()
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            self.send_error(400, "Expected multipart/form-data"); return

        form = self._parse_multipart()
        # accepteer verschillende veldnamen die vaak voorkomen
        candidate_names = ["firmware", "file", "fw", "upload", "filename"]
        fileitem = None
        for name in candidate_names:
            if name in form:
                fileitem = form[name]; break
        if fileitem is None or getattr(fileitem, "file", None) is None:
            self.send_error(400, "Missing firmware file field"); return

        raw_name = getattr(fileitem, "filename", None) or "firmware.bin"
        fname = os.path.basename(raw_name)
        out_path = os.path.join(UPLOAD_DIR, f"firmware_{fname}")

        with open(out_path, "wb") as f:
            while True:
                chunk = fileitem.file.read(64*1024)
                if not chunk: break
                f.write(chunk)

        # Geen type/signature/size-validatie 
        msg = f"Firmware uploaded (NOT validated): {out_path}\n".encode()
        self._send(200, msg)

    # BakNRestoreRpm – config restore (CSRF/config injection)
    def handle_restore(self):
        self._ensure_upload_dir()
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            self.send_error(400, "Expected multipart/form-data"); return

        form = self._parse_multipart()
        fileitem = form["config"] if "config" in form else None
        if fileitem is None or getattr(fileitem, "file", None) is None:
            self.send_error(400, "Missing file field 'config'"); return

        raw_name = getattr(fileitem, "filename", None) or "backup.bin"
        fname = os.path.basename(raw_name)
        out_path = os.path.join(UPLOAD_DIR, f"restore_{fname}")
        with open(out_path, "wb") as f:
            while True:
                chunk = fileitem.file.read(64*1024)
                if not chunk: break
                f.write(chunk)

        # Geen CSRF, geen verify - PoC voor config injection via CSRF
        self._send(200, f"Restore OK: saved to {out_path}\n".encode())

    # DiagnosticRpm – command injection via ping_addr
    def handle_diagnostic(self):
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("multipart/form-data"):
            form = self._parse_multipart()
            ping_addr = form["ping_addr"].value if "ping_addr" in form else None
        else:
            fields = self._parse_urlencoded()
            ping_addr = fields.get("ping_addr")

        if not ping_addr:
            self.send_error(400, "Missing field 'ping_addr'"); return

        # shell=True + ongefilterde interpolatie
        cmd = f"sh -lc 'ping -c 1 {ping_addr} 2>&1 || true'"
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        output = (proc.stdout or "") + (proc.stderr or "")
        if not output: output = "(no output)\n"
        if len(output) > 64_000:
            output = output[:64_000] + "\n--[truncated]--\n"

        body = f"Diagnostic output for input [{ping_addr}]:\n\n{output}".encode()
        self._send(200, body)

    # WlanAdvRpm – stored XSS via ssid
    def handle_wlan_adv(self):
        ctype = self.headers.get("Content-Type", "")
        if ctype.startswith("multipart/form-data"):
            form = self._parse_multipart()
            ssid = form["ssid"].value if "ssid" in form else None
        else:
            fields = self._parse_urlencoded()
            ssid = fields.get("ssid")

        if ssid is None:
            self.send_error(400, "Missing field 'ssid'"); return

        # Geen sanitization/encoding – exact opslaan voor stored XSS
        self._write_ssid(ssid)
        self._send(200, f"SSID updated to: {ssid}\n".encode())

    # ---------- SSID storage ----------
    def _read_ssid(self) -> str:
        try:
            with open(SSID_STORE_PATH, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except FileNotFoundError:
            return "TP-LINK_841N"

    def _write_ssid(self, value: str):
        self._ensure_upload_dir()
        with open(SSID_STORE_PATH, "w", encoding="utf-8", errors="ignore") as f:
            f.write(value)

# ---------- Main ----------
if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
    print(f"[i] Listening on 0.0.0.0:{port}")
    print("    Routes:")
    print(f"      - {ROUTE_LOGIN_LOGIN}  (alias {ROUTE_LOGIN_USERRPM})  LoginRpm PoC (hash accepted, no CSRF)")
    print(f"      - {ROUTE_ENCRYPT_JS}   encrypt.js placeholder")
    print(f"      - {ROUTE_FW_UPGRADE}   Firmware upload (NO validation)")
    print(f"      - {ROUTE_RESTORE}      Config restore (CSRF/config injection PoC)")
    print(f"      - {ROUTE_DIAG}         DiagnosticRpm (command injection via ping_addr)")
    print(f"      - {ROUTE_WLAN_ADV}     WlanAdvRpm (stored XSS via ssid)")
    print(f"    Upload dir: {UPLOAD_DIR} (SSID store: {SSID_STORE_PATH})")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
