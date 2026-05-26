#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, os, pathlib

REPORTS_DIR = pathlib.Path("/home/hyper/honeypot/reportes")
REPORTS_DIR.mkdir(exist_ok=True)
TOKEN = "YOUR_WEBHOOK_TOKEN"

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("X-Honeypot-Token") != TOKEN:
            self.send_response(401)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))

        filename = body.get("filename", "reporte.md")
        content  = body.get("content", "")

        filepath = REPORTS_DIR / filename
        filepath.write_text(content, encoding="utf-8")
        print(f"✓ Guardado: {filepath}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args):
        pass  # silencia logs de HTTP

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 9000), Handler)
    print("Servidor de reportes escuchando en :9000")
    server.serve_forever()
