"""
DeadDrop — LAN file transfer with client-side AES-256-GCM encryption.

Browser encrypts files before upload; the server never sees plaintext.
Encrypted blobs land in /storage. On download the browser decrypts
locally, then the server securely wipes and deletes the file.

Usage:
    pip install flask
    python cipherdrop.py
"""

import json
import os
import socket
import sys
import time
from pathlib import Path

from flask import Flask, request, render_template_string, send_file


ROOT    = Path(__file__).resolve().parent
CONFIG  = ROOT / "config.json"
STORAGE = ROOT / "storage"
INDEX   = ROOT / "static" / "index.html"
STYLES  = ROOT / "static" / "styles.css"
SCRIPT  = ROOT / "static" / "app.js"


with open(CONFIG, encoding="utf-8") as f:
    cfg = json.load(f)

HOST = cfg.get("host", "0.0.0.0")
PORT = cfg.get("port", 9999)


with open(STYLES, encoding="utf-8") as f:
    _css = f.read()
with open(SCRIPT, encoding="utf-8") as f:
    _js = f.read()
with open(INDEX, encoding="utf-8") as f:
    _html = f.read().replace("/*CSS*/", _css).replace("/*JS*/", _js)


STORAGE.mkdir(exist_ok=True)

app = Flask(__name__)


def _local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _file_list() -> list[tuple[str, float, int]]:
    """Return [(filename, mtime, size_bytes), ...] newest first."""
    entries = []
    for p in STORAGE.iterdir():
        if p.is_file():
            entries.append((p.name, p.stat().st_mtime, p.stat().st_size))
    entries.sort(key=lambda x: x[1], reverse=True)
    return entries




@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            dest = STORAGE / f.filename
            f.save(str(dest))
            ts = time.strftime("%H:%M:%S")
            print(f"  [+ {ts}] received: {f.filename}  ({dest.stat().st_size:,} bytes)")
        else:
            print("  [!] POST with no file attached")

    files = _file_list()
    return render_template_string(_html, files=files)


@app.route("/download/<filename>")
def download(filename: str):
    path = STORAGE / filename
    if not path.exists():
        return "not found", 404
    return send_file(str(path), as_attachment=True)


@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename: str):
    path = STORAGE / filename
    if not path.exists():
        return "not found", 404
    try:
        size = path.stat().st_size
        # secure overwrite with zeros before unlink
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
        path.unlink()
        ts = time.strftime("%H:%M:%S")
        print(f"  [- {ts}] wiped & deleted: {filename}  ({size:,} bytes)")
        return "ok", 200
    except Exception as e:
        print(f"  [!] delete failed: {filename} — {e}")
        return "error", 500




def main():
    ip = _local_ip()
    print(f"""
  ╔══════════════════════════════════════════╗
  ║            DeadDrop                      ║
  ╠══════════════════════════════════════════╣
  ║  Local    https://localhost:{PORT:<5}    ║
  ║  Network  https://{ip}:{PORT:<5}         ║
  ║  Storage  {str(STORAGE):<30}             ║
  ╚══════════════════════════════════════════╝
""")
    app.run(host=HOST, port=PORT, ssl_context="adhoc")


if __name__ == "__main__":
    main()
