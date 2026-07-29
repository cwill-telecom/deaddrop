# DeadDrop

End-to-end encrypted file transfer over your local network. Files are encrypted with AES-256-GCM in the browser before upload — the server, your router, and anyone on the wire never sees plaintext content or original filenames.

## How it works

```
Browser                          Flask server                     Recipient browser
───────                          ────────────                     ─────────────────
Pick file + passphrase
    │
PBKDF2 → 256-bit key
    │
AES-256-GCM encrypts
  file content + filename
    │                               POST / (encrypted blob)
    └──────────────────────────────────────>│  saves as file_NNN.dat
                                            │
                                            │  GET /download/file_NNN.dat
    Enter passphrase               <────────┘
    │
PBKDF2 → same key
    │
AES-256-GCM decrypts
  filename + file content
    │
Save original file to disk
    │                               POST /delete/file_NNN.dat
    └──────────────────────────────────────>│  zero-fill overwrite + unlink
```

## Quick Start

```bash
pip install flask
python deaddrop.py
```

Opens on `https://localhost:9999` with a self-signed TLS certificate. Other devices on your LAN connect via `https://<your-ip>:9999` (printed in the console on startup).

Accept the browser warning about the self-signed cert — traffic is encrypted on the wire but the cert isn't from a public CA.

## Features

- **Client-side encryption** — AES-256-GCM via Web Crypto API. Key derived with PBKDF2 (250,000 iterations, SHA-256)
- **Encrypted filenames** — original filenames are encrypted alongside the file content. Random names on disk
- **Auto-delete after download** — server securely overwrites the encrypted blob with zeros before unlinking
- **Drag-and-drop upload** — click the zone or drag files onto it
- **Self-signed HTTPS** — no plaintext on the wire, even on LAN
- **Zero dependencies** beyond Flask — all crypto is Web Crypto API (built into every modern browser)

## Configuration

Edit `config.json`:

```json
{
    "host": "0.0.0.0",
    "port": 9999,
    "max_file_size_mb": 500
}
```

## Storage

Encrypted blobs live in `./storage/`. They're named `file_<timestamp>.dat`. Contents are unintelligible without the passphrase used at upload time.

## Requirements

- Python 3.9+
- Flask 3.0+
- A modern browser (Chrome, Firefox, Edge, Safari — all support Web Crypto API)
