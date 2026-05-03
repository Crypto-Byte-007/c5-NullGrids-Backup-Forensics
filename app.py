#!/usr/bin/env python3
"""
Challenge 5 — Disk/Forensics
Players are given a tarball of "employee files" and must find the hidden flag.
This script generates the disk image (tarball) when the container starts.
The actual challenge binary is challenge_disk.tar.gz available at /download
"""

import os, tarfile, base64, io, struct, zlib, tempfile
from flask import Flask, send_file, jsonify

app = Flask(__name__)
FLAG = open("flag.txt").read().strip()

DISK_PATH = os.path.join(tempfile.gettempdir(), "nullgrids_backup.tar.gz")

def make_png_with_hidden_data(flag: str) -> bytes:
    """Create a minimal valid PNG with the flag appended after IEND (steganography-lite)."""
    # Minimal 1x1 red PNG
    PNG_HEADER = b'\x89PNG\r\n\x1a\n'
    def chunk(name, data):
        c = struct.pack('>I', len(data)) + name + data
        return c + struct.pack('>I', zlib.crc32(name + data) & 0xFFFFFFFF)
    
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)  # 1x1 RGB
    idat_raw = b'\x00\xff\x00\x00'  # filter + RGB red pixel
    idat_data = zlib.compress(idat_raw)
    
    png = PNG_HEADER
    png += chunk(b'IHDR', ihdr_data)
    png += chunk(b'IDAT', idat_data)
    png += chunk(b'IEND', b'')
    # Append hidden data after IEND (common steganography spot)
    png += b'\n# nullgrids_hidden: ' + base64.b64encode(flag.encode()) + b'\n'
    return png

def build_disk_image():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:

        def add_file(name, content):
            if isinstance(content, str):
                content = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))

        # Realistic employee backup structure
        add_file("nullgrids_backup/README.txt",
            "NullGrids Q1 2026 Employee Backup\nGenerated: 2026-01-15 03:00 UTC\nDo not distribute.\n")

        add_file("nullgrids_backup/employees/alice/notes.txt",
            "Project: Infra Migration\nStatus: In progress\nDeadline: 2026-02-28\n")

        add_file("nullgrids_backup/employees/alice/todo.md",
            "- [ ] Review firewall rules\n- [x] Update SSH keys\n- [ ] Audit cron jobs\n")

        add_file("nullgrids_backup/employees/bob/notes.txt",
            "Worked on platform stability.\nFixed memory leak in service mesh.\n")

        add_file("nullgrids_backup/employees/bob/meeting_notes.txt",
            "Q1 All-hands:\n- Budget approved for 2026\n- New hires: 3 engineers\n- RED TEAM engagement scheduled March\n")

        # More red herrings
        add_file("nullgrids_backup/employees/bob/ssh_keys.txt",
            "Public keys only:\nssh-rsa AAAAB3NzaC1yc... bob@nullgrids\n# Flag encoded? No.\n" + base64.b64encode(b"nullgrids{just_k1dd1ng_1ts_n0t_h3r3}").decode() + "\n")

        add_file("nullgrids_backup/system/debug.log.1",
            "WARN: system memory high\n" * 50 + "ERROR: exfil_test payload is " + base64.b64encode(b"decoy_data_do_not_flag").decode() + "\n")

        # Red herring: base64 string that decodes to something innocent
        add_file("nullgrids_backup/employees/charlie/encoded_note.txt",
            "Encoded reminder:\n" + base64.b64encode(b"Review Q1 salary adjustments before March 1st").decode() + "\n")

        add_file("nullgrids_backup/employees/charlie/access_review.txt",
            "Reviewed: alice (ok), bob (ok), svc_audit (FLAGGED - unusual access pattern)\n")

        # Red herring: a "passwords.txt" with fake data
        add_file("nullgrids_backup/shared/passwords.txt",
            "# OLD PASSWORDS - DEPRECATED #\nwiki: nullgrids2024!\njira: Jira@2023\n# These have been rotated.\n")

        # Hidden: the flag is inside a PNG (after IEND chunk)
        png_data = make_png_with_hidden_data(FLAG)
        add_file("nullgrids_backup/shared/company_logo.png", png_data)

        # Another red herring: a .env-like file with junk credentials
        add_file("nullgrids_backup/system/.env.bak",
            "# OUTDATED\nDB_PASS=old_password_123\nAPI_KEY=AAAA-BBBB-CCCC\n")

        # Misleading: a file called "flag_draft.txt" that contains nothing useful
        add_file("nullgrids_backup/shared/flag_draft.txt",
            "Internal flag process:\n1. Submit incident\n2. Assign severity\n3. Escalate to CIRT\n(This file is not the flag you seek.)\n")

    with open(DISK_PATH, 'wb') as f:
        f.write(buf.getvalue())


build_disk_image()

@app.route("/")
def index():
    return """
    <html><head><title>NullGrids Forensics</title></head>
    <body style='font-family:monospace;background:#111;color:#ff6600;padding:40px'>
    <h1>NullGrids Internal Forensics Portal</h1>
    <p>A backup archive from a compromised workstation has been recovered.</p>
    <p>Download and analyze it:</p>
    <code>GET /download</code>
    <br><br>
    <p>Submit your decoded flag to the CTF platform.</p>
    </body></html>
    """

@app.route("/download")
def download():
    return send_file(DISK_PATH, as_attachment=True, download_name="nullgrids_backup.tar.gz")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
