#!/usr/bin/env python3
import json
import time
import requests
from pathlib import Path
from collections import defaultdict

COWRIE_LOG = Path("/home/hyper/honeypot/cowrie/logs/cowrie.json")
WEBHOOK_URL = "YOUR_N8N_WEBHOOK_URL"
WEBHOOK_TOKEN = "YOUR_WEBHOOK_TOKEN"
STATE_FILE = Path("/home/hyper/honeypot/processed_sessions.json")

def load_processed():
    if STATE_FILE.exists():
        return set(json.loads(STATE_FILE.read_text()))
    return set()

def save_processed(processed):
    STATE_FILE.write_text(json.dumps(list(processed)))

def parse_log():
    sessions = defaultdict(lambda: {
        "login_attempts": [],
        "login_success": None,
        "commands": [],
        "files_downloaded": [],
        "src_ip": None,
        "timestamp": None,
        "duration": None,
        "closed": False
    })

    if not COWRIE_LOG.exists():
        return sessions

    with open(COWRIE_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            sid = event.get("session")
            if not sid:
                continue

            eid = event.get("eventid", "")

            if eid == "cowrie.session.connect":
                sessions[sid]["src_ip"] = event.get("src_ip")
                sessions[sid]["timestamp"] = event.get("timestamp")

            elif eid == "cowrie.login.failed":
                sessions[sid]["login_attempts"].append({
                    "username": event.get("username"),
                    "password": event.get("password")
                })

            elif eid == "cowrie.login.success":
                sessions[sid]["login_success"] = {
                    "username": event.get("username"),
                    "password": event.get("password")
                }
                sessions[sid]["login_attempts"].append({
                    "username": event.get("username"),
                    "password": event.get("password")
                })

            elif eid == "cowrie.command.input":
                sessions[sid]["commands"].append(event.get("input", ""))

            elif eid == "cowrie.session.file_download":
                sessions[sid]["files_downloaded"].append(
                    event.get("url") or event.get("shasum", "unknown")
                )

            elif eid == "cowrie.session.closed":
                sessions[sid]["duration"] = event.get("duration")
                sessions[sid]["closed"] = True

    return sessions

def send_session(session_id, data):
    payload = {
        "session_id": session_id,
        "src_ip": data["src_ip"],
        "timestamp": data["timestamp"],
        "duration": str(data["duration"] or 0),
        "login_success": data["login_success"],
        "login_attempts": data["login_attempts"],
        "commands": data["commands"],
        "files_downloaded": data["files_downloaded"]
    }
    try:
        r = requests.post(
            WEBHOOK_URL,
            json=payload,
            headers={"X-Honeypot-Token": WEBHOOK_TOKEN},
            timeout=10
        )
        print(f"✓ Sesión {session_id[:8]} enviada → {r.status_code}")
        return True
    except Exception as e:
        print(f"✗ Error enviando {session_id[:8]}: {e}")
        return False

def main():
    print("🔍 Log-shipper iniciado — vigilando cowrie.json")
    processed = load_processed()

    while True:
        sessions = parse_log()
        nuevas = 0

        for sid, data in sessions.items():
            if data["closed"] and sid not in processed:
                if send_session(sid, data):
                    processed.add(sid)
                    save_processed(processed)
                    nuevas += 1

        if nuevas == 0:
            pass  # silencioso si no hay sesiones nuevas
        
        time.sleep(30)  # revisa cada 30 segundos

if __name__ == "__main__":
    main()
