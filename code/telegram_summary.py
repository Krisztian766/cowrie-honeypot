#!/usr/bin/env python3
import collections
import datetime
import json
import os
import sys
import urllib.request
import urllib.parse

LOG_FILE = "/opt/cowrie/log/cowrie.json"
STATE_FILE = "/opt/cowrie/secrets/.last_summary"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
WINDOW_HOURS = 6


def send_telegram(text):
    if not BOT_TOKEN or not CHAT_ID:
        print("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID hiányzik, összefoglaló kihagyva", file=sys.stderr)
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
    }).encode()
    urllib.request.urlopen(url, data=data, timeout=10)


def parse_ts(ts):
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def main():
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=WINDOW_HOURS)

    sessions = set()
    logins_ok = 0
    logins_fail = 0
    downloads = 0
    ip_counter = collections.Counter()

    try:
        with open(LOG_FILE) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = parse_ts(e.get("timestamp", ""))
                if ts is None or ts < since:
                    continue
                eventid = e.get("eventid")
                src_ip = e.get("src_ip")
                if src_ip:
                    ip_counter[src_ip] += 1
                if eventid == "cowrie.session.connect":
                    sessions.add(e.get("session"))
                elif eventid == "cowrie.login.success":
                    logins_ok += 1
                elif eventid == "cowrie.login.failed":
                    logins_fail += 1
                elif eventid == "cowrie.session.file_download":
                    downloads += 1
    except FileNotFoundError:
        print(f"Log fájl nem található: {LOG_FILE}", file=sys.stderr)
        return

    top_ips = ip_counter.most_common(5)
    top_ips_text = "\n".join(f"  {ip} — {n} esemény" for ip, n in top_ips) or "  (nincs adat)"

    msg = (
        f"📊 <b>Cowrie honeypot összefoglaló</b> (utolsó {WINDOW_HOURS} óra)\n"
        f"Kapcsolatok: {len(sessions)}\n"
        f"Sikeres login: {logins_ok}\n"
        f"Sikertelen login: {logins_fail}\n"
        f"Malware letöltés: {downloads}\n"
        f"Top támadó IP-k:\n{top_ips_text}"
    )
    send_telegram(msg)


if __name__ == "__main__":
    main()
