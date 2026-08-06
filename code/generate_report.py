#!/usr/bin/env python3
"""Aggregate all Cowrie logs into data/ files used by the HTML threat report.

Single full pass over every log rotation (plain + .gz) in /opt/cowrie/log,
computing: daily event volume, per-IP totals, credential combo totals, and
the malware/download timeline. Re-run any time to refresh the report data.
"""
import gzip
import json
import collections
import glob
import os

LOG_DIR = "/opt/cowrie/log"
OUT_DIR = "/root/cowrie-honeypot-export/data"


def open_any(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, "r", errors="replace")


def main():
    daily_events = collections.Counter()
    daily_logins = collections.Counter()
    ip_counts = collections.Counter()
    combo_counts = collections.Counter()
    combo_success = collections.Counter()
    downloads = []  # (timestamp, src_ip, shasum, url)

    paths = sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json*")))
    print(f"Scanning {len(paths)} log files...")

    for path in paths:
        with open_any(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue

                ts = e.get("timestamp", "")
                day = ts[:10] if len(ts) >= 10 else None
                eventid = e.get("eventid", "")

                if day:
                    daily_events[day] += 1

                if "src_ip" in e:
                    ip_counts[e["src_ip"]] += 1

                if eventid in ("cowrie.login.success", "cowrie.login.failed"):
                    if day:
                        daily_logins[day] += 1
                    combo = f"{e.get('username', '?')} / {e.get('password', '?')}"
                    combo_counts[combo] += 1
                    if eventid == "cowrie.login.success":
                        combo_success[combo] += 1

                if eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
                    downloads.append({
                        "timestamp": ts,
                        "src_ip": e.get("src_ip"),
                        "shasum": e.get("shasum"),
                        "url": e.get("url"),
                    })

    os.makedirs(OUT_DIR, exist_ok=True)

    with open(os.path.join(OUT_DIR, "daily_volume.json"), "w") as f:
        json.dump({
            "events_per_day": dict(sorted(daily_events.items())),
            "logins_per_day": dict(sorted(daily_logins.items())),
        }, f, indent=2)

    with open(os.path.join(OUT_DIR, "ip_counts.json"), "w") as f:
        json.dump(dict(ip_counts.most_common()), f, indent=2)

    with open(os.path.join(OUT_DIR, "credential_counts.json"), "w") as f:
        json.dump([
            {"combo": combo, "count": n, "ever_succeeded": bool(combo_success.get(combo))}
            for combo, n in combo_counts.most_common()
        ], f, indent=2)

    with open(os.path.join(OUT_DIR, "downloads_timeline.json"), "w") as f:
        json.dump(downloads, f, indent=2)

    print(f"Unique IPs: {len(ip_counts)}, unique combos: {len(combo_counts)}, downloads: {len(downloads)}")
    print(f"Day range: {min(daily_events)} .. {max(daily_events)}")


if __name__ == "__main__":
    main()
