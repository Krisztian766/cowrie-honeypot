#!/bin/bash
# Re-runs the full threat-report pipeline and pushes any changes.
# Intended to run daily via systemd timer (cowrie-report-refresh.timer).
set -euo pipefail

REPO_DIR="/root/cowrie-honeypot-export"
LOG_PREFIX="[cowrie-report-refresh]"

echo "$LOG_PREFIX Starting refresh at $(date -u +%FT%TZ)"

echo "$LOG_PREFIX Running generate_report.py"
python3 /opt/cowrie/generate_report.py

echo "$LOG_PREFIX Running geoip_lookup.py"
python3 /opt/cowrie/geoip_lookup.py

echo "$LOG_PREFIX Regenerating legacy full-text breakdowns"
python3 - <<'PYEOF'
import json
ip_counts = json.load(open('/root/cowrie-honeypot-export/data/ip_counts.json'))
total = sum(ip_counts.values())
with open('/root/cowrie-honeypot-export/data/attacker_ips_full.txt', 'w') as f:
    f.write(f'# Osszes esemeny (nem csak login): {total}, egyedi IP: {len(ip_counts)}\n')
    for ip, n in ip_counts.items():
        f.write(f'{n:8d}  {ip}\n')

creds = json.load(open('/root/cowrie-honeypot-export/data/credential_counts.json'))
total_c = sum(c['count'] for c in creds)
success_c = sum(c['count'] for c in creds if c['ever_succeeded'])
with open('/root/cowrie-honeypot-export/data/credentials_full.txt', 'w') as f:
    f.write(f'# Osszes probalkozas: {total_c}, sikeres: {success_c}\n')
    f.write(f'# Egyedi user/jelszo kombinacio: {len(creds)}\n\n')
    for c in creds:
        tag = ' [SIKERES is volt]' if c['ever_succeeded'] else ''
        f.write(f"{c['count']:8d}  {c['combo']}{tag}\n")
PYEOF

echo "$LOG_PREFIX Running render_report.py"
python3 /opt/cowrie/render_report.py

cd "$REPO_DIR"

if git diff --quiet data/ docs/ 2>/dev/null; then
    echo "$LOG_PREFIX No changes in data/ or docs/, nothing to commit"
    exit 0
fi

git add data/ docs/
git commit -m "Auto-refresh threat report ($(date -u +%F))"
git push origin master

echo "$LOG_PREFIX Done at $(date -u +%FT%TZ)"
