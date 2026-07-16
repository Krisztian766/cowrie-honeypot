#!/bin/bash
echo "=== Lemezhasználat ==="
df -h / | tail -1
du -sh /opt/cowrie/downloads /opt/cowrie/log 2>/dev/null

echo
echo "=== Letöltött fájlok (zsákmány) ==="
ls -la /opt/cowrie/downloads | tail -n +2

echo
echo "=== Top 10 támadó IP (ma) ==="
python3 -c "
import json, collections
c = collections.Counter()
with open('/opt/cowrie/log/cowrie.json') as f:
    for line in f:
        try:
            e = json.loads(line)
        except Exception:
            continue
        if 'src_ip' in e:
            c[e['src_ip']] += 1
for ip, n in c.most_common(10):
    print(f'{n:6d}  {ip}')
"

echo
echo "=== Legutóbb kipróbált jelszavak ==="
python3 -c "
import json
with open('/opt/cowrie/log/cowrie.json') as f:
    lines = f.readlines()
for line in lines:
    try:
        e = json.loads(line)
    except Exception:
        continue
    if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed'):
        print(e['timestamp'], e['eventid'], e.get('username'), e.get('password'), e.get('src_ip'))
" | tail -20

echo
echo "=== Top 20 user/jelszó kombináció ==="
python3 -c "
import json, collections
combos = collections.Counter()
success = collections.Counter()
with open('/opt/cowrie/log/cowrie.json') as f:
    for line in f:
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed'):
            combo = f\"{e.get('username','?')} / {e.get('password','?')}\"
            combos[combo] += 1
            if e['eventid'] == 'cowrie.login.success':
                success[combo] += 1
print(f'Összes próbálkozás: {sum(combos.values())}  (sikeres: {sum(success.values())})')
print()
for combo, n in combos.most_common(20):
    tag = ' [SIKERES is volt]' if success.get(combo) else ''
    print(f'{n:6d}  {combo}{tag}')
"
