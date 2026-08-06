#!/usr/bin/env python3
"""Batch-geolocate every unique attacker IP via ip-api.com's free batch endpoint
(up to 100 IPs/request, ~45 req/min limit) and write country totals weighted by
each IP's actual event count."""
import json
import time
import urllib.request
import collections

DATA_DIR = "/root/cowrie-honeypot-export/data"

with open(f"{DATA_DIR}/ip_counts.json") as f:
    ip_counts = json.load(f)

ips = list(ip_counts.keys())
print(f"Geolocating {len(ips)} unique IPs in batches of 100...")

ip_country = {}
for i in range(0, len(ips), 100):
    batch = ips[i:i + 100]
    payload = json.dumps([{"query": ip, "fields": "status,country,countryCode,query"} for ip in batch]).encode()
    req = urllib.request.Request(
        "http://ip-api.com/batch",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                results = json.loads(resp.read())
            break
        except Exception as e:
            print(f"  batch {i}: retry after error {e}")
            time.sleep(5)
    else:
        results = []

    for r in results:
        if r.get("status") == "success":
            ip_country[r["query"]] = {"country": r.get("country"), "code": r.get("countryCode")}

    print(f"  {i + len(batch)}/{len(ips)} done")
    time.sleep(1.5)

country_totals = collections.Counter()
country_unique_ips = collections.Counter()
for ip, count in ip_counts.items():
    info = ip_country.get(ip)
    country = info["country"] if info else "Unknown"
    country_totals[country] += count
    country_unique_ips[country] += 1

with open(f"{DATA_DIR}/ip_geo.json", "w") as f:
    json.dump(ip_country, f, indent=2)

with open(f"{DATA_DIR}/country_totals.json", "w") as f:
    json.dump([
        {"country": c, "events": n, "unique_ips": country_unique_ips[c]}
        for c, n in country_totals.most_common()
    ], f, indent=2)

print(f"Resolved {len(ip_country)}/{len(ips)} IPs, {len(country_totals)} countries")
