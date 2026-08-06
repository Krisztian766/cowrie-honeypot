#!/usr/bin/env python3
"""Render data/*.json into a self-contained static HTML threat report.

No external JS/CSS/fonts/CDNs — everything inline so the page works offline
and forever, served via GitHub Pages from docs/index.html.
"""
import json
import datetime

DATA_DIR = "/root/cowrie-honeypot-export/data"
OUT_PATH = "/root/cowrie-honeypot-export/docs/index.html"

BLUE_L, BLUE_D = "#2a78d6", "#3987e5"


def load(name):
    with open(f"{DATA_DIR}/{name}") as f:
        return json.load(f)


def compact(n):
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def stat_tile(label, value):
    return f'''<div class="stat-tile">
  <div class="stat-label">{esc(label)}</div>
  <div class="stat-value">{esc(value)}</div>
</div>'''


def hbar_chart(title, rows, value_key, label_key, unit="", max_rows=15):
    rows = rows[:max_rows]
    max_v = max(r[value_key] for r in rows) if rows else 1
    bar_h, gap, left_w, w = 22, 6, 200, 640
    row_h = bar_h + gap
    height = row_h * len(rows) + 10
    svg_rows = []
    for i, r in enumerate(rows):
        y = i * row_h + 5
        bw = (r[value_key] / max_v) * (w - left_w - 60)
        label = esc(r[label_key])
        val_label = f"{compact(r[value_key])}{unit}"
        svg_rows.append(f'''
    <text x="{left_w - 10}" y="{y + bar_h/2 + 4}" text-anchor="end" class="bar-row-label">{label}</text>
    <rect x="{left_w}" y="{y}" width="{bw:.1f}" height="{bar_h}" rx="4" class="bar-fill">
      <title>{label}: {r[value_key]:,}{unit}</title>
    </rect>
    <text x="{left_w + bw + 8:.1f}" y="{y + bar_h/2 + 4}" class="bar-value">{val_label}</text>''')
    return f'''<div class="chart-card">
  <h3>{esc(title)}</h3>
  <svg viewBox="0 0 {w} {height}" class="viz-root" role="img" aria-label="{esc(title)}">
    {''.join(svg_rows)}
  </svg>
</div>'''


def area_chart(title, series):
    days = list(series.keys())
    values = list(series.values())
    w, h, pad_l, pad_b, pad_t = 900, 260, 60, 30, 20
    max_v = max(values) if values else 1
    plot_w, plot_h = w - pad_l - 20, h - pad_b - pad_t
    n = len(days)
    pts = []
    for i, v in enumerate(values):
        x = pad_l + (i / max(n - 1, 1)) * plot_w
        y = pad_t + plot_h - (v / max_v) * plot_h
        pts.append((x, y))
    line_path = "M " + " L ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area_path = line_path + f" L {pts[-1][0]:.1f},{pad_t+plot_h} L {pts[0][0]:.1f},{pad_t+plot_h} Z"

    # gridlines at 0/25/50/75/100%
    grid = []
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        y = pad_t + plot_h - frac * plot_h
        grid.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{w-20}" y2="{y:.1f}" class="gridline"/>')
        grid.append(f'<text x="{pad_l-8}" y="{y+4:.1f}" text-anchor="end" class="axis-label">{compact(int(frac*max_v))}</text>')

    # x labels: first, middle, last day only
    xlabels = []
    for idx in (0, n // 2, n - 1):
        x, _ = pts[idx]
        xlabels.append(f'<text x="{x:.1f}" y="{h-8}" text-anchor="middle" class="axis-label">{days[idx][5:]}</text>')

    end_x, end_y = pts[-1]
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.2" class="line-dot"><title>{days[i]}: {values[i]:,}</title></circle>'
        for i, (x, y) in enumerate(pts)
    )

    return f'''<div class="chart-card">
  <h3>{esc(title)}</h3>
  <svg viewBox="0 0 {w} {h}" class="viz-root" role="img" aria-label="{esc(title)}">
    {''.join(grid)}
    <path d="{area_path}" class="area-fill"/>
    <path d="{line_path}" class="line-stroke" fill="none"/>
    {dots}
    <circle cx="{end_x:.1f}" cy="{end_y:.1f}" r="4" class="line-end"/>
    {''.join(xlabels)}
  </svg>
</div>'''


def main():
    daily = load("daily_volume.json")
    countries = load("country_totals.json")
    creds = load("credential_counts.json")
    ip_counts = load("ip_counts.json")
    downloads = load("downloads_timeline.json")
    families = load("malware_classification.json")

    total_events = sum(daily["events_per_day"].values())
    total_logins = sum(daily["logins_per_day"].values())
    unique_ips = len(ip_counts)
    unique_combos = len(creds)
    unique_samples = len({d["shasum"] for d in downloads if d.get("shasum")})
    days_sorted = sorted(daily["events_per_day"].keys())
    coverage = f"{days_sorted[0]} → {days_sorted[-1]}"
    updated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    stat_tiles = "".join([
        stat_tile("Total events logged", f"{total_events:,}"),
        stat_tile("Login attempts", f"{total_logins:,}"),
        stat_tile("Unique attacker IPs", f"{unique_ips:,}"),
        stat_tile("Unique credential combos", f"{unique_combos:,}"),
        stat_tile("Unique malware samples", f"{unique_samples}"),
        stat_tile("Countries observed", f"{len(countries)}"),
    ])

    country_rows = [{"country": c["country"], "events": c["events"]} for c in countries]
    cred_rows = [{"combo": c["combo"] + (" ✓" if c["ever_succeeded"] else ""), "count": c["count"]} for c in creds]

    family_rows = "".join(f'''<tr>
      <td>{esc(f['family'])}</td>
      <td>{esc(f['c2'] or '—')}</td>
      <td>{esc(', '.join(f['arch_payloads']) or '—')}</td>
      <td>{esc(f['vt_detection'])}</td>
      <td>{esc(f['notes'])}</td>
    </tr>''' for f in families)

    html = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cowrie Honeypot — Live Threat Report</title>
<meta name="description" content="Real attacker traffic, credentials, and malware samples captured by a live Cowrie honeypot.">
<style>
  :root {{ color-scheme: light; }}
  body {{
    margin: 0; padding: 0 0 4rem;
    background: #f9f9f7; color: #0b0b0b;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) body {{ background: #0d0d0d; color: #ffffff; }}
  }}
  :root[data-theme="dark"] body {{ background: #0d0d0d; color: #ffffff; }}

  header {{ max-width: 1000px; margin: 0 auto; padding: 3rem 1.5rem 1rem; }}
  header h1 {{ font-size: 1.9rem; margin: 0 0 .4rem; }}
  header p {{ color: #52514e; max-width: 700px; line-height: 1.5; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) header p {{ color: #c3c2b7; }}
  }}
  :root[data-theme="dark"] header p {{ color: #c3c2b7; }}

  main {{ max-width: 1000px; margin: 0 auto; padding: 0 1.5rem; display: flex; flex-direction: column; gap: 1.5rem; }}

  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1px; background: rgba(11,11,11,0.10); border: 1px solid rgba(11,11,11,0.10); border-radius: 10px; overflow: hidden; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .stat-grid {{ background: rgba(255,255,255,0.10); border-color: rgba(255,255,255,0.10); }}
  }}
  .stat-tile {{ background: #fcfcfb; padding: 1.1rem 1rem; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .stat-tile {{ background: #1a1a19; }}
  }}
  :root[data-theme="dark"] .stat-tile {{ background: #1a1a19; }}
  .stat-label {{ font-size: .78rem; color: #898781; margin-bottom: .35rem; }}
  .stat-value {{ font-size: 1.6rem; font-weight: 600; }}

  .chart-card {{ background: #fcfcfb; border: 1px solid rgba(11,11,11,0.10); border-radius: 10px; padding: 1.2rem 1.4rem; overflow-x: auto; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .chart-card {{ background: #1a1a19; border-color: rgba(255,255,255,0.10); }}
  }}
  :root[data-theme="dark"] .chart-card {{ background: #1a1a19; border-color: rgba(255,255,255,0.10); }}
  .chart-card h3 {{ margin: 0 0 1rem; font-size: 1rem; }}
  .chart-card svg {{ width: 100%; height: auto; display: block; }}

  .bar-row-label {{ font-size: 12px; fill: #52514e; }}
  .bar-value {{ font-size: 12px; fill: #0b0b0b; font-variant-numeric: tabular-nums; }}
  .bar-fill {{ fill: {BLUE_L}; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .bar-fill {{ fill: {BLUE_D}; }}
    :root:where(:not([data-theme="light"])) .bar-row-label {{ fill: #c3c2b7; }}
    :root:where(:not([data-theme="light"])) .bar-value {{ fill: #ffffff; }}
  }}
  :root[data-theme="dark"] .bar-fill {{ fill: {BLUE_D}; }}
  :root[data-theme="dark"] .bar-row-label {{ fill: #c3c2b7; }}
  :root[data-theme="dark"] .bar-value {{ fill: #ffffff; }}

  .gridline {{ stroke: #e1e0d9; stroke-width: 1; }}
  .axis-label {{ font-size: 11px; fill: #898781; }}
  .area-fill {{ fill: {BLUE_L}; opacity: .10; }}
  .line-stroke {{ stroke: {BLUE_L}; stroke-width: 2; }}
  .line-dot {{ fill: {BLUE_L}; opacity: 0; }}
  .line-dot:hover {{ opacity: 1; }}
  .line-end {{ fill: {BLUE_L}; stroke: #fcfcfb; stroke-width: 2; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) .gridline {{ stroke: #2c2c2a; }}
    :root:where(:not([data-theme="light"])) .area-fill {{ fill: {BLUE_D}; }}
    :root:where(:not([data-theme="light"])) .line-stroke {{ stroke: {BLUE_D}; }}
    :root:where(:not([data-theme="light"])) .line-end {{ fill: {BLUE_D}; stroke: #1a1a19; }}
  }}

  table {{ width: 100%; border-collapse: collapse; font-size: .88rem; }}
  th, td {{ text-align: left; padding: .55rem .6rem; border-bottom: 1px solid #e1e0d9; vertical-align: top; }}
  @media (prefers-color-scheme: dark) {{
    :root:where(:not([data-theme="light"])) th, :root:where(:not([data-theme="light"])) td {{ border-color: #2c2c2a; }}
  }}
  th {{ color: #898781; font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .02em; }}

  footer {{ max-width: 1000px; margin: 2rem auto 0; padding: 0 1.5rem; color: #898781; font-size: .82rem; line-height: 1.6; }}
  a {{ color: {BLUE_L}; }}
  @media (prefers-color-scheme: dark) {{ :root:where(:not([data-theme="light"])) a {{ color: {BLUE_D}; }} }}
</style>
</head>
<body>
<header>
  <h1>Cowrie Honeypot — Live Threat Report</h1>
  <p>Real attacker traffic against a live Telnet/SSH honeypot on a small production VPS.
     Every number below comes from raw Cowrie event logs — not a simulation or a sample dataset.
     Full raw logs, code, and captured malware are in the
     <a href="https://github.com/Krisztian766/cowrie-honeypot">source repo</a>.</p>
</header>
<main>
  <div class="stat-grid">{stat_tiles}</div>

  {area_chart("Daily event volume", daily["events_per_day"])}

  {hbar_chart("Top attacker countries by event volume", country_rows, "events", "country")}

  {hbar_chart("Top credential combos tried (✓ = succeeded at least once)", cred_rows, "count", "combo")}

  <div class="chart-card">
    <h3>Identified malware / attack chains</h3>
    <table>
      <thead><tr><th>Family</th><th>C2 server</th><th>Payloads</th><th>VirusTotal</th><th>Notes</th></tr></thead>
      <tbody>{family_rows}</tbody>
    </table>
  </div>
</main>
<footer>
  Generated {esc(updated)} from {esc(coverage)} of collected data.
  Coordinates and countries via <a href="https://ip-api.com">ip-api.com</a>.
  Deployment details, code, and full raw logs: <a href="https://github.com/Krisztian766/cowrie-honeypot">github.com/Krisztian766/cowrie-honeypot</a>.
</footer>
</body>
</html>'''

    import os
    os.makedirs("/root/cowrie-honeypot-export/docs", exist_ok=True)
    with open(OUT_PATH, "w") as f:
        f.write(html)
    print(f"Wrote {OUT_PATH} ({len(html)} bytes)")


if __name__ == "__main__":
    main()
