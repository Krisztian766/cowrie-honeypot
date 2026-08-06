# Cowrie Honeypot – VPS Deployment

Lightweight [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot running on a small
production VPS (1 vCPU / 2GB RAM), deployed for passive real-world malware collection, with
custom Telegram alerting and automated dropper-chain follow-through.

**[Live threat report →](https://krisztian766.github.io/cowrie-honeypot/)** — auto-generated
charts of attack volume over time, attacker countries, top credentials, and identified malware
families, built straight from the raw logs in this repo (`code/generate_report.py` +
`code/geoip_lookup.py` + `code/render_report.py`).

## At a glance

| | |
|---|---|
| Total events logged | 5,813,788 |
| Login attempts logged | 577,143 |
| Unique attacker source IPs | 2,381 |
| Unique username/password combos tried | 27,960 |
| Unique malware/dropper samples captured | 87 |
| Distinct attack chains identified | 4 (see the [live report](https://krisztian766.github.io/cowrie-honeypot/) for the full family/C2 table) |
| Distinct C2 servers observed | 2 (`205.237.110.232`, `45.150.195.235`) |
| Coverage window | 2026-07-14 → 2026-08-06 (ongoing) |

Top offenders (see `data/attacker_ips_full.txt` / `data/credentials_full.txt` for the complete
lists, not just these top few):

```
1760441  195.182.16.23
1212556  5.61.209.44
 218099  8.134.58.87
 186920  36.67.6.139
 153681  123.129.134.146

  13995  Alphanetworks / Wj5eH%JC     [also used successfully]
  12401  guest / 12345                [also used successfully]
   9830  root / 12345                 [also used successfully]
   9616  root / 7ujMko0vizxv          [also used successfully]
   9336  GlobalAdmin / GlobalAdmin    [also used successfully]
```

## Repo layout

```
config/     cowrie.cfg, userdb.txt, docker-compose.yml — the honeypot itself
code/       telegram_notify.py, telegram_summary.py, check_status.sh — alerting/reporting
            generate_report.py, geoip_lookup.py, render_report.py — threat-report pipeline
docs/       index.html — the static live report (served via GitHub Pages)
systemd/    the notifier service + 6-hourly summary timer/service
logrotate/  logrotate config (copytruncate) for the JSON event log
data/       seen_hashes.json, fetched_urls.json — notifier state/dedup caches
            attacker_ips_full.txt, credentials_full.txt — full (not top-N) breakdowns
            daily_volume.json, ip_counts.json, ip_geo.json, country_totals.json,
            credential_counts.json, downloads_timeline.json, malware_classification.json —
            structured data behind the live report
logs/       raw Cowrie JSON event logs, gzip-compressed, all rotations 2026-07-14→present
samples/    samples.zip — all 87 captured files, password-protected (see below)
```

## Threat report pipeline (`code/generate_report.py`, `geoip_lookup.py`, `render_report.py`)

Three scripts turn the raw logs into the [live report](https://krisztian766.github.io/cowrie-honeypot/):

1. **`generate_report.py`** — single full pass over every log rotation in `/opt/cowrie/log`
   (plain + gzip), producing daily event/login volume, per-IP totals, credential combo
   totals, and the malware download timeline.
2. **`geoip_lookup.py`** — batch-geolocates every unique attacker IP via
   [ip-api.com](https://ip-api.com)'s free batch endpoint (no key needed), weighted by each
   IP's actual event count so the country ranking reflects attack volume, not just IP count.
3. **`render_report.py`** — renders `docs/index.html`: a single self-contained static page
   (inline SVG charts, no external JS/CSS/fonts/CDN) so it loads fast and keeps working even
   if this repo goes fully offline. Re-run all three, then commit `data/` and `docs/`, to
   refresh the live report.

## Honeypot setup

- **Telnet (23)** and a decoy **SSH (2222)** are the honeypot ports. The box's *real* SSH stays on
  port 22, untouched — there was no out-of-band console access to the host, so any risk of an SSH
  misconfiguration causing lockout was unacceptable.
- Deployed via Docker (`config/docker-compose.yml`), with egress from the honeypot container
  restricted (iptables `DOCKER-USER` chain, host-level — not checked into this repo) to only the
  ports needed for Cowrie's wget/curl/tftp emulation to actually fetch the malware an attacker
  references (80/443/21/69). Everything else is dropped, so a compromised/escaped container can't
  be used to attack third parties.
- `config/cowrie.cfg` — Telnet enabled, hostname/kernel/SSH banners spoofed to match the real
  host's Debian 13 / OpenSSH profile for believability. `config/userdb.txt` — the honeypot's own
  decoy credential database (what Cowrie *accepts* from attackers), not a real credential store.

## Automation (`code/`)

- **`telegram_notify.py`** — tails Cowrie's JSON event log and sends an immediate Telegram alert
  only on `cowrie.session.file_download` / `file_upload` (i.e. actual captured malware), enriched
  with a VirusTotal verdict. Deliberately does *not* alert on every login attempt — Telnet brute
  force traffic is constant (~2,000+ attempts/day) and would flood the channel.
  - Also recursively scans small/text-like captures (≤8KB) for embedded URLs and fetches any
    referenced follow-on payloads (`expand_dropper_chain`) — closes the gap where Cowrie's shell
    emulation doesn't execute nested downloaded scripts, so multi-stage droppers (loader script →
    arch-specific ELF payload) don't stop at the loader stage.
  - Dedup cache (`data/seen_hashes.json`) — first sighting of a hash gets the full VT-enriched
    message, repeats are only counted, not re-announced.
  - `follow()` detects log rotation two ways: in-place truncation (`logrotate` + `copytruncate`)
    *and* rename-based rotation, i.e. an inode change at the watched path — Cowrie's own internal
    `DailyLogFile` rotates by renaming the live file at midnight and opening a fresh one, which a
    naive "did the file shrink" check doesn't catch. Missing the second case caused a real ~18h
    silent outage in production before this was fixed.
- **`telegram_summary.py`** — periodic aggregate stats (sessions, login success/fail, top attacker
  IPs, download count) every 6 hours via a systemd timer.
- **`check_status.sh`** — quick CLI status/loot summary (disk usage, downloaded files, top attacker
  IPs, top user/password combos) parsed directly from the JSON log.

## Ops (`systemd/`, `logrotate/`)

- `cowrie-telegram-notify.service` — long-running notifier, `Restart=always`.
- `cowrie-telegram-summary.timer` / `.service` — 6-hourly summary.
- `cowrie-report-refresh.timer` / `.service` — **daily** (04:00 UTC + random delay) full
  re-run of the report pipeline (`generate_report.py` → `geoip_lookup.py` → `render_report.py`),
  followed by an automatic `git commit` + `push` if `data/`/`docs/` changed. This is what keeps
  the [live report](https://krisztian766.github.io/cowrie-honeypot/) live rather than a one-time
  snapshot. Runner script: `code/refresh_report.sh`.
- `logrotate/cowrie` — daily rotation, 14-day retention, `copytruncate` (Cowrie also does its own
  internal daily rotation independently — see the `follow()` note above).

## Captured activity

Within hours of going live, two distinct attack chains were observed and are represented in
`samples/samples.zip` (password: `infected` — standard convention so nothing auto-executes or gets
flagged/quarantined on download):

1. **SSH persistence worm** ("mdrfckr") on port 2222 — wipes `~/.ssh`, drops the attacker's own
   public key into `authorized_keys` for passwordless return access. Seen from 10+ distinct source
   IPs, same script every time.
2. **Mirai/gafgyt-family Telnet dropper** on port 23 — CLI fingerprinting, `iptables -F`,
   anti-forensics (kills processes whose `/proc/<pid>/exe` resolves to a `(deleted)` binary — i.e.
   kills rival bots/debuggers), then a 4-protocol loader (wget/tftp/ftpget/curl) pulling
   architecture-specific payloads from its C2. Two separate C2s observed so far
   (`205.237.110.232` and `45.150.195.235`). The pulled ELF payloads (`arm`, `arm5`, `arm7`,
   `mips`, `mpsl`, `tmips`) are VT-classified `trojan.mirai/ddos` and contain the same
   self-propagation shell chain seen live on the honeypot, plus the classic Mirai `GET /dlr.`
   C2-callback string.

Samples are provided **for static analysis only** — never execute them, including on this host.
VirusTotal's `/files/{hash}/behaviours` endpoint (already-sandboxed) or an isolated VM/container
is the recommended way to get dynamic behavior data.

## Raw data (`logs/`, `data/`)

- `logs/cowrie.json*.gz` — the complete, unfiltered event log across every rotation captured so
  far (2026-07-14 → present): every login attempt, session, download, and command with timestamp
  and source IP. Gzip-compressed (10-20x) to stay well under GitHub's per-file limit as the raw
  logs grew past several hundred MB/day at peak traffic; this is the source of truth everything
  else in `data/` is derived from.
- `data/attacker_ips_full.txt` / `data/credentials_full.txt` — full breakdowns (not just a top-N
  sample) of every unique attacker IP and every unique username/password combination tried,
  regenerated from the raw logs above.

## Explicitly excluded from this repo

- `secrets/telegram.env` (Telegram bot token, chat ID, VirusTotal API key) — real credentials,
  never committed, `.gitignore`d as a backstop. This is the one boundary kept firm regardless of
  what else gets published here.
