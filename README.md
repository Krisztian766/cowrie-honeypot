# Cowrie Honeypot – VPS Deployment

Lightweight [Cowrie](https://github.com/cowrie/cowrie) SSH/Telnet honeypot running on a small
production VPS (1 vCPU / 2GB RAM), deployed for passive real-world malware collection, with
custom Telegram alerting and automated dropper-chain follow-through.

## At a glance

| | |
|---|---|
| Login attempts logged | 6,997 (6,746 "successful" — Cowrie accepts everything by design) |
| Unique attacker source IPs | 185 |
| Unique username/password combos tried | 530 |
| Unique malware/dropper samples captured | 19 |
| Distinct attack chains identified | 2 (SSH persistence worm, Mirai/gafgyt Telnet dropper) |
| Distinct C2 servers observed | 2 (`205.237.110.232`, `45.150.195.235`) |

Top offenders (see `data/attacker_ips_full.txt` / `data/credentials_full.txt` for the complete
lists, not just these top few):

```
2012  92.204.138.51
1747  5.61.209.43
 895  205.237.110.232   (also one of the two Mirai C2s below)
 745  132.148.29.10
 378  70.32.86.195

 280  root / vizxv               [also used successfully]
 270  admin / admin              [also used successfully]
 249  root / xc3511               [also used successfully]
 226  enable / linuxshell         [also used successfully]
 218  support / support           [also used successfully]
```

## Repo layout

```
config/     cowrie.cfg, userdb.txt, docker-compose.yml — the honeypot itself
code/       telegram_notify.py, telegram_summary.py, check_status.sh — alerting/reporting
systemd/    the notifier service + 6-hourly summary timer/service
logrotate/  logrotate config (copytruncate) for the JSON event log
data/       seen_hashes.json, fetched_urls.json — notifier state/dedup caches
            attacker_ips_full.txt, credentials_full.txt — full (not top-N) breakdowns
logs/       raw Cowrie JSON event logs, all 4 rotations (~129MB total)
samples/    samples.zip — all 19 captured files, password-protected (see below)
```

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

- `logs/cowrie.json*` — the complete, unfiltered event log across all 4 rotations captured so far:
  every login attempt, session, download, and command with timestamp and source IP. This is the
  source of truth everything else in `data/` is derived from.
- `data/attacker_ips_full.txt` / `data/credentials_full.txt` — full breakdowns (not just a top-N
  sample) of every unique attacker IP and every unique username/password combination tried,
  regenerated from the raw logs above.

## Explicitly excluded from this repo

- `secrets/telegram.env` (Telegram bot token, chat ID, VirusTotal API key) — real credentials,
  never committed, `.gitignore`d as a backstop. This is the one boundary kept firm regardless of
  what else gets published here.
