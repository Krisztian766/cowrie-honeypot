#!/usr/bin/env python3
import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("cowrie-telegram")

LOG_FILE = "/opt/cowrie/log/cowrie.json"
DOWNLOADS_DIR = "/opt/cowrie/downloads"
CACHE_FILE = "/opt/cowrie/seen_hashes.json"
URL_CACHE_FILE = "/opt/cowrie/fetched_urls.json"
SAMPLES_DIR = "/opt/cowrie/samples"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
VT_API_KEY = os.environ.get("VT_API_KEY", "")

NOTIFY_EVENTS = {"cowrie.session.file_download", "cowrie.session.file_upload"}

# a dropper-lancban hivatkozott tovabbi URL-eket csak akkor keressuk, ha a
# leszedett fajl kicsi es szoveges (pl. wget.sh) - valodi ELF payloadok
# ennel jocskan nagyobbak, igy ez termeszetesen megallitja a lancot 1 szinten
DROPPER_SCAN_MAX_BYTES = 8192
URL_RE = re.compile(rb'https?://[^\s;|&"\'<>]+')

VT_MIN_INTERVAL = 16  # ingyenes VT API: max 4 keres/perc
_vt_last_call = 0.0


def vt_lookup(sha256):
    if not VT_API_KEY or not sha256 or sha256 == "?":
        return None
    global _vt_last_call
    wait = VT_MIN_INTERVAL - (time.monotonic() - _vt_last_call)
    if wait > 0:
        time.sleep(wait)
    _vt_last_call = time.monotonic()
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        stats = data["data"]["attributes"]["last_analysis_stats"]
        hits = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())
        return (
            f"{hits}/{total} motor jelezte rosszindulatúnak\n"
            f"https://www.virustotal.com/gui/file/{sha256}"
        )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "nincs a VirusTotal adatbázisában (valószínűleg vadonatúj minta)"
        return f"VT lekérdezés hiba: HTTP {e.code}"
    except Exception as e:
        return f"VT lekérdezés sikertelen: {e}"


def load_json_cache(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json_cache(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def extract_urls(data):
    urls = set()
    for m in URL_RE.finditer(data):
        try:
            urls.add(m.group().decode("ascii"))
        except UnicodeDecodeError:
            continue
    return urls


def find_dropper_urls(shasum):
    if not shasum or shasum == "?":
        return set()
    path = os.path.join(DOWNLOADS_DIR, shasum)
    try:
        if os.path.getsize(path) > DROPPER_SCAN_MAX_BYTES:
            return set()
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return set()
    return extract_urls(data)


def fetch_payload(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Wget/1.20"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read(20 * 1024 * 1024)
    except Exception as e:
        return None, str(e)
    sha256 = hashlib.sha256(data).hexdigest()
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    os.chmod(SAMPLES_DIR, 0o700)
    path = os.path.join(SAMPLES_DIR, sha256)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o440)  # olvashato, soha nem futtathato
    return sha256, None


def send_telegram(text):
    if not BOT_TOKEN or not CHAT_ID:
        log.warning("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID hiányzik, üzenet kihagyva")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode()
    try:
        urllib.request.urlopen(url, data=data, timeout=10)
    except Exception:
        log.exception("Telegram küldés sikertelen")


def format_message(event, vt_result=None):
    eventid = event.get("eventid")
    src_ip = event.get("src_ip", "?")
    ts = event.get("timestamp", "?")
    if eventid == "cowrie.session.file_download":
        msg = (
            "🎯 <b>Malware letöltve!</b>\n"
            f"Idő: {ts}\n"
            f"Támadó IP: <code>{src_ip}</code>\n"
            f"URL: <code>{event.get('url', '?')}</code>\n"
            f"SHA256: <code>{event.get('shasum', '?')}</code>\n"
            f"Tárolva: {event.get('outfile', '?')}"
        )
        if vt_result:
            msg += f"\nVirusTotal: {vt_result}"
        return msg
    if eventid == "cowrie.session.file_upload":
        msg = (
            "📤 <b>Fájl feltöltve a honeypotra!</b>\n"
            f"Idő: {ts}\n"
            f"Támadó IP: <code>{src_ip}</code>\n"
            f"Fájlnév: {event.get('filename', '?')}\n"
            f"SHA256: <code>{event.get('shasum', '?')}</code>"
        )
        if vt_result:
            msg += f"\nVirusTotal: {vt_result}"
        return msg
    return None


def follow(path):
    f = None
    buf = ""
    while True:
        try:
            if f is None:
                f = open(path, "r")
                f.seek(0, os.SEEK_END)
                buf = ""
            chunk = f.readline()
            if not chunk:
                try:
                    cur_size = os.fstat(f.fileno()).st_size
                    if f.tell() > cur_size:
                        log.info("Naplófájl rövidebb lett (rotáció), újraolvasás az elejétől: %s", path)
                        f.close()
                        f = open(path, "r")
                        buf = ""
                        continue
                    # Cowrie sajat DailyLogFile rotacioja atnevezessel jar:
                    # a mar nyitva tartott fajlleiro egy halott, statikus
                    # inode-ra mutat tovabb (meret nem csokken, csak leall a
                    # novekedes) - ezt csak ugy vesszuk eszre, ha a path-on
                    # levo aktualis fajl inode-jat osszevetjuk a nyitottaval
                    path_ino = os.stat(path).st_ino
                    open_ino = os.fstat(f.fileno()).st_ino
                    if path_ino != open_ino:
                        log.info("Naplófájl rotálva (új inode), újranyitás: %s", path)
                        f.close()
                        f = open(path, "r")
                        buf = ""
                        continue
                except OSError:
                    pass
                time.sleep(2)
                continue
            buf += chunk
            if not buf.endswith("\n"):
                # readline() a fajl vegen (meg le nem zart sor) torott
                # reszletet is visszaadhat, ha epp irás kozben olvasunk -
                # ezt megtartjuk es a kovetkezo olvasassal egeszitjuk ki,
                # kulonben a sor felig-parsolhatatlanul csendben elveszne
                continue
            line, buf = buf, ""
            yield line
        except FileNotFoundError:
            f = None
            time.sleep(5)


def expand_dropper_chain(shasum, url_cache):
    for url in find_dropper_urls(shasum):
        if url in url_cache:
            continue
        sha, err = fetch_payload(url)
        url_cache[url] = {
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sha256": sha,
            "error": err,
        }
        save_json_cache(URL_CACHE_FILE, url_cache)
        if sha:
            vt_result = vt_lookup(sha)
            msg = (
                "🧬 <b>Lánc-payload kinyerve a dropperből</b>\n"
                f"URL: <code>{url}</code>\n"
                f"SHA256: <code>{sha}</code>\n"
                f"Tárolva: {SAMPLES_DIR}/{sha} (nem futtatható)"
            )
            if vt_result:
                msg += f"\nVirusTotal: {vt_result}"
        else:
            msg = (
                "⚠️ <b>Lánc-payload letöltése sikertelen</b>\n"
                f"URL: <code>{url}</code>\n"
                f"Hiba: {err}"
            )
        send_telegram(msg)


def process_event(line, cache, url_cache):
    event = json.loads(line)
    if event.get("eventid") not in NOTIFY_EVENTS:
        return
    shasum = event.get("shasum", "")
    entry = cache.get(shasum) if shasum and shasum != "?" else None
    if entry:
        entry["count"] += 1
        entry["last_seen"] = event.get("timestamp", "?")
        save_json_cache(CACHE_FILE, cache)
        log.info("Ismert minta ismétlődése: %s (összesen %d alkalommal)", shasum, entry["count"])
        msg = None  # ismert minta ismétlődése - nincs kulon Telegram uzenet, csak a cache szamol
    else:
        log.info("Uj minta eszlelve: %s (eventid=%s, src_ip=%s)", shasum, event.get("eventid"), event.get("src_ip"))
        vt_result = vt_lookup(shasum)
        if shasum and shasum != "?":
            cache[shasum] = {
                "first_seen": event.get("timestamp", "?"),
                "last_seen": event.get("timestamp", "?"),
                "count": 1,
            }
            save_json_cache(CACHE_FILE, cache)
        msg = format_message(event, vt_result)
        if event.get("eventid") == "cowrie.session.file_download":
            expand_dropper_chain(shasum, url_cache)
    if msg:
        send_telegram(msg)


def main():
    log.info("Cowrie Telegram notifier elindult, figyeli: %s", LOG_FILE)
    cache = load_json_cache(CACHE_FILE)
    url_cache = load_json_cache(URL_CACHE_FILE)
    for line in follow(LOG_FILE):
        line = line.strip()
        if not line:
            continue
        try:
            process_event(line, cache, url_cache)
        except json.JSONDecodeError:
            log.warning("Nem parszolhato JSON sor, kihagyva: %r", line[:500])
        except Exception:
            log.exception("Hiba esemeny feldolgozasa kozben, folytatas a kovetkezovel: %r", line[:500])


if __name__ == "__main__":
    main()
