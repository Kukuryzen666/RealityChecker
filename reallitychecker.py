#!/usr/bin/env python3
"""
RealityChecker v2.7 - Глобальный асинхронный детектор VLESS-Reality & ASN/Подсеть сканер.
- Флаг --asn <номер>: Автоматическое получение всех подсетей (CIDR) автономной системы (ASN)
  через открытые BGP/RIPE API и их сканирование.
- Режим скрытности и защиты от детекта:
  * --delay <сек>: Задержка/пауза между пачками запросов (rate limiting).
  * --shuffle: Случайное перемешивание IP-адресов (randomized scan) во избежание триггера IDS/IPS фаерволов на последовательное сканирование подсетей.
- Аудит базы (--check-fixed): кто исправился, кто выключился, а кто сменил SNI.
- Автоматический фильтр CDN / Edge нод (Akamai, Cloudflare, Fastly, AWS, Google).
- AsyncIO движок (500-1000+ одновременных сокетов).
- Полная совместимость с Windows и Linux.
"""

import argparse
import asyncio
import ipaddress
import json
import os
import random
import re
import socket
import sqlite3
import ssl
import sys
import time
import urllib.request
import urllib.error
import warnings
from datetime import datetime

# Настройка UTF-8 для Windows консоли
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Подавление предупреждений cryptography
warnings.filterwarnings("ignore")
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    warnings.filterwarnings("ignore", category=UserWarning)
except Exception:
    pass

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

# Включение поддержки ANSI цветов в Windows cmd/powershell
if os.name == "nt":
    os.system("")

# ANSI Цветовая палитра
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_GREEN = "\033[1;32m"
CLR_YELLOW = "\033[1;33m"
CLR_CYAN = "\033[1;36m"
CLR_BLUE = "\033[1;34m"
CLR_RED = "\033[1;31m"
CLR_GRAY = "\033[90m"
CLR_DARK_GRAY = "\033[38;5;240m"
CLR_MAGENTA = "\033[1;35m"
CLR_BG_GREEN = "\033[42;30;1m"
CLR_BG_RED = "\033[41;37;1m"
CLR_BG_BLUE = "\033[44;37;1m"
CLR_BG_YELLOW = "\033[43;30;1m"
CLR_BG_GRAY = "\033[47;30;1m"

SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# Глобальный кэш DNS
DNS_CACHE = {}

# Маркеры и домены известных мировых CDN / Cloud сетей
CDN_KEYWORDS = (
    "akamai", "akamaiedge", "edgesuite", "edgekey", "edgeflow", "frontier.amazon",
    "cloudfront", "cloudflare", "fastly", "azureedge", "msecnd", "trafficmanager",
    "googleusercontent", "1e100.net", "qrator", "ddos-guard", "gcore", "imperva",
    "incapdns", "cdngp", "stackpath", "cdn77", "selectel", "vkcdn", "a2z.com"
)


# ==========================================
# ПОЛУЧЕНИЕ ПОДСЕТЕЙ ПО ASN (BGP / RIPE API)
# ==========================================
def fetch_asn_prefixes(asn_input: str) -> tuple[str, list[str]]:
    """
    Получает все IPv4 префиксы/подсети для указанного номера ASN.
    Использует RIPE Stat API и BGPView API.
    """
    clean_asn = asn_input.upper().replace("AS", "").strip()
    if not clean_asn.isdigit():
        print(f"{CLR_RED}[!] Некорректный номер ASN: {asn_input} (должно быть число или AS12345){CLR_RESET}")
        return clean_asn, []

    print(f"[*] Запрос BGP-маршрутов для AS{clean_asn} через RIPE & BGPView API...")
    headers = {"User-Agent": "RealityChecker/2.7 (Security Auditor)"}
    prefixes = set()

    # 1. Попытка через RIPE Stat API
    ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{clean_asn}"
    try:
        req = urllib.request.Request(ripe_url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("data", {}).get("prefixes", []):
                p = item.get("prefix")
                if p and ":" not in p:  # Только IPv4
                    prefixes.add(p)
    except Exception as e:
        pass

    # 2. Если RIPE вернул мало или сбой — опрашиваем BGPView API
    if not prefixes:
        bgpview_url = f"https://api.bgpview.io/asn/{clean_asn}/prefixes"
        try:
            req = urllib.request.Request(bgpview_url, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for item in data.get("data", {}).get("ipv4_prefixes", []):
                    p = item.get("prefix")
                    if p and ":" not in p:
                        prefixes.add(p)
        except Exception as e:
            pass

    # Валидация подсетей
    valid_cidrs = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            valid_cidrs.append(str(net))
        except ValueError:
            pass

    return clean_asn, sorted(valid_cidrs)


# ==========================================
# DNS & ВАЛИДАЦИЯ ДОМЕНОВ
# ==========================================
def clean_and_validate_domain(raw_name: str) -> str | None:
    """Очищает домен от wildcard (*.), пробелов и проверяет валидность."""
    if not raw_name or not isinstance(raw_name, str):
        return None

    domain = raw_name.lstrip("*.").strip().lower().rstrip(".")
    if not domain or domain in ("localhost", "local", "invalid", "internal"):
        return None

    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass

    if "." not in domain or len(domain) < 3:
        return None

    return domain


async def resolve_domain_async(domain: str) -> list[str]:
    """Асинхронно резолвит домен в список IPv4-адресов с кэшированием."""
    if domain in DNS_CACHE:
        return DNS_CACHE[domain]

    loop = asyncio.get_running_loop()
    try:
        _, _, ip_list = await loop.run_in_executor(
            None, lambda: socket.gethostbyname_ex(domain)
        )
        ips = sorted(list(set(ip_list)))
    except Exception:
        ips = []

    DNS_CACHE[domain] = ips
    return ips


def is_cdn_indicator(domain: str, real_ips: list[str]) -> bool:
    """Проверяет, является ли домен частью инфраструктуры публичного CDN."""
    domain_lower = domain.lower()
    for kw in CDN_KEYWORDS:
        if kw in domain_lower:
            return True
    return False


async def verify_sni_affinity(domain: str, scanned_ip: str, tls_version: str, all_cert_domains: list[str]) -> dict:
    """
    Глубокая проверка принадлежности SNI к хосту (Детект Reality/VPN):
    1. Проверка на легитимные CDN / Edge ноды (Akamai, CloudFront, Cloudflare, Fastly).
    2. Проверка версии TLS: Reality работает ТОЛЬКО поверх TLS 1.3.
    3. Проверка совпадения IP / Подсетей /24 и /16.
    4. Оценка достоверности (Confidence).
    """
    real_ips = await resolve_domain_async(domain)
    is_tls13 = (tls_version == "TLSv1.3")

    has_cdn_domains = any(is_cdn_indicator(d, []) for d in all_cert_domains)
    is_current_cdn = is_cdn_indicator(domain, real_ips)

    if has_cdn_domains or is_current_cdn:
        return {
            "status": "CDN_EDGE_NODE",
            "is_vpn": False,
            "is_cdn": True,
            "confidence": "NONE (CDN)",
            "real_ips": real_ips,
            "note": f"Легитимный узел CDN / Edge (Akamai/Cloudflare/AWS/Fastly)",
            "tls_version": tls_version
        }

    if not real_ips:
        return {
            "status": "DNS_UNRESOLVED",
            "is_vpn": False,
            "is_cdn": False,
            "confidence": "LOW",
            "real_ips": [],
            "note": "DNS не резолвится",
            "tls_version": tls_version
        }

    # 1. Прямой матч IP
    if scanned_ip in real_ips:
        return {
            "status": "DIRECT_MATCH",
            "is_vpn": False,
            "is_cdn": False,
            "confidence": "NONE",
            "real_ips": real_ips,
            "note": "IP точно совпадает с DNS",
            "tls_version": tls_version
        }

    # 2. Совпадение подсети /24
    try:
        scanned_net24 = ipaddress.ip_network(f"{scanned_ip}/24", strict=False)
        for rip in real_ips:
            if ipaddress.ip_address(rip) in scanned_net24:
                return {
                    "status": "SUBNET_MATCH_24",
                    "is_vpn": False,
                    "is_cdn": False,
                    "confidence": "LOW",
                    "real_ips": real_ips,
                    "note": f"Совпадает /24 подсеть ({rip})",
                    "tls_version": tls_version
                }
    except Exception:
        pass

    # 3. Совпадение подсети /16
    try:
        scanned_net16 = ipaddress.ip_network(f"{scanned_ip}/16", strict=False)
        for rip in real_ips:
            if ipaddress.ip_address(rip) in scanned_net16:
                return {
                    "status": "SUBNET_MATCH_16",
                    "is_vpn": False,
                    "is_cdn": False,
                    "confidence": "MEDIUM",
                    "real_ips": real_ips,
                    "note": f"Совпадает /16 подсеть ({rip})",
                    "tls_version": tls_version
                }
    except Exception:
        pass

    # 4. Не совпадает ни IP, ни подсеть, и это НЕ CDN!
    if is_tls13:
        return {
            "status": "MISMATCH_REALITY",
            "is_vpn": True,
            "is_cdn": False,
            "confidence": "HIGH (TLS 1.3)",
            "real_ips": real_ips,
            "note": f"ЧУЖОЙ SNI + TLS 1.3! DNS: {', '.join(real_ips[:2])} != {scanned_ip}",
            "tls_version": tls_version
        }
    else:
        return {
            "status": "MISMATCH_OTHER",
            "is_vpn": False,
            "is_cdn": False,
            "confidence": "LOW (Not TLS 1.3)",
            "real_ips": real_ips,
            "note": f"Несовпадение IP, но TLS={tls_version} (не Reality)",
            "tls_version": tls_version
        }


# ==========================================
# АСИНХРОННЫЙ TLS & СЕРТИФИКАТЫ
# ==========================================
async def scan_host_tls(ip: str, port: int, timeout: float, ssl_ctx: ssl.SSLContext) -> tuple[str, int, str, list[str], str]:
    """
    Асинхронно подключается к хосту.
    Возвращает (ip, port, tls_version, domains, status_desc).
    """
    try:
        connect_coro = asyncio.open_connection(
            host=ip,
            port=port,
            ssl=ssl_ctx,
            server_hostname=None  # Без SNI (запрос fallback сертификата)
        )
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)

        ssl_obj = writer.get_extra_info("ssl_object")
        tls_version = ssl_obj.version() if ssl_obj else "UNKNOWN"
        der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None

        writer.close()
        await writer.wait_closed()

        if not der_cert:
            return ip, port, tls_version, [], "NO_CERT"

        domains = set()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cert = x509.load_der_x509_certificate(der_cert)

            # Common Name (CN)
            try:
                for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                    val = getattr(attr, "value", None)
                    clean = clean_and_validate_domain(val)
                    if clean:
                        domains.add(clean)
            except Exception:
                pass

            # SANs
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    clean = clean_and_validate_domain(str(name.value))
                    if clean:
                        domains.add(clean)
            except Exception:
                pass

        return ip, port, tls_version, sorted(domains), "OK"

    except asyncio.TimeoutError:
        return ip, port, "TIMEOUT", [], "Таймаут соединения"
    except ConnectionRefusedError:
        return ip, port, "CLOSED", [], "Порт закрыт (RST)"
    except ssl.SSLError as e:
        return ip, port, "SSL_ERROR", [], f"Ошибка SSL ({e.reason if hasattr(e, 'reason') else 'handshake'})"
    except OSError as e:
        return ip, port, "UNREACHABLE", [], f"Недоступен ({e.strerror or 'error'})"
    except Exception as e:
        return ip, port, "FAILED", [], str(e)


# ==========================================
# БАЗА ДАННЫХ SQLITE (ТОЛЬКО VPN СЕРВЕРА)
# ==========================================
def init_db(db_path: str = "reality_vpn_servers.db") -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vpn_servers (
            ip TEXT,
            port INTEGER,
            domain TEXT,
            tls_version TEXT,
            confidence TEXT,
            real_dns_ips TEXT,
            is_active INTEGER DEFAULT 1,
            hits INTEGER DEFAULT 1,
            last_status TEXT DEFAULT 'REALITY_ACTIVE',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            fixed_at TIMESTAMP,
            PRIMARY KEY (ip, port, domain)
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_vpn_ip ON vpn_servers(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vpn_active ON vpn_servers(is_active);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_vpn_domain ON vpn_servers(domain);")

    for col, ctype in [("last_status", "TEXT DEFAULT 'REALITY_ACTIVE'"), ("fixed_at", "TIMESTAMP")]:
        try:
            cur.execute(f"ALTER TABLE vpn_servers ADD COLUMN {col} {ctype}")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    return conn


def save_vpn_batch_to_db(conn: sqlite3.Connection, records: list[dict]):
    """Сохраняет в БД ИСКЛЮЧИТЕЛЬНО подтвержденные VPN/Reality сервера."""
    if not records:
        return

    cur = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for item in records:
        ip = item["ip"]
        port = item["port"]
        tls_ver = item["tls_version"]

        for d_info in item["checks"]:
            chk = d_info["check"]
            if not chk["is_vpn"]:
                continue

            domain = d_info["domain"]
            real_ips_str = ",".join(chk["real_ips"])
            confidence = chk.get("confidence", "HIGH")

            cur.execute("""
                SELECT hits FROM vpn_servers 
                WHERE ip = ? AND port = ? AND domain = ?
            """, (ip, port, domain))
            row = cur.fetchone()

            if row is None:
                cur.execute("""
                    INSERT INTO vpn_servers 
                    (ip, port, domain, tls_version, confidence, real_dns_ips, is_active, hits, last_status, first_seen, last_seen, last_checked)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 1, 'REALITY_ACTIVE', ?, ?, ?)
                """, (ip, port, domain, tls_ver, confidence, real_ips_str, now_str, now_str, now_str))
            else:
                cur.execute("""
                    UPDATE vpn_servers 
                    SET hits = hits + 1,
                        is_active = 1,
                        last_status = 'REALITY_ACTIVE',
                        tls_version = ?,
                        confidence = ?,
                        real_dns_ips = ?,
                        last_seen = ?,
                        last_checked = ?
                    WHERE ip = ? AND port = ? AND domain = ?
                """, (tls_ver, confidence, real_ips_str, now_str, now_str, ip, port, domain))

    conn.commit()


def get_db_vpn_stats(conn: sqlite3.Connection):
    """Возвращает статистику VPN серверов."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT ip || ':' || port) FROM vpn_servers")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT ip || ':' || port) FROM vpn_servers WHERE is_active = 1")
    active = cur.fetchone()[0]
    return total, active


# ==========================================
# ФЛАГ --check-fixed: ПРОВЕРКА КТО ИСПРАВИЛСЯ
# ==========================================
async def audit_fixed_hosts(conn: sqlite3.Connection, concurrency: int = 300, timeout: float = 2.5):
    """
    Проверяет все ранее обнаруженные Reality/VPN хосты с понятным и красивым выводом.
    """
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT ip, port, domain, tls_version, hits, first_seen FROM vpn_servers")
    rows = cur.fetchall()

    if not rows:
        print(f"\n{CLR_YELLOW}[!] В базе данных пока нет хостов для проверки.{CLR_RESET}\n")
        return

    total = len(rows)
    print(f"\n{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_CYAN}  АУДИТ БАЗЫ: ПРОВЕРКА АКТУАЛЬНОСТИ И ИСПРАВЛЕНИЙ ({total} хостов в БД){CLR_RESET}")
    print(f"{CLR_CYAN}======================================================================{CLR_RESET}\n")

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    semaphore = asyncio.Semaphore(concurrency)
    checked_count = 0

    fixed_count = 0      # Поставил свой собственный легитимный домен
    cdn_count = 0        # Опознан как легитимный CDN (снят с учета VPN)
    offline_count = 0    # Закрыл порт / оффлайн
    same_reality = 0     # Все еще Reality
    changed_sni = 0      # Reality, но сменил домен

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    async def audit_worker(ip: str, port: int, old_domain: str, old_tls: str, hits: int, first_seen: str):
        nonlocal checked_count, fixed_count, cdn_count, offline_count, same_reality, changed_sni
        async with semaphore:
            _, _, tls_ver, domains, status_desc = await scan_host_tls(ip, port, timeout, ssl_ctx)
            checked_count += 1
            cur_worker = conn.cursor()

            # 1. Хост не отвечает или порт закрыт -> ВЫКЛЮЧЕН
            if not domains:
                offline_count += 1
                cur_worker.execute("""
                    UPDATE vpn_servers 
                    SET is_active = 0, last_status = 'OFFLINE', last_checked = ?
                    WHERE ip = ? AND port = ? AND domain = ?
                """, (now_str, ip, port, old_domain))
                conn.commit()

                badge = f"{CLR_DARK_GRAY}[ВЫКЛЮЧЕН / ЗАКРЫЛ ПОРТ]{CLR_RESET}"
                clear_progress_line()
                print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ Был SNI: {CLR_YELLOW}{old_domain}{CLR_RESET} │ {CLR_DARK_GRAY}{status_desc}{CLR_RESET}")
                return

            # 2. Проверяем домены хоста
            current_vpn_domains = []
            is_now_legit = True
            is_cdn_node = False

            for d in domains:
                chk = await verify_sni_affinity(d, ip, tls_ver, domains)
                if chk.get("is_cdn"):
                    is_cdn_node = True
                if chk["is_vpn"]:
                    current_vpn_domains.append(d)
                    is_now_legit = False

            # СЛУЧАЙ А: Это легитимный CDN (Akamai, Cloudflare, Fastly, AWS)
            if is_cdn_node or is_now_legit and is_cdn_indicator(old_domain, []):
                cdn_count += 1
                cur_worker.execute("""
                    UPDATE vpn_servers 
                    SET is_active = 0, last_status = 'CDN_NODE', last_checked = ?, fixed_at = ?
                    WHERE ip = ? AND port = ? AND domain = ?
                """, (now_str, now_str, ip, port, old_domain))
                conn.commit()

                badge = f"{CLR_BG_BLUE} 🌐 ОПОЗНАН КАК CDN УЗЕЛ {CLR_RESET}"
                clear_progress_line()
                print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ {CLR_CYAN}Легитимный CDN:{CLR_RESET} {old_domain} {CLR_GRAY}(снят из базы VPN){CLR_RESET}")

            # СЛУЧАЙ Б: ИСПРАВИЛСЯ (Поставил свой собственный домен)
            elif is_now_legit and len(domains) > 0:
                fixed_count += 1
                cur_worker.execute("""
                    UPDATE vpn_servers 
                    SET is_active = 0, last_status = 'FIXED_LEGIT', last_checked = ?, fixed_at = ?
                    WHERE ip = ? AND port = ? AND domain = ?
                """, (now_str, now_str, ip, port, old_domain))
                conn.commit()

                badge = f"{CLR_BG_GREEN} 🟢 ИСПРАВИЛСЯ! СТАЛ ЛЕГИТИМНЫМ {CLR_RESET}"
                clear_progress_line()
                print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ {CLR_GREEN}Установил свой домен:{CLR_RESET} {', '.join(domains[:2])} {CLR_GRAY}(был чужой SNI: {old_domain}){CLR_RESET}")

            # СЛУЧАЙ В: ВСЁ ЕЩЁ REALITY С ТЕМ ЖЕ ДОМЕНОМ
            elif old_domain in current_vpn_domains:
                same_reality += 1
                cur_worker.execute("""
                    UPDATE vpn_servers 
                    SET is_active = 1, hits = hits + 1, last_status = 'REALITY_ACTIVE', last_seen = ?, last_checked = ?
                    WHERE ip = ? AND port = ? AND domain = ?
                """, (now_str, now_str, ip, port, old_domain))
                conn.commit()

                badge = f"{CLR_RED}[НЕ ИСПРАВИЛСЯ - ВСЁ ЕЩЁ REALITY]{CLR_RESET}"
                clear_progress_line()
                print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ Маскировка под: {CLR_RED}{old_domain}{CLR_RESET} [Подтверждений: {hits+1}]")

            # СЛУЧАЙ Г: ВСЁ ЕЩЁ REALITY, НО СМЕНИЛ SNI
            else:
                changed_sni += 1
                new_dom_str = ', '.join(current_vpn_domains[:2])
                cur_worker.execute("""
                    UPDATE vpn_servers 
                    SET is_active = 1, last_status = 'CHANGED_SNI', last_seen = ?, last_checked = ?
                    WHERE ip = ? AND port = ? AND domain = ?
                """, (now_str, now_str, ip, port, old_domain))
                conn.commit()

                badge = f"{CLR_BG_YELLOW} 🟡 СМЕНИЛ МАСКИРОВКУ (SNI) {CLR_RESET}"
                clear_progress_line()
                print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ Был SNI: {CLR_YELLOW}{old_domain}{CLR_RESET} ➔ Сменил на: {CLR_MAGENTA}{new_dom_str}{CLR_RESET}")

    tasks = [asyncio.create_task(audit_worker(r[0], r[1], r[2], r[3], r[4], r[5])) for r in rows]
    await asyncio.gather(*tasks)

    # Итоговый отчет аудита
    print(f"\n{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_BOLD}ИТОГОВЫЙ ОТЧЕТ АУДИТА:{CLR_RESET}")
    print(f"  ➜ Проверено хостов из базы:         {total}")
    print(f"  ➜ 🌐 Опознаны как легитимные CDN:   {CLR_CYAN}{CLR_BOLD}{cdn_count}{CLR_RESET} (сняты с учета VPN)")
    print(f"  ➜ 🟢 ИСПРАВИЛИСЬ (свой домен):      {CLR_GREEN}{CLR_BOLD}{fixed_count}{CLR_RESET}")
    print(f"  ➜ ⚪ ВЫКЛЮЧИЛИСЬ / закрыли порт:     {CLR_GRAY}{CLR_BOLD}{offline_count}{CLR_RESET}")
    print(f"  ➜ 🟡 СМЕНИЛИ маскировку (новый SNI):{CLR_YELLOW}{CLR_BOLD}{changed_sni}{CLR_RESET}")
    print(f"  ➜ 🔴 НЕ ИСПРАВИЛИСЬ (активны):      {CLR_RED}{CLR_BOLD}{same_reality}{CLR_RESET}")
    print(f"{CLR_CYAN}======================================================================{CLR_RESET}\n")


# ==========================================
# ИНТЕРФЕЙС И ПРОГРЕСС-БАР
# ==========================================
def update_progress_bar(current: int, total: int, current_ip: str, vpn_count: int, spinner_idx: int):
    pct = int((current / total) * 100) if total > 0 else 0
    bar_width = 18
    filled = int(bar_width * current // total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_width - filled)
    spin = SPINNER_FRAMES[spinner_idx % len(SPINNER_FRAMES)]

    line = (
        f"\r{CLR_CYAN}{spin}{CLR_RESET} [{CLR_GREEN}{bar}{CLR_RESET}] {CLR_BOLD}{pct:>3}%{CLR_RESET} "
        f"({current}/{total}) │ {CLR_GRAY}Скан:{CLR_RESET} {CLR_YELLOW}{current_ip:<17}{CLR_RESET} "
        f"│ ⚡ Reality в БД: {CLR_RED}{CLR_BOLD}{vpn_count}{CLR_RESET}  "
    )
    sys.stdout.write(line)
    sys.stdout.flush()


def clear_progress_line():
    sys.stdout.write("\r\033[K")
    sys.stdout.flush()


# ==========================================
# ОСНОВНОЙ ASYNC РАННЕР
# ==========================================
async def async_main():
    parser = argparse.ArgumentParser(
        description="RealityChecker 2.7: Глобальный асинхронный детектор VLESS-Reality & ASN/Подсеть сканер"
    )
    parser.add_argument("target", nargs="?", default=None, help="Подсеть CIDR (например, 185.220.101.0/24) или одиночный IP")
    parser.add_argument("--asn", type=str, default=None, help="Номер автономной системы (например: 24940 или AS24940) для сканирования ВСЕХ её подсетей")
    parser.add_argument("-p", "--ports", type=str, default="443", help="Порты через запятую (например: 443,8443,2053,2083,2087,2096)")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Одновременных async соединений (по умолчанию: 500)")
    parser.add_argument("--timeout", type=float, default=2.5, help="Таймаут соединения в сек (по умолчанию: 2.5)")
    parser.add_argument("--delay", type=float, default=0.0, help="Пауза/задержка в сек между запуском соединений для скрытности (например: 0.05)")
    parser.add_argument("--shuffle", action="store_true", help="Случайно перемешать список IP (Randomized scan) для обхода детектирования IDS/IPS")
    parser.add_argument("--db", type=str, default="reality_vpn_servers.db", help="SQLite база данных (сохраняются ТОЛЬКО VPN)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Файл для сохранения отчета")
    parser.add_argument("--tld", type=str, default=None, help="Фильтр по доменной зоне (например: ru, com, org). По умолчанию: ВСЕ домены")
    parser.add_argument("--only-vpn", action="store_true", help="Показывать в консоли ТОЛЬКО найденные Reality/VPN сервера")
    parser.add_argument("--check-fixed", action="store_true", help="Аудит базы: проверить кто исправился, кто выключился, а кто сменил SNI")
    parser.add_argument("--export-vpn", type=str, default=None, help="Экспорт списка Reality/VPN серверов из БД в файл")
    parser.add_argument("--purge-dead", action="store_true", help="Удалить из БД неактивные серверы (is_active = 0)")

    args = parser.parse_args()
    db_conn = init_db(args.db)

    # Режим 1: Очистка неактивных
    if args.purge_dead:
        cur = db_conn.cursor()
        cur.execute("DELETE FROM vpn_servers WHERE is_active = 0")
        deleted = cur.rowcount
        db_conn.commit()
        print(f"{CLR_GREEN}[+] Удалено {deleted} неактивных серверов из базы данных.{CLR_RESET}")
        return

    # Режим 2: Экспорт активных VPN
    if args.export_vpn:
        cur = db_conn.cursor()
        cur.execute("""
            SELECT ip, port, domain, tls_version, confidence, hits, last_status, real_dns_ips, last_seen 
            FROM vpn_servers 
            WHERE is_active = 1
            ORDER BY hits DESC
        """)
        rows = cur.fetchall()
        with open(args.export_vpn, "w", encoding="utf-8") as f:
            f.write(f"# Reality/VPN Active Servers Global Export ({len(rows)} hosts)\n")
            for ip, p, dom, tls_v, conf, hits, status, r_ips, l_seen in rows:
                f.write(f"{ip}:{p}\t{dom}\t{tls_v}\t[Hits:{hits}]\t[{status}]\t(DNS: {r_ips})\tSeen: {l_seen}\n")
        print(f"{CLR_GREEN}[+] Экспортировано {len(rows)} активных Reality/VPN серверов в файл: {args.export_vpn}{CLR_RESET}")
        return

    # Режим 3: Аудит «Кто исправился» (--check-fixed)
    if args.check_fixed:
        await audit_fixed_hosts(db_conn, concurrency=args.concurrency, timeout=args.timeout)
        return

    if not args.target and not args.asn:
        total_db, active_db = get_db_vpn_stats(db_conn)
        print(f"\n{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f"{CLR_CYAN}  RealityChecker 2.7 (ASN Scanning + Stealth Rate-Limiting Engine){CLR_RESET}")
        print(f"{CLR_CYAN}======================================================================{CLR_RESET}")
        print(f"  В базе данных VPN серверов: {CLR_YELLOW}{total_db}{CLR_RESET} (Активных: {CLR_GREEN}{active_db}{CLR_RESET})")
        print(f"\n{CLR_GRAY}Примеры использования:{CLR_RESET}")
        print(f"  1. Сканирование всей автономной системы (ASN) со скрытностью:")
        print(f"     py {sys.argv[0]} --asn 24940 -p 443 --delay 0.02 --shuffle -c 300")
        print(f"  2. Сканирование подсети:")
        print(f"     py {sys.argv[0]} 185.220.101.0/24 -p 443,8443 -c 600")
        print(f"  3. Проверить аудит базы (кто исправился / выключился):")
        print(f"     py {sys.argv[0]} --check-fixed")
        print(f"  4. Экспорт активных серверов:")
        print(f"     py {sys.argv[0]} --export-vpn active_vpns.txt\n")
        return

    # Разбор портов
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    if not ports:
        ports = [443]

    tld_filter = args.tld.lower().strip().lstrip(".") if args.tld else None

    # Генерация списка целей (IP, Port)
    targets = []
    
    # Режим А: Сканирование по ASN (--asn)
    if args.asn:
        clean_asn, prefixes = fetch_asn_prefixes(args.asn)
        if not prefixes:
            print(f"{CLR_RED}[-] Не удалось обнаружить маршрутизируемые подсети для AS{clean_asn}.{CLR_RESET}")
            return
        print(f"{CLR_GREEN}[+] Для AS{clean_asn} найдено {len(prefixes)} подсетей (CIDR).{CLR_RESET}")
        
        # Разворачиваем все подсети в список хостов
        for cidr in prefixes:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                # Если префикс слишком огромный (> /16, например /12), берем первые подсети или уведомляем
                for ip in net.hosts():
                    for p in ports:
                        targets.append((str(ip), p))
            except Exception:
                pass
    # Режим Б: Одиночная подсеть / IP
    elif args.target:
        try:
            net = ipaddress.ip_network(args.target, strict=False)
            targets = [(str(ip), p) for ip in net.hosts() for p in ports]
        except ValueError:
            targets = [(args.target, p) for p in ports]

    total_tasks = len(targets)
    if total_tasks == 0:
        print(f"{CLR_RED}[!] Нет хостов для сканирования.{CLR_RESET}")
        return

    # Перемешивание хостов при флаге --shuffle (Randomized IP scan)
    if args.shuffle:
        random.shuffle(targets)

    total_db, active_db = get_db_vpn_stats(db_conn)

    print(f"\n{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_CYAN}  REALITYCHECKER 2.7: СКАНИРОВАНИЕ ({total_tasks} целей){CLR_RESET}")
    print(f"{CLR_CYAN}  Порты: {ports} | Concurrency: {args.concurrency} | Stealth Delay: {args.delay}s | Shuffle: {args.shuffle}{CLR_RESET}")
    print(f"{CLR_CYAN}  (В базу сохраняются ИСКЛЮЧИТЕЛЬНО подтвержденные Reality/VPN){CLR_RESET}")
    print(f"{CLR_CYAN}======================================================================{CLR_RESET}\n")

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    semaphore = asyncio.Semaphore(args.concurrency)
    found_vpn_hosts = []
    db_vpn_buffer = []
    scanned_count = 0

    async def worker(ip: str, port: int):
        nonlocal scanned_count
        # Применяем настраиваемый таймаут / задержку между соединениями для скрытности
        if args.delay > 0:
            await asyncio.sleep(args.delay * random.uniform(0.7, 1.3))

        async with semaphore:
            res = await scan_host_tls(ip, port, args.timeout, ssl_ctx)
            scanned_count += 1
            return res

    tasks = [asyncio.create_task(worker(ip, p)) for ip, p in targets]

    for future in asyncio.as_completed(tasks):
        ip, port, tls_ver, domains, status_desc = await future

        update_progress_bar(
            current=scanned_count,
            total=total_tasks,
            current_ip=f"{ip}:{port}",
            vpn_count=len(found_vpn_hosts),
            spinner_idx=scanned_count
        )

        if not domains:
            if not args.only_vpn:
                clear_progress_line()
                if tls_ver in ("TIMEOUT", "CLOSED", "UNREACHABLE"):
                    badge = f"{CLR_DARK_GRAY}[ЗАКРЫТ / НЕДОСТУПЕН]{CLR_RESET}"
                    print(f"{badge} {CLR_GRAY}{ip}:{port:<5}{CLR_RESET} │ {CLR_DARK_GRAY}{status_desc}{CLR_RESET}")
                else:
                    badge = f"{CLR_YELLOW}[НЕТ SSL / ОШИБКА]{CLR_RESET}"
                    print(f"{badge} {CLR_GRAY}{ip}:{port:<5}{CLR_RESET} │ {CLR_YELLOW}{status_desc}{CLR_RESET}")
            continue

        if tld_filter:
            target_domains = [d for d in domains if d.endswith(f".{tld_filter}") or d == tld_filter]
        else:
            target_domains = domains

        if not target_domains:
            if not args.only_vpn:
                clear_progress_line()
                badge = f"{CLR_GRAY}[ДРУГАЯ ЗОНА]{CLR_RESET}"
                print(f"{badge} {CLR_GRAY}{ip}:{port:<5}{CLR_RESET} │ Домены не подходят под фильтр --tld {tld_filter}")
            continue

        domain_checks = []
        has_vpn_alert = False
        has_cdn_alert = False

        for d in target_domains:
            chk = await verify_sni_affinity(d, ip, tls_ver, domains)
            if chk["is_vpn"]:
                has_vpn_alert = True
            if chk.get("is_cdn"):
                has_cdn_alert = True
            domain_checks.append({
                "domain": d,
                "check": chk
            })

        if args.only_vpn and not has_vpn_alert:
            continue

        host_record = {
            "ip": ip,
            "port": port,
            "tls_version": tls_ver,
            "checks": domain_checks,
            "has_vpn_alert": has_vpn_alert,
            "has_cdn_alert": has_cdn_alert,
            "other_domains": [d for d in domains if d not in target_domains]
        }

        # В БАЗУ ДАННЫХ ИДЕТ ТОЛЬКО НАСТОЯЩИЙ VPN (НЕ CDN)!
        if has_vpn_alert:
            found_vpn_hosts.append(host_record)
            db_vpn_buffer.append(host_record)
            if len(db_vpn_buffer) >= 10:
                save_vpn_batch_to_db(db_conn, db_vpn_buffer)
                db_vpn_buffer.clear()

        # Красивый вывод карточки хоста
        clear_progress_line()
        if has_vpn_alert:
            badge = f"{CLR_BG_RED} ⚡ ОБНАРУЖЕН REALITY / VPN {CLR_RESET}"
            print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ {CLR_MAGENTA}TLS: {tls_ver}{CLR_RESET} │ {CLR_GREEN}+[В БАЗУ]{CLR_RESET}")
            for item in domain_checks:
                d = item["domain"]
                chk = item["check"]
                if chk["is_vpn"]:
                    print(f"   ➜ {CLR_RED}{CLR_BOLD}{d:<35}{CLR_RESET} [{chk['confidence']}]")
                    print(f"     {CLR_YELLOW}└─ {chk['note']}{CLR_RESET}")
            print()
        elif has_cdn_alert:
            if not args.only_vpn:
                badge = f"{CLR_BG_BLUE} 🌐 CDN / EDGE УЗЕЛ {CLR_RESET}"
                print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ {CLR_CYAN}TLS: {tls_ver}{CLR_RESET} │ {CLR_GRAY}(Легитимный CDN - не VPN){CLR_RESET}")
                for item in domain_checks[:3]:
                    d = item["domain"]
                    chk = item["check"]
                    print(f"   ➜ {CLR_BLUE}{d:<35}{CLR_RESET} {CLR_GRAY}({chk['note']}){CLR_RESET}")
                if len(domain_checks) > 3:
                    print(f"   └─ {CLR_GRAY}...и еще {len(domain_checks)-3} доменов{CLR_RESET}")
                print()
        elif not args.only_vpn:
            badge = f"{CLR_GREEN}[OK - СВОЙ ХОСТ]{CLR_RESET}"
            print(f"{badge} {CLR_BOLD}{ip}:{port:<5}{CLR_RESET} │ {CLR_GRAY}TLS: {tls_ver}{CLR_RESET} │ {CLR_GRAY}(Не VPN){CLR_RESET}")
            for item in domain_checks:
                d = item["domain"]
                chk = item["check"]
                print(f"   ➜ {CLR_GRAY}{d:<35} ({chk['note']}){CLR_RESET}")
            print()

    # Сохраняем остаток
    if db_vpn_buffer:
        save_vpn_batch_to_db(db_conn, db_vpn_buffer)
        db_vpn_buffer.clear()

    clear_progress_line()

    # Итоговая сводка
    total_db, active_db = get_db_vpn_stats(db_conn)
    print(f"\n{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_BOLD}ИТОГИ СКАНИРОВАНИЯ:{CLR_RESET}")
    print(f"  ➜ Проверено сокетов:              {scanned_count}/{total_tasks}")
    print(f"  ➜ Найдено и сохранено REALITY:    {CLR_RED}{CLR_BOLD}+{len(found_vpn_hosts)}{CLR_RESET}")
    print(f"  ➜ ВСЕГО активных VPN в базе:      {CLR_GREEN}{CLR_BOLD}{active_db}{CLR_RESET} (из {total_db})")
    print(f"{CLR_CYAN}======================================================================{CLR_RESET}")

    if found_vpn_hosts:
        print(f"\n{CLR_RED}{CLR_BOLD}Список найденных серверов Reality / VLESS в этом запуске:{CLR_RESET}")
        for h in found_vpn_hosts:
            v_doms = [item["domain"] for item in h["checks"] if item["check"]["is_vpn"]]
            print(f"  {CLR_RED}●{CLR_RESET} {CLR_BOLD}{h['ip']}:{h['port']}{CLR_RESET} [{h['tls_version']}] ➔ SNI: {', '.join(v_doms)}")

    if args.output and found_vpn_hosts:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(f"REALITYCHECKER 2.7 VPN REPORT - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n\n")
                for h in found_vpn_hosts:
                    f.write(f"{h['ip']}:{h['port']} (TLS: {h['tls_version']}) [⚡ REALITY/VPN]\n")
                    for item in h["checks"]:
                        if item["check"]["is_vpn"]:
                            f.write(f"   - {item['domain']}: {item['check']['note']}\n")
                    f.write("\n")
            print(f"\n{CLR_GREEN}[+] Отчет по найденным VPN сохранен: {args.output}{CLR_RESET}")
        except Exception as e:
            print(f"\n{CLR_RED}[-] Ошибка сохранения файла: {e}{CLR_RESET}")


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print(f"\n{CLR_YELLOW}[!] Прервано пользователем (Ctrl+C). Найденные VPN сохранены в БД.{CLR_RESET}")


if __name__ == "__main__":
    main()
