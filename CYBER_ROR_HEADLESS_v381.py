#!/usr/bin/env python3
"""
CYBER-ROR HEADLESS v3.81
Cyber Response & Operational Resilience - Bakgrunnsversjon

Nytt i v3.81 (alt er konfigurerbart i config.json):
- Valgbare porter OVERALT: honeypot_ports, tarpit_ports, emulated_services.
  En feil port repareres ved å redigere config.json og starte på nytt.
  Porter som ikke kan bindes (opptatt/ugyldig) hoppes over med tydelig
  loggmelding - programmet krasjer aldri.
- Emulerte honeypots (medium-interaction): falsk SSH-banner, Telnet-login,
  FTP-login og falsk router-loginside (HTTP). Fanger brukernavn/passord
  og payload til data/captured_credentials.json
- Skanne-detektor: IP som rører N porter innen X sekunder blir blokkert
- Instant-block ved felle-berøring (private nettverk er hardkodet unntatt)
- Botnet-feeds: Feodo Tracker (C2), DShield, Spamhaus DROP (subnett)
- Bulk-brannmurregler: tusenvis av IP-er i få regler i stedet for én om gangen
- X-ARF auto-rapport genereres per blokkering (data/reports/)
- Arver ALT fra v3.80: VT/AbuseIPDB, geo-cache, statistikk, robust config
"""

import os
import sys
import json
import time
import logging
import requests
import subprocess
import threading
import socket
import csv
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, deque

BASE_DIR = Path("C:/cyber")
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
CONFIG_FILE = BASE_DIR / "config.json"
BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"
VT_RESULTS_FILE = DATA_DIR / "vt_results.json"
ABUSEIPDB_RESULTS_FILE = DATA_DIR / "abuseipdb_results.json"
GEO_CACHE_FILE = DATA_DIR / "geoip_cache.json"
STATS_FILE = DATA_DIR / "statistics.json"
CREDENTIALS_FILE = DATA_DIR / "captured_credentials.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_DIR / 'cyber_ror.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('CYBER-ROR')


def load_config():
    default_config = {
        # --- arvet fra tidligere versjoner (beholdes alltid hvis de finnes) ---
        "virustotal_api_key": "",
        "abuseipdb_api_key": "",
        "greynoise_api_key": "",
        "alienvault_api_key": "",
        "blocklist_api_key": "",
        "auto_block_threshold": 5,
        "log_level": "INFO",
        "blocklist_interval": 300,
        "honeypot_ports": [8080, 9090, 8443, 3000, 5000, 7000, 9000, 10000],
        "tarpit_enabled": True,
        "virustotal_check_enabled": True,
        "virustotal_block_threshold": 3,
        "abuseipdb_check_enabled": True,
        "abuseipdb_block_threshold": 75,
        "abuseipdb_max_age_days": 90,
        "geoip_enabled": True,
        "auto_export_csv": True,
        "export_interval": 3600,
        "auto_report_abuseipdb": True,
        "message_server_enabled": True,
        "message_server_port": 8081,
        "default_message": "Your IP has been blocked by CYBER-ROR.",
        "warning_message": "WARNING: Your IP has been logged and reported.",
        "whitelist_ips": ["127.0.0.1", "192.168.1.1"],
        "manual_subnets": ["204.76.203.0/24"],
        "email_alerts_enabled": False,
        "email_smtp_server": "",
        "email_port": 587,
        "email_username": "",
        "email_password": "",
        "email_to": "",
        "reporter_name": "",
        "reporter_email": "",
        # --- NYTT i v3.81: valgbare felle-porter ---
        "tarpit_ports": [23, 21, 3389, 3306, 1433, 5900, 6379, 27017, 5432,
                         110, 143, 993, 995, 25, 587, 5555, 9200, 11211],
        "tarpit_delay_seconds": 10,
        # Emulerte tjenester: port -> protokoll (ssh/telnet/ftp/http)
        "emulated_services": {
            "23": "telnet",
            "21": "ftp",
            "80": "http",
            "7547": "http",
            "2323": "telnet",
            "2222": "ssh",
            "2121": "ftp",
            "8888": "http"
        },
        "emulation_enabled": True,
        # --- NYTT: skanne-detektor ---
        "scan_detector_enabled": True,
        "scan_ports_threshold": 3,
        "scan_window_seconds": 60,
        # --- NYTT: instant-block ---
        "instant_block_on_trap": True,
        # --- NYTT: botnet-feeds ---
        "feeds_enabled": {
            "blocklist_de": True,
            "feodo": True,
            "dshield": True,
            "spamhaus_drop": False
        },
        # --- NYTT: bulk-blokkering ---
        "bulk_block_enabled": True,
        "bulk_rule_chunk_size": 500,
        # --- NYTT: X-ARF ---
        "xarf_autoreport": True
    }

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                changed = False
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                        changed = True
                if changed:
                    save_config(config)  # legg nye nøkler inn i filen så de kan redigeres
                return config
        except Exception as e:
            logger.error(f"Feil ved lasting av config (bruker defaults): {e}")
            try:
                backup = CONFIG_FILE.with_suffix('.json.bak')
                with open(CONFIG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    bad = f.read()
                with open(backup, 'w', encoding='utf-8') as f:
                    f.write(bad)
                logger.info(f"Korrupt config sikkerhetskopiert til {backup}")
            except Exception:
                pass

    save_config(default_config)
    return default_config


def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        logger.info("Konfigurasjon lagret")
    except Exception as e:
        logger.error(f"Feil ved lagring av config: {e}")


# === SIKKERHET: aldri blokker oss selv ===
PRIVATE_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
]


def is_safe_ip(ip, whitelist):
    """True hvis IP ALDRI skal blokkeres (privat/lokal/whitelist)."""
    if ip in whitelist:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        for net in PRIVATE_NETWORKS:
            if addr in net:
                return True
    except ValueError:
        return True  # ugyldig IP -> ikke blokker
    return False


def parse_ports(value, name):
    """v3.81: robust port-parsing - tåler strenger, hopper over tull."""
    ports = []
    for p in (value or []):
        try:
            port = int(p)
            if 1 <= port <= 65535:
                ports.append(port)
            else:
                logger.error(f"{name}: port {port} utenfor 1-65535 - ignorert")
        except (TypeError, ValueError):
            logger.error(f"{name}: ugyldig port '{p}' - ignorert")
    return ports


# === GEOIP MED PERSISTENT CACHE ===
class GeoIPLookup:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.cache = {}
        self._dirty = 0
        self.load_cache()

    def load_cache(self):
        if GEO_CACHE_FILE.exists():
            try:
                with open(GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                logger.info(f"Geo-cache lastet: {len(self.cache)} IP-er")
            except Exception as e:
                logger.error(f"Geo-cache feil: {e}")

    def save_cache(self):
        try:
            with open(GEO_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Geo-cache lagringsfeil: {e}")

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]
        if not self.enabled:
            return {'country': 'Unknown', 'country_code': 'Unknown',
                    'city': 'Unknown', 'isp': 'Unknown', 'lat': 0, 'lon': 0}
        try:
            r = requests.get("http://ip-api.com/json/" + ip, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'lat': data.get('lat', 0),
                        'lon': data.get('lon', 0)
                    }
                    self.cache[ip] = result
                    self._dirty += 1
                    if self._dirty >= 10:
                        self._dirty = 0
                        self.save_cache()
                    time.sleep(1.4)
                    return result
        except Exception as e:
            logger.error(f"GeoIP error: {e}")
        return {'country': 'Unknown', 'country_code': 'Unknown',
                'city': 'Unknown', 'isp': 'Unknown', 'lat': 0, 'lon': 0}


# === STATISTIKK (deles med GUI-dashboardet) ===
class StatisticsWriter:
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.hourly_ips = defaultdict(list)
        self.load()

    def load(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
                    self.hourly_ips = defaultdict(list,
                        {k: list(v) for k, v in data.get('hourly_ips', {}).items()})
            except Exception:
                pass

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')
        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        if country and country != 'Unknown':
            self.country_stats[country] += 1
        if ip not in self.hourly_ips[hour_key]:
            self.hourly_ips[hour_key].append(ip)
        self.save()

    def save(self):
        try:
            with open(STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats),
                    'hourly_ips': dict(self.hourly_ips)
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Statistikk lagringsfeil: {e}")


# === VIRUSTOTAL API v3 ===
class VirusTotalChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}
        self.rate_limit_delay = 15
        self.last_request_time = 0

    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def check_ip(self, ip):
        if not self.api_key:
            return None
        self._rate_limit()
        try:
            response = requests.get(f"{self.base_url}/ip_addresses/{ip}",
                                    headers=self.headers, timeout=15)
            if response.status_code == 200:
                attrs = response.json()['data']['attributes']
                stats = attrs['last_analysis_stats']
                result = {
                    'ip': ip, 'timestamp': datetime.now().isoformat(), 'source': 'virustotal',
                    'malicious': stats.get('malicious', 0), 'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0), 'undetected': stats.get('undetected', 0),
                    'reputation': attrs.get('reputation', 0),
                    'country': attrs.get('country', 'Unknown'),
                    'as_owner': attrs.get('as_owner', 'Unknown'),
                    'total_engines': sum(stats.values()) if stats else 0
                }
                logger.info(f"VirusTotal {ip}: {result['malicious']}/{result['total_engines']} ondsinnede")
                return result
            return {'ip': ip, 'source': 'virustotal', 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"VirusTotal feil: {e}")
            return {'ip': ip, 'source': 'virustotal', 'error': str(e)}

    def should_block(self, result, threshold=3):
        if not result or 'error' in result:
            return False
        malicious = result.get('malicious', 0)
        total = result.get('total_engines', 1)
        if malicious >= threshold:
            return True
        if total > 0 and (malicious / total) > 0.2:
            return True
        return False


# === ABUSEIPDB API v2 ===
class AbuseIPDBChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {"Accept": "application/json", "Key": api_key}
        self.rate_limit_delay = 5
        self.last_request_time = 0
        self.daily_limit = 1000
        self.daily_count = 0
        self.daily_reset = datetime.now().date()

    def _rate_limit(self):
        today = datetime.now().date()
        if today != self.daily_reset:
            self.daily_count = 0
            self.daily_reset = today
        if self.daily_count >= self.daily_limit:
            logger.warning("AbuseIPDB: Daglig grense nådd (1000)")
            return False
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
        return True

    def check_ip(self, ip, max_age_days=90):
        if not self.api_key or not self._rate_limit():
            return None if not self.api_key else {'ip': ip, 'source': 'abuseipdb', 'error': 'Daily limit'}
        try:
            response = requests.get(f"{self.base_url}/check", headers=self.headers,
                                    params={'ipAddress': ip, 'maxAgeInDays': str(max_age_days)}, timeout=15)
            self.daily_count += 1
            if response.status_code == 200:
                data = response.json()['data']
                result = {
                    'ip': ip, 'timestamp': datetime.now().isoformat(), 'source': 'abuseipdb',
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported_at': data.get('lastReportedAt', 'Unknown'),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
                logger.info(f"AbuseIPDB {ip}: score={result['abuse_confidence_score']}%")
                return result
            return {'ip': ip, 'source': 'abuseipdb', 'error': f'HTTP {response.status_code}'}
        except Exception as e:
            logger.error(f"AbuseIPDB feil: {e}")
            return {'ip': ip, 'source': 'abuseipdb', 'error': str(e)}

    def report_ip(self, ip, categories="18,22", comment=""):
        if not self.api_key or not self._rate_limit():
            return False
        try:
            response = requests.post(
                f"{self.base_url}/report", headers=self.headers,
                data={'ip': ip, 'categories': categories,
                      'comment': comment or f'Port scan/brute-force detected by CYBER-ROR honeypot at {datetime.now().isoformat()}'},
                timeout=15)
            self.daily_count += 1
            if response.status_code == 200:
                logger.info(f"AbuseIPDB: Reported {ip} successfully")
                return True
            return False
        except Exception as e:
            logger.error(f"AbuseIPDB report feil: {e}")
            return False

    def fetch_blacklist(self, confidence_minimum=75, limit=1000):
        if not self.api_key or not self._rate_limit():
            return []
        try:
            response = requests.get(f"{self.base_url}/blacklist", headers=self.headers,
                                    params={'confidenceMinimum': str(confidence_minimum), 'limit': str(limit)},
                                    timeout=30)
            self.daily_count += 1
            if response.status_code == 200:
                ips = [item['ipAddress'] for item in response.json()['data']]
                logger.info(f"AbuseIPDB: Hentet {len(ips)} IP-er fra blacklist")
                return ips
            return []
        except Exception as e:
            logger.error(f"AbuseIPDB blacklist feil: {e}")
            return []

    def should_block(self, result, threshold=75):
        if not result or 'error' in result:
            return False
        score = result.get('abuse_confidence_score', 0)
        total_reports = result.get('total_reports', 0)
        if result.get('is_whitelisted', False):
            return False
        if score >= threshold:
            return True
        if total_reports >= 10 and score >= 50:
            return True
        return False


# === IP-BLOKKERING + BULK-BRANNUR (v3.81) ===
class IPBlocker:
    def __init__(self, manual_subnets=None, whitelist=None):
        self.blocked_ips = set()
        self.manual_subnets = manual_subnets or []
        self.whitelist = whitelist or []
        self.load_blocked_ips()

    def load_blocked_ips(self):
        if BLOCKED_IPS_FILE.exists():
            try:
                with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked', []))
                logger.info(f"Lastet {len(self.blocked_ips)} blokkerte IP-er")
            except Exception as e:
                logger.error(f"Feil ved lasting av blokkerte IP-er: {e}")

    def save_blocked_ips(self):
        try:
            with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                json.dump({'blocked': list(self.blocked_ips)}, f, indent=2)
        except Exception as e:
            logger.error(f"Feil ved lagring av blokkerte IP-er: {e}")

    def covered_by_subnet(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            for s in self.manual_subnets:
                try:
                    if addr in ipaddress.ip_network(s, strict=False):
                        return s
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

    def block_ip(self, ip, reason=""):
        if is_safe_ip(ip, self.whitelist):
            logger.warning(f"SIKKE RHETSSPERRE: {ip} er lokal/whitelist - blokkeres IKKE")
            return False
        if ip in self.blocked_ips:
            return False
        covering = self.covered_by_subnet(ip)
        if covering:
            logger.info(f"Skipper {ip} - dekket av manuell regel {covering}")
            return False
        try:
            rule_name = f"CYBER-ROR-BLOCK-{ip.replace('.', '-')}"
            ok = True
            for direction, suffix in (('in', ''), ('out', '-OUT')):
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name={rule_name}{suffix}', f'dir={direction}',
                       'action=block', f'remoteip={ip}', 'enable=yes']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    ok = False
            if ok:
                self.blocked_ips.add(ip)
                self.save_blocked_ips()
                logger.info(f"Blokkert IP: {ip} ({reason})")
                return True
            return False
        except Exception as e:
            logger.error(f"Feil ved blokkering av {ip}: {e}")
            return False

    def unblock_ip(self, ip):
        rule_name = f"CYBER-ROR-BLOCK-{ip.replace('.', '-')}"
        try:
            for suffix in ('', '-OUT'):
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                                f'name={rule_name}{suffix}'], capture_output=True, timeout=30)
            self.blocked_ips.discard(ip)
            self.save_blocked_ips()
            logger.info(f"Fjernet blokkering: {ip}")
            return True
        except Exception as e:
            logger.error(f"Feil ved fjerning av blokkering: {e}")
            return False


class BulkFirewallManager:
    """v3.81: én brannmurregel per N IP-er i stedet for én regel per IP.
    Gjør at 25 000+ blocklist-IP-er kan ligge inne samtidig."""

    def __init__(self, chunk_size=500):
        self.chunk_size = chunk_size
        self.current_ips = set()

    def _delete_all_bulk_rules(self):
        try:
            subprocess.run(
                ['powershell', '-Command',
                 'Get-NetFirewallRule | Where-Object {$_.DisplayName -like "CYBER-ROR-BULK-*"} | Remove-NetFirewallRule'],
                capture_output=True, text=True, timeout=60)
        except Exception as e:
            logger.error(f"Feil ved sletting av bulk-regler: {e}")

    def update(self, ips):
        """Erstatt alle bulk-regler med ny IP-mengde (kun hvis endret)."""
        new_set = set(ips)
        if new_set == self.current_ips:
            logger.info(f"Bulk-blokkering uendret ({len(new_set)} IP-er)")
            return
        self._delete_all_bulk_rules()
        ip_list = sorted(new_set)
        chunks = [ip_list[i:i + self.chunk_size] for i in range(0, len(ip_list), self.chunk_size)]
        for idx, chunk in enumerate(chunks):
            remote = ','.join(chunk)
            for direction, suffix in (('in', ''), ('out', '-OUT')):
                cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                       f'name=CYBER-ROR-BULK-{idx:03d}{suffix}', f'dir={direction}',
                       'action=block', f'remoteip={remote}', 'enable=yes']
                subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        self.current_ips = new_set
        logger.info(f"Bulk-blokkering oppdatert: {len(ip_list)} IP-er i {len(chunks)} regler")


# === X-ARF AUTO-RAPPORT (v3.81) ===
class XarfReporter:
    """Genererer X-ARF-fil per blokkering. Sender med SMTP hvis konfigurert."""

    @staticmethod
    def build(ip, reporter_email=""):
        ts_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S +0000')
        return {
            "xarf": {
                "Version": "0.2",
                "ReporterInfo": {
                    "ReporterOrg": "CYBER-ROR",
                    "ReporterOrgEmail": reporter_email or "unknown@example.com",
                    "ReporterOrgDomain": "localhost"
                },
                "ReportInfo": {
                    "ReportID": f"cyber-ror-{ip.replace('.', '-')}-{int(time.time())}",
                    "ReportClass": "abuse",
                    "ReportType": "login-attack",
                    "Date": ts_utc,
                    "UserAgent": "CYBER-ROR v3.81"
                },
                "SourceInfo": {
                    "Source": ip,
                    "SourceType": "ipv4",
                    "Port": "multiple",
                    "Service": "honeypot"
                }
            }
        }

    @staticmethod
    def save(ip, reporter_email=""):
        try:
            xarf = XarfReporter.build(ip, reporter_email)
            fname = REPORTS_DIR / f"xarf_{ip.replace('.', '_')}_{int(time.time())}.json"
            with open(fname, 'w', encoding='utf-8') as f:
                json.dump(xarf, f, indent=2)
            logger.info(f"X-ARF lagret: {fname}")
            return str(fname)
        except Exception as e:
            logger.error(f"X-ARF feil: {e}")
            return None


# === FELLER (v3.81: alle porter valgbare, bind-feil krasjer aldri) ===
class CredentialLogger:
    """Lagrer fangede brukernavn/passord til data/captured_credentials.json"""
    @staticmethod
    def log(ip, port, service, username="", password="", raw=""):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip, 'port': port, 'service': service,
            'username': username, 'password': password,
            'raw': raw[:500]
        }
        try:
            data = []
            if CREDENTIALS_FILE.exists():
                with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            data.insert(0, entry)
            data = data[:5000]
            with open(CREDENTIALS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            if username or password:
                logger.warning(f"CREDENTIAL FANGST [{service}] {ip}: {username}/{password}")
        except Exception as e:
            logger.error(f"Credential-logg feil: {e}")


class EmulatedHoneypot:
    """v3.81: medium-interaction honeypot. Falske tjenester som fanger
    brukernavn/passord og payloads. Porter velges i config (emulated_services)."""

    ROUTER_PAGE = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<html><head><title>NETGEAR Router</title></head><body>"
        "<h2>Router Login</h2>"
        "<form method='POST' action='/login'>"
        "Username: <input name='username'><br>"
        "Password: <input name='password' type='password'><br>"
        "<input type='submit' value='Login'></form>"
        "</body></html>"
    )

    def __init__(self, services, on_attack):
        """services: dict port(int) -> protokoll(str). on_attack(ip, port) kalles ved treff."""
        self.services = services
        self.on_attack = on_attack
        self.running = False
        self.servers = []

    def start(self):
        self.running = True
        started = 0
        for port, proto in self.services.items():
            t = threading.Thread(target=self._listen, args=(port, proto), daemon=True)
            t.start()
            started += 1
        logger.info(f"Emulerte honeypots: {started} tjenester våkner ({self.services})")

    def _listen(self, port, proto):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            server.settimeout(1.0)
            self.servers.append(server)
            logger.info(f"Emulert {proto} lytter på port {port}")
        except Exception as e:
            # v3.81: en feil port skal være lett å reparere - logg tydelig, fortsett uten
            logger.error(f"EMULERT FELLE: Kunne ikke binde port {port} ({proto}): {e} "
                         f"- hoppet over. Sjekk config.json -> emulated_services")
            return
        while self.running:
            try:
                conn, addr = server.accept()
                ip = addr[0]
                logger.warning(f"EMULERT FELLE: {ip} koblet til {proto} på port {port}")
                self.on_attack(ip, port)
                t = threading.Thread(target=self._handle, args=(conn, ip, port, proto), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Emulert felle feil på port {port}: {e}")

    def _handle(self, conn, ip, port, proto):
        try:
            conn.settimeout(30)
            if proto == 'telnet':
                self._telnet(conn, ip, port)
            elif proto == 'ftp':
                self._ftp(conn, ip, port)
            elif proto == 'ssh':
                self._ssh(conn, ip, port)
            elif proto == 'http':
                self._http(conn, ip, port)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _recv_line(self, conn, maxlen=256):
        buf = b''
        try:
            while len(buf) < maxlen:
                chunk = conn.recv(1)
                if not chunk or chunk == b'\n':
                    break
                if chunk != b'\r':
                    buf += chunk
        except Exception:
            pass
        return buf.decode('utf-8', errors='ignore').strip()

    def _telnet(self, conn, ip, port):
        """Falsk Telnet-login - Mirai-fellende."""
        for attempt in range(3):
            conn.sendall(b"\r\nUbuntu 18.04.5 LTS\r\nlogin: ")
            user = self._recv_line(conn)
            conn.sendall(b"Password: ")
            pwd = self._recv_line(conn)
            if user or pwd:
                CredentialLogger.log(ip, port, 'telnet', user, pwd)
            conn.sendall(b"\r\nLogin incorrect\r\n")
        conn.sendall(b"\r\n")

    def _ftp(self, conn, ip, port):
        """Falsk FTP-server med USER/PASS-fangst."""
        conn.sendall(b"220 (vsFTPd 3.0.3)\r\n")
        user = pwd = ""
        for _ in range(10):
            line = self._recv_line(conn)
            if not line:
                break
            cmd = line.upper()
            if cmd.startswith('USER'):
                user = line[5:].strip()
                conn.sendall(b"331 Please specify the password.\r\n")
            elif cmd.startswith('PASS'):
                pwd = line[5:].strip()
                CredentialLogger.log(ip, port, 'ftp', user, pwd)
                conn.sendall(b"530 Login incorrect.\r\n")
            elif cmd.startswith('QUIT'):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"530 Please login with USER and PASS.\r\n")

    def _ssh(self, conn, ip, port):
        """Falsk SSH-banner - logger hva klienten sender (banner/kex-start)."""
        conn.sendall(b"SSH-2.0-OpenSSH_7.4\r\n")
        try:
            data = conn.recv(512)
            if data:
                CredentialLogger.log(ip, port, 'ssh', raw=repr(data[:200]))
        except Exception:
            pass
        time.sleep(2)

    def _http(self, conn, ip, port):
        """Falsk router-loginside - fanger POST-data (loginforsøk/eksploits)."""
        try:
            data = b''
            conn.settimeout(5)
            while len(data) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b'\r\n\r\n' in data and b'POST' not in data[:10]:
                    break
                if b'POST' in data[:10] and len(data) > 4096:
                    break
        except Exception:
            pass
        if data:
            text = data.decode('utf-8', errors='ignore')
            first_line = text.split('\r\n')[0] if text else ''
            logger.warning(f"HTTP-FELLE: {ip} -> {first_line[:120]}")
            user = pwd = ""
            if 'POST' in text[:10]:
                body = text.split('\r\n\r\n')[-1]
                for pair in body.split('&'):
                    if '=' in pair:
                        k, v = pair.split('=', 1)
                        if 'user' in k.lower():
                            user = v
                        if 'pass' in k.lower():
                            pwd = v
                CredentialLogger.log(ip, port, 'http', user, pwd, raw=first_line)
            else:
                CredentialLogger.log(ip, port, 'http', raw=first_line)
        try:
            conn.sendall(self.ROUTER_PAGE.encode('utf-8'))
        except Exception:
            pass

    def stop(self):
        self.running = False
        for s in self.servers:
            try:
                s.close()
            except Exception:
                pass


class Tarpit:
    """v3.81: porter fra config (tarpit_ports). Bind-feil krasjer aldri."""
    def __init__(self, ports, delay, on_attack):
        self.ports = ports
        self.delay = delay
        self.on_attack = on_attack
        self.running = False
        self.servers = []

    def start(self):
        self.running = True
        started = 0
        for port in self.ports:
            t = threading.Thread(target=self._tarpit_listen, args=(port,), daemon=True)
            t.start()
            started += 1
        logger.info(f"Tarpit våkner på {started} porter")

    def _tarpit_listen(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            server.settimeout(1.0)
            self.servers.append(server)
            logger.info(f"Tarpit lytter på port {port}")
        except Exception as e:
            logger.error(f"TARPIT: Kunne ikke binde port {port}: {e} "
                         f"- hoppet over. Sjekk config.json -> tarpit_ports")
            return
        while self.running:
            try:
                conn, addr = server.accept()
                ip = addr[0]
                logger.warning(f"TARPIT: Angriper {ip} fanget på port {port}")
                self.on_attack(ip, port)
                while self.running:
                    try:
                        conn.send(b'\x00')
                        time.sleep(self.delay)
                    except Exception:
                        break
                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Tarpit feil: {e}")

    def stop(self):
        self.running = False
        for s in self.servers:
            try:
                s.close()
            except Exception:
                pass
        logger.info("Tarpit stoppet")


class SimpleHoneypot:
    """Enkel connect-and-close honeypot (honeypot_ports fra config)."""
    def __init__(self, ports, on_attack):
        self.ports = ports
        self.on_attack = on_attack
        self.servers = []
        self.running = False

    def start(self):
        self.running = True
        for port in self.ports:
            t = threading.Thread(target=self._listen, args=(port,), daemon=True)
            t.start()

    def _listen(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            server.settimeout(1.0)
            self.servers.append(server)
            logger.info(f"Honeypot startet på port {port}")
        except Exception as e:
            logger.error(f"HONEYPOT: Kunne ikke binde port {port}: {e} "
                         f"- hoppet over. Sjekk config.json -> honeypot_ports")
            return
        while self.running:
            try:
                conn, addr = server.accept()
                ip = addr[0]
                logger.warning(f"HONEYPOT: Tilkobling fra {ip} på port {port}")
                self.on_attack(ip, port)
                conn.close()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Honeypot feil på port {port}: {e}")

    def stop(self):
        self.running = False
        for server in self.servers:
            try:
                server.close()
            except Exception:
                pass
        logger.info("Honeypot stoppet")


# === SKANNE-DETEKTOR (v3.81) ===
class ScanDetector:
    """IP som rører >= threshold ulike porter innen window sekunder = skanning."""
    def __init__(self, threshold=3, window=60):
        self.threshold = threshold
        self.window = window
        self.events = defaultdict(deque)  # ip -> deque av (port, timestamp)
        self.lock = threading.Lock()

    def record(self, ip, port):
        """Returnerer True hvis dette utløser skanne-alarm."""
        now = time.time()
        with self.lock:
            dq = self.events[ip]
            dq.append((port, now))
            cutoff = now - self.window
            while dq and dq[0][1] < cutoff:
                dq.popleft()
            ports = {p for p, _ in dq}
            if len(ports) >= self.threshold:
                dq.clear()  # unngå gjentatte alarmer
                return True
        return False


# === FEEDS (v3.81: blocklist.de + Feodo + DShield + Spamhaus) ===
class FeedFetcher:
    URLS = {
        'blocklist_de': 'https://lists.blocklist.de/lists/all.txt',
        'feodo': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'dshield': 'https://www.dshield.org/ipsascii.html?limit=100',
        'spamhaus_drop': 'https://www.spamhaus.org/drop/drop.txt'
    }

    @staticmethod
    def fetch_ips(feed_name):
        """Henter rene IP-lister (blocklist.de, feodo)."""
        url = FeedFetcher.URLS.get(feed_name)
        if not url:
            return []
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                ips = []
                for line in r.text.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    # dshield/feodo kan ha ekstra kolonner
                    candidate = line.split()[0] if ' ' in line else line
                    try:
                        ipaddress.ip_address(candidate)
                        ips.append(candidate)
                    except ValueError:
                        continue
                logger.info(f"Feed {feed_name}: {len(ips)} IP-er hentet")
                return ips
            logger.error(f"Feed {feed_name}: HTTP {r.status_code}")
            return []
        except Exception as e:
            logger.error(f"Feed {feed_name} feil: {e}")
            return []

    @staticmethod
    def fetch_subnets(feed_name):
        """Henter subnett-lister (spamhaus DROP, dshield block)."""
        url = FeedFetcher.URLS.get(feed_name)
        if not url:
            return []
        try:
            r = requests.get(url, timeout=30)
            if r.status_code == 200:
                nets = []
                for line in r.text.split('\n'):
                    line = line.strip()
                    if not line or line.startswith(';') or line.startswith('#'):
                        continue
                    candidate = line.split()[0]
                    try:
                        nets.append(str(ipaddress.ip_network(candidate, strict=False)))
                    except ValueError:
                        continue
                logger.info(f"Feed {feed_name}: {len(nets)} subnett hentet")
                return nets
            return []
        except Exception as e:
            logger.error(f"Feed {feed_name} feil: {e}")
            return []


# === HOVEDPROGRAM ===
class CyberRorHeadless:
    def __init__(self):
        logger.info("=" * 50)
        logger.info("CYBER-ROR HEADLESS v3.81 starter")
        logger.info("Emulerte fellere + skannedetektor + bulk-blokkering + feeds")
        logger.info("=" * 50)

        self.config = load_config()
        self.whitelist = self.config.get('whitelist_ips', [])
        self.ip_blocker = IPBlocker(self.config.get('manual_subnets', []), self.whitelist)
        self.geo = GeoIPLookup(self.config.get('geoip_enabled', True))
        self.stats = StatisticsWriter()
        self.vt_checker = VirusTotalChecker(self.config.get('virustotal_api_key', ''))
        self.abuseipdb_checker = AbuseIPDBChecker(self.config.get('abuseipdb_api_key', ''))
        self.bulk = BulkFirewallManager(self.config.get('bulk_rule_chunk_size', 500))
        self.scan_detector = ScanDetector(
            self.config.get('scan_ports_threshold', 3),
            self.config.get('scan_window_seconds', 60))

        self.honeypot = None
        self.tarpit = None
        self.emulated = None
        self.running = False

        self.vt_results = {}
        self.abuseipdb_results = {}
        if VT_RESULTS_FILE.exists():
            try:
                with open(VT_RESULTS_FILE, 'r', encoding='utf-8') as f:
                    self.vt_results = json.load(f)
            except Exception:
                pass
        if ABUSEIPDB_RESULTS_FILE.exists():
            try:
                with open(ABUSEIPDB_RESULTS_FILE, 'r', encoding='utf-8') as f:
                    self.abuseipdb_results = json.load(f)
            except Exception:
                pass

    # ---- felles angrepshåndtering fra alle feller ----
    def on_trap_hit(self, ip, port):
        """Kalles ved enhver felle-berøring: skanne-detektor + instant-block."""
        if is_safe_ip(ip, self.whitelist):
            return

        # Skanne-detektor
        if self.config.get('scan_detector_enabled', True):
            if self.scan_detector.record(ip, port):
                logger.warning(f"SKANNING OPPDAGET: {ip} rørte "
                               f"{self.config.get('scan_ports_threshold', 3)}+ porter - blokkerer")
                self._block_and_enrich(ip, f"port scan (threshold {self.config.get('scan_ports_threshold', 3)})")
                return

        # Instant-block ved felle-berøring
        if self.config.get('instant_block_on_trap', True):
            self._block_and_enrich(ip, f"trap hit on port {port}")

    def _block_and_enrich(self, ip, reason):
        """Blokker med en gang; berik (geo/stats/rapport) i bakgrunnen."""
        blocked = self.ip_blocker.block_ip(ip, reason)
        if blocked:
            threading.Thread(target=self._enrich, args=(ip,), daemon=True).start()

    def _enrich(self, ip):
        g = self.geo.lookup(ip)
        self.stats.add_block(ip, g.get('country', 'Unknown'))
        if self.config.get('auto_report_abuseipdb', True) and self.abuseipdb_checker.api_key:
            self.abuseipdb_checker.report_ip(ip)
        if self.config.get('xarf_autoreport', True):
            XarfReporter.save(ip, self.config.get('reporter_email', ''))

    def process_suspicious_ip(self, ip, source="unknown"):
        """Feed-basert flyt: sjekk VT/AbuseIPDB, blokker ved terskel."""
        if is_safe_ip(ip, self.whitelist):
            return False
        should_block = False
        block_reason = ""

        if self.config.get('virustotal_check_enabled', True) and self.vt_checker.api_key:
            vt_result = self.vt_checker.check_ip(ip)
            if vt_result and 'error' not in vt_result:
                self.vt_results[ip] = vt_result
                self._save_vt_results()
                if self.vt_checker.should_block(vt_result, self.config.get('virustotal_block_threshold', 3)):
                    should_block = True
                    block_reason = f"VirusTotal: {vt_result['malicious']}/{vt_result['total_engines']} ondsinnede"

        if not should_block and self.config.get('abuseipdb_check_enabled', True) and self.abuseipdb_checker.api_key:
            abuse_result = self.abuseipdb_checker.check_ip(ip, self.config.get('abuseipdb_max_age_days', 90))
            if abuse_result and 'error' not in abuse_result:
                self.abuseipdb_results[ip] = abuse_result
                self._save_abuseipdb_results()
                if self.abuseipdb_checker.should_block(abuse_result, self.config.get('abuseipdb_block_threshold', 75)):
                    should_block = True
                    block_reason = f"AbuseIPDB: score={abuse_result['abuse_confidence_score']}%"

        if not should_block and source in ('blocklist', 'feodo', 'dshield'):
            block_reason = f"Feed: {source}"
            should_block = True

        if should_block:
            return self._block_feed_ip(ip, block_reason)
        return False

    def _block_feed_ip(self, ip, reason):
        """Feed-IP-er: bulk-modus (brannmur samles) eller enkeltregler."""
        if self.config.get('bulk_block_enabled', True):
            # Samles i bulk-settet (håndteres av bulk-loop)
            self.bulk.current_ips.add(ip)
            return True
        else:
            blocked = self.ip_blocker.block_ip(ip, reason)
            if blocked:
                threading.Thread(target=self._enrich, args=(ip,), daemon=True).start()
                return True
            return False

    def _save_vt_results(self):
        try:
            with open(VT_RESULTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.vt_results, f, indent=2)
        except Exception as e:
            logger.error(f"Feil ved lagring av VT-resultater: {e}")

    def _save_abuseipdb_results(self):
        try:
            with open(ABUSEIPDB_RESULTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.abuseipdb_results, f, indent=2)
        except Exception as e:
            logger.error(f"Feil ved lagring av AbuseIPDB-resultater: {e}")

    def export_to_csv(self):
        if not self.config.get('auto_export_csv', True):
            return
        csv_file = DATA_DIR / f"blocked_ips_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Country', 'City', 'ISP', 'Time', 'Source', 'VT', 'AbuseIPDB'])
                for ip in sorted(self.ip_blocker.blocked_ips):
                    g = self.geo.lookup(ip)
                    vt = self.vt_results.get(ip, {})
                    abuse = self.abuseipdb_results.get(ip, {})
                    writer.writerow([
                        ip, g.get('country', 'Unknown'), g.get('city', 'Unknown'),
                        g.get('isp', 'Unknown'), datetime.now().strftime('%Y-%m-%d %H:%M'),
                        'auto', vt.get('malicious', 'N/A'),
                        abuse.get('abuse_confidence_score', 'N/A')
                    ])
            logger.info(f"Eksportert {len(self.ip_blocker.blocked_ips)} IP-er til {csv_file}")
        except Exception as e:
            logger.error(f"Feil ved CSV-eksport: {e}")

    # ---- løkker ----
    def feed_loop(self):
        """Henter alle aktiverte feeds, mater bulk-blokkeringen."""
        while self.running:
            try:
                interval = int(self.config.get('blocklist_interval', 300))
                feeds = self.config.get('feeds_enabled', {})
                all_ips = set()

                if feeds.get('blocklist_de', True):
                    all_ips.update(FeedFetcher.fetch_ips('blocklist_de'))
                if feeds.get('feodo', True):
                    all_ips.update(FeedFetcher.fetch_ips('feodo'))
                if feeds.get('dshield', True):
                    all_ips.update(FeedFetcher.fetch_ips('dshield'))

                # Fjern alltid lokale/private og whitelisted fra feed-blokkering
                all_ips = {ip for ip in all_ips if not is_safe_ip(ip, self.whitelist)}

                if self.config.get('bulk_block_enabled', True):
                    # Behold manuelle enkelt-blokkeringer + nye feed-IP-er
                    combined = set(all_ips)
                    self.bulk.update(combined)
                    logger.info(f"Feed-oppdatering: {len(combined)} IP-er aktive i bulk-brannmur")
                else:
                    count = 0
                    for ip in list(all_ips)[:100]:
                        if not self.running:
                            break
                        if ip not in self.ip_blocker.blocked_ips:
                            if self._block_feed_ip(ip, 'feed'):
                                count += 1
                    logger.info(f"Feed-oppdatering: {count} nye IP-er blokkert (enkelmodus)")

                if feeds.get('spamhaus_drop', False):
                    subnets = FeedFetcher.fetch_subnets('spamhaus_drop')
                    for net in subnets[:50]:
                        if net not in self.config.get('manual_subnets', []):
                            self.config.setdefault('manual_subnets', []).append(net)
                    if subnets:
                        save_config(self.config)

                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Feil i feed-loop: {e}")
                time.sleep(60)

    def export_loop(self):
        while self.running:
            try:
                interval = int(self.config.get('export_interval', 3600))
                time.sleep(interval)
                if self.running:
                    self.export_to_csv()
            except Exception as e:
                logger.error(f"Feil i eksport-loop: {e}")

    def start(self):
        self.running = True

        # 1. Emulerte honeypots (fanger credentials) - port fra config
        if self.config.get('emulation_enabled', True):
            services = {}
            for p, proto in self.config.get('emulated_services', {}).items():
                try:
                    port = int(p)
                    if 1 <= port <= 65535 and proto in ('ssh', 'telnet', 'ftp', 'http'):
                        services[port] = proto
                    else:
                        logger.error(f"emulated_services: ugyldig '{p}': '{proto}' - ignorert")
                except (TypeError, ValueError):
                    logger.error(f"emulated_services: ugyldig port '{p}' - ignorert")
            if services:
                self.emulated = EmulatedHoneypot(services, self.on_trap_hit)
                self.emulated.start()

        # 2. Tarpit - porter fra config
        if self.config.get('tarpit_enabled', True):
            tarpit_ports = parse_ports(self.config.get('tarpit_ports'), 'tarpit_ports')
            # Ikke dobbelt-bind porter som allerede har emulert tjeneste
            if self.emulated:
                tarpit_ports = [p for p in tarpit_ports if p not in self.emulated.services]
            if tarpit_ports:
                self.tarpit = Tarpit(tarpit_ports,
                                     int(self.config.get('tarpit_delay_seconds', 10)),
                                     self.on_trap_hit)
                self.tarpit.start()

        # 3. Enkel honeypot - porter fra config
        simple_ports = parse_ports(self.config.get('honeypot_ports'), 'honeypot_ports')
        if self.emulated:
            simple_ports = [p for p in simple_ports if p not in self.emulated.services]
        if simple_ports:
            self.honeypot = SimpleHoneypot(simple_ports, self.on_trap_hit)
            self.honeypot.start()

        feed_thread = threading.Thread(target=self.feed_loop, daemon=True)
        feed_thread.start()

        export_thread = threading.Thread(target=self.export_loop, daemon=True)
        export_thread.start()

        logger.info("CYBER-ROR HEADLESS v3.81 er aktiv og overvåker")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Avbrutt av bruker")
            self.stop()

    def stop(self):
        self.running = False
        if self.honeypot:
            self.honeypot.stop()
        if self.tarpit:
            self.tarpit.stop()
        if self.emulated:
            self.emulated.stop()
        try:
            self.geo.save_cache()
        except Exception:
            pass
        logger.info("CYBER-ROR HEADLESS stoppet")


def main():
    cyber_ror = CyberRorHeadless()
    import signal
    def signal_handler(sig, frame):
        logger.info("Shutdown signal mottatt")
        cyber_ror.stop()
        sys.exit(0)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    cyber_ror.start()


if __name__ == "__main__":
    main()
