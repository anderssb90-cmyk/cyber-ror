#!/usr/bin/env python3
"""
CYBER-ROR HEADLESS v3.58
Cyber Response & Operational Resilience - Bakgrunnsversjon
Kjoerer uten GUI, logger til fil, stoetter VirusTotal API v3 og AbuseIPDB API v2
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
from datetime import datetime
from pathlib import Path

# === KONFIGURASJON ===
BASE_DIR = Path("C:/cyber")
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
CONFIG_FILE = BASE_DIR / "config.json"
BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"
VT_RESULTS_FILE = DATA_DIR / "vt_results.json"
ABUSEIPDB_RESULTS_FILE = DATA_DIR / "abuseipdb_results.json"

# Opprett mapper
LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# === LOGGING ===
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

# === KONFIGURASJONS-HAANDTERING ===
def load_config():
    """Last inn konfigurasjon fra config.json"""
    default_config = {
        "virustotal_api_key": "",
        "abuseipdb_api_key": "",
        "blocklist_api_key": "",
        "auto_block_threshold": 5,
        "log_level": "INFO",
        "blocklist_interval": 300,
        "honeypot_ports": [8080, 9090],
        "tarpit_enabled": True,
        "virustotal_check_enabled": True,
        "virustotal_block_threshold": 3,
        "abuseipdb_check_enabled": True,
        "abuseipdb_block_threshold": 75,
        "abuseipdb_max_age_days": 90,
        "geoip_enabled": True,
        "auto_export_csv": True,
        "export_interval": 3600
    }

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except Exception as e:
            logger.error(f"Feil ved lasting av config: {e}")

    save_config(default_config)
    return default_config

def save_config(config):
    """Lagre konfigurasjon til config.json"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        logger.info("Konfigurasjon lagret")
    except Exception as e:
        logger.error(f"Feil ved lagring av config: {e}")

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
            sleep_time = self.rate_limit_delay - elapsed
            logger.debug(f"VT rate limit: venter {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def check_ip(self, ip):
        if not self.api_key:
            logger.warning("VirusTotal API-noekkel ikke konfigurert")
            return None

        self._rate_limit()
        url = f"{self.base_url}/ip_addresses/{ip}"
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                attrs = data['data']['attributes']
                stats = attrs['last_analysis_stats']
                result = {
                    'ip': ip,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'virustotal',
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': attrs.get('reputation', 0),
                    'country': attrs.get('country', 'Unknown'),
                    'as_owner': attrs.get('as_owner', 'Unknown'),
                    'total_engines': sum(stats.values()) if stats else 0
                }
                logger.info(f"VirusTotal {ip}: {result['malicious']}/{result['total_engines']} ondsinnede")
                return result
            elif response.status_code == 404:
                return {'ip': ip, 'source': 'virustotal', 'error': 'IP not found'}
            elif response.status_code == 401:
                logger.error("VirusTotal: Ugyldig API-noekkel")
                return {'ip': ip, 'source': 'virustotal', 'error': 'Invalid API key'}
            else:
                return {'ip': ip, 'source': 'virustotal', 'error': f'HTTP {response.status_code}'}
        except requests.exceptions.Timeout:
            return {'ip': ip, 'source': 'virustotal', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"VirusTotal feil: {e}")
            return {'ip': ip, 'source': 'virustotal', 'error': str(e)}

    def should_block(self, result, threshold=3):
        if not result or 'error' in result:
            return False
        malicious = result.get('malicious', 0)
        total = result.get('total_engines', 1)
        if malicious >= threshold:
            logger.warning(f"VirusTotal: {result['ip']} blokkeres ({malicious}/{total} ondsinnede)")
            return True
        if total > 0 and (malicious / total) > 0.2:
            logger.warning(f"VirusTotal: {result['ip']} blokkeres ({malicious/total*100:.1f}% ondsinnede)")
            return True
        return False

# === ABUSEIPDB API v2 ===
class AbuseIPDBChecker:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        self.rate_limit_delay = 5  # Sekunder mellom forespoersler
        self.last_request_time = 0
        self.daily_limit = 1000  # Gratis tier: 1000 sjekker/dag
        self.daily_count = 0
        self.daily_reset = datetime.now().date()

    def _rate_limit(self):
        """Respekter rate limiting og daglig grense"""
        # Sjekk daglig grense
        today = datetime.now().date()
        if today != self.daily_reset:
            self.daily_count = 0
            self.daily_reset = today

        if self.daily_count >= self.daily_limit:
            logger.warning("AbuseIPDB: Daglig grense naaet (1000)")
            return False

        # Rate limit per forespoersel
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            logger.debug(f"AbuseIPDB rate limit: venter {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()
        return True

    def check_ip(self, ip, max_age_days=90):
        """Sjekk IP mot AbuseIPDB /check endpoint"""
        if not self.api_key:
            logger.warning("AbuseIPDB API-noekkel ikke konfigurert")
            return None

        if not self._rate_limit():
            return {'ip': ip, 'source': 'abuseipdb', 'error': 'Daily limit reached'}

        url = f"{self.base_url}/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': str(max_age_days)
        }

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=15)
            self.daily_count += 1

            if response.status_code == 200:
                data = response.json()['data']
                result = {
                    'ip': ip,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'abuseipdb',
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'hostnames': data.get('hostnames', []),
                    'total_reports': data.get('totalReports', 0),
                    'num_distinct_users': data.get('numDistinctUsers', 0),
                    'last_reported_at': data.get('lastReportedAt', 'Unknown'),
                    'is_public': data.get('isPublic', True),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
                logger.info(f"AbuseIPDB {ip}: score={result['abuse_confidence_score']}%, "
                          f"rapporter={result['total_reports']}, land={result['country_code']}")
                return result

            elif response.status_code == 422:
                error_data = response.json()
                error_msg = error_data.get('errors', [{}])[0].get('detail', 'Invalid IP')
                logger.warning(f"AbuseIPDB: {ip} - {error_msg}")
                return {'ip': ip, 'source': 'abuseipdb', 'error': error_msg}

            elif response.status_code == 401:
                logger.error("AbuseIPDB: Ugyldig API-noekkel")
                return {'ip': ip, 'source': 'abuseipdb', 'error': 'Invalid API key'}
            elif response.status_code == 429:
                logger.warning("AbuseIPDB: Rate limit naaet")
                return {'ip': ip, 'source': 'abuseipdb', 'error': 'Rate limit'}
            else:
                logger.error(f"AbuseIPDB HTTP {response.status_code}")
                return {'ip': ip, 'source': 'abuseipdb', 'error': f'HTTP {response.status_code}'}

        except requests.exceptions.Timeout:
            return {'ip': ip, 'source': 'abuseipdb', 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"AbuseIPDB feil: {e}")
            return {'ip': ip, 'source': 'abuseipdb', 'error': str(e)}

    def fetch_blacklist(self, confidence_minimum=75, limit=1000):
        """Hent blacklist fra AbuseIPDB"""
        if not self.api_key:
            logger.warning("AbuseIPDB API-noekkel ikke konfigurert")
            return []

        if not self._rate_limit():
            return []

        url = f"{self.base_url}/blacklist"
        params = {
            'confidenceMinimum': str(confidence_minimum),
            'limit': str(limit)
        }

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=30)
            self.daily_count += 1

            if response.status_code == 200:
                data = response.json()['data']
                ips = [item['ipAddress'] for item in data]
                logger.info(f"AbuseIPDB: Hentet {len(ips)} IP-er fra blacklist (confidence >= {confidence_minimum})")
                return ips
            else:
                logger.error(f"AbuseIPDB blacklist HTTP {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"AbuseIPDB blacklist feil: {e}")
            return []

    def should_block(self, result, threshold=75):
        """Bestem om IP skal blokkeres basert paa AbuseIPDB-score"""
        if not result or 'error' in result:
            return False

        score = result.get('abuse_confidence_score', 0)
        total_reports = result.get('total_reports', 0)
        is_whitelisted = result.get('is_whitelisted', False)

        # Ikke blokker whitelisted IP-er
        if is_whitelisted:
            logger.info(f"AbuseIPDB: {result['ip']} er whitelisted - blokkeres IKKE")
            return False

        # Blokker hvis confidence score >= threshold
        if score >= threshold:
            logger.warning(f"AbuseIPDB: {result['ip']} blokkeres (score: {score}%)")
            return True

        # Blokker ogsaa hvis mange rapporter (>= 10) og score >= 50
        if total_reports >= 10 and score >= 50:
            logger.warning(f"AbuseIPDB: {result['ip']} blokkeres ({total_reports} rapporter, score: {score}%)")
            return True

        return False

# === IP-BLOKKERING (Windows Firewall) ===
class IPBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.load_blocked_ips()

    def load_blocked_ips(self):
        if BLOCKED_IPS_FILE.exists():
            try:
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked', []))
                logger.info(f"Lastet {len(self.blocked_ips)} blokkerte IP-er")
            except Exception as e:
                logger.error(f"Feil ved lasting av blokkerte IP-er: {e}")

    def save_blocked_ips(self):
        try:
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump({'blocked': list(self.blocked_ips)}, f, indent=2)
        except Exception as e:
            logger.error(f"Feil ved lagring av blokkerte IP-er: {e}")

    def block_ip(self, ip, reason=""):
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} er allerede blokkert")
            return False

        try:
            rule_name = f"CYBER-ROR-BLOCK-{ip.replace('.', '-')}"
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=in',
                'action=block',
                f'remoteip={ip}',
                'enable=yes'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                self.save_blocked_ips()
                logger.info(f"Blokkert IP: {ip} ({reason})")
                return True
            else:
                logger.error(f"Feil ved blokkering av {ip}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Feil ved blokkering av {ip}: {e}")
            return False

    def unblock_ip(self, ip):
        rule_name = f"CYBER-ROR-BLOCK-{ip.replace('.', '-')}"
        try:
            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
            subprocess.run(cmd, capture_output=True, timeout=30)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                self.save_blocked_ips()
            logger.info(f"Fjernet blokkering: {ip}")
            return True
        except Exception as e:
            logger.error(f"Feil ved fjerning av blokkering: {e}")
            return False

    def unblock_all(self):
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-NetFirewallRule | Where-Object {$_.DisplayName -like "CYBER-ROR-BLOCK-*"} | Remove-NetFirewallRule'],
                capture_output=True, text=True, timeout=30
            )
            self.blocked_ips.clear()
            self.save_blocked_ips()
            logger.info("Alle blokkeringer fjernet")
            return True
        except Exception as e:
            logger.error(f"Feil ved fjerning av alle blokkeringer: {e}")
            return False

# === HONEYPOT ===
class Honeypot:
    def __init__(self, ports, log_callback):
        self.ports = ports
        self.log_callback = log_callback
        self.servers = []
        self.running = False

    def start(self):
        self.running = True
        for port in self.ports:
            t = threading.Thread(target=self._listen, args=(port,), daemon=True)
            t.start()
            logger.info(f"Honeypot startet paa port {port}")

    def _listen(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            server.settimeout(1.0)
            self.servers.append(server)
            while self.running:
                try:
                    conn, addr = server.accept()
                    ip = addr[0]
                    logger.warning(f"HONEYPOT: Tilkobling fra {ip} paa port {port}")
                    self.log_callback(ip, 'honeypot', port)
                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Honeypot feil paa port {port}: {e}")
        except Exception as e:
            logger.error(f"Kunne ikke starte honeypot paa port {port}: {e}")

    def stop(self):
        self.running = False
        for server in self.servers:
            try:
                server.close()
            except:
                pass
        logger.info("Honeypot stoppet")

# === TARPIT ===
class Tarpit:
    def __init__(self, log_callback):
        self.log_callback = log_callback
        self.running = False

    def start(self):
        self.running = True
        # Vanlige angrepsporter: RDP, SSH, Telnet, FTP, SMB, MySQL, MSSQL, VNC, Redis, MongoDB
        ports = [3389, 22, 23, 21, 3306, 1433, 5900, 6379, 27017, 5432, 110, 143, 993, 995, 25, 587]
        for port in ports:
            t = threading.Thread(target=self._tarpit_listen, args=(port,), daemon=True)
            t.start()

    def _tarpit_listen(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            server.settimeout(1.0)
            while self.running:
                try:
                    conn, addr = server.accept()
                    ip = addr[0]
                    logger.warning(f"TARPIT: Angriper {ip} fanget paa port {port}")
                    self.log_callback(ip, 'tarpit', port)
                    while self.running:
                        try:
                            conn.send(b'\x00' * 1)
                            time.sleep(10)
                        except:
                            break
                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Tarpit feil: {e}")
        except Exception as e:
            logger.error(f"Kunne ikke starte tarpit paa port {port}: {e}")

    def stop(self):
        self.running = False
        logger.info("Tarpit stoppet")

# === BLOCKLIST.DE ===
class BlocklistFetcher:
    def __init__(self, api_key=""):
        self.api_key = api_key
        self.urls = {
            'all': 'https://lists.blocklist.de/lists/all.txt',
            'ssh': 'https://lists.blocklist.de/lists/ssh.txt',
            'mail': 'https://lists.blocklist.de/lists/mail.txt',
            'apache': 'https://lists.blocklist.de/lists/apache.txt',
            'imap': 'https://lists.blocklist.de/lists/imap.txt',
            'ftp': 'https://lists.blocklist.de/lists/ftp.txt',
            'sip': 'https://lists.blocklist.de/lists/sip.txt',
            'bots': 'https://lists.blocklist.de/lists/bots.txt',
            'strongips': 'https://lists.blocklist.de/lists/strongips.txt',
            'bruteforcelogin': 'https://lists.blocklist.de/lists/bruteforcelogin.txt'
        }

    def fetch(self, list_type='all'):
        url = self.urls.get(list_type, self.urls['all'])
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                ips = [line.strip() for line in response.text.split('\n')
                       if line.strip() and not line.startswith('#')]
                logger.info(f"Hentet {len(ips)} IP-er fra Blocklist.de ({list_type})")
                return ips
            else:
                logger.error(f"Blocklist.de HTTP {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Feil ved henting fra Blocklist.de: {e}")
            return []

# === HOVEDPROGRAM ===
class CyberRorHeadless:
    def __init__(self):
        logger.info("=" * 50)
        logger.info("CYBER-ROR HEADLESS v3.58 starter")
        logger.info("Stoetter: VirusTotal + AbuseIPDB + Blocklist.de")
        logger.info("=" * 50)

        self.config = load_config()
        self.ip_blocker = IPBlocker()
        self.vt_checker = VirusTotalChecker(self.config.get('virustotal_api_key', ''))
        self.abuseipdb_checker = AbuseIPDBChecker(self.config.get('abuseipdb_api_key', ''))
        self.blocklist_fetcher = BlocklistFetcher(self.config.get('blocklist_api_key', ''))
        self.honeypot = None
        self.tarpit = None
        self.running = False

        # Last inn resultater
        self.vt_results = {}
        self.abuseipdb_results = {}
        if VT_RESULTS_FILE.exists():
            try:
                with open(VT_RESULTS_FILE, 'r') as f:
                    self.vt_results = json.load(f)
            except:
                pass
        if ABUSEIPDB_RESULTS_FILE.exists():
            try:
                with open(ABUSEIPDB_RESULTS_FILE, 'r') as f:
                    self.abuseipdb_results = json.load(f)
            except:
                pass

    def log_event(self, ip, event_type, port=None, details=None):
        event = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'type': event_type,
            'port': port,
            'details': details or {}
        }
        logger.info(f"Hendelse: {event_type} fra {ip}" + (f" paa port {port}" if port else ""))

    def process_suspicious_ip(self, ip, source="unknown"):
        """Behandle mistenkelig IP - sjekk VirusTotal, AbuseIPDB og blokker om noedvendig"""
        logger.info(f"Behandler mistenkelig IP: {ip} (kilde: {source})")

        should_block = False
        block_reason = ""

        # 1. Sjekk VirusTotal
        if self.config.get('virustotal_check_enabled', True) and self.vt_checker.api_key:
            vt_result = self.vt_checker.check_ip(ip)
            if vt_result and 'error' not in vt_result:
                self.vt_results[ip] = vt_result
                self._save_vt_results()
                vt_threshold = self.config.get('virustotal_block_threshold', 3)
                if self.vt_checker.should_block(vt_result, vt_threshold):
                    should_block = True
                    block_reason = f"VirusTotal: {vt_result['malicious']}/{vt_result['total_engines']} ondsinnede"

        # 2. Sjekk AbuseIPDB (hvis ikke allerede blokkeres)
        if not should_block and self.config.get('abuseipdb_check_enabled', True) and self.abuseipdb_checker.api_key:
            max_age = self.config.get('abuseipdb_max_age_days', 90)
            abuse_result = self.abuseipdb_checker.check_ip(ip, max_age)
            if abuse_result and 'error' not in abuse_result:
                self.abuseipdb_results[ip] = abuse_result
                self._save_abuseipdb_results()
                abuse_threshold = self.config.get('abuseipdb_block_threshold', 75)
                if self.abuseipdb_checker.should_block(abuse_result, abuse_threshold):
                    should_block = True
                    score = abuse_result['abuse_confidence_score']
                    reports = abuse_result['total_reports']
                    block_reason = f"AbuseIPDB: score={score}%, {reports} rapporter"

        # 3. Blokker hvis noedvendig
        if should_block:
            self.ip_blocker.block_ip(ip, block_reason)
            return True

        # 4. Blokker automatisk hvis fra blocklist
        if source == 'blocklist':
            threshold = self.config.get('auto_block_threshold', 5)
            self.ip_blocker.block_ip(ip, f"Blocklist.de (auto-block threshold: {threshold})")
            return True

        return False

    def _save_vt_results(self):
        try:
            with open(VT_RESULTS_FILE, 'w') as f:
                json.dump(self.vt_results, f, indent=2)
        except Exception as e:
            logger.error(f"Feil ved lagring av VT-resultater: {e}")

    def _save_abuseipdb_results(self):
        try:
            with open(ABUSEIPDB_RESULTS_FILE, 'w') as f:
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
                writer.writerow(['IP', 'Blokkert_tid', 'Kilde', 'VT_Malicious', 'VT_Suspicious', 'AbuseIPDB_Score', 'AbuseIPDB_Reports', 'Land', 'ISP'])
                for ip in self.ip_blocker.blocked_ips:
                    vt = self.vt_results.get(ip, {})
                    abuse = self.abuseipdb_results.get(ip, {})
                    writer.writerow([
                        ip,
                        datetime.now().isoformat(),
                        'auto',
                        vt.get('malicious', 'N/A'),
                        vt.get('suspicious', 'N/A'),
                        abuse.get('abuse_confidence_score', 'N/A'),
                        abuse.get('total_reports', 'N/A'),
                        abuse.get('country_code', vt.get('country', 'Unknown')),
                        abuse.get('isp', 'Unknown')
                    ])
            logger.info(f"Eksportert {len(self.ip_blocker.blocked_ips)} IP-er til {csv_file}")
        except Exception as e:
            logger.error(f"Feil ved CSV-eksport: {e}")

    def blocklist_update_loop(self):
        while self.running:
            try:
                interval = self.config.get('blocklist_interval', 300)
                logger.info(f"Henter blocklist (intervall: {interval}s)")

                # Hent fra Blocklist.de
                ips = self.blocklist_fetcher.fetch('all')
                for ip in ips[:100]:
                    if ip not in self.ip_blocker.blocked_ips:
                        self.process_suspicious_ip(ip, 'blocklist')

                # Hent fra AbuseIPDB blacklist
                if self.config.get('abuseipdb_check_enabled', True) and self.abuseipdb_checker.api_key:
                    abuse_ips = self.abuseipdb_checker.fetch_blacklist(confidence_minimum=75, limit=500)
                    for ip in abuse_ips[:50]:
                        if ip not in self.ip_blocker.blocked_ips:
                            self.process_suspicious_ip(ip, 'abuseipdb_blacklist')

                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Feil i blocklist-loop: {e}")
                time.sleep(60)

    def export_loop(self):
        while self.running:
            try:
                interval = self.config.get('export_interval', 3600)
                time.sleep(interval)
                if self.running:
                    self.export_to_csv()
            except Exception as e:
                logger.error(f"Feil i eksport-loop: {e}")

    def start(self):
        self.running = True

        if self.config.get('honeypot_ports'):
            self.honeypot = Honeypot(self.config['honeypot_ports'], self.log_event)
            self.honeypot.start()

        if self.config.get('tarpit_enabled', True):
            self.tarpit = Tarpit(self.log_event)
            self.tarpit.start()

        blocklist_thread = threading.Thread(target=self.blocklist_update_loop, daemon=True)
        blocklist_thread.start()

        export_thread = threading.Thread(target=self.export_loop, daemon=True)
        export_thread.start()

        logger.info("CYBER-ROR HEADLESS er aktiv og monitorerer")

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
        logger.info("CYBER-ROR HEADLESS stoppet")

# === HOVEDFUNKSJON ===
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
