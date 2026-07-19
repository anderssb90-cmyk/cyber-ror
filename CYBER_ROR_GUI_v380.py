#!/usr/bin/env python3
"""
CYBER-ROR GUI v3.80 - Ultimate Defense Edition
Cyber Response & Operational Resilience

Nytt i v3.80:
- Fikset: COUNTRY_COORDINATES manglet (geo viste alltid "Unknown")
- Fikset: 7x dupliserte klasser fjernet (raskere oppstart)
- Fikset: setup_map_tab manglet (krasj ved oppstart)
- Fikset: matplotlib logg-spam (loggen holdes ren)
- Fikset: message server tåler port som streng fra config
- Fikset: robust config (overlever korrupt config.json)
- Nytt: persistent geo-cache (data/geoip_cache.json)
- Nytt: Analysis-fane (top subnets, klassifisering, /24-forslag)
- Nytt: klikkbare søyler i 24t-grafen (vis IP-er per time)
- Nytt: /24-synk mot manuelle brannmurregler
- Nytt: "Generer abuse-rapport" per IP (RDAP + ferdig e-post)
- Nytt: X-ARF-eksport for abuse-rapporter
- Nytt: "Rapportert"-flagg per IP med dato/saksnummer
- Nytt: grønn progressbar nederst ved masse-utsendelse
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
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import defaultdict, deque

# For graf
import matplotlib
matplotlib.use('TkAgg')
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

BASE_DIR = Path("C:/cyber")
LOG_DIR = BASE_DIR / "logs"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
CONFIG_FILE = BASE_DIR / "config.json"
BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"
VT_RESULTS_FILE = DATA_DIR / "vt_results.json"
ABUSEIPDB_RESULTS_FILE = DATA_DIR / "abuseipdb_results.json"
GREYNOISE_RESULTS_FILE = DATA_DIR / "greynoise_results.json"
ALIENVAULT_RESULTS_FILE = DATA_DIR / "alienvault_results.json"
MESSAGES_FILE = DATA_DIR / "sent_messages.json"
REPLIES_FILE = DATA_DIR / "incoming_replies.json"
STATS_FILE = DATA_DIR / "statistics.json"
GEO_CACHE_FILE = DATA_DIR / "geoip_cache.json"
REPORTED_FILE = DATA_DIR / "reported.json"
MAP_HTML_FILE = DATA_DIR / "blocked_ips_map.html"

LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_DIR / 'cyber_ror_gui.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('CYBER-ROR-GUI')

# BUGFIKS (v3.80): matplotlib spammet loggen med "categorical units" hvert 5. sek
logging.getLogger('matplotlib').setLevel(logging.WARNING)


def load_config():
    default_config = {
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
        "greynoise_check_enabled": True,
        "alienvault_check_enabled": True,
        "geoip_enabled": True,
        "auto_export_csv": True,
        "export_interval": 3600,
        "message_server_enabled": True,
        "message_server_port": 8081,
        "default_message": "Your IP has been blocked by CYBER-ROR. Contact admin to appeal.",
        "auto_report_abuseipdb": True,
        "tarpit_delay_seconds": 10,
        "tarpit_max_connections": 100,
        "warning_message": "WARNING: Your IP has been logged and reported. Cease all attack attempts immediately!",
        "whitelist_ips": ["127.0.0.1", "192.168.1.1"],
        "time_based_blocking": False,
        "blocking_start_hour": 22,
        "blocking_end_hour": 6,
        "email_alerts_enabled": False,
        "email_smtp_server": "",
        "email_port": 587,
        "email_username": "",
        "email_password": "",
        "email_to": "",
        "mobile_app_enabled": False,
        "mobile_app_port": 5000,
        "manual_subnets": ["204.76.203.0/24"],
        "reporter_name": "",
        "reporter_email": ""
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
            # BUGFIKS (v3.80): korrupt config drepte programmet - ta backup og bruk defaults
            logger.error("Error loading config (using defaults): " + str(e))
            try:
                backup = CONFIG_FILE.with_suffix('.json.bak')
                with open(CONFIG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    bad = f.read()
                with open(backup, 'w', encoding='utf-8') as f:
                    f.write(bad)
                logger.info("Korrupt config sikkerhetskopiert til " + str(backup))
            except Exception:
                pass

    save_config(default_config)
    return default_config


def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        logger.info("Configuration saved")
    except Exception as e:
        logger.error("Error saving config: " + str(e))


# ==================== KOORDINATER FOR ALLE LAND ====================
# BUGFIKS (v3.80): denne ordboken manglet helt -> all geo viste "Unknown"
COUNTRY_COORDINATES = {
    "Afghanistan": {"lat": 33.9, "lon": 67.7}, "Albania": {"lat": 41.2, "lon": 20.2},
    "Algeria": {"lat": 28.0, "lon": 1.7}, "Andorra": {"lat": 42.5, "lon": 1.6},
    "Angola": {"lat": -11.2, "lon": 17.9}, "Argentina": {"lat": -38.4, "lon": -63.6},
    "Armenia": {"lat": 40.1, "lon": 45.0}, "Australia": {"lat": -25.3, "lon": 133.8},
    "Austria": {"lat": 47.5, "lon": 14.6}, "Azerbaijan": {"lat": 40.1, "lon": 47.6},
    "Bahamas": {"lat": 25.0, "lon": -77.4}, "Bahrain": {"lat": 26.1, "lon": 50.6},
    "Bangladesh": {"lat": 23.7, "lon": 90.4}, "Belarus": {"lat": 53.7, "lon": 27.9},
    "Belgium": {"lat": 50.5, "lon": 4.5}, "Belize": {"lat": 17.2, "lon": -88.5},
    "Benin": {"lat": 9.3, "lon": 2.3}, "Bolivia": {"lat": -16.3, "lon": -63.6},
    "Bosnia and Herzegovina": {"lat": 43.9, "lon": 17.7}, "Botswana": {"lat": -22.3, "lon": 24.7},
    "Brazil": {"lat": -14.2, "lon": -51.9}, "Bulgaria": {"lat": 42.7, "lon": 25.5},
    "Burkina Faso": {"lat": 12.2, "lon": -1.6}, "Cambodia": {"lat": 12.6, "lon": 105.0},
    "Cameroon": {"lat": 7.4, "lon": 12.4}, "Canada": {"lat": 56.1, "lon": -106.3},
    "Chile": {"lat": -35.7, "lon": -71.5}, "China": {"lat": 35.9, "lon": 104.2},
    "Colombia": {"lat": 4.6, "lon": -74.1}, "Costa Rica": {"lat": 9.7, "lon": -83.8},
    "Croatia": {"lat": 45.1, "lon": 15.2}, "Cuba": {"lat": 21.5, "lon": -77.8},
    "Cyprus": {"lat": 35.1, "lon": 33.4}, "Czechia": {"lat": 49.8, "lon": 15.5},
    "Czech Republic": {"lat": 49.8, "lon": 15.5}, "Denmark": {"lat": 56.3, "lon": 9.5},
    "Dominican Republic": {"lat": 18.7, "lon": -70.2}, "Ecuador": {"lat": -1.8, "lon": -78.2},
    "Egypt": {"lat": 26.8, "lon": 30.8}, "El Salvador": {"lat": 13.8, "lon": -88.9},
    "Estonia": {"lat": 58.6, "lon": 25.0}, "Ethiopia": {"lat": 9.1, "lon": 40.5},
    "Finland": {"lat": 61.9, "lon": 25.7}, "France": {"lat": 46.2, "lon": 2.2},
    "Georgia": {"lat": 42.3, "lon": 43.4}, "Germany": {"lat": 51.2, "lon": 10.5},
    "Ghana": {"lat": 7.9, "lon": -1.0}, "Greece": {"lat": 39.1, "lon": 21.8},
    "Guatemala": {"lat": 15.8, "lon": -90.2}, "Honduras": {"lat": 15.2, "lon": -86.2},
    "Hong Kong": {"lat": 22.3, "lon": 114.2}, "Hungary": {"lat": 47.2, "lon": 19.5},
    "Iceland": {"lat": 64.9, "lon": -19.0}, "India": {"lat": 20.6, "lon": 78.9},
    "Indonesia": {"lat": -0.8, "lon": 113.9}, "Iran": {"lat": 32.4, "lon": 53.7},
    "Iraq": {"lat": 33.2, "lon": 43.7}, "Ireland": {"lat": 53.4, "lon": -8.2},
    "Israel": {"lat": 31.0, "lon": 34.9}, "Italy": {"lat": 41.9, "lon": 12.6},
    "Ivory Coast": {"lat": 7.5, "lon": -5.5}, "Jamaica": {"lat": 18.1, "lon": -77.3},
    "Japan": {"lat": 36.2, "lon": 138.3}, "Jordan": {"lat": 30.6, "lon": 36.2},
    "Kazakhstan": {"lat": 48.0, "lon": 68.0}, "Kenya": {"lat": -0.02, "lon": 37.9},
    "Kuwait": {"lat": 29.3, "lon": 47.5}, "Latvia": {"lat": 56.9, "lon": 24.6},
    "Lebanon": {"lat": 33.9, "lon": 35.9}, "Lithuania": {"lat": 55.2, "lon": 23.9},
    "Luxembourg": {"lat": 49.8, "lon": 6.1}, "Malaysia": {"lat": 4.2, "lon": 102.0},
    "Mexico": {"lat": 23.6, "lon": -102.6}, "Moldova": {"lat": 47.4, "lon": 28.4},
    "Mongolia": {"lat": 46.9, "lon": 103.8}, "Montenegro": {"lat": 42.7, "lon": 19.4},
    "Morocco": {"lat": 31.8, "lon": -7.1}, "Myanmar": {"lat": 21.9, "lon": 96.0},
    "Nepal": {"lat": 28.4, "lon": 84.1}, "Netherlands": {"lat": 52.1, "lon": 5.3},
    "The Netherlands": {"lat": 52.1, "lon": 5.3}, "New Zealand": {"lat": -40.9, "lon": 174.9},
    "Nigeria": {"lat": 9.1, "lon": 8.7}, "North Korea": {"lat": 40.3, "lon": 127.5},
    "North Macedonia": {"lat": 41.6, "lon": 21.7}, "Norway": {"lat": 60.5, "lon": 8.8},
    "Pakistan": {"lat": 30.4, "lon": 69.3}, "Palestine": {"lat": 31.9, "lon": 35.2},
    "Panama": {"lat": 8.5, "lon": -80.8}, "Peru": {"lat": -9.2, "lon": -75.0},
    "Philippines": {"lat": 12.9, "lon": 121.8}, "Poland": {"lat": 51.9, "lon": 19.1},
    "Portugal": {"lat": 39.4, "lon": -8.2}, "Qatar": {"lat": 25.4, "lon": 51.2},
    "Romania": {"lat": 45.9, "lon": 25.0}, "Russia": {"lat": 61.5, "lon": 105.3},
    "Saudi Arabia": {"lat": 23.9, "lon": 45.1}, "Serbia": {"lat": 44.0, "lon": 21.0},
    "Singapore": {"lat": 1.35, "lon": 103.8}, "Slovakia": {"lat": 48.7, "lon": 19.7},
    "Slovenia": {"lat": 46.2, "lon": 14.9}, "South Africa": {"lat": -30.6, "lon": 22.9},
    "South Korea": {"lat": 35.9, "lon": 127.8}, "Spain": {"lat": 40.5, "lon": -3.7},
    "Sri Lanka": {"lat": 7.9, "lon": 80.8}, "Sweden": {"lat": 60.1, "lon": 18.6},
    "Switzerland": {"lat": 46.8, "lon": 8.2}, "Taiwan": {"lat": 23.7, "lon": 121.0},
    "Thailand": {"lat": 15.9, "lon": 101.0}, "Turkey": {"lat": 38.9, "lon": 35.2},
    "Ukraine": {"lat": 48.4, "lon": 31.2}, "United Arab Emirates": {"lat": 23.4, "lon": 53.8},
    "United Kingdom": {"lat": 55.4, "lon": -3.4}, "United States": {"lat": 37.1, "lon": -95.7},
    "Uruguay": {"lat": -32.5, "lon": -55.8}, "Venezuela": {"lat": 6.4, "lon": -66.6},
    "Vietnam": {"lat": 14.1, "lon": 108.3}, "Unknown": {"lat": 0, "lon": 0}
}


class StatisticsTracker:
    """Spor statistikk over tid for graf-visning (deduplisert i v3.80)"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.hourly_ips = defaultdict(list)   # v3.80: IP-er per time (klikkbare søyler)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        if ip not in self.hourly_ips[hour_key]:
            self.hourly_ips[hour_key].append(ip)
        self.recent_blocks.append({'time': now, 'ip': ip, 'country': country})
        self.save_stats()

    def load_stats(self):
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

    def save_stats(self):
        try:
            # Beskjær gammel time-data (behold siste 7 dager)
            cutoff = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:00')
            hourly = {k: v for k, v in self.hourly_blocks.items() if k >= cutoff}
            hourly_ips = {k: v for k, v in self.hourly_ips.items() if k >= cutoff}
            with open(STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump({
                    'hourly': hourly,
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats),
                    'hourly_ips': hourly_ips
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer. Returnerer (keys, labels, values)."""
        now = datetime.now()
        keys, labels, values = [], [], []
        for i in range(hours - 1, -1, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            keys.append(key)
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return keys, labels, values

    def get_top_countries(self, n=10):
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]


class GeoIPLookup:
    """GeoIP lookup med persistent cache (v3.80).
    Leser fra cache umiddelbart; nettverksoppslag skjer i bakgrunnstråd."""
    def __init__(self):
        self.cache = {}
        self.queue = deque()
        self.queued = set()
        self.lock = threading.Lock()
        self._dirty = 0
        self.load_cache()
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    def load_cache(self):
        if GEO_CACHE_FILE.exists():
            try:
                with open(GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                logger.info("Geo-cache lastet: " + str(len(self.cache)) + " IP-er")
            except Exception as e:
                logger.error("Geo-cache feil: " + str(e))

    def save_cache(self):
        try:
            with open(GEO_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error("Geo-cache lagringsfeil: " + str(e))

    def lookup(self, ip):
        """Synkront oppslag: cache-treff med en gang, ellers Unknown + kølagt."""
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
            if ip not in self.queued:
                self.queued.add(ip)
                self.queue.append(ip)
        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown',
                'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def _worker(self):
        """Bakgrunnstråd: ~1 oppslag per 1.4s (ip-api gratisgrense 45/min)."""
        while True:
            ip = None
            with self.lock:
                if self.queue:
                    ip = self.queue.popleft()
            if ip is None:
                time.sleep(1.0)
                continue
            try:
                response = requests.get("http://ip-api.com/json/" + ip, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        country = data.get('country', 'Unknown')
                        coords = COUNTRY_COORDINATES.get(country, {"lat": 0, "lon": 0})
                        result = {
                            'country': country,
                            'country_code': data.get('countryCode', 'Unknown'),
                            'city': data.get('city', 'Unknown'),
                            'isp': data.get('isp', 'Unknown'),
                            'lat': data.get('lat', coords['lat']),
                            'lon': data.get('lon', coords['lon'])
                        }
                        with self.lock:
                            self.cache[ip] = result
                            self._dirty += 1
                            if self._dirty >= 10:
                                self._dirty = 0
                                self.save_cache()
            except Exception as e:
                logger.error("GeoIP error: " + str(e))
            with self.lock:
                self.queued.discard(ip)
            time.sleep(1.4)

    def get_coordinates(self, country_name):
        return COUNTRY_COORDINATES.get(country_name, {"lat": 0, "lon": 0})


class GreyNoiseChecker:
    """GreyNoise API - sjekk om IP er kjent bot/angriper"""
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3"
        self.headers = {"key": api_key}

    def check_ip(self, ip):
        if not self.api_key:
            return None
        try:
            url = self.base_url + "/community/" + ip
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification', 'unknown'),
                    'name': data.get('name', 'Unknown'),
                    'last_seen': data.get('last_seen', 'Unknown')
                }
        except Exception as e:
            logger.error("GreyNoise feil: " + str(e))
        return None


class AlienVaultChecker:
    """AlienVault OTX API - threat intelligence"""
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": api_key}

    def check_ip(self, ip):
        if not self.api_key:
            return None
        try:
            url = self.base_url + "/indicators/IPv4/" + ip + "/general"
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('pulse_info', {}).get('pulses', [])
                return {
                    'ip': ip,
                    'pulse_count': len(pulses),
                    'reputation': data.get('reputation', 0),
                    'first_seen': data.get('first_seen', 'Unknown')
                }
        except Exception as e:
            logger.error("AlienVault feil: " + str(e))
        return None


class IPBlocker:
    """Handles blocking and management of IPs via Windows Firewall"""
    def __init__(self):
        self.blocked_ips = set()
        self.load_blocked_ips()

    def load_blocked_ips(self):
        if BLOCKED_IPS_FILE.exists():
            try:
                with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked', []))
            except Exception as e:
                logger.error("Error loading blocked IPs: " + str(e))

    def save_blocked_ips(self):
        try:
            with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                json.dump({'blocked': sorted(list(self.blocked_ips))}, f, indent=2)
        except Exception as e:
            logger.error("Error saving blocked IPs: " + str(e))

    def block_ip(self, ip, reason='auto'):
        if ip in self.blocked_ips:
            return False
        try:
            rule_name = "CYBER-ROR-BLOCK-" + ip.replace('.', '-')
            for direction, suffix in (('in', ''), ('out', '-OUT')):
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=' + rule_name + suffix,
                    'dir=' + direction,
                    'action=block',
                    'remoteip=' + ip,
                    'protocol=any',
                    'profile=any'
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            self.blocked_ips.add(ip)
            self.save_blocked_ips()
            logger.info("Blocked IP: " + ip + " (" + reason + ")")
            return True
        except Exception as e:
            logger.error("Error blocking " + ip + ": " + str(e))
            return False

    def block_subnet(self, subnet, reason='manual'):
        """v3.80: blokker et helt subnett (f.eks. 101.126.0.0/16) i Windows Firewall."""
        try:
            safe = subnet.replace('.', '-').replace('/', '_')
            rule_name = "CYBER-ROR-SUBNET-" + safe
            for direction, suffix in (('in', ''), ('out', '-OUT')):
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=' + rule_name + suffix,
                    'dir=' + direction,
                    'action=block',
                    'remoteip=' + subnet,
                    'protocol=any',
                    'profile=any'
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            logger.info("Blocked subnet: " + subnet + " (" + reason + ")")
            return True
        except Exception as e:
            logger.error("Error blocking subnet " + subnet + ": " + str(e))
            return False

    def unblock_ip(self, ip):
        if ip not in self.blocked_ips:
            return False
        try:
            rule_name = "CYBER-ROR-BLOCK-" + ip.replace('.', '-')
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            'name=' + rule_name], capture_output=True, text=True, timeout=10)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            'name=' + rule_name + '-OUT'], capture_output=True, text=True, timeout=10)
            self.blocked_ips.discard(ip)
            self.save_blocked_ips()
            logger.info("Unblocked IP: " + ip)
            return True
        except Exception as e:
            logger.error("Error unblocking " + ip + ": " + str(e))
            return False

    def unblock_all(self):
        ips = list(self.blocked_ips)
        for ip in ips:
            self.unblock_ip(ip)
        self.blocked_ips.clear()
        self.save_blocked_ips()
        logger.info("All blocks removed")

    def is_blocked(self, ip):
        return ip in self.blocked_ips


def ip_in_subnets(ip, subnets):
    """v3.80: sjekk om IP allerede dekkes av en manuell /24-regel."""
    try:
        addr = ipaddress.ip_address(ip)
        for s in subnets:
            try:
                if addr in ipaddress.ip_network(s, strict=False):
                    return s
            except ValueError:
                continue
    except ValueError:
        return None
    return None


class MessageServer:
    """Server to send and receive messages to/from blocked IPs"""
    def __init__(self, port=8081, log_callback=None):
        # BUGFIKS (v3.80): config kan gi port som streng -> 'str' cannot be interpreted as int
        try:
            self.port = int(port)
        except (TypeError, ValueError):
            logger.error("Ugyldig port '" + str(port) + "' - bruker 8081")
            self.port = 8081
        self.log_callback = log_callback
        self.reply_callback = None
        self.running = False
        self.server_socket = None

    def start_listener(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.running = True
            logger.info("Message server started on port " + str(self.port))
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    conn, addr = self.server_socket.accept()
                    client_thread = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error("Server error: " + str(e))
        except Exception as e:
            logger.error("Could not start message server: " + str(e))
        finally:
            if self.server_socket:
                self.server_socket.close()

    def _handle_client(self, conn, addr):
        try:
            conn.settimeout(10)
            data = conn.recv(4096)
            if data:
                message = data.decode('utf-8', errors='ignore').strip()
                ip = addr[0]
                logger.info("Message received from " + ip + ": " + message[:100])
                if self.log_callback:
                    self.log_callback(ip, "incoming_message", message)
                if self.reply_callback:
                    self.reply_callback(ip, "tcp", message)
                conn.sendall(b"ACK: Message received by CYBER-ROR")
        except Exception as e:
            logger.error("Error handling client: " + str(e))
        finally:
            conn.close()

    def send_message(self, ip, message, method='icmp'):
        try:
            if method == 'tcp':
                return self._send_tcp(ip, message)
            elif method == 'http':
                return self._send_http(ip, message)
            elif method == 'icmp':
                return self._send_icmp(ip, message)
            else:
                return False, "Unknown method: " + method
        except Exception as e:
            logger.error("Error sending to " + ip + ": " + str(e))
            return False, str(e)

    def _send_tcp(self, ip, message):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 80))
            sock.sendall(message.encode('utf-8'))
            sock.close()
            return True, "TCP sent"
        except Exception as e:
            return False, "TCP error: " + str(e)

    def _send_http(self, ip, message):
        try:
            url = "http://" + ip + ":80/"
            response = requests.get(url, timeout=5, headers={'User-Agent': 'CYBER-ROR/' + message})
            return True, "HTTP sent (status: " + str(response.status_code) + ")"
        except Exception as e:
            return False, "HTTP error: " + str(e)

    def _send_icmp(self, ip, message):
        try:
            import platform
            if platform.system() == 'Windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '2000', ip],
                                        capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '2', ip],
                                        capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return True, "ICMP (ping) sent - host is up"
            return False, "ICMP error - host not responding"
        except Exception as e:
            return False, "ICMP error: " + str(e)

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass


# ==================== ABUSE-RAPPORT (v3.80) ====================
class AbuseReportGenerator:
    """Slår opp abuse-kontakt via RDAP og genererer ferdig rapport + X-ARF."""

    @staticmethod
    def find_abuse_contact(ip):
        """Returnerer dict med abuse_email, org, netrange - eller None."""
        try:
            response = requests.get("https://rdap.org/ip/" + ip, timeout=10)
            if response.status_code != 200:
                return None
            data = response.json()
            result = {
                'org': data.get('name', 'Unknown'),
                'netrange': (data.get('startAddress', '?') + " - " + data.get('endAddress', '?')),
                'abuse_email': None,
                'all_contacts': []
            }

            def walk(entities):
                for ent in entities:
                    vcard = ent.get('vcardArray', [None, []])[1]
                    name = email = None
                    for item in vcard:
                        if item[0] == 'fn':
                            name = item[3]
                        if item[0] == 'email':
                            email = item[3]
                    roles = ent.get('roles', [])
                    if email:
                        result['all_contacts'].append((roles, name, email))
                        if 'abuse' in roles and result['abuse_email'] is None:
                            result['abuse_email'] = email
                    walk(ent.get('entities', []))

            walk(data.get('entities', []))
            return result
        except Exception as e:
            logger.error("RDAP feil: " + str(e))
            return None

    @staticmethod
    def build_email(ip, contact, reporter_name="", reporter_email="", timestamp_local=None):
        """Bygger ferdig engelsk abuse-e-post."""
        if timestamp_local is None:
            timestamp_local = datetime.now()
        ts_utc = timestamp_local.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        abuse_to = contact.get('abuse_email') or "(no abuse contact found - check whois)"
        org = contact.get('org', 'the network owner')

        subject = "Abuse report - " + ip + " scanning/brute-force from your network (" + ts_utc.split()[0] + ")"
        body = (
            "To: " + abuse_to + "\n"
            "Subject: " + subject + "\n\n"
            "Hello Abuse Team,\n\n"
            "The following IP address in your address space (" + org + ") performed\n"
            "unauthorized port scanning / brute-force attempts against my honeypot server:\n\n"
            "Source IP: " + ip + "\n"
            "Timestamp: " + ts_utc + "\n"
            "Destination port: 22/TCP (SSH honeypot)\n\n"
            "This host is most likely compromised and acting without the owner's\n"
            "knowledge. Log excerpts can be provided on request.\n\n"
            "Regards,\n"
            + (reporter_name or "[Your name]") + "\n"
            + (reporter_email or "[Your email]") + "\n"
        )
        return body

    @staticmethod
    def build_xarf(ip, reporter_email="", timestamp_local=None):
        """Bygger X-ARF (v0.2) JSON-dokument - akseptert av DigitalOcean m.fl."""
        if timestamp_local is None:
            timestamp_local = datetime.now()
        ts_utc = timestamp_local.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S +0000')
        return {
            "xarf": {
                "Version": "0.2",
                "ReporterInfo": {
                    "ReporterOrg": "CYBER-ROR",
                    "ReporterOrgEmail": reporter_email or "unknown@example.com",
                    "ReporterOrgDomain": "localhost"
                },
                "ReportInfo": {
                    "ReportID": "cyber-ror-" + ip.replace('.', '-') + "-" + str(int(time.time())),
                    "ReportClass": "abuse",
                    "ReportType": "login-attack",
                    "Date": ts_utc,
                    "UserAgent": "CYBER-ROR v3.80"
                },
                "SourceInfo": {
                    "Source": ip,
                    "SourceType": "ipv4",
                    "Port": "22",
                    "Service": "ssh"
                }
            }
        }


class ReportedTracker:
    """v3.80: holder oversikt over hvilke IP-er som er rapportert til abuse-desks."""
    def __init__(self):
        self.reported = {}
        self.load()

    def load(self):
        if REPORTED_FILE.exists():
            try:
                with open(REPORTED_FILE, 'r', encoding='utf-8') as f:
                    self.reported = json.load(f)
            except Exception:
                self.reported = {}

    def save(self):
        try:
            with open(REPORTED_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.reported, f, indent=2)
        except Exception as e:
            logger.error("Reported lagringsfeil: " + str(e))

    def mark(self, ip, provider, case_id=""):
        self.reported[ip] = {
            'date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'provider': provider,
            'case': case_id
        }
        self.save()

    def unmark(self, ip):
        self.reported.pop(ip, None)
        self.save()

    def get(self, ip):
        return self.reported.get(ip)


# ==================== KLASSIFISERING (v3.80) ====================
SCANNER_KEYWORDS = ['censys', 'onyphe', 'modat', 'shodan', 'binaryedge', 'shadowserver',
                    'internet-census', 'stretchoid', 'leakix', 'netsystems']
CLOUD_KEYWORDS = ['amazon', 'aws', 'microsoft', 'azure', 'google', 'alibaba', 'tencent',
                  'volcano', 'oracle', 'digitalocean', 'akamai', 'linode', 'hetzner',
                  'ucloud', 'hurricane', 'ovh', 'vultr', 'contabo', 'ghsx', 'byteplus',
                  'aceville', 'scloud', 'hosting', 'cloud', 'datacenter', 'data center',
                  'vps', 'server', 'hydra', 'techoff', 'pfcloud', 'ionos', 'a2 hosting']
CONSUMER_KEYWORDS = ['broadband', 'telecom', 'mobile', 'vodafone', 'verizon', 'comcast',
                     'spectrum', 'dacom', 'chinanet', 'china unicom', 'china mobile',
                     'chunghwa', 'tot public', 'fpt ', 'viettel', 'pccw', 'korea telecom',
                     'rostelecom', 'megafon', 'cogeco', 'maroc', 'moov', 'hutchison']


def classify_isp(isp):
    """Klassifiser ISP: scanner / cloud / botnet-forbruker / ukjent."""
    low = (isp or '').lower()
    if not low or low == 'unknown':
        return 'Ukjent'
    for kw in SCANNER_KEYWORDS:
        if kw in low:
            return 'Scanner (legitim)'
    for kw in CONSUMER_KEYWORDS:
        if kw in low:
            return 'Botnet (forbruker)'
    for kw in CLOUD_KEYWORDS:
        if kw in low:
            return 'Sky/hosting'
    return 'Ukjent'


class CyberRorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CYBER-ROR v3.80 - Ultimate Defense")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a1a')

        self.config = load_config()
        self.ip_blocker = IPBlocker()
        self.stats = StatisticsTracker()
        self.geo = GeoIPLookup()
        self.reported = ReportedTracker()
        self.greynoise = GreyNoiseChecker(self.config.get('greynoise_api_key', ''))
        self.alienvault = AlienVaultChecker(self.config.get('alienvault_api_key', ''))

        self.message_server = MessageServer(
            port=self.config.get('message_server_port', 8081),
            log_callback=self.log_event
        )
        self.message_server.reply_callback = self.handle_incoming_reply
        self.cancel_sending = False
        self._hour_keys = []   # for klikkbare søyler

        self.setup_ui()
        self.load_data()

        if self.config.get('message_server_enabled', True):
            msg_thread = threading.Thread(target=self.message_server.start_listener, daemon=True)
            msg_thread.start()

        self.update_interval = 5000
        self.schedule_update()

    # ---------------- UI-OPPSETT ----------------
    def setup_ui(self):
        self.header_frame = tk.Frame(self.root, bg='#16213e', height=60)
        self.header_frame.pack(fill=tk.X)
        self.header_frame.pack_propagate(False)

        title_frame = tk.Frame(self.header_frame, bg='#16213e')
        title_frame.pack(side=tk.LEFT, padx=20)

        tk.Label(title_frame, text="CYBER-ROR", font=('Orbitron', 24, 'bold'),
                bg='#16213e', fg='#00ff88').pack(side=tk.LEFT)
        tk.Label(title_frame, text="v3.80", font=('Consolas', 12),
                bg='#16213e', fg='#ff6b35').pack(side=tk.LEFT, padx=5)

        self.status_frame = tk.Frame(self.header_frame, bg='#16213e')
        self.status_frame.pack(side=tk.RIGHT, padx=20)

        self.status_dot = tk.Canvas(self.status_frame, width=12, height=12,
                                     bg='#16213e', highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT)
        self.status_dot.create_oval(2, 2, 10, 10, fill='#00ff88', tags='dot')

        tk.Label(self.status_frame, text="AKTIV", font=('Consolas', 12, 'bold'),
                bg='#16213e', fg='#00ff88').pack(side=tk.LEFT, padx=5)

        self.counter_frame = tk.Frame(self.header_frame, bg='#16213e')
        self.counter_frame.pack(side=tk.RIGHT, padx=20)

        self.blocked_counter = tk.Label(self.counter_frame, text="Blokkert: 0",
                                       font=('Consolas', 11), bg='#16213e', fg='white')
        self.blocked_counter.pack(side=tk.LEFT, padx=10)

        self.attack_counter = tk.Label(self.counter_frame, text="Angrep i dag: 0",
                                      font=('Consolas', 11), bg='#16213e', fg='#ff6b35')
        self.attack_counter.pack(side=tk.LEFT, padx=10)

        style = ttk.Style()
        # v3.80: 'clam'-temaet respekterer farger (Windows-standardtemaet ignorerer dem)
        style.theme_use('clam')
        style.configure('TNotebook', background='#0a0a1a', tabmargins=[2, 5, 2, 0],
                        borderwidth=0)
        # Fane-tekst: svart når ikke valgt, mørkegrønn når valgt
        style.configure('TNotebook.Tab', background='#d9d9d9', foreground='black',
                       padding=[15, 5], font=('Consolas', 10, 'bold'))
        style.map('TNotebook.Tab',
                  background=[('selected', '#ffffff'), ('active', '#e8e8e8')],
                  foreground=[('selected', '#006400'), ('!selected', '#000000')])

        # Behold mørkt design på tabeller og progressbar under clam-temaet
        style.configure('Treeview', background='#16213e', fieldbackground='#16213e',
                        foreground='white', borderwidth=0)
        style.map('Treeview', background=[('selected', '#0f3460')])
        style.configure('Treeview.Heading', background='#1a1a2e', foreground='white',
                        relief='flat')
        style.map('Treeview.Heading', background=[('active', '#0f3460')])
        style.configure('green.Horizontal.TProgressbar', background='#00ff88',
                        troughcolor='#16213e', borderwidth=0)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.dashboard_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard_tab()

        self.blocked_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.blocked_frame, text="Blokkerte IP-er")
        self.setup_blocked_tab()

        self.analysis_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.analysis_frame, text="Analyse")
        self.setup_analysis_tab()

        self.message_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.message_frame, text="Send Melding")
        self.setup_message_tab()

        self.map_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.map_frame, text="Kart")
        self.setup_map_tab()

        self.vt_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.vt_frame, text="VirusTotal")
        self.setup_vt_tab()

        self.abuse_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.abuse_frame, text="AbuseIPDB")
        self.setup_abuse_tab()

        self.gn_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.gn_frame, text="GreyNoise")
        self.setup_gn_tab()

        self.av_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.av_frame, text="AlienVault")
        self.setup_av_tab()

        self.replies_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.replies_frame, text="Innkommende svar")
        self.setup_replies_tab()

        self.log_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.log_frame, text="Logg")
        self.setup_log_tab()

        self.settings_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.settings_frame, text="Innstillinger")
        self.setup_settings_tab()

        # v3.80: grønn progressbar nederst (brukes ved masse-utsendelse)
        self.progress = ttk.Progressbar(self.root, orient='horizontal',
                                        mode='determinate')
        self.progress.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 5))
        style.configure('green.Horizontal.TProgressbar', background='#00ff88')
        self.progress.configure(style='green.Horizontal.TProgressbar')
        self.progress['value'] = 0

    # ---------------- DASHBOARD ----------------
    def setup_dashboard_tab(self):
        cards_frame = tk.Frame(self.dashboard_frame, bg='#0a0a1a')
        cards_frame.pack(fill=tk.X, padx=10, pady=10)

        card1 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card1, text="Totalt blokkert", bg='#16213e', fg='#888',
                font=('Consolas', 10)).pack(pady=5)
        self.total_blocked_label = tk.Label(card1, text="0", bg='#16213e', fg='#00ff88',
                                           font=('Orbitron', 28, 'bold'))
        self.total_blocked_label.pack(pady=5)

        card2 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card2, text="I dag", bg='#16213e', fg='#888',
                font=('Consolas', 10)).pack(pady=5)
        self.today_blocked_label = tk.Label(card2, text="0", bg='#16213e', fg='#ff6b35',
                                           font=('Orbitron', 28, 'bold'))
        self.today_blocked_label.pack(pady=5)

        card3 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card3, text="Aktive feller", bg='#16213e', fg='#888',
                font=('Consolas', 10)).pack(pady=5)
        self.active_traps_label = tk.Label(card3, text="0", bg='#16213e', fg='#e94560',
                                          font=('Orbitron', 28, 'bold'))
        self.active_traps_label.pack(pady=5)

        card4 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card4.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card4, text="Topp land", bg='#16213e', fg='#888',
                font=('Consolas', 10)).pack(pady=5)
        self.top_country_label = tk.Label(card4, text="-", bg='#16213e', fg='#00d4ff',
                                           font=('Orbitron', 20, 'bold'))
        self.top_country_label.pack(pady=5)

        graphs_frame = tk.Frame(self.dashboard_frame, bg='#0a0a1a')
        graphs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.hourly_fig = Figure(figsize=(6, 3), facecolor='#0a0a1a')
        self.hourly_ax = self.hourly_fig.add_subplot(111)
        self.hourly_ax.set_facecolor('#16213e')
        self.hourly_ax.tick_params(colors='white')
        self.hourly_ax.set_title('Blokkeringer siste 24 timer (klikk på en søyle for IP-liste)',
                                 color='white', fontsize=10)

        self.hourly_canvas = FigureCanvasTkAgg(self.hourly_fig, master=graphs_frame)
        self.hourly_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        # v3.80: klikkbare søyler
        self.hourly_canvas.mpl_connect('button_press_event', self._on_hourly_click)

        self.country_fig = Figure(figsize=(4, 3), facecolor='#0a0a1a')
        self.country_ax = self.country_fig.add_subplot(111)
        self.country_ax.set_facecolor('#16213e')

        self.country_canvas = FigureCanvasTkAgg(self.country_fig, master=graphs_frame)
        self.country_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

    def update_dashboard(self):
        total = len(self.ip_blocker.blocked_ips)
        today = datetime.now().strftime('%Y-%m-%d')
        today_count = self.stats.daily_blocks.get(today, 0)

        self.total_blocked_label.config(text=str(total))
        self.today_blocked_label.config(text=str(today_count))
        self.blocked_counter.config(text="Blokkert: " + str(total))
        self.attack_counter.config(text="Angrep i dag: " + str(today_count))

        traps = len(self.config.get('honeypot_ports', []))
        if self.config.get('tarpit_enabled', True):
            traps += 16
        self.active_traps_label.config(text=str(traps))

        top_countries = self.stats.get_top_countries(1)
        if top_countries:
            self.top_country_label.config(text=top_countries[0][0])

        # BUGFIKS (v3.80): numeriske x-posisjoner -> ingen "categorical units"-spam
        keys, labels, values = self.stats.get_hourly_data(24)
        self._hour_keys = keys
        x = list(range(len(labels)))
        self.hourly_ax.clear()
        self.hourly_ax.set_facecolor('#16213e')
        self.hourly_ax.tick_params(colors='white')
        self.hourly_ax.set_title('Blokkeringer siste 24 timer (klikk på en søyle for IP-liste)',
                                 color='white', fontsize=10)
        self.hourly_ax.bar(x, values, color='#00ff88', alpha=0.7)
        self.hourly_ax.set_xticks(x[::2])
        self.hourly_ax.set_xticklabels(labels[::2], rotation=45, fontsize=7)
        self.hourly_fig.tight_layout()
        self.hourly_canvas.draw()

        top_countries = self.stats.get_top_countries(5)
        if top_countries:
            countries = [c[0] for c in top_countries]
            counts = [c[1] for c in top_countries]
            self.country_ax.clear()
            self.country_ax.set_facecolor('#16213e')
            colors = ['#00ff88', '#ff6b35', '#e94560', '#00d4ff', '#ff00ff']
            self.country_ax.pie(counts, labels=countries, colors=colors[:len(countries)],
                               autopct='%1.1f%%', textprops={'color': 'white'})
            self.country_fig.tight_layout()
            self.country_canvas.draw()

    def _on_hourly_click(self, event):
        """v3.80: klikk på søyle -> popup med IP-er blokkert den timen."""
        if event.xdata is None or not self._hour_keys:
            return
        idx = int(round(event.xdata))
        if idx < 0 or idx >= len(self._hour_keys):
            return
        hour_key = self._hour_keys[idx]
        ips = self.stats.hourly_ips.get(hour_key, [])

        popup = tk.Toplevel(self.root)
        popup.title("IP-er blokkert " + hour_key)
        popup.geometry("420x400")
        popup.configure(bg='#0a0a1a')
        tk.Label(popup, text="Time: " + hour_key + "  (" + str(len(ips)) + " IP-er)",
                 bg='#0a0a1a', fg='#00ff88', font=('Consolas', 11, 'bold')).pack(pady=5)

        listbox = tk.Listbox(popup, bg='#16213e', fg='white', font=('Consolas', 10))
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        for ip in ips:
            g = self.geo.lookup(ip)
            listbox.insert(tk.END, ip + "  (" + g.get('country', 'Unknown') + ")")
        if not ips:
            listbox.insert(tk.END, "(ingen IP-er logget denne timen)")

        def copy_selected():
            sel = listbox.curselection()
            if sel and ips:
                ip = listbox.get(sel[0]).split()[0]
                self.root.clipboard_clear()
                self.root.clipboard_append(ip)
        tk.Button(popup, text="Kopier valgt IP", command=copy_selected,
                  bg='#0f3460', fg='white').pack(pady=5)

    # ---------------- BLOKKERTE IP-ER ----------------
    def setup_blocked_tab(self):
        toolbar = tk.Frame(self.blocked_frame, bg='#0a0a1a')
        toolbar.pack(fill=tk.X, pady=5)

        tk.Button(toolbar, text="Oppdater", command=self.load_blocked_ips,
                 bg='#0f3460', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Fjern alle", command=self.unblock_all,
                 bg='#e94560', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Eksporter CSV", command=self.export_csv,
                 bg='#0f3460', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Legg til whitelist", command=self.add_to_whitelist,
                 bg='#00ff88', fg='black', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Abuse-rapport", command=self.generate_abuse_report_selected,
                 bg='#ff6b35', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        tree_scroll = ttk.Scrollbar(self.blocked_frame, orient="vertical")
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        columns = ('ip', 'land', 'by', 'isp', 'kilde', 'vt_score', 'abuse_score', 'rapp')
        self.blocked_tree = ttk.Treeview(
            self.blocked_frame,
            columns=columns,
            show='headings',
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=self.blocked_tree.yview)

        self.blocked_tree.heading('ip', text='IP-adresse')
        self.blocked_tree.heading('land', text='Land')
        self.blocked_tree.heading('by', text='By')
        self.blocked_tree.heading('isp', text='ISP')
        self.blocked_tree.heading('kilde', text='Kilde')
        self.blocked_tree.heading('vt_score', text='VT')
        self.blocked_tree.heading('abuse_score', text='AbuseIPDB')
        self.blocked_tree.heading('rapp', text='Rapp.')

        self.blocked_tree.column('ip', width=110)
        self.blocked_tree.column('land', width=100)
        self.blocked_tree.column('by', width=100)
        self.blocked_tree.column('isp', width=200)
        self.blocked_tree.column('kilde', width=60)
        self.blocked_tree.column('vt_score', width=50)
        self.blocked_tree.column('abuse_score', width=80)
        self.blocked_tree.column('rapp', width=50)

        self.blocked_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        def on_mousewheel(event):
            self.blocked_tree.yview_scroll(int(-1*(event.delta/120)), "units")
        self.blocked_tree.bind("<MouseWheel>", on_mousewheel)
        self.blocked_tree.bind("<Button-4>", lambda e: self.blocked_tree.yview_scroll(-1, "units"))
        self.blocked_tree.bind("<Button-5>", lambda e: self.blocked_tree.yview_scroll(1, "units"))
        self.blocked_tree.bind("<Button-3>", self.show_blocked_context_menu)

    def load_blocked_ips(self):
        for item in self.blocked_tree.get_children():
            self.blocked_tree.delete(item)

        whitelist = self.config.get('whitelist_ips', [])
        for ip in sorted(self.ip_blocker.blocked_ips):
            if ip in whitelist:
                continue
            g = self.geo.lookup(ip)
            vt = self.get_vt_result(ip) or {}
            ab = self.get_abuse_result(ip) or {}
            vt_score = vt.get('malicious', 'N/A') if isinstance(vt, dict) else 'N/A'
            ab_score = ab.get('abuse_confidence_score', 'N/A') if isinstance(ab, dict) else 'N/A'
            rapp = "✔" if self.reported.get(ip) else ""
            self.blocked_tree.insert('', 'end', values=(
                ip,
                g.get('country', 'Unknown'),
                g.get('city', 'Unknown'),
                g.get('isp', 'Unknown'),
                'auto',
                vt_score,
                ab_score,
                rapp
            ))

    def show_blocked_context_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Send melding", command=self.select_blocked_ip)
        menu.add_command(label="Kopier IP", command=self.copy_selected_ip)
        menu.add_command(label="Generer abuse-rapport", command=self.generate_abuse_report_selected)
        menu.add_command(label="Merk som rapportert...", command=self.mark_reported_selected)
        menu.add_command(label="Fjern rapportert-merke", command=self.unmark_reported_selected)
        menu.add_separator()
        menu.add_command(label="Legg til whitelist", command=self.add_to_whitelist)
        menu.add_command(label="Fjern blokkering", command=self.unblock_selected)
        menu.post(event.x_root, event.y_root)

    def _selected_ip(self):
        selected = self.blocked_tree.selection()
        if selected:
            return self.blocked_tree.item(selected[0])['values'][0]
        return None

    def copy_selected_ip(self):
        ip = self._selected_ip()
        if ip:
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def select_blocked_ip(self):
        ip = self._selected_ip()
        if ip:
            self.msg_ip_entry.delete(0, tk.END)
            self.msg_ip_entry.insert(0, ip)
            self.msg_status.config(text="Valgt IP: " + ip, fg='#00ff88')

    def unblock_selected(self):
        ip = self._selected_ip()
        if ip:
            self.ip_blocker.unblock_ip(ip)
            self.load_blocked_ips()

    def add_to_whitelist(self):
        ip = self._selected_ip()
        if ip and ip not in self.config['whitelist_ips']:
            self.config['whitelist_ips'].append(ip)
            save_config(self.config)
            self.ip_blocker.unblock_ip(ip)
            self.load_blocked_ips()
            messagebox.showinfo("Suksess", ip + " lagt til whitelist")

    # ---------------- ANALYSE-FANE (v3.80) ----------------
    def setup_analysis_tab(self):
        toolbar = tk.Frame(self.analysis_frame, bg='#0a0a1a')
        toolbar.pack(fill=tk.X, pady=5, padx=5)

        tk.Button(toolbar, text="Kjør analyse", command=self.run_analysis,
                  bg='#00ff88', fg='black', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Blokker valgt /24", command=self.block_suggested_subnet,
                  bg='#e94560', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Fjern redundante IP-regler", command=self.cleanup_redundant,
                  bg='#ff6b35', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        paned = tk.Frame(self.analysis_frame, bg='#0a0a1a')
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Venstre: top /24-subnets
        left = tk.Frame(paned, bg='#0a0a1a')
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(left, text="Topp /24-subnett (≥3 blokkerte IP-er = forslag)",
                 bg='#0a0a1a', fg='white', font=('Consolas', 10, 'bold')).pack(anchor=tk.W)

        sub_scroll = ttk.Scrollbar(left, orient="vertical")
        sub_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.subnet_tree = ttk.Treeview(left, columns=('subnet', 'antall', 'eksempel_isp'),
                                        show='headings', yscrollcommand=sub_scroll.set, height=12)
        sub_scroll.config(command=self.subnet_tree.yview)
        self.subnet_tree.heading('subnet', text='/24-subnett')
        self.subnet_tree.heading('antall', text='Antall')
        self.subnet_tree.heading('eksempel_isp', text='ISP (eksempel)')
        self.subnet_tree.column('subnet', width=120)
        self.subnet_tree.column('antall', width=60)
        self.subnet_tree.column('eksempel_isp', width=240)
        self.subnet_tree.pack(fill=tk.BOTH, expand=True)

        # Høyre: klassifisering + info
        right = tk.Frame(paned, bg='#0a0a1a')
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(right, text="Klassifisering av blokkerte IP-er",
                 bg='#0a0a1a', fg='white', font=('Consolas', 10, 'bold')).pack(anchor=tk.W)
        self.analysis_text = tk.Text(right, bg='#16213e', fg='#00ff88',
                                     font=('Consolas', 10), height=14)
        self.analysis_text.pack(fill=tk.BOTH, expand=True)

        # Nederst: /24-synk status
        tk.Label(self.analysis_frame, text="/24-synk (manuelle brannmurregler vs. enkelt-IP-er):",
                 bg='#0a0a1a', fg='white', font=('Consolas', 10, 'bold')).pack(anchor=tk.W, padx=10)
        self.subnet_sync_text = tk.Text(self.analysis_frame, bg='#16213e', fg='#ff6b35',
                                        font=('Consolas', 10), height=6)
        self.subnet_sync_text.pack(fill=tk.X, padx=10, pady=5)

    def run_analysis(self):
        """Analyser alle blokkerte IP-er: subnets + klassifisering + /24-synk."""
        blocked = sorted(self.ip_blocker.blocked_ips)
        subnets = defaultdict(list)
        classes = defaultdict(int)

        for ip in blocked:
            parts = ip.split('.')
            if len(parts) == 4:
                subnets['.'.join(parts[:3]) + '.0/24'].append(ip)
            g = self.geo.lookup(ip)
            classes[classify_isp(g.get('isp', 'Unknown'))] += 1

        # Fyll subnet-tabellen
        for item in self.subnet_tree.get_children():
            self.subnet_tree.delete(item)
        for subnet, ips in sorted(subnets.items(), key=lambda x: -len(x[1])):
            if len(ips) >= 3:
                g = self.geo.lookup(ips[0])
                self.subnet_tree.insert('', 'end', values=(subnet, len(ips), g.get('isp', 'Unknown')))

        # Klassifiseringstekst
        total = max(len(blocked), 1)
        lines = ["Totalt blokkert: " + str(len(blocked)) + " IP-er", ""]
        for cls, count in sorted(classes.items(), key=lambda x: -x[1]):
            pct = count * 100.0 / total
            lines.append(cls.ljust(20) + str(count).rjust(5) + "  (" + ("%.1f" % pct) + "%)")
        lines.append("")
        lines.append("Scanner (legitim) = Censys/Onyphe m.fl. - vurder opt-out")
        lines.append("Sky/hosting       = kompromitterte VM-er - rapporter til leverandør")
        lines.append("Botnet (forbruker)= infiserte hjemmeenheter - AbuseIPDB")
        self.analysis_text.delete('1.0', tk.END)
        self.analysis_text.insert('1.0', "\n".join(lines))

        # /24-synk
        manual_subnets = self.config.get('manual_subnets', [])
        covered = []
        for ip in blocked:
            s = ip_in_subnets(ip, manual_subnets)
            if s:
                covered.append((ip, s))
        sync_lines = []
        if manual_subnets:
            sync_lines.append("Manuelle subnett-regler: " + ", ".join(manual_subnets))
        if covered:
            sync_lines.append(str(len(covered)) + " enkelt-IP-er dekkes allerede av disse reglene:")
            for ip, s in covered[:20]:
                sync_lines.append("  " + ip + "  (dekket av " + s + ")")
            if len(covered) > 20:
                sync_lines.append("  ... og " + str(len(covered) - 20) + " til")
            sync_lines.append("")
            sync_lines.append("Bruk 'Fjern redundante IP-regler' for å rydde opp.")
        else:
            sync_lines.append("Ingen overlapp funnet - alt er synket. ✔")
        self.subnet_sync_text.delete('1.0', tk.END)
        self.subnet_sync_text.insert('1.0', "\n".join(sync_lines))

    def block_suggested_subnet(self):
        selected = self.subnet_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Velg et subnett i tabellen først")
            return
        subnet = self.subnet_tree.item(selected[0])['values'][0]
        count = self.subnet_tree.item(selected[0])['values'][1]
        if not messagebox.askyesno("Bekreft", "Blokker HELE " + subnet + " (" + str(count) + " kjente IP-er)?"):
            return
        if self.ip_blocker.block_subnet(subnet, reason='analysis suggestion'):
            if subnet not in self.config.get('manual_subnets', []):
                self.config.setdefault('manual_subnets', []).append(subnet)
                save_config(self.config)
            messagebox.showinfo("Ferdig", subnet + " er blokkert i Windows-brannmuren")
            self.run_analysis()

    def cleanup_redundant(self):
        manual_subnets = self.config.get('manual_subnets', [])
        covered = [ip for ip in self.ip_blocker.blocked_ips
                   if ip_in_subnets(ip, manual_subnets)]
        if not covered:
            messagebox.showinfo("Info", "Ingen redundante IP-regler funnet")
            return
        if not messagebox.askyesno("Bekreft",
                str(len(covered)) + " enkelt-IP-regler er overflødige (dekket av /24).\nFjern dem?"):
            return
        removed = 0
        for ip in covered:
            if self.ip_blocker.unblock_ip(ip):
                removed += 1
        messagebox.showinfo("Ferdig", str(removed) + " redundante regler fjernet")
        self.load_blocked_ips()
        self.run_analysis()

    # ---------------- KART (v3.80: var ikke definert i v3.59!) ----------------
    def setup_map_tab(self):
        top = tk.Frame(self.map_frame, bg='#0a0a1a')
        top.pack(fill=tk.X, pady=10, padx=10)
        tk.Button(top, text="Generer kart over blokkerte IP-er", command=self.generate_map,
                  bg='#00ff88', fg='black', font=('Consolas', 11, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(top, text="Åpne kart i nettleser", command=self.open_map,
                  bg='#0f3460', fg='white', font=('Consolas', 11)).pack(side=tk.LEFT, padx=5)
        self.map_status = tk.Label(self.map_frame, text="Kart ikke generert ennå",
                                   bg='#0a0a1a', fg='#888', font=('Consolas', 10))
        self.map_status.pack(pady=10)
        tk.Label(self.map_frame,
                 text="Kartet lagres som " + str(MAP_HTML_FILE) + " og åpnes i nettleseren din.",
                 bg='#0a0a1a', fg='#888').pack(pady=5)

    def generate_map(self):
        self.map_status.config(text="Genererer kart...", fg='yellow')
        self.root.update()
        threading.Thread(target=self._generate_map_thread, daemon=True).start()

    def _generate_map_thread(self):
        points = []
        for ip in sorted(self.ip_blocker.blocked_ips):
            g = self.geo.lookup(ip)
            lat, lon = g.get('lat', 0), g.get('lon', 0)
            if lat == 0 and lon == 0:
                continue
            points.append({
                'ip': ip, 'lat': lat, 'lon': lon,
                'country': g.get('country', 'Unknown'),
                'city': g.get('city', 'Unknown'),
                'isp': g.get('isp', 'Unknown')
            })

        markers_js = ""
        for p in points[:2000]:  # ytelsesgrense
            popup = (p['ip'] + "<br>" + p['city'] + ", " + p['country'] + "<br>" + p['isp'])
            popup = popup.replace("'", "\\'")
            markers_js += ("L.circleMarker([" + str(p['lat']) + ", " + str(p['lon']) + "], "
                           "{radius: 5, color: '#ff6b35', fillColor: '#ff6b35', fillOpacity: 0.7})"
                           ".addTo(map).bindPopup('" + popup + "');\n")

        html = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>CYBER-ROR Blocked IPs Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>body{margin:0;background:#0a0a1a}#map{height:100vh;width:100%}</style>
</head><body>
<div id="map"></div>
<script>
var map = L.map('map').setView([30, 10], 2);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; OpenStreetMap &copy; CARTO', maxZoom: 18
}).addTo(map);
""" + markers_js + """
</script></body></html>"""

        try:
            with open(MAP_HTML_FILE, 'w', encoding='utf-8') as f:
                f.write(html)
            self.root.after(0, lambda: self.map_status.config(
                text="Kart generert: " + str(len(points)) + " punkter. Klikk 'Åpne kart i nettleser'.",
                fg='#00ff88'))
        except Exception as e:
            self.root.after(0, lambda: self.map_status.config(text="Feil: " + str(e), fg='red'))

    def open_map(self):
        if MAP_HTML_FILE.exists():
            try:
                os.startfile(str(MAP_HTML_FILE))
            except Exception as e:
                messagebox.showerror("Feil", str(e))
        else:
            messagebox.showinfo("Info", "Generer kartet først")

    # ---------------- SEND MELDING ----------------
    def setup_message_tab(self):
        ip_frame = tk.Frame(self.message_frame, bg='#0a0a1a', padx=10, pady=10)
        ip_frame.pack(fill=tk.X)
        tk.Label(ip_frame, text="IP-adresse:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.msg_ip_entry = tk.Entry(ip_frame, width=20, bg='#16213e', fg='white')
        self.msg_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(ip_frame, text="Velg fra blokkerte", command=self.show_ip_selection_dialog,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)

        msg_frame = tk.Frame(self.message_frame, bg='#0a0a1a', padx=10, pady=10)
        msg_frame.pack(fill=tk.X)
        tk.Label(msg_frame, text="Melding:", bg='#0a0a1a', fg='white').pack(anchor=tk.W)
        self.msg_text = tk.Text(msg_frame, height=5, bg='#16213e', fg='white')
        self.msg_text.insert('1.0', self.config.get('default_message', ''))
        self.msg_text.pack(fill=tk.X, pady=5)

        method_frame = tk.Frame(self.message_frame, bg='#0a0a1a', padx=10)
        method_frame.pack(fill=tk.X)
        tk.Label(method_frame, text="Metode:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.msg_method = ttk.Combobox(method_frame, values=['http', 'tcp', 'icmp'], width=10)
        self.msg_method.set('icmp')
        self.msg_method.pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(self.message_frame, bg='#0a0a1a')
        btn_frame.pack(pady=10)
        self.send_btn = tk.Button(btn_frame, text="Send Melding", command=self.send_message,
                 bg='#00ff88', fg='black', font=('Arial', 12, 'bold'))
        self.send_btn.pack(side=tk.LEFT, padx=5)
        self.send_all_btn = tk.Button(btn_frame, text="Send til ALLE", command=self.send_message_to_all,
                 bg='#ff6b35', fg='white', font=('Arial', 12, 'bold'))
        self.send_all_btn.pack(side=tk.LEFT, padx=5)
        self.cancel_btn = tk.Button(btn_frame, text="AVBRYT", command=self.cancel_send,
                 bg='#e94560', fg='white', font=('Arial', 12, 'bold'), state='disabled')
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Send ADVARSEL", command=self.send_warning_message,
                 bg='#ff0000', fg='white', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="ADVARSEL til ALLE", command=self.send_warning_to_all,
                 bg='#8b0000', fg='white', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)

        self.msg_status = tk.Label(self.message_frame, text="", bg='#0a0a1a', fg='#00ff88')
        self.msg_status.pack()

        tk.Label(self.message_frame, text="Sendte meldinger:", bg='#0a0a1a', fg='white').pack(anchor=tk.W, padx=10)
        sent_scroll = ttk.Scrollbar(self.message_frame, orient="vertical")
        sent_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10))
        self.sent_tree = ttk.Treeview(self.message_frame, columns=('ip', 'tid', 'metode', 'status'),
                                     show='headings', yscrollcommand=sent_scroll.set)
        sent_scroll.config(command=self.sent_tree.yview)
        self.sent_tree.heading('ip', text='IP')
        self.sent_tree.heading('tid', text='Tid')
        self.sent_tree.heading('metode', text='Metode')
        self.sent_tree.heading('status', text='Status')
        self.sent_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        def on_sent_mousewheel(event):
            self.sent_tree.yview_scroll(int(-1*(event.delta/120)), "units")
        self.sent_tree.bind("<MouseWheel>", on_sent_mousewheel)

    def send_message(self):
        ip = self.msg_ip_entry.get().strip()
        message = self.msg_text.get('1.0', tk.END).strip()
        method = self.msg_method.get()
        if not ip or not message:
            messagebox.showerror("Feil", "Fyll inn IP og melding")
            return
        self.msg_status.config(text="Sender...", fg='yellow')
        self.root.update()
        success, result = self.message_server.send_message(ip, message, method)
        self._record_sent_message(ip, method, "Sendt" if success else "Feilet: " + result)
        if success:
            self.msg_status.config(text="Sendt! " + result, fg='#00ff88')
        else:
            self.msg_status.config(text="Feil: " + result, fg='#e94560')

    def send_message_to_all(self):
        message = self.msg_text.get('1.0', tk.END).strip()
        method = self.msg_method.get()
        if not message:
            messagebox.showerror("Feil", "Skriv inn melding")
            return
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "Ingen blokkerte IP-er")
            return
        total = len(self.ip_blocker.blocked_ips)
        if not messagebox.askyesno("Bekreft", "Send til " + str(total) + " IP-er?"):
            return
        self._start_mass_send(message, method, total, warning=False)

    def send_warning_to_all(self):
        warning = self.config.get('warning_message', 'WARNING!')
        method = self.msg_method.get()
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "Ingen blokkerte IP-er")
            return
        total = len(self.ip_blocker.blocked_ips)
        if not messagebox.askyesno("Bekreft", "Send ADVARSEL til " + str(total) + " IP-er?"):
            return
        self.msg_text.delete('1.0', tk.END)
        self.msg_text.insert('1.0', warning)
        self._start_mass_send(warning, method, total, warning=True)

    def _start_mass_send(self, message, method, total, warning=False):
        self.cancel_sending = False
        self.cancel_btn.config(state='normal')
        self.send_btn.config(state='disabled')
        self.send_all_btn.config(state='disabled')
        self.progress['maximum'] = total
        self.progress['value'] = 0
        self.msg_status.config(text=("Sender ADVARSEL..." if warning else "Sender..."), fg='yellow')
        t = threading.Thread(target=self._mass_send_thread,
                             args=(message, method, total, warning), daemon=True)
        t.start()

    def _mass_send_thread(self, message, method, total, warning):
        success_count = 0
        fail_count = 0
        for i, ip in enumerate(sorted(self.ip_blocker.blocked_ips)):
            if self.cancel_sending:
                self.root.after(0, lambda: self._send_cancelled(success_count, fail_count))
                return
            try:
                success, result = self.message_server.send_message(ip, message, method)
                if success:
                    success_count += 1
                else:
                    fail_count += 1
                self._record_sent_message(ip, method, "Sendt" if success else "Feilet")
            except Exception as e:
                logger.error("Feil ved sending til " + ip + ": " + str(e))
                fail_count += 1
            # v3.80: oppdater grønn progressbar + status
            self.root.after(0, lambda v=i + 1: self.progress.configure(value=v))
            if i % 10 == 0 or i == total - 1:
                status_text = "Sendt: " + str(success_count) + "/" + str(total) + " (feilet: " + str(fail_count) + ")"
                self.root.after(0, lambda st=status_text: self.msg_status.config(text=st, fg='yellow'))
        self.root.after(0, lambda: self._send_complete(success_count, fail_count))

    def _send_complete(self, success_count, fail_count):
        self.cancel_btn.config(state='disabled')
        self.send_btn.config(state='normal')
        self.send_all_btn.config(state='normal')
        self.load_sent_messages()
        if fail_count == 0:
            self.msg_status.config(text="Sendt til alle " + str(success_count) + "!", fg='#00ff88')
        else:
            self.msg_status.config(text="Sendt: " + str(success_count) + ", Feilet: " + str(fail_count), fg='orange')
        messagebox.showinfo("Ferdig", "Sending fullfoert!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count))

    def _send_cancelled(self, success_count, fail_count):
        self.cancel_btn.config(state='disabled')
        self.send_btn.config(state='normal')
        self.send_all_btn.config(state='normal')
        self.load_sent_messages()
        self.msg_status.config(text="AVBRUTT! Sendt: " + str(success_count) + ", Feilet: " + str(fail_count), fg='red')
        messagebox.showinfo("Avbrutt", "Sending avbrutt!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count))

    def cancel_send(self):
        self.cancel_sending = True
        self.cancel_btn.config(state='disabled')
        self.msg_status.config(text="Avbryter...", fg='red')

    def send_warning_message(self):
        ip = self.msg_ip_entry.get().strip()
        warning = self.config.get('warning_message', 'WARNING!')
        if not ip:
            messagebox.showerror("Feil", "Velg IP")
            return
        self.msg_text.delete('1.0', tk.END)
        self.msg_text.insert('1.0', warning)
        self.msg_status.config(text="Advarsel klar", fg='orange')

    def _record_sent_message(self, ip, method, status):
        messages = {}
        if MESSAGES_FILE.exists():
            try:
                with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
                    messages = json.load(f)
            except Exception:
                pass
        messages[ip] = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'method': method,
            'status': status
        }
        try:
            with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
                json.dump(messages, f, indent=2)
        except Exception as e:
            logger.error("Feil ved lagring av melding: " + str(e))

    def show_ip_selection_dialog(self):
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "Ingen blokkerte IP-er")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Velg IP")
        dialog.geometry("400x300")
        dialog.configure(bg='#0a0a1a')
        tk.Label(dialog, text="Dobbeltklikk for aa velge:", bg='#0a0a1a', fg='white').pack(pady=5)
        listbox = tk.Listbox(dialog, bg='#16213e', fg='white', selectmode=tk.SINGLE)
        for ip in sorted(self.ip_blocker.blocked_ips):
            listbox.insert(tk.END, ip)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        def on_select(event):
            selection = listbox.curselection()
            if selection:
                ip = listbox.get(selection[0])
                self.msg_ip_entry.delete(0, tk.END)
                self.msg_ip_entry.insert(0, ip)
                self.msg_status.config(text="Valgt IP: " + ip, fg='#00ff88')
                dialog.destroy()
        listbox.bind("<Double-Button-1>", on_select)
        tk.Button(dialog, text="Lukk", command=dialog.destroy, bg='#e94560', fg='white').pack(pady=5)

    # ---------------- THREAT INTEL-FANER ----------------
    def setup_vt_tab(self):
        check_frame = tk.Frame(self.vt_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)
        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.vt_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.vt_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Sjekk VirusTotal", command=self.check_vt,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        self.vt_result = tk.Text(self.vt_frame, height=15, bg='#16213e', fg='white')
        self.vt_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def check_vt(self):
        ip = self.vt_ip_entry.get().strip()
        if not ip:
            return
        self.vt_result.delete('1.0', tk.END)
        self.vt_result.insert('1.0', "Sjekker VirusTotal...\n")
        self.root.update()

        def worker():
            result = None
            api_key = self.config.get('virustotal_api_key', '')
            if api_key:
                try:
                    r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/" + ip,
                                     headers={"x-apikey": api_key}, timeout=15)
                    if r.status_code == 200:
                        attrs = r.json()['data']['attributes']
                        stats = attrs['last_analysis_stats']
                        result = ("IP: " + ip + "\n"
                                  "Malicious: " + str(stats.get('malicious', 0)) + "\n"
                                  "Suspicious: " + str(stats.get('suspicious', 0)) + "\n"
                                  "Harmless: " + str(stats.get('harmless', 0)) + "\n"
                                  "Undetected: " + str(stats.get('undetected', 0)) + "\n"
                                  "Reputation: " + str(attrs.get('reputation', 0)) + "\n"
                                  "Country: " + str(attrs.get('country', 'Unknown')) + "\n"
                                  "AS owner: " + str(attrs.get('as_owner', 'Unknown')) + "\n")
                    else:
                        result = "HTTP " + str(r.status_code) + " - sjekk API-nøkkel"
                except Exception as e:
                    result = "Feil: " + str(e)
            else:
                result = "Ingen API-nøkkel. Legg den inn under Innstillinger."
            self.root.after(0, lambda: self.vt_result.insert(tk.END, result or "Ingen data"))
        threading.Thread(target=worker, daemon=True).start()

    def setup_abuse_tab(self):
        check_frame = tk.Frame(self.abuse_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)
        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.abuse_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.abuse_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Sjekk AbuseIPDB", command=self.check_abuse,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        self.abuse_result = tk.Text(self.abuse_frame, height=15, bg='#16213e', fg='white')
        self.abuse_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def check_abuse(self):
        ip = self.abuse_ip_entry.get().strip()
        if not ip:
            return
        self.abuse_result.delete('1.0', tk.END)
        self.abuse_result.insert('1.0', "Sjekker AbuseIPDB...\n")
        self.root.update()

        def worker():
            result = None
            api_key = self.config.get('abuseipdb_api_key', '')
            if api_key:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check",
                                     headers={"Accept": "application/json", "Key": api_key},
                                     params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=15)
                    if r.status_code == 200:
                        d = r.json()['data']
                        result = ("IP: " + ip + "\n"
                                  "Confidence score: " + str(d.get('abuseConfidenceScore', 0)) + "%\n"
                                  "Total reports: " + str(d.get('totalReports', 0)) + "\n"
                                  "Country: " + str(d.get('countryCode', 'Unknown')) + "\n"
                                  "ISP: " + str(d.get('isp', 'Unknown')) + "\n"
                                  "Usage type: " + str(d.get('usageType', 'Unknown')) + "\n"
                                  "Last reported: " + str(d.get('lastReportedAt', 'Unknown')) + "\n")
                    else:
                        result = "HTTP " + str(r.status_code) + " - sjekk API-nøkkel"
                except Exception as e:
                    result = "Feil: " + str(e)
            else:
                result = "Ingen API-nøkkel. Legg den inn under Innstillinger."
            self.root.after(0, lambda: self.abuse_result.insert(tk.END, result or "Ingen data"))
        threading.Thread(target=worker, daemon=True).start()

    def setup_gn_tab(self):
        check_frame = tk.Frame(self.gn_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)
        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.gn_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.gn_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Sjekk GreyNoise", command=self.check_gn,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        self.gn_result = tk.Text(self.gn_frame, height=15, bg='#16213e', fg='white')
        self.gn_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def check_gn(self):
        ip = self.gn_ip_entry.get().strip()
        if not ip:
            return
        self.gn_result.delete('1.0', tk.END)
        self.gn_result.insert('1.0', "Sjekker GreyNoise...\n")
        self.root.update()
        result = self.greynoise.check_ip(ip)
        if result:
            self.gn_result.insert(tk.END, "IP: " + ip + "\n")
            self.gn_result.insert(tk.END, "Noise: " + str(result.get('noise', False)) + "\n")
            self.gn_result.insert(tk.END, "RIOT: " + str(result.get('riot', False)) + "\n")
            self.gn_result.insert(tk.END, "Classification: " + result.get('classification', 'Unknown') + "\n")
            self.gn_result.insert(tk.END, "Name: " + result.get('name', 'Unknown') + "\n")
        else:
            self.gn_result.insert(tk.END, "Ingen data funnet. Sjekk API-noekkel.")

    def setup_av_tab(self):
        check_frame = tk.Frame(self.av_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)
        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.av_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.av_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Sjekk AlienVault", command=self.check_av,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        self.av_result = tk.Text(self.av_frame, height=15, bg='#16213e', fg='white')
        self.av_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def check_av(self):
        ip = self.av_ip_entry.get().strip()
        if not ip:
            return
        self.av_result.delete('1.0', tk.END)
        self.av_result.insert('1.0', "Sjekker AlienVault...\n")
        self.root.update()
        result = self.alienvault.check_ip(ip)
        if result:
            self.av_result.insert(tk.END, "IP: " + ip + "\n")
            self.av_result.insert(tk.END, "Pulse count: " + str(result.get('pulse_count', 0)) + "\n")
            self.av_result.insert(tk.END, "Reputation: " + str(result.get('reputation', 0)) + "\n")
        else:
            self.av_result.insert(tk.END, "Ingen data funnet. Sjekk API-noekkel.")

    # ---------------- INNKOMMENDE SVAR / LOGG / INNSTILLINGER ----------------
    def setup_replies_tab(self):
        toolbar = tk.Frame(self.replies_frame, bg='#0a0a1a')
        toolbar.pack(fill=tk.X, pady=5)
        tk.Button(toolbar, text="Oppdater", command=self.load_replies, bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Slett alle", command=self.clear_replies, bg='#e94560', fg='white').pack(side=tk.LEFT, padx=5)
        self.replies_status = tk.Label(toolbar, text="Venter paa svar...", bg='#0a0a1a', fg='#00ff88')
        self.replies_status.pack(side=tk.RIGHT, padx=10)

        tree_scroll = ttk.Scrollbar(self.replies_frame, orient="vertical")
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        columns = ('tid', 'ip', 'type', 'data', 'svar')
        self.replies_tree = ttk.Treeview(self.replies_frame, columns=columns, show='headings', yscrollcommand=tree_scroll.set)
        tree_scroll.config(command=self.replies_tree.yview)
        self.replies_tree.heading('tid', text='Tid')
        self.replies_tree.heading('ip', text='IP')
        self.replies_tree.heading('type', text='Type')
        self.replies_tree.heading('data', text='Data')
        self.replies_tree.heading('svar', text='Auto-svar')
        self.replies_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        def on_mousewheel(event):
            self.replies_tree.yview_scroll(int(-1*(event.delta/120)), "units")
        self.replies_tree.bind("<MouseWheel>", on_mousewheel)

    def setup_log_tab(self):
        self.log_text = scrolledtext.ScrolledText(self.log_frame, bg='#16213e', fg='#00ff88')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        tk.Button(self.log_frame, text="Oppdater logg", command=self.load_log, bg='#0f3460', fg='white').pack(pady=5)

    def setup_settings_tab(self):
        canvas = tk.Canvas(self.settings_frame, bg='#0a0a1a', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.settings_frame, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg='#0a0a1a')

        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        scroll_frame.bind("<Configure>", on_frame_configure)

        settings = [
            ("virustotal_api_key", "VirusTotal API Key"),
            ("abuseipdb_api_key", "AbuseIPDB API Key"),
            ("greynoise_api_key", "GreyNoise API Key"),
            ("alienvault_api_key", "AlienVault OTX API Key"),
            ("message_server_port", "Meldingserver Port"),
            ("default_message", "Standard melding"),
            ("warning_message", "Advarsel melding"),
            ("reporter_name", "Ditt navn (abuse-rapporter)"),
            ("reporter_email", "Din e-post (abuse-rapporter)"),
            ("email_smtp_server", "SMTP Server"),
            ("email_username", "E-post brukernavn"),
            ("email_password", "E-passord"),
            ("email_to", "Varsel til e-post")
        ]

        self.settings_entries = {}
        for key, label in settings:
            frame = tk.Frame(scroll_frame, bg='#0a0a1a', padx=10, pady=5)
            frame.pack(fill=tk.X)
            tk.Label(frame, text=label + ":", bg='#0a0a1a', fg='white', width=28, anchor='w').pack(side=tk.LEFT)
            entry = tk.Entry(frame, bg='#16213e', fg='white', width=50)
            entry.insert(0, str(self.config.get(key, '')))
            entry.pack(side=tk.LEFT, padx=5)
            self.settings_entries[key] = entry

        cb_frame = tk.Frame(scroll_frame, bg='#0a0a1a', padx=10, pady=10)
        cb_frame.pack(fill=tk.X)

        self.cb_vars = {}
        for key, label in [("auto_report_abuseipdb", "Auto-rapporter AbuseIPDB"),
                           ("geoip_enabled", "GeoIP aktivert"),
                           ("message_server_enabled", "Meldingserver aktivert"),
                           ("email_alerts_enabled", "E-post varsler")]:
            var = tk.BooleanVar(value=bool(self.config.get(key, False)))
            self.cb_vars[key] = var
            tk.Checkbutton(cb_frame, text=label, variable=var, bg='#0a0a1a', fg='white',
                          selectcolor='#16213e').pack(anchor=tk.W)

        tk.Button(scroll_frame, text="Lagre innstillinger", command=self.save_settings,
                 bg='#00ff88', fg='black').pack(pady=20)

    def save_settings(self):
        for key, entry in self.settings_entries.items():
            self.config[key] = entry.get()
        for key, var in self.cb_vars.items():
            self.config[key] = var.get()
        save_config(self.config)
        messagebox.showinfo("Suksess", "Innstillinger lagret!")

    # ---------------- ABUSE-RAPPORT (v3.80) ----------------
    def generate_abuse_report_selected(self):
        ip = self._selected_ip()
        if not ip:
            messagebox.showinfo("Info", "Velg en IP i listen først")
            return
        self.msg_status if hasattr(self, 'msg_status') else None
        dlg = tk.Toplevel(self.root)
        dlg.title("Genererer abuse-rapport for " + ip)
        dlg.geometry("700x560")
        dlg.configure(bg='#0a0a1a')
        tk.Label(dlg, text="Slår opp abuse-kontakt via RDAP...", bg='#0a0a1a', fg='yellow',
                 font=('Consolas', 10)).pack(pady=5)
        text = tk.Text(dlg, bg='#16213e', fg='#00ff88', font=('Consolas', 9))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = tk.Frame(dlg, bg='#0a0a1a')
        btn_frame.pack(pady=5)

        def worker():
            contact = AbuseReportGenerator.find_abuse_contact(ip)
            if contact is None:
                self.root.after(0, lambda: text.insert('1.0',
                    "RDAP-oppslag feilet. Sjekk internettforbindelsen."))
                return
            body = AbuseReportGenerator.build_email(
                ip, contact,
                reporter_name=self.config.get('reporter_name', ''),
                reporter_email=self.config.get('reporter_email', '')
            )
            header = ("Org: " + contact.get('org', '?') + "\n"
                      "Netrange: " + contact.get('netrange', '?') + "\n"
                      "Abuse-kontakt: " + str(contact.get('abuse_email') or 'IKKE FUNNET') + "\n"
                      + "-" * 60 + "\n\n")
            self.root.after(0, lambda: text.insert('1.0', header + body))

            def copy_all():
                self.root.clipboard_clear()
                self.root.clipboard_append(text.get('1.0', tk.END).strip())
                messagebox.showinfo("Kopiert", "Rapporten er kopiert til utklippstavlen", parent=dlg)

            def save_txt():
                fname = REPORTS_DIR / ("abuse_report_" + ip.replace('.', '_') + ".txt")
                with open(fname, 'w', encoding='utf-8') as f:
                    f.write(text.get('1.0', tk.END).strip())
                messagebox.showinfo("Lagret", "Lagret som\n" + str(fname), parent=dlg)

            def save_xarf():
                xarf = AbuseReportGenerator.build_xarf(
                    ip, reporter_email=self.config.get('reporter_email', ''))
                fname = REPORTS_DIR / ("xarf_" + ip.replace('.', '_') + ".json")
                with open(fname, 'w', encoding='utf-8') as f:
                    json.dump(xarf, f, indent=2)
                messagebox.showinfo("Lagret", "X-ARF lagret som\n" + str(fname) +
                                    "\n\nSend denne som vedlegg til abuse-innbokser med automatisering (f.eks. DigitalOcean).",
                                    parent=dlg)

            self.root.after(0, lambda: (
                tk.Button(btn_frame, text="Kopier alt", command=copy_all,
                          bg='#00ff88', fg='black').pack(side=tk.LEFT, padx=5),
                tk.Button(btn_frame, text="Lagre .txt", command=save_txt,
                          bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5),
                tk.Button(btn_frame, text="Generer X-ARF (.json)", command=save_xarf,
                          bg='#ff6b35', fg='white').pack(side=tk.LEFT, padx=5)
            ))

        threading.Thread(target=worker, daemon=True).start()

    def mark_reported_selected(self):
        ip = self._selected_ip()
        if not ip:
            return
        provider = simpledialog.askstring("Rapportert", "Leverandør (f.eks. AWS, Hetzner):", parent=self.root)
        if provider is None:
            return
        case_id = simpledialog.askstring("Saksnummer", "Saksnummer/ticket (valgfritt):", parent=self.root) or ""
        self.reported.mark(ip, provider, case_id)
        self.load_blocked_ips()

    def unmark_reported_selected(self):
        ip = self._selected_ip()
        if ip:
            self.reported.unmark(ip)
            self.load_blocked_ips()

    # ---------------- DATALASTING ----------------
    def load_data(self):
        self.load_blocked_ips()
        self.load_sent_messages()
        self.load_log()
        self.load_replies()

    def get_vt_result(self, ip):
        if VT_RESULTS_FILE.exists():
            try:
                with open(VT_RESULTS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get(ip)
            except Exception:
                pass
        return None

    def get_abuse_result(self, ip):
        if ABUSEIPDB_RESULTS_FILE.exists():
            try:
                with open(ABUSEIPDB_RESULTS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get(ip)
            except Exception:
                pass
        return None

    def load_sent_messages(self):
        for item in self.sent_tree.get_children():
            self.sent_tree.delete(item)
        if MESSAGES_FILE.exists():
            try:
                with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
                    messages = json.load(f)
                    for ip, data in messages.items():
                        self.sent_tree.insert('', 'end', values=(ip, data.get('timestamp', ''),
                                                                  data.get('method', ''), data.get('status', '')))
            except Exception:
                pass

    def load_log(self):
        self.log_text.delete('1.0', tk.END)
        for name in ('cyber_ror.log', 'cyber_ror_gui.log'):
            log_file = LOG_DIR / name
            if log_file.exists():
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.readlines()
                        self.log_text.insert('1.0', ''.join(lines[-100:]))
                    return
                except Exception:
                    pass

    def load_replies(self):
        for item in self.replies_tree.get_children():
            self.replies_tree.delete(item)
        if REPLIES_FILE.exists():
            try:
                with open(REPLIES_FILE, 'r', encoding='utf-8') as f:
                    replies = json.load(f)
                    for entry in replies:
                        self.replies_tree.insert('', 'end', values=(
                            entry.get('timestamp', ''), entry.get('ip', ''), entry.get('type', ''),
                            entry.get('data', '')[:50], entry.get('auto_reply', '')))
                    self.replies_status.config(text=str(len(replies)) + " svar", fg='white')
            except Exception:
                pass

    def clear_replies(self):
        if messagebox.askyesno("Bekreft", "Slett alle svar?"):
            if REPLIES_FILE.exists():
                try:
                    os.remove(REPLIES_FILE)
                except Exception:
                    pass
            for item in self.replies_tree.get_children():
                self.replies_tree.delete(item)
            self.replies_status.config(text="Ingen svar", fg='white')

    def unblock_all(self):
        if messagebox.askyesno("Bekreft", "Fjern alle blokkeringer?"):
            self.ip_blocker.unblock_all()
            self.load_blocked_ips()

    def export_csv(self):
        csv_file = DATA_DIR / ("blocked_ips_" + datetime.now().strftime('%Y%m%d_%H%M%S') + ".csv")
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Country', 'City', 'ISP', 'Time', 'Source', 'VT', 'AbuseIPDB'])
                for ip in sorted(self.ip_blocker.blocked_ips):
                    g = self.geo.lookup(ip)
                    vt = self.get_vt_result(ip) or {}
                    ab = self.get_abuse_result(ip) or {}
                    writer.writerow([
                        ip,
                        g.get('country', 'Unknown'),
                        g.get('city', 'Unknown'),
                        g.get('isp', 'Unknown'),
                        datetime.now().strftime('%Y-%m-%d %H:%M'),
                        'auto',
                        vt.get('malicious', 'N/A') if isinstance(vt, dict) else 'N/A',
                        ab.get('abuse_confidence_score', 'N/A') if isinstance(ab, dict) else 'N/A'
                    ])
            messagebox.showinfo("Suksess", "Eksportert til " + str(csv_file))
        except Exception as e:
            messagebox.showerror("Feil", str(e))

    def schedule_update(self):
        self.load_data()
        self.update_dashboard()
        self.root.after(self.update_interval, self.schedule_update)

    def log_event(self, ip, event_type, details=None):
        logger.info("Hendelse: " + event_type + " fra " + ip)

    def handle_incoming_reply(self, ip, message_type, data):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if ip not in self.ip_blocker.blocked_ips:
            return
        auto_reply = ""
        if hasattr(self, 'auto_reply_var') and self.auto_reply_var.get():
            reply_msg = self.auto_reply_msg.get()
            try:
                self.message_server.send_message(ip, reply_msg, "icmp")
                auto_reply = "Auto-svar sendt"
            except Exception as e:
                auto_reply = "Auto-svar feilet: " + str(e)
        reply_entry = {
            "timestamp": timestamp,
            "ip": ip,
            "type": message_type,
            "data": data[:200] if data else "",
            "auto_reply": auto_reply
        }
        replies = []
        if REPLIES_FILE.exists():
            try:
                with open(REPLIES_FILE, 'r', encoding='utf-8') as f:
                    replies = json.load(f)
            except Exception:
                pass
        replies.insert(0, reply_entry)
        if len(replies) > 1000:
            replies = replies[:1000]
        try:
            with open(REPLIES_FILE, 'w', encoding='utf-8') as f:
                json.dump(replies, f, indent=2)
        except Exception as e:
            logger.error("Feil ved lagring av svar: " + str(e))
        self.root.after(0, lambda: self._add_reply_to_tree(reply_entry))
        logger.info("Innkommende svar fra " + ip + " (" + message_type + ")")

    def _add_reply_to_tree(self, entry):
        self.replies_tree.insert('', 0, values=(
            entry['timestamp'],
            entry['ip'],
            entry['type'],
            entry['data'][:50] + "..." if len(entry['data']) > 50 else entry['data'],
            entry['auto_reply']
        ))
        self.replies_status.config(text="Nytt svar mottatt!", fg='#00ff88')

    def on_closing(self):
        try:
            if hasattr(self, 'message_server') and self.message_server:
                self.message_server.stop()
        except Exception:
            pass
        try:
            self.geo.save_cache()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = CyberRorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
