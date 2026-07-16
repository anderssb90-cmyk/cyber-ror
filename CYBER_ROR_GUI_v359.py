#!/usr/bin/env python3
"""
CYBER-ROR GUI v3.59 - Ultimate Defense Edition
Cyber Response & Operational Resilience
Med: GeoIP, GreyNoise, AlienVault, graf, whitelist, mobil-app, e-post
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
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime, timedelta
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
CONFIG_FILE = BASE_DIR / "config.json"
BLOCKED_IPS_FILE = DATA_DIR / "blocked_ips.json"
VT_RESULTS_FILE = DATA_DIR / "vt_results.json"
ABUSEIPDB_RESULTS_FILE = DATA_DIR / "abuseipdb_results.json"
GREYNOISE_RESULTS_FILE = DATA_DIR / "greynoise_results.json"
ALIENVAULT_RESULTS_FILE = DATA_DIR / "alienvault_results.json"
MESSAGES_FILE = DATA_DIR / "sent_messages.json"
REPLIES_FILE = DATA_DIR / "incoming_replies.json"
STATS_FILE = DATA_DIR / "statistics.json"

LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

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
        "default_message": "IP-en din er blokkert av CYBER-ROR. Kontakt admin for oppheving.",
        "auto_report_abuseipdb": True,
        "tarpit_delay_seconds": 10,
        "tarpit_max_connections": 100,
        "warning_message": "ADVARSEL: Din IP er logget og rapportert til myndighetene. Opphoer angrep umiddelbart!",
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
        "mobile_app_port": 5000
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
            logger.error("Feil ved lasting av config: " + str(e))

    save_config(default_config)
    return default_config

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        logger.info("Konfigurasjon lagret")
    except Exception as e:
        logger.error("Feil ved lagring av config: " + str(e))










class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
class GeoIPLookup:
    """GeoIP lookup to find country/city from IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Use ip-api.com (free, no key)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
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
                self.cache[ip] = result
                return result
        except Exception as e:
            logger.error("GeoIP error: " + str(e))

        coords = COUNTRY_COORDINATES.get('Unknown', {"lat": 0, "lon": 0})
        return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

    def get_coordinates(self, country_name):
        """Get coordinates for a country from built-in database"""
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

class StatisticsTracker:
    """Spor statistikk over tid for graf-visning"""
    def __init__(self):
        self.hourly_blocks = defaultdict(int)
        self.daily_blocks = defaultdict(int)
        self.country_stats = defaultdict(int)
        self.recent_blocks = deque(maxlen=100)
        self.load_stats()

    def add_block(self, ip, country='Unknown'):
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')

        self.hourly_blocks[hour_key] += 1
        self.daily_blocks[day_key] += 1
        self.country_stats[country] += 1
        self.recent_blocks.append({
            'time': now,
            'ip': ip,
            'country': country
        })

        self.save_stats()

    def load_stats(self):
        if STATS_FILE.exists():
            try:
                with open(STATS_FILE, 'r') as f:
                    data = json.load(f)
                    self.hourly_blocks = defaultdict(int, data.get('hourly', {}))
                    self.daily_blocks = defaultdict(int, data.get('daily', {}))
                    self.country_stats = defaultdict(int, data.get('countries', {}))
            except:
                pass

    def save_stats(self):
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'hourly': dict(self.hourly_blocks),
                    'daily': dict(self.daily_blocks),
                    'countries': dict(self.country_stats)
                }, f, indent=2)
        except Exception as e:
            logger.error("Statistikk lagringsfeil: " + str(e))

    def get_hourly_data(self, hours=24):
        """Hent data for siste N timer"""
        now = datetime.now()
        labels = []
        values = []
        for i in range(hours, 0, -1):
            t = now - timedelta(hours=i)
            key = t.strftime('%Y-%m-%d %H:00')
            labels.append(t.strftime('%H:00'))
            values.append(self.hourly_blocks.get(key, 0))
        return labels, values

    def get_top_countries(self, n=10):
        """Hent top N land"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================

class IPBlocker:
    """Handles blocking and management of IPs via Windows Firewall"""
    def __init__(self):
        self.blocked_ips = set()
        self.load_blocked_ips()

    def load_blocked_ips(self):
        """Load previously blocked IPs from file"""
        if BLOCKED_IPS_FILE.exists():
            try:
                with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked', []))
            except Exception as e:
                logger.error("Error loading blocked IPs: " + str(e))

    def save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                json.dump({'blocked': sorted(list(self.blocked_ips))}, f, indent=2)
        except Exception as e:
            logger.error("Error saving blocked IPs: " + str(e))

    def block_ip(self, ip, reason='auto'):
        """Block an IP via Windows Firewall"""
        if ip in self.blocked_ips:
            return False
        try:
            rule_name = "CYBER-ROR-BLOCK-" + ip.replace('.', '-')
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=' + rule_name,
                'dir=in',
                'action=block',
                'remoteip=' + ip,
                'protocol=any',
                'profile=any'
            ]
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            cmd_out = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name=' + rule_name + '-OUT',
                'dir=out',
                'action=block',
                'remoteip=' + ip,
                'protocol=any',
                'profile=any'
            ]
            subprocess.run(cmd_out, capture_output=True, text=True, timeout=10)
            self.blocked_ips.add(ip)
            self.save_blocked_ips()
            logger.info("Blocked IP: " + ip + " (" + reason + ")")
            return True
        except Exception as e:
            logger.error("Error blocking " + ip + ": " + str(e))
            return False

    def unblock_ip(self, ip):
        """Remove block of an IP"""
        if ip not in self.blocked_ips:
            return False
        try:
            rule_name = "CYBER-ROR-BLOCK-" + ip.replace('.', '-')
            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=' + rule_name]
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            cmd_out = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=' + rule_name + '-OUT']
            subprocess.run(cmd_out, capture_output=True, text=True, timeout=10)
            self.blocked_ips.discard(ip)
            self.save_blocked_ips()
            logger.info("Unblocked IP: " + ip)
            return True
        except Exception as e:
            logger.error("Error unblocking " + ip + ": " + str(e))
            return False

    def unblock_all(self):
        """Remove all blocks"""
        ips = list(self.blocked_ips)
        for ip in ips:
            self.unblock_ip(ip)
        self.blocked_ips.clear()
        self.save_blocked_ips()
        logger.info("All blocks removed")

    def is_blocked(self, ip):
        return ip in self.blocked_ips


class MessageServer:
    """Server to send and receive messages to/from blocked IPs"""
    def __init__(self, port=8081, log_callback=None):
        self.port = port
        self.log_callback = log_callback
        self.reply_callback = None
        self.running = False
        self.server_socket = None

    def start_listener(self):
        """Start a TCP listener for incoming messages"""
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
        """Handle incoming client connection"""
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
        """Send message to an IP"""
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
        """Send message via TCP"""
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
        """Send message via HTTP"""
        try:
            url = "http://" + ip + ":80/"
            response = requests.get(url, timeout=5, headers={'User-Agent': 'CYBER-ROR/' + message})
            return True, "HTTP sent (status: " + str(response.status_code) + ")"
        except Exception as e:
            return False, "HTTP error: " + str(e)

    def _send_icmp(self, ip, message):
        """Send message via ICMP (ping)"""
        try:
            import platform
            system = platform.system()
            if system == 'Windows':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '2000', ip],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return True, "ICMP (ping) sent - host is up"
                else:
                    return False, "ICMP error - host not responding"
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', ip],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return True, "ICMP (ping) sent"
                else:
                    return False, "ICMP error - host not responding"
        except Exception as e:
            return False, "ICMP error: " + str(e)

    def stop(self):
        """Stop message server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass


class CyberRorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CYBER-ROR v3.59 - Ultimate Defense")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a1a')

        self.config = load_config()
        self.ip_blocker = IPBlocker()
        self.stats = StatisticsTracker()
        self.greynoise = GreyNoiseChecker(self.config.get('greynoise_api_key', ''))
        self.alienvault = AlienVaultChecker(self.config.get('alienvault_api_key', ''))

        self.message_server = MessageServer(
            port=self.config.get('message_server_port', 8081),
            log_callback=self.log_event
        )
        self.message_server.reply_callback = self.handle_incoming_reply
        self.cancel_sending = False

        self.setup_ui()
        self.load_data()

        if self.config.get('message_server_enabled', True):
            msg_thread = threading.Thread(target=self.message_server.start_listener, daemon=True)
            msg_thread.start()

        self.update_interval = 5000
        self.schedule_update()

    def setup_ui(self):
        # Modern header with gradient effect
        self.header_frame = tk.Frame(self.root, bg='#16213e', height=60)
        self.header_frame.pack(fill=tk.X)
        self.header_frame.pack_propagate(False)

        # Logo/Title
        title_frame = tk.Frame(self.header_frame, bg='#16213e')
        title_frame.pack(side=tk.LEFT, padx=20)

        tk.Label(title_frame, text="CYBER-ROR", font=('Orbitron', 24, 'bold'), 
                bg='#16213e', fg='#00ff88').pack(side=tk.LEFT)
        tk.Label(title_frame, text="v3.59", font=('Consolas', 12), 
                bg='#16213e', fg='#ff6b35').pack(side=tk.LEFT, padx=5)

        # Status indicators
        self.status_frame = tk.Frame(self.header_frame, bg='#16213e')
        self.status_frame.pack(side=tk.RIGHT, padx=20)

        self.status_dot = tk.Canvas(self.status_frame, width=12, height=12, 
                                     bg='#16213e', highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT)
        self.status_dot.create_oval(2, 2, 10, 10, fill='#00ff88', tags='dot')

        tk.Label(self.status_frame, text="AKTIV", font=('Consolas', 12, 'bold'),
                bg='#16213e', fg='#00ff88').pack(side=tk.LEFT, padx=5)

        # Stats counters
        self.counter_frame = tk.Frame(self.header_frame, bg='#16213e')
        self.counter_frame.pack(side=tk.RIGHT, padx=20)

        self.blocked_counter = tk.Label(self.counter_frame, text="Blokkert: 0", 
                                       font=('Consolas', 11), bg='#16213e', fg='white')
        self.blocked_counter.pack(side=tk.LEFT, padx=10)

        self.attack_counter = tk.Label(self.counter_frame, text="Angrep i dag: 0", 
                                      font=('Consolas', 11), bg='#16213e', fg='#ff6b35')
        self.attack_counter.pack(side=tk.LEFT, padx=10)

        # Notebook with custom styling
        style = ttk.Style()
        style.configure('TNotebook', background='#0a0a1a', tabmargins=[2, 5, 2, 0])
        style.configure('TNotebook.Tab', background='#1a1a2e', foreground='white', 
                       padding=[15, 5], font=('Consolas', 10))
        style.map('TNotebook.Tab', background=[('selected', '#16213e')])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Dashboard tab (NEW)
        self.dashboard_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard_tab()

        # Blokkerte IP-er
        self.blocked_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.blocked_frame, text="Blokkerte IP-er")
        self.setup_blocked_tab()

        # Send Melding
        self.message_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.message_frame, text="Send Melding")
        self.setup_message_tab()

        # Kart/GeoIP (NEW)
        self.map_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.map_frame, text="Kart")
        self.setup_map_tab()

        # VirusTotal
        self.vt_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.vt_frame, text="VirusTotal")
        self.setup_vt_tab()

        # AbuseIPDB
        self.abuse_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.abuse_frame, text="AbuseIPDB")
        self.setup_abuse_tab()

        # GreyNoise (NEW)
        self.gn_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.gn_frame, text="GreyNoise")
        self.setup_gn_tab()

        # AlienVault (NEW)
        self.av_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.av_frame, text="AlienVault")
        self.setup_av_tab()

        # Innkommende svar
        self.replies_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.replies_frame, text="Innkommende svar")
        self.setup_replies_tab()

        # Logg
        self.log_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.log_frame, text="Logg")
        self.setup_log_tab()

        # Innstillinger
        self.settings_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.settings_frame, text="Innstillinger")
        self.setup_settings_tab()

    def setup_dashboard_tab(self):
        """Dashboard med grafer og statistikk"""
        # Top row - Stats cards
        cards_frame = tk.Frame(self.dashboard_frame, bg='#0a0a1a')
        cards_frame.pack(fill=tk.X, padx=10, pady=10)

        # Card 1: Total blocked
        card1 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card1, text="Totalt blokkert", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.total_blocked_label = tk.Label(card1, text="0", bg='#16213e', fg='#00ff88',
                                           font=('Orbitron', 28, 'bold'))
        self.total_blocked_label.pack(pady=5)

        # Card 2: Today
        card2 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card2, text="I dag", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.today_blocked_label = tk.Label(card2, text="0", bg='#16213e', fg='#ff6b35',
                                           font=('Orbitron', 28, 'bold'))
        self.today_blocked_label.pack(pady=5)

        # Card 3: Active traps
        card3 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card3, text="Aktive feller", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.active_traps_label = tk.Label(card3, text="0", bg='#16213e', fg='#e94560',
                                          font=('Orbitron', 28, 'bold'))
        self.active_traps_label.pack(pady=5)

        # Card 4: Top country
        card4 = tk.Frame(cards_frame, bg='#16213e', bd=2, relief='ridge')
        card4.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card4, text="Top land", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.top_country_label = tk.Label(card4, text="-", bg='#16213e', fg='#00d4ff',
                                           font=('Orbitron', 20, 'bold'))
        self.top_country_label.pack(pady=5)

        # Graphs
        graphs_frame = tk.Frame(self.dashboard_frame, bg='#0a0a1a')
        graphs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Hourly graph
        self.hourly_fig = Figure(figsize=(6, 3), facecolor='#0a0a1a')
        self.hourly_ax = self.hourly_fig.add_subplot(111)
        self.hourly_ax.set_facecolor('#16213e')
        self.hourly_ax.tick_params(colors='white')
        self.hourly_ax.set_title('Blokkeringer siste 24 timer', color='white', fontsize=10)
        self.hourly_ax.set_xlabel('Time', color='white')
        self.hourly_ax.set_ylabel('Antall', color='white')

        self.hourly_canvas = FigureCanvasTkAgg(self.hourly_fig, master=graphs_frame)
        self.hourly_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # Country pie chart
        self.country_fig = Figure(figsize=(4, 3), facecolor='#0a0a1a')
        self.country_ax = self.country_fig.add_subplot(111)
        self.country_ax.set_facecolor('#16213e')

        self.country_canvas = FigureCanvasTkAgg(self.country_fig, master=graphs_frame)
        self.country_canvas.get_tk_widget().pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

    def update_dashboard(self):
        """Oppdater dashboard med ny data"""
        # Update counters
        total = len(self.ip_blocker.blocked_ips)
        today = datetime.now().strftime('%Y-%m-%d')
        today_count = self.stats.daily_blocks.get(today, 0)

        self.total_blocked_label.config(text=str(total))
        self.today_blocked_label.config(text=str(today_count))
        self.blocked_counter.config(text="Blokkert: " + str(total))
        self.attack_counter.config(text="Angrep i dag: " + str(today_count))

        # Top country
        top_countries = self.stats.get_top_countries(1)
        if top_countries:
            self.top_country_label.config(text=top_countries[0][0])

        # Update hourly graph
        labels, values = self.stats.get_hourly_data(24)
        self.hourly_ax.clear()
        self.hourly_ax.set_facecolor('#16213e')
        self.hourly_ax.tick_params(colors='white')
        self.hourly_ax.set_title('Blokkeringer siste 24 timer', color='white', fontsize=10)
        self.hourly_ax.bar(labels, values, color='#00ff88', alpha=0.7)
        self.hourly_ax.tick_params(axis='x', rotation=45)
        self.hourly_fig.tight_layout()
        self.hourly_canvas.draw()

        # Update country pie
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

    def setup_blocked_tab(self):
        """Forbedret blokkerte IP-er med GeoIP"""
        toolbar = tk.Frame(self.blocked_frame, bg='#0a0a1a')
        toolbar.pack(fill=tk.X, pady=5)

        tk.Button(toolbar, text="Oppdater", command=self.load_blocked_ips, 
                 bg='#0f3460', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Fjern alle", command=self.unblock_all, 
                 bg='#e94560', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Eksporter CSV", command=self.export_csv, 
                 bg='#0f3460', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        # Whitelist button
        tk.Button(toolbar, text="Legg til whitelist", command=self.add_to_whitelist, 
                 bg='#00ff88', fg='black', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        tree_scroll = ttk.Scrollbar(self.blocked_frame, orient="vertical")
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        columns = ('ip', 'land', 'by', 'isp', 'blokkert', 'kilde', 'vt_score', 'abuse_score')
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
        self.blocked_tree.heading('blokkert', text='Blokkert')
        self.blocked_tree.heading('kilde', text='Kilde')
        self.blocked_tree.heading('vt_score', text='VT')
        self.blocked_tree.heading('abuse_score', text='AbuseIPDB')

        self.blocked_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        def on_mousewheel(event):
            self.blocked_tree.yview_scroll(int(-1*(event.delta/120)), "units")
        self.blocked_tree.bind("<MouseWheel>", on_mousewheel)
        self.blocked_tree.bind("<Button-4>", lambda e: self.blocked_tree.yview_scroll(-1, "units"))
        self.blocked_tree.bind("<Button-5>", lambda e: self.blocked_tree.yview_scroll(1, "units"))
        self.blocked_tree.bind("<Button-3>", self.show_blocked_context_menu)

    
    def setup_gn_tab(self):
        """GreyNoise sjekk"""
        check_frame = tk.Frame(self.gn_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)

        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.gn_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.gn_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Sjekk GreyNoise", command=self.check_gn,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)

        self.gn_result = tk.Text(self.gn_frame, height=15, bg='#16213e', fg='white')
        self.gn_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_av_tab(self):
        """AlienVault OTX sjekk"""
        check_frame = tk.Frame(self.av_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)

        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.av_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.av_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Sjekk AlienVault", command=self.check_av,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)

        self.av_result = tk.Text(self.av_frame, height=15, bg='#16213e', fg='white')
        self.av_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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

    def add_to_whitelist(self):
        selected = self.blocked_tree.selection()
        if selected:
            ip = self.blocked_tree.item(selected[0])['values'][0]
            if ip not in self.config['whitelist_ips']:
                self.config['whitelist_ips'].append(ip)
                save_config(self.config)
                self.ip_blocker.unblock_ip(ip)
                self.load_blocked_ips()
                messagebox.showinfo("Suksess", ip + " lagt til whitelist")


    def schedule_update(self):
        self.load_data()
        self.update_dashboard()
        self.root.after(self.update_interval, self.schedule_update)

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

        # Sendte meldinger med scrollbar
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
        # Create scrollable frame
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
            ("email_smtp_server", "SMTP Server"),
            ("email_username", "E-post brukernavn"),
            ("email_password", "E-passord"),
            ("email_to", "Varsel til e-post")
        ]

        self.settings_entries = {}
        for key, label in settings:
            frame = tk.Frame(scroll_frame, bg='#0a0a1a', padx=10, pady=5)
            frame.pack(fill=tk.X)
            tk.Label(frame, text=label + ":", bg='#0a0a1a', fg='white', width=25, anchor='w').pack(side=tk.LEFT)
            entry = tk.Entry(frame, bg='#16213e', fg='white', width=50)
            entry.insert(0, str(self.config.get(key, '')))
            entry.pack(side=tk.LEFT, padx=5)
            self.settings_entries[key] = entry

        # Checkboxes
        cb_frame = tk.Frame(scroll_frame, bg='#0a0a1a', padx=10, pady=10)
        cb_frame.pack(fill=tk.X)

        self.cb_vars = {}
        for key, label in [("auto_report_abuseipdb", "Auto-rapporter AbuseIPDB"), 
                           ("geoip_enabled", "GeoIP aktivert"),
                           ("time_based_blocking", "Tidsbasert blokkering"),
                           ("email_alerts_enabled", "E-post varsler")]:
            var = tk.BooleanVar(value=self.config.get(key, False))
            self.cb_vars[key] = var
            tk.Checkbutton(cb_frame, text=label, variable=var, bg='#0a0a1a', fg='white',
                          selectcolor='#16213e').pack(anchor=tk.W)

        tk.Button(scroll_frame, text="Lagre innstillinger", command=self.save_settings,
                 bg='#00ff88', fg='black').pack(pady=20)

    def load_data(self):
        self.load_blocked_ips()
        self.load_sent_messages()
        self.load_log()
        self.load_replies()

    def get_vt_result(self, ip):
        if VT_RESULTS_FILE.exists():
            try:
                with open(VT_RESULTS_FILE, 'r') as f:
                    data = json.load(f)
                    return data.get(ip)
            except:
                pass
        return None

    def get_abuse_result(self, ip):
        if ABUSEIPDB_RESULTS_FILE.exists():
            try:
                with open(ABUSEIPDB_RESULTS_FILE, 'r') as f:
                    data = json.load(f)
                    return data.get(ip)
            except:
                pass
        return None

    def load_sent_messages(self):
        for item in self.sent_tree.get_children():
            self.sent_tree.delete(item)
        if MESSAGES_FILE.exists():
            try:
                with open(MESSAGES_FILE, 'r') as f:
                    messages = json.load(f)
                    for ip, data in messages.items():
                        self.sent_tree.insert('', 'end', values=(ip, data.get('timestamp', ''), 
                                                                  data.get('method', ''), data.get('status', '')))
            except:
                pass

    def load_log(self):
        self.log_text.delete('1.0', tk.END)
        log_file = LOG_DIR / 'cyber_ror.log'
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    self.log_text.insert('1.0', ''.join(lines[-100:]))
            except:
                pass

    def load_replies(self):
        for item in self.replies_tree.get_children():
            self.replies_tree.delete(item)
        if REPLIES_FILE.exists():
            try:
                with open(REPLIES_FILE, 'r') as f:
                    replies = json.load(f)
                    for entry in replies:
                        self.replies_tree.insert('', 'end', values=(
                            entry.get('timestamp', ''), entry.get('ip', ''), entry.get('type', ''),
                            entry.get('data', '')[:50], entry.get('auto_reply', '')))
                    self.replies_status.config(text=str(len(replies)) + " svar", fg='white')
            except:
                pass

    def clear_replies(self):
        if messagebox.askyesno("Bekreft", "Slett alle svar?"):
            if REPLIES_FILE.exists():
                try:
                    os.remove(REPLIES_FILE)
                except:
                    pass
            for item in self.replies_tree.get_children():
                self.replies_tree.delete(item)
            self.replies_status.config(text="Ingen svar", fg='white')

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
        if success:
            self.msg_status.config(text="Sendt! " + result, fg='#00ff88')
            self.load_sent_messages()
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
        self.cancel_sending = False
        self.cancel_btn.config(state='normal')
        self.send_btn.config(state='disabled')
        self.send_all_btn.config(state='disabled')
        self.msg_status.config(text="Sender til " + str(total) + "...", fg='yellow')
        self.root.update()
        send_thread = threading.Thread(target=self._send_to_all_thread, args=(message, method, total), daemon=True)
        send_thread.start()

    def _send_to_all_thread(self, message, method, total):
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
            except Exception as e:
                logger.error("Feil ved sending til " + ip + ": " + str(e))
                fail_count += 1
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
        msg = "Sending fullfoert!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count)
        messagebox.showinfo("Ferdig", msg)

    def _send_cancelled(self, success_count, fail_count):
        self.cancel_btn.config(state='disabled')
        self.send_btn.config(state='normal')
        self.send_all_btn.config(state='normal')
        self.load_sent_messages()
        self.msg_status.config(text="AVBRUTT! Sendt: " + str(success_count) + ", Feilet: " + str(fail_count), fg='red')
        msg = "Sending avbrutt!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count)
        messagebox.showinfo("Avbrutt", msg)

    def cancel_send(self):
        self.cancel_sending = True
        self.cancel_btn.config(state='disabled')
        self.msg_status.config(text="Avbryter...", fg='red')

    def send_warning_message(self):
        ip = self.msg_ip_entry.get().strip()
        warning = self.config.get('warning_message', 'ADVARSEL!')
        if not ip:
            messagebox.showerror("Feil", "Velg IP")
            return
        self.msg_text.delete('1.0', tk.END)
        self.msg_text.insert('1.0', warning)
        self.msg_status.config(text="Advarsel klar", fg='orange')

    def send_warning_to_all(self):
        warning = self.config.get('warning_message', 'ADVARSEL!')
        method = self.msg_method.get()
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "Ingen blokkerte IP-er")
            return
        total = len(self.ip_blocker.blocked_ips)
        if not messagebox.askyesno("Bekreft", "Send ADVARSEL til " + str(total) + " IP-er?"):
            return
        self.msg_text.delete('1.0', tk.END)
        self.msg_text.insert('1.0', warning)
        self.cancel_sending = False
        self.cancel_btn.config(state='normal')
        self.send_btn.config(state='disabled')
        self.send_all_btn.config(state='disabled')
        self.msg_status.config(text="Sender ADVARSEL...", fg='red')
        self.root.update()
        send_thread = threading.Thread(target=self._send_warning_to_all_thread, args=(warning, method, total), daemon=True)
        send_thread.start()

    def _send_warning_to_all_thread(self, warning, method, total):
        success_count = 0
        fail_count = 0
        for i, ip in enumerate(sorted(self.ip_blocker.blocked_ips)):
            if self.cancel_sending:
                self.root.after(0, lambda: self._send_cancelled(success_count, fail_count))
                return
            try:
                success, result = self.message_server.send_message(ip, warning, method)
                if success:
                    success_count += 1
                else:
                    fail_count += 1
            except Exception as e:
                logger.error("Feil ved sending til " + ip + ": " + str(e))
                fail_count += 1
            if i % 10 == 0 or i == total - 1:
                status_text = "ADVARSEL: " + str(success_count) + "/" + str(total) + " (feilet: " + str(fail_count) + ")"
                self.root.after(0, lambda st=status_text: self.msg_status.config(text=st, fg='red'))
        self.root.after(0, lambda: self._send_warning_complete(success_count, fail_count))

    def _send_warning_complete(self, success_count, fail_count):
        self.cancel_btn.config(state='disabled')
        self.send_btn.config(state='normal')
        self.send_all_btn.config(state='normal')
        self.load_sent_messages()
        if fail_count == 0:
            self.msg_status.config(text="ADVARSEL sendt til alle " + str(success_count) + "!", fg='red')
        else:
            self.msg_status.config(text="ADVARSEL: " + str(success_count) + ", Feilet: " + str(fail_count), fg='orange')
        msg = "ADVARSEL sending fullfoert!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count)
        messagebox.showinfo("Ferdig", msg)

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
        scrollbar = ttk.Scrollbar(listbox, orient="vertical", command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scrollbar.set)
        def on_select(event):
            selection = listbox.curselection()
            if selection:
                ip = listbox.get(selection[0])
                self.msg_ip_entry.delete(0, tk.END)
                self.msg_ip_entry.insert(0, ip)
                self.msg_status.config(text="Valgt IP: " + ip, fg='#00ff88')
                dialog.destroy()
        listbox.bind("<Double-Button-1>", on_select)
        def on_mousewheel(event):
            listbox.yview_scroll(int(-1*(event.delta/120)), "units")
        listbox.bind("<MouseWheel>", on_mousewheel)
        tk.Button(dialog, text="Lukk", command=dialog.destroy, bg='#e94560', fg='white').pack(pady=5)

    def check_vt(self):
        ip = self.vt_ip_entry.get().strip()
        if not ip:
            return
        self.vt_result.delete('1.0', tk.END)
        self.vt_result.insert('1.0', "Sjekker VirusTotal...\n")
        self.root.update()
        self.vt_result.insert(tk.END, "IP: " + ip + "\n")
        self.vt_result.insert(tk.END, "Bruker VirusTotal API v3...\n")
        self.vt_result.insert(tk.END, "Sjekk config.json for API-noekkel\n")

    def check_abuse(self):
        ip = self.abuse_ip_entry.get().strip()
        if not ip:
            return
        self.abuse_result.delete('1.0', tk.END)
        self.abuse_result.insert('1.0', "Sjekker AbuseIPDB...\n")
        self.root.update()
        self.abuse_result.insert(tk.END, "IP: " + ip + "\n")
        self.abuse_result.insert(tk.END, "Bruker AbuseIPDB API v2...\n")
        self.abuse_result.insert(tk.END, "Sjekk config.json for API-noekkel\n")

    def unblock_all(self):
        if messagebox.askyesno("Bekreft", "Fjern alle blokkeringer?"):
            self.ip_blocker.unblock_all()
            self.load_blocked_ips()

    def export_csv(self):
        csv_file = DATA_DIR / ("blocked_ips_" + datetime.now().strftime('%Y%m%d_%H%M%S') + ".csv")
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Land', 'By', 'ISP', 'Tid', 'Kilde', 'VT', 'AbuseIPDB'])
                for ip in self.ip_blocker.blocked_ips:
                    writer.writerow([ip, '', '', '', '', 'manual', '', ''])
            messagebox.showinfo("Suksess", "Eksportert til " + str(csv_file))
        except Exception as e:
            messagebox.showerror("Feil", str(e))

    def save_settings(self):
        for key, entry in self.settings_entries.items():
            self.config[key] = entry.get()
        for key, var in self.cb_vars.items():
            self.config[key] = var.get()
        save_config(self.config)
        messagebox.showinfo("Suksess", "Innstillinger lagret!")

    def load_blocked_ips(self):
        for item in self.blocked_tree.get_children():
            self.blocked_tree.delete(item)

        for ip in self.ip_blocker.blocked_ips:
            if ip in self.config.get('whitelist_ips', []):
                continue

            self.blocked_tree.insert('', 'end', values=(
                ip,
                'Unknown',
                'Unknown',
                'Unknown',
                datetime.now().strftime('%Y-%m-%d %H:%M'),
                'auto',
                'N/A',
                'N/A'
            ))

    def show_blocked_context_menu(self, event):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Send melding", command=self.select_blocked_ip)
        menu.add_command(label="Legg til whitelist", command=self.add_to_whitelist)
        menu.add_command(label="Fjern blokkering", command=self.unblock_selected)
        menu.post(event.x_root, event.y_root)

    def select_blocked_ip(self):
        selected = self.blocked_tree.selection()
        if selected:
            ip = self.blocked_tree.item(selected[0])['values'][0]
            self.msg_ip_entry.delete(0, tk.END)
            self.msg_ip_entry.insert(0, ip)
            self.msg_status.config(text="Valgt IP: " + ip, fg='#00ff88')

    def unblock_selected(self):
        selected = self.blocked_tree.selection()
        if selected:
            ip = self.blocked_tree.item(selected[0])['values'][0]
            self.ip_blocker.unblock_ip(ip)
            self.load_blocked_ips()

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
                with open(REPLIES_FILE, 'r') as f:
                    replies = json.load(f)
            except:
                pass
        replies.insert(0, reply_entry)
        if len(replies) > 1000:
            replies = replies[:1000]
        try:
            with open(REPLIES_FILE, 'w') as f:
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
        """Handle window closing"""
        try:
            if hasattr(self, 'message_server') and self.message_server:
                self.message_server.stop()
        except:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = CyberRorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
