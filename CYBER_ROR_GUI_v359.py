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

# Suppress matplotlib categorical warnings
import warnings
warnings.filterwarnings('ignore', category=UserWarning, module='matplotlib')

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
        "default_message": "Your IP has been blocked by CYBER-ROR. Contact admin for unblocking.",
        "auto_report_abuseipdb": True,
        "tarpit_delay_seconds": 10,
        "tarpit_max_connections": 100,
        "warning_message": "WARNING: Your IP has been logged and reported to authorities. Cease attacks immediately!",
        "whitelist_ips": ["127.0.0.1", "192.168.1.1"],
        # Tidsbasert varsling og e-postvarsler fjernet
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
            logger.error("Error loading config: " + str(e))

    save_config(default_config)
    return default_config

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        logger.info("Configuration saved")
    except Exception as e:
        logger.error("Error saving config: " + str(e))

class GeoIPLookup:
    """GeoIP oppslag for aa finne land/by fra IP"""
    def __init__(self):
        self.cache = {}

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        try:
            # Bruk ip-api.com (gratis, ingen noekkel)
            url = "http://ip-api.com/json/" + ip
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                country = data.get('country', 'Unknown')
                coords = COUNTRY_COORDINATES.get(country, {'lat': 0, 'lon': 0})
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

        coords = COUNTRY_COORDINATES.get('Unknown', {'lat': 0, 'lon': 0}); return {'country': 'Unknown', 'country_code': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown', 'lat': coords['lat'], 'lon': coords['lon']}

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
            logger.error("GreyNoise error: " + str(e))
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
            logger.error("AlienVault error: " + str(e))
        return None

class StatisticsTracker:
    """Track statistics over time for graph display"""
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
            logger.error("Statistics save error: " + str(e))

    def get_hourly_data(self, hours=24):
        """Get data for last N hours"""
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
        """Get top N countries"""
        sorted_countries = sorted(self.country_stats.items(), key=lambda x: x[1], reverse=True)
        return sorted_countries[:n]



# ==================== KOORDINATER FOR ALLE LAND ====================
COUNTRY_COORDINATES = {
    "Afghanistan": {"lat": 33.93911, "lon": 67.709953},
    "Albania": {"lat": 41.153332, "lon": 20.168331},
    "Algeria": {"lat": 28.033886, "lon": 1.659626},
    "Andorra": {"lat": 42.546245, "lon": 1.601554},
    "Angola": {"lat": -11.202692, "lon": 17.873887},
    "Antigua and Barbuda": {"lat": 17.060816, "lon": -61.796428},
    "Argentina": {"lat": -38.416097, "lon": -63.616672},
    "Armenia": {"lat": 40.069099, "lon": 45.038189},
    "Australia": {"lat": -25.274398, "lon": 133.775136},
    "Austria": {"lat": 47.516231, "lon": 14.550072},
    "Azerbaijan": {"lat": 40.143105, "lon": 47.576927},
    "Bahamas": {"lat": 25.03428, "lon": -77.39628},
    "Bahrain": {"lat": 25.930414, "lon": 50.637772},
    "Bangladesh": {"lat": 23.684994, "lon": 90.356331},
    "Barbados": {"lat": 13.193887, "lon": -59.543198},
    "Belarus": {"lat": 53.709807, "lon": 27.953389},
    "Belgium": {"lat": 50.503887, "lon": 4.469936},
    "Belize": {"lat": 17.189877, "lon": -88.49765},
    "Benin": {"lat": 9.30769, "lon": 2.315834},
    "Bhutan": {"lat": 27.514162, "lon": 90.433601},
    "Bolivia": {"lat": -16.290154, "lon": -63.588653},
    "Bosnia and Herzegovina": {"lat": 43.915886, "lon": 17.679076},
    "Botswana": {"lat": -22.328474, "lon": 24.684866},
    "Brazil": {"lat": -14.235004, "lon": -51.92528},
    "Brunei": {"lat": 4.535277, "lon": 114.727669},
    "Bulgaria": {"lat": 42.733883, "lon": 25.48583},
    "Burkina Faso": {"lat": 12.238333, "lon": -1.561593},
    "Burundi": {"lat": -3.373056, "lon": 29.918886},
    "Cambodia": {"lat": 12.565679, "lon": 104.990963},
    "Cameroon": {"lat": 7.369722, "lon": 12.354722},
    "Canada": {"lat": 56.130366, "lon": -106.346771},
    "Cape Verde": {"lat": 16.002082, "lon": -24.013197},
    "Central African Republic": {"lat": 6.611111, "lon": 20.939444},
    "Chad": {"lat": 15.454166, "lon": 18.732207},
    "Chile": {"lat": -35.675147, "lon": -71.542969},
    "China": {"lat": 35.86166, "lon": 104.195397},
    "Colombia": {"lat": 4.570868, "lon": -74.297333},
    "Comoros": {"lat": -11.875001, "lon": 43.872219},
    "Congo": {"lat": -0.228021, "lon": 15.827659},
    "Congo, Democratic Republic": {"lat": -4.038333, "lon": 21.758664},
    "Costa Rica": {"lat": 9.748917, "lon": -83.753428},
    "Croatia": {"lat": 45.1, "lon": 15.2},
    "Cuba": {"lat": 21.521757, "lon": -77.781167},
    "Cyprus": {"lat": 35.126413, "lon": 33.429859},
    "Czech Republic": {"lat": 49.817492, "lon": 15.472962},
    "Denmark": {"lat": 56.26392, "lon": 9.501785},
    "Djibouti": {"lat": 11.825138, "lon": 42.590275},
    "Dominica": {"lat": 15.414999, "lon": -61.370976},
    "Dominican Republic": {"lat": 18.735693, "lon": -70.162651},
    "Ecuador": {"lat": -1.831239, "lon": -78.183406},
    "Egypt": {"lat": 26.820553, "lon": 30.802498},
    "El Salvador": {"lat": 13.794185, "lon": -88.89653},
    "Equatorial Guinea": {"lat": 1.650801, "lon": 10.267895},
    "Eritrea": {"lat": 15.179384, "lon": 39.782334},
    "Estonia": {"lat": 58.595272, "lon": 25.013607},
    "Eswatini": {"lat": -26.522503, "lon": 31.465866},
    "Ethiopia": {"lat": 9.145, "lon": 40.489673},
    "Fiji": {"lat": -16.578193, "lon": 179.414413},
    "Finland": {"lat": 61.92411, "lon": 25.748151},
    "France": {"lat": 46.227638, "lon": 2.213749},
    "Gabon": {"lat": -0.803689, "lon": 11.609444},
    "Gambia": {"lat": 13.443182, "lon": -15.310139},
    "Georgia": {"lat": 42.315407, "lon": 43.356892},
    "Germany": {"lat": 51.165691, "lon": 10.451526},
    "Ghana": {"lat": 7.946527, "lon": -1.023194},
    "Greece": {"lat": 39.074208, "lon": 21.824312},
    "Grenada": {"lat": 12.262776, "lon": -61.604171},
    "Guatemala": {"lat": 15.783471, "lon": -90.230759},
    "Guinea": {"lat": 9.945587, "lon": -9.696645},
    "Guinea-Bissau": {"lat": 11.803749, "lon": -15.180413},
    "Guyana": {"lat": 4.860416, "lon": -58.93018},
    "Haiti": {"lat": 18.971187, "lon": -72.285215},
    "Honduras": {"lat": 15.199999, "lon": -86.241905},
    "Hungary": {"lat": 47.162494, "lon": 19.503304},
    "Iceland": {"lat": 64.963051, "lon": -19.020835},
    "India": {"lat": 20.593684, "lon": 78.96288},
    "Indonesia": {"lat": -0.789275, "lon": 113.921327},
    "Iran": {"lat": 32.427908, "lon": 53.688046},
    "Iraq": {"lat": 33.223191, "lon": 43.679291},
    "Ireland": {"lat": 53.41291, "lon": -8.24389},
    "Israel": {"lat": 31.046051, "lon": 34.851612},
    "Italy": {"lat": 41.87194, "lon": 12.56738},
    "Jamaica": {"lat": 18.109581, "lon": -77.297508},
    "Japan": {"lat": 36.204824, "lon": 138.252924},
    "Jordan": {"lat": 30.585164, "lon": 36.238414},
    "Kazakhstan": {"lat": 48.019573, "lon": 66.923684},
    "Kenya": {"lat": -0.023559, "lon": 37.906193},
    "Kiribati": {"lat": -3.370417, "lon": -168.734039},
    "Korea, North": {"lat": 40.339852, "lon": 127.510093},
    "Korea, South": {"lat": 35.907757, "lon": 127.766922},
    "Kosovo": {"lat": 42.602636, "lon": 20.902977},
    "Kuwait": {"lat": 29.31166, "lon": 47.481766},
    "Kyrgyzstan": {"lat": 41.20438, "lon": 74.766098},
    "Laos": {"lat": 19.85627, "lon": 102.495496},
    "Latvia": {"lat": 56.879635, "lon": 24.603189},
    "Lebanon": {"lat": 33.854721, "lon": 35.862285},
    "Lesotho": {"lat": -29.609988, "lon": 28.233608},
    "Liberia": {"lat": 6.428055, "lon": -9.429499},
    "Libya": {"lat": 26.3351, "lon": 17.228331},
    "Liechtenstein": {"lat": 47.166, "lon": 9.555373},
    "Lithuania": {"lat": 55.169438, "lon": 23.881275},
    "Luxembourg": {"lat": 49.815273, "lon": 6.129583},
    "Madagascar": {"lat": -18.766947, "lon": 46.869107},
    "Malawi": {"lat": -13.254308, "lon": 34.301525},
    "Malaysia": {"lat": 4.210484, "lon": 101.975766},
    "Maldives": {"lat": 3.202778, "lon": 73.22068},
    "Mali": {"lat": 17.570692, "lon": -3.996166},
    "Malta": {"lat": 35.937496, "lon": 14.375416},
    "Marshall Islands": {"lat": 7.131474, "lon": 171.184478},
    "Mauritania": {"lat": 21.00789, "lon": -10.940835},
    "Mauritius": {"lat": -20.348404, "lon": 57.552152},
    "Mexico": {"lat": 23.634501, "lon": -102.552784},
    "Micronesia": {"lat": 7.425554, "lon": 150.550812},
    "Moldova": {"lat": 47.411631, "lon": 28.369885},
    "Monaco": {"lat": 43.750298, "lon": 7.412841},
    "Mongolia": {"lat": 46.862496, "lon": 103.846656},
    "Montenegro": {"lat": 42.708678, "lon": 19.37439},
    "Morocco": {"lat": 31.791702, "lon": -7.09262},
    "Mozambique": {"lat": -18.665695, "lon": 35.529562},
    "Myanmar": {"lat": 21.913965, "lon": 95.956223},
    "Namibia": {"lat": -22.95764, "lon": 18.49041},
    "Nauru": {"lat": -0.522778, "lon": 166.931503},
    "Nepal": {"lat": 28.394857, "lon": 84.124008},
    "Netherlands": {"lat": 52.132633, "lon": 5.291266},
    "New Zealand": {"lat": -40.900557, "lon": 174.885971},
    "Nicaragua": {"lat": 12.865416, "lon": -85.207229},
    "Niger": {"lat": 17.607789, "lon": 8.081666},
    "Nigeria": {"lat": 9.081999, "lon": 8.675277},
    "North Macedonia": {"lat": 41.608635, "lon": 21.745275},
    "Norway": {"lat": 60.472024, "lon": 8.468946},
    "Oman": {"lat": 21.512583, "lon": 55.923255},
    "Pakistan": {"lat": 30.375321, "lon": 69.345116},
    "Palau": {"lat": 7.51498, "lon": 134.58252},
    "Panama": {"lat": 8.537981, "lon": -80.782127},
    "Papua New Guinea": {"lat": -6.314993, "lon": 143.95555},
    "Paraguay": {"lat": -23.442503, "lon": -58.443832},
    "Peru": {"lat": -9.189967, "lon": -75.015152},
    "Philippines": {"lat": 12.879721, "lon": 121.774017},
    "Poland": {"lat": 51.919438, "lon": 19.145136},
    "Portugal": {"lat": 39.399872, "lon": -8.224454},
    "Qatar": {"lat": 25.354826, "lon": 51.183884},
    "Romania": {"lat": 45.943161, "lon": 24.96676},
    "Russia": {"lat": 61.52401, "lon": 105.318756},
    "Rwanda": {"lat": -1.940278, "lon": 29.873888},
    "Saint Kitts and Nevis": {"lat": 17.357822, "lon": -62.782998},
    "Saint Lucia": {"lat": 13.909444, "lon": -60.978893},
    "Saint Vincent and the Grenadines": {"lat": 12.984305, "lon": -61.287228},
    "Samoa": {"lat": -13.759029, "lon": -172.104629},
    "San Marino": {"lat": 43.94236, "lon": 12.457777},
    "Sao Tome and Principe": {"lat": 0.18636, "lon": 6.613081},
    "Saudi Arabia": {"lat": 23.885942, "lon": 45.079162},
    "Senegal": {"lat": 14.497401, "lon": -14.452362},
    "Serbia": {"lat": 44.016521, "lon": 21.005859},
    "Seychelles": {"lat": -4.679574, "lon": 55.491977},
    "Sierra Leone": {"lat": 8.460555, "lon": -11.779889},
    "Singapore": {"lat": 1.352083, "lon": 103.819836},
    "Slovakia": {"lat": 48.669026, "lon": 19.699024},
    "Slovenia": {"lat": 46.151241, "lon": 14.995463},
    "Solomon Islands": {"lat": -9.64571, "lon": 160.156194},
    "Somalia": {"lat": 5.152149, "lon": 46.199616},
    "South Africa": {"lat": -30.559482, "lon": 22.937506},
    "South Sudan": {"lat": 6.876991, "lon": 31.306979},
    "Spain": {"lat": 40.463667, "lon": -3.74922},
    "Sri Lanka": {"lat": 7.873054, "lon": 80.771797},
    "Sudan": {"lat": 12.862807, "lon": 30.217636},
    "Suriname": {"lat": 3.919305, "lon": -56.027783},
    "Sweden": {"lat": 60.128161, "lon": 18.643501},
    "Switzerland": {"lat": 46.818188, "lon": 8.227512},
    "Syria": {"lat": 34.802075, "lon": 38.996815},
    "Taiwan": {"lat": 23.69781, "lon": 120.960515},
    "Tajikistan": {"lat": 38.861034, "lon": 71.276093},
    "Tanzania": {"lat": -6.369028, "lon": 34.888822},
    "Thailand": {"lat": 15.870032, "lon": 100.992541},
    "Timor-Leste": {"lat": -8.874217, "lon": 125.727539},
    "Togo": {"lat": 8.619543, "lon": 0.824782},
    "Tonga": {"lat": -21.178986, "lon": -175.198242},
    "Trinidad and Tobago": {"lat": 10.691803, "lon": -61.222503},
    "Tunisia": {"lat": 33.886917, "lon": 9.537499},
    "Turkey": {"lat": 38.963745, "lon": 35.243322},
    "Turkmenistan": {"lat": 38.969719, "lon": 59.556278},
    "Tuvalu": {"lat": -7.109535, "lon": 177.64933},
    "Uganda": {"lat": 1.373333, "lon": 32.290275},
    "Ukraine": {"lat": 48.379433, "lon": 31.16558},
    "United Arab Emirates": {"lat": 23.424076, "lon": 53.847818},
    "United Kingdom": {"lat": 55.378051, "lon": -3.435973},
    "United States": {"lat": 37.09024, "lon": -95.712891},
    "Uruguay": {"lat": -32.522779, "lon": -55.765835},
    "Uzbekistan": {"lat": 41.377491, "lon": 64.585262},
    "Vanuatu": {"lat": -15.376706, "lon": 166.959158},
    "Vatican City": {"lat": 41.902916, "lon": 12.453389},
    "Venezuela": {"lat": 6.42375, "lon": -66.58973},
    "Vietnam": {"lat": 14.058324, "lon": 108.277199},
    "Yemen": {"lat": 15.552727, "lon": 48.516388},
    "Zambia": {"lat": -13.133897, "lon": 27.849332},
    "Zimbabwe": {"lat": -19.015438, "lon": 29.154857},
    "Unknown": {"lat": 0, "lon": 0}
}


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
            self.server_socket.bind(('0.0.0.0', int(self.port)))
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
                conn.sendall(b"ACK: Melding mottatt av CYBER-ROR\n")
        except Exception as e:
            logger.error("Feil ved handtering av klient: " + str(e))
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
                return False, "Ukjent metode: " + method
        except Exception as e:
            logger.error("Feil ved sending til " + ip + ": " + str(e))
            return False, str(e)

    def _send_tcp(self, ip, message):
        """Send message via TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, 80))
            sock.sendall(message.encode('utf-8'))
            sock.close()
            return True, "TCP sendt"
        except Exception as e:
            return False, "TCP feil: " + str(e)

    def _send_http(self, ip, message):
        """Send message via HTTP"""
        try:
            url = "http://" + ip + ":80/"
            response = requests.get(url, timeout=5, headers={'User-Agent': 'CYBER-ROR/' + message})
            return True, "HTTP sendt (status: " + str(response.status_code) + ")"
        except Exception as e:
            return False, "HTTP feil: " + str(e)

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
                    return True, "ICMP (ping) sendt - host er oppe"
                else:
                    return False, "ICMP feil - host svarer ikke"
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', ip],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    return True, "ICMP (ping) sendt"
                else:
                    return False, "ICMP feil - host svarer ikke"
        except Exception as e:
            return False, "ICMP feil: " + str(e)

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
        self.geoip = GeoIPLookup()
        self.stats = StatisticsTracker()
        self.greynoise = GreyNoiseChecker(self.config.get('greynoise_api_key', ''))
        self.alienvault = AlienVaultChecker(self.config.get('alienvault_api_key', ''))

        self.message_server = MessageServer(
            port=int(self.config.get('message_server_port', 8081)),
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

        tk.Label(self.status_frame, text="ACTIVE", font=('Consolas', 12, 'bold'),
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
        style.configure('TNotebook', background='#000000', tabmargins=[2, 5, 2, 0])

        # Treeview styling for dark mode
        style.configure('Treeview', 
                       background='#0d1b2a',
                       foreground='#ffffff',
                       fieldbackground='#0d1b2a',
                       font=('Consolas', 10))
        style.configure('Treeview.Heading', 
                       background='#1b263b',
                       foreground='#00ff88',
                       font=('Consolas', 11, 'bold'))
        style.map('Treeview', background=[('selected', '#1b263b')])

        # Notebook tabs: black background, orange text for selected
        style.configure('TNotebook.Tab', 
                       background='#000000', 
                       foreground='#ff6b35', 
                       padding=[15, 8], 
                       font=('Consolas', 11, 'bold'))
        style.map('TNotebook.Tab', 
                   background=[('selected', '#1a1a1a'), ('active', '#0d0d0d')],
                   foreground=[('selected', '#ff6b35'), ('active', '#ff8c5a')])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Dashboard tab (NEW)
        self.dashboard_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.setup_dashboard_tab()

        # Blokkerte IP-er
        self.blocked_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.blocked_frame, text="Blocked IPs")
        self.setup_blocked_tab()

        # Send Melding
        self.message_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.message_frame, text="Send Message")
        self.setup_message_tab()

        # Kart/GeoIP (NEW)
        self.map_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.map_frame, text="Map")
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
        self.notebook.add(self.replies_frame, text="Incoming replies")
        self.setup_replies_tab()

        # Logg
        self.log_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.log_frame, text="Log")
        self.setup_log_tab()

        # Innstillinger
        self.settings_frame = tk.Frame(self.notebook, bg='#0a0a1a')
        self.notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_tab()

    def setup_dashboard_tab(self):
        """Dashboard with graphs and statistics"""
        # Top row - Stats cards
        cards_frame = tk.Frame(self.dashboard_frame, bg='#0a0a1a')
        cards_frame.pack(fill=tk.X, padx=10, pady=10)

        # Card 1: Total blocked
        card1 = tk.Frame(cards_frame, bg='#0d1b2a', bd=2, relief='ridge')
        card1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card1, text="Total blocked", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.total_blocked_label = tk.Label(card1, text="0", bg='#16213e', fg='#00ff88',
                                           font=('Orbitron', 28, 'bold'))
        self.total_blocked_label.pack(pady=5)

        # Card 2: Today
        card2 = tk.Frame(cards_frame, bg='#0d1b2a', bd=2, relief='ridge')
        card2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card2, text="Today", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.today_blocked_label = tk.Label(card2, text="0", bg='#16213e', fg='#ff6b35',
                                           font=('Orbitron', 28, 'bold'))
        self.today_blocked_label.pack(pady=5)

        # Card 3: Active traps
        card3 = tk.Frame(cards_frame, bg='#0d1b2a', bd=2, relief='ridge')
        card3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card3, text="Active traps", bg='#16213e', fg='#888', 
                font=('Consolas', 10)).pack(pady=5)
        self.active_traps_label = tk.Label(card3, text="0", bg='#16213e', fg='#e94560',
                                          font=('Orbitron', 28, 'bold'))
        self.active_traps_label.pack(pady=5)

        # Card 4: Top country
        card4 = tk.Frame(cards_frame, bg='#0d1b2a', bd=2, relief='ridge')
        card4.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        tk.Label(card4, text="Top country", bg='#16213e', fg='#888', 
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
        self.blocked_counter.config(text="Blocked: " + str(total))
        self.attack_counter.config(text="Attacks today: " + str(today_count))

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
        """Enhanced blocked IPs with GeoIP"""
        toolbar = tk.Frame(self.blocked_frame, bg='#0a0a1a')
        toolbar.pack(fill=tk.X, pady=5)

        tk.Button(toolbar, text="Update", command=self.load_blocked_ips, 
                 bg='#0f3460', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Remove all", command=self.unblock_all, 
                 bg='#e94560', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Export CSV", command=self.export_csv, 
                 bg='#0f3460', fg='white', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)

        # Whitelist button
        tk.Button(toolbar, text="Add to whitelist", command=self.add_to_whitelist, 
                 bg='#00ff88', fg='black', font=('Consolas', 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Check & Report ALL", command=self.check_and_report_all, 
                 bg='#ff6b35', fg='white', font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=5)

        # Progress bar for check & report
        self.check_progress_label = tk.Label(toolbar, text="", bg='#0a0a1a', fg='#00ff88', font=('Consolas', 9))
        self.check_progress_label.pack(side=tk.LEFT, padx=10)
        self.check_progress = ttk.Progressbar(toolbar, orient='horizontal', length=200, mode='determinate')
        self.check_progress.pack(side=tk.LEFT, padx=5)

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

        # Also select item on right-click
        def on_right_click(event):
            # Select the row under cursor
            item = self.blocked_tree.identify_row(event.y)
            if item:
                self.blocked_tree.selection_set(item)
                self.blocked_tree.focus(item)
        self.blocked_tree.bind("<Button-3>", on_right_click, add="+")

    def setup_map_tab(self):
        """Map view with country statistics and coordinates"""
        # Dark background matching log tab
        self.map_frame.configure(bg='#0a0a1a')

        tk.Label(self.map_frame, text="Attacks by country", bg='#0a0a1a', fg='white',
                font=('Orbitron', 16)).pack(pady=10)

        tk.Label(self.map_frame, text="Coordinates built-in for 195+ countries", bg='#0a0a1a', fg='#00ff88',
                font=('Consolas', 10)).pack(pady=5)

        self.map_tree = ttk.Treeview(self.map_frame, columns=('land', 'antall', 'prosent', 'lat', 'lon'), 
                                     show='headings')
        self.map_tree.heading('land', text='Land')
        self.map_tree.heading('antall', text='Antall')
        self.map_tree.heading('prosent', text='%')
        self.map_tree.heading('lat', text='Breddegrad')
        self.map_tree.heading('lon', text='Lengdegrad')
        self.map_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(self.map_tree, orient="vertical", command=self.map_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.map_tree.config(yscrollcommand=scrollbar.set)

    def setup_gn_tab(self):
        """GreyNoise check"""
        check_frame = tk.Frame(self.gn_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)

        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.gn_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.gn_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Check GreyNoise", command=self.check_gn,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)

        self.gn_result = tk.Text(self.gn_frame, height=15, bg='#16213e', fg='white')
        self.gn_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_av_tab(self):
        """AlienVault OTX check"""
        check_frame = tk.Frame(self.av_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)

        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.av_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.av_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Check AlienVault", command=self.check_av,
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
            self.gn_result.insert(tk.END, "No data found. Check API key.")

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
            self.av_result.insert(tk.END, "No data found. Check API key.")

    def add_to_whitelist(self):
        selected = self.blocked_tree.selection()
        if selected:
            ip = self.blocked_tree.item(selected[0])['values'][0]
            if ip not in self.config['whitelist_ips']:
                self.config['whitelist_ips'].append(ip)
                save_config(self.config)
                self.ip_blocker.unblock_ip(ip)
                self.load_blocked_ips()
                messagebox.showinfo("Success", ip + " added to whitelist")

    def load_blocked_ips(self):
        for item in self.blocked_tree.get_children():
            self.blocked_tree.delete(item)

        for ip in self.ip_blocker.blocked_ips:
            # Skip whitelisted IPs
            if ip in self.config.get('whitelist_ips', []):
                continue

            geo = self.geoip.lookup(ip)
            vt = self.get_vt_result(ip)
            abuse = self.get_abuse_result(ip)

            self.blocked_tree.insert('', 'end', values=(
                ip,
                geo.get('country', 'Unknown'),
                geo.get('city', 'Unknown'),
                geo.get('isp', 'Unknown'),
                datetime.now().strftime('%Y-%m-%d %H:%M'),
                'auto',
                str(vt.get('malicious', 'N/A')) + "/" + str(vt.get('total_engines', 'N/A')) if vt else 'N/A',
                str(abuse.get('abuse_confidence_score', 'N/A')) + "%" if abuse else 'N/A'
            ))

        # Update map
        self.update_map()

    def update_map(self):
        for item in self.map_tree.get_children():
            self.map_tree.delete(item)

        total = sum(self.stats.country_stats.values())
        if total == 0:
            return

        for country, count in self.stats.get_top_countries(20):
            pct = (count / total) * 100
            coords = COUNTRY_COORDINATES.get(country, {"lat": 0, "lon": 0})
            self.map_tree.insert('', 'end', values=(
                country, count, f"{pct:.1f}%", 
                f"{coords['lat']:.4f}", f"{coords['lon']:.4f}"
            ))

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
        tk.Button(ip_frame, text="Select from blocked", command=self.show_ip_selection_dialog,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)

        msg_frame = tk.Frame(self.message_frame, bg='#0a0a1a', padx=10, pady=10)
        msg_frame.pack(fill=tk.X)
        tk.Label(msg_frame, text="Message:", bg='#0a0a1a', fg='white').pack(anchor=tk.W)
        self.msg_text = tk.Text(msg_frame, height=5, bg='#16213e', fg='white')
        self.msg_text.insert('1.0', self.config.get('default_message', ''))
        self.msg_text.pack(fill=tk.X, pady=5)

        method_frame = tk.Frame(self.message_frame, bg='#0a0a1a', padx=10)
        method_frame.pack(fill=tk.X)
        tk.Label(method_frame, text="Method:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.msg_method = ttk.Combobox(method_frame, values=['http', 'tcp', 'icmp'], width=10)
        self.msg_method.set('icmp')
        self.msg_method.pack(side=tk.LEFT, padx=5)

        btn_frame = tk.Frame(self.message_frame, bg='#0a0a1a')
        btn_frame.pack(pady=10)
        self.send_btn = tk.Button(btn_frame, text="Send Message", command=self.send_message,
                 bg='#00ff88', fg='black', font=('Arial', 12, 'bold'))
        self.send_btn.pack(side=tk.LEFT, padx=5)
        self.send_all_btn = tk.Button(btn_frame, text="Send to ALL", command=self.send_message_to_all,
                 bg='#ff6b35', fg='white', font=('Arial', 12, 'bold'))
        self.send_all_btn.pack(side=tk.LEFT, padx=5)
        self.cancel_btn = tk.Button(btn_frame, text="CANCEL", command=self.cancel_send,
                 bg='#e94560', fg='white', font=('Arial', 12, 'bold'), state='disabled')
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Send WARNING", command=self.send_warning_message,
                 bg='#ff0000', fg='white', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="WARNING to ALL", command=self.send_warning_to_all,
                 bg='#8b0000', fg='white', font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=5)

        self.msg_status = tk.Label(self.message_frame, text="", bg='#0a0a1a', fg='#00ff88')
        self.msg_status.pack()

        # Sendte meldinger med scrollbar
        tk.Label(self.message_frame, text="Sent messages:", bg='#0a0a1a', fg='white').pack(anchor=tk.W, padx=10)
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
        tk.Button(check_frame, text="Check VirusTotal", command=self.check_vt,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        self.vt_result = tk.Text(self.vt_frame, height=15, bg='#16213e', fg='white')
        self.vt_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_abuse_tab(self):
        check_frame = tk.Frame(self.abuse_frame, bg='#0a0a1a', padx=10, pady=10)
        check_frame.pack(fill=tk.X)
        tk.Label(check_frame, text="IP:", bg='#0a0a1a', fg='white').pack(side=tk.LEFT)
        self.abuse_ip_entry = tk.Entry(check_frame, width=20, bg='#16213e', fg='white')
        self.abuse_ip_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(check_frame, text="Check AbuseIPDB", command=self.check_abuse,
                 bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        self.abuse_result = tk.Text(self.abuse_frame, height=15, bg='#16213e', fg='white')
        self.abuse_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_replies_tab(self):
        # Dark background matching log tab
        self.replies_frame.configure(bg='#0a0a1a')

        toolbar = tk.Frame(self.replies_frame, bg='#0a0a1a')
        toolbar.pack(fill=tk.X, pady=5)
        tk.Button(toolbar, text="Update", command=self.load_replies, bg='#0f3460', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(toolbar, text="Slett alle", command=self.clear_replies, bg='#e94560', fg='white').pack(side=tk.LEFT, padx=5)
        self.replies_status = tk.Label(toolbar, text="Waiting for replies...", bg='#0a0a1a', fg='#00ff88')
        self.replies_status.pack(side=tk.RIGHT, padx=10)

        # Use a dark text widget instead of Treeview for consistent look
        self.replies_text = scrolledtext.ScrolledText(self.replies_frame, bg='#16213e', fg='#00ff88', font=('Consolas', 10))
        self.replies_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Keep treeview but styled dark
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
        tk.Button(self.log_frame, text="Update log", command=self.load_log, bg='#0f3460', fg='white').pack(pady=5)

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
            ("message_server_port", "Message server port"),
            ("default_message", "Default message"),
            ("warning_message", "Warning message"),
            # E-post innstillinger fjernet
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
        for key, label in [("auto_report_abuseipdb", "Auto-report AbuseIPDB"), 
                           ("geoip_enabled", "GeoIP enabled")]:
            var = tk.BooleanVar(value=self.config.get(key, False))
            self.cb_vars[key] = var
            tk.Checkbutton(cb_frame, text=label, variable=var, bg='#0a0a1a', fg='white',
                          selectcolor='#16213e').pack(anchor=tk.W)

        tk.Button(scroll_frame, text="Save settings", command=self.save_settings,
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
        if messagebox.askyesno("Confirm", "Delete all replies?"):
            if REPLIES_FILE.exists():
                try:
                    os.remove(REPLIES_FILE)
                except:
                    pass
            for item in self.replies_tree.get_children():
                self.replies_tree.delete(item)
            self.replies_status.config(text="No replies", fg='white')

    def send_message(self):
        ip = self.msg_ip_entry.get().strip()
        message = self.msg_text.get('1.0', tk.END).strip()
        method = self.msg_method.get()
        if not ip or not message:
            messagebox.showerror("Error", "Fill in IP and message")
            return
        self.msg_status.config(text="Sending...", fg='yellow')
        self.root.update()
        success, result = self.message_server.send_message(ip, message, method)
        if success:
            self.msg_status.config(text="Sent! " + result, fg='#00ff88')
            self.load_sent_messages()
        else:
            self.msg_status.config(text="Error: " + result, fg='#e94560')

    def send_message_to_all(self):
        message = self.msg_text.get('1.0', tk.END).strip()
        method = self.msg_method.get()
        if not message:
            messagebox.showerror("Error", "Enter message")
            return
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "No blocked IPs")
            return
        total = len(self.ip_blocker.blocked_ips)
        if not messagebox.askyesno("Confirm", "Send to " + str(total) + " IPs?"):
            return
        self.cancel_sending = False
        self.cancel_btn.config(state='normal')
        self.send_btn.config(state='disabled')
        self.send_all_btn.config(state='disabled')
        self.msg_status.config(text="Sending to " + str(total) + "...", fg='yellow')
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
                status_text = "Sent: " + str(success_count) + "/" + str(total) + " (failed: " + str(fail_count) + ")"
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
            self.msg_status.config(text="Sent: " + str(success_count) + ", Feilet: " + str(fail_count), fg='orange')
        msg = "Sending fullfoert!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count)
        messagebox.showinfo("Done", msg)

    def _send_cancelled(self, success_count, fail_count):
        self.cancel_btn.config(state='disabled')
        self.send_btn.config(state='normal')
        self.send_all_btn.config(state='normal')
        self.load_sent_messages()
        self.msg_status.config(text="CANCELLED! Sent: " + str(success_count) + ", Feilet: " + str(fail_count), fg='red')
        msg = "Sending avbrutt!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count)
        messagebox.showinfo("Cancelled", msg)

    def cancel_send(self):
        self.cancel_sending = True
        self.cancel_btn.config(state='disabled')
        self.msg_status.config(text="Avbryter...", fg='red')

    def send_warning_message(self):
        ip = self.msg_ip_entry.get().strip()
        warning = self.config.get('warning_message', 'WARNING!')
        if not ip:
            messagebox.showerror("Error", "Select IP")
            return
        self.msg_text.delete('1.0', tk.END)
        self.msg_text.insert('1.0', warning)
        self.msg_status.config(text="Warning ready", fg='orange')

    def send_warning_to_all(self):
        warning = self.config.get('warning_message', 'WARNING!')
        method = self.msg_method.get()
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "No blocked IPs")
            return
        total = len(self.ip_blocker.blocked_ips)
        if not messagebox.askyesno("Confirm", "Send ADVARSEL til " + str(total) + " IPs?"):
            return
        self.msg_text.delete('1.0', tk.END)
        self.msg_text.insert('1.0', warning)
        self.cancel_sending = False
        self.cancel_btn.config(state='normal')
        self.send_btn.config(state='disabled')
        self.send_all_btn.config(state='disabled')
        self.msg_status.config(text="Sending WARNING...", fg='red')
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
                status_text = "WARNING: " + str(success_count) + "/" + str(total) + " (failed: " + str(fail_count) + ")"
                self.root.after(0, lambda st=status_text: self.msg_status.config(text=st, fg='red'))
        self.root.after(0, lambda: self._send_warning_complete(success_count, fail_count))

    def _send_warning_complete(self, success_count, fail_count):
        self.cancel_btn.config(state='disabled')
        self.send_btn.config(state='normal')
        self.send_all_btn.config(state='normal')
        self.load_sent_messages()
        if fail_count == 0:
            self.msg_status.config(text="WARNING sent to all " + str(success_count) + "!", fg='red')
        else:
            self.msg_status.config(text="WARNING: " + str(success_count) + ", Feilet: " + str(fail_count), fg='orange')
        msg = "ADVARSEL sending fullfoert!\n\nSendt: " + str(success_count) + "\nFeilet: " + str(fail_count)
        messagebox.showinfo("Done", msg)

    def show_ip_selection_dialog(self):
        if not self.ip_blocker.blocked_ips:
            messagebox.showinfo("Info", "No blocked IPs")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Select IP")
        dialog.geometry("400x300")
        dialog.configure(bg='#0a0a1a')
        tk.Label(dialog, text="Double-click to select:", bg='#0a0a1a', fg='white').pack(pady=5)
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
                self.msg_status.config(text="Selected IP: " + ip, fg='#00ff88')
                dialog.destroy()
        listbox.bind("<Double-Button-1>", on_select)
        def on_mousewheel(event):
            listbox.yview_scroll(int(-1*(event.delta/120)), "units")
        listbox.bind("<MouseWheel>", on_mousewheel)
        tk.Button(dialog, text="Close", command=dialog.destroy, bg='#e94560', fg='white').pack(pady=5)

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
        if messagebox.askyesno("Confirm", "Remove all blocks?"):
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
            messagebox.showinfo("Success", "Exported to " + str(csv_file))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_settings(self):
        for key, entry in self.settings_entries.items():
            self.config[key] = entry.get()
        for key, var in self.cb_vars.items():
            self.config[key] = var.get()
        save_config(self.config)
        messagebox.showinfo("Success", "Settings saved!")

    def check_and_report_all(self):
        """Check and report all blocked IPs to VirusTotal, AbuseIPDB, GreyNoise and AlienVault"""
        logger.info("=== Check & Report ALL button clicked ===")

        if not self.ip_blocker.blocked_ips:
            logger.warning("No blocked IPs to check")
            messagebox.showinfo("Info", "No blocked IPs to check")
            return

        total = len(self.ip_blocker.blocked_ips)
        logger.info("Total IPs to check: " + str(total))

        if not messagebox.askyesno("Confirm", "Check and REPORT " + str(total) + " IPs to all services?"):
            logger.info("User cancelled Check & Report")
            return

        logger.info("Starting Check & Report for " + str(total) + " IPs")

        # Reset progress bar
        try:
            self.check_progress['maximum'] = total
            self.check_progress['value'] = 0
            self.check_progress_label.config(text="Starting...", fg='#00ff88')
            logger.info("Progress bar initialized")
        except Exception as e:
            logger.error("Progress bar init error: " + str(e))

        # Run in background thread to keep GUI responsive
        check_thread = threading.Thread(target=self._check_and_report_all_thread, daemon=True)
        check_thread.start()
        logger.info("Background thread started")

    def _check_and_report_all_thread(self):
        """Bakgrunnstraad for aa sjekke alle IP-er"""
        total = len(self.ip_blocker.blocked_ips)
        processed = 0
        results = {}

        for ip in sorted(self.ip_blocker.blocked_ips):
            processed += 1
            result = {'ip': ip, 'vt': None, 'abuse': None, 'gn': None, 'av': None}

            # VirusTotal check
            if self.config.get('virustotal_check_enabled') and self.config.get('virustotal_api_key'):
                try:
                    result['vt'] = self._check_vt_api(ip)
                except Exception as e:
                    logger.error("VT error for " + ip + ": " + str(e))

            # AbuseIPDB check
            if self.config.get('abuseipdb_check_enabled') and self.config.get('abuseipdb_api_key'):
                try:
                    result['abuse'] = self._check_abuse_api(ip)
                except Exception as e:
                    logger.error("AbuseIPDB error for " + ip + ": " + str(e))

            # GreyNoise check
            if self.config.get('greynoise_check_enabled') and self.config.get('greynoise_api_key'):
                try:
                    result['gn'] = self.greynoise.check_ip(ip)
                except Exception as e:
                    logger.error("GreyNoise error for " + ip + ": " + str(e))

            # AlienVault check
            if self.config.get('alienvault_check_enabled') and self.config.get('alienvault_api_key'):
                try:
                    result['av'] = self.alienvault.check_ip(ip)
                except Exception as e:
                    logger.error("AlienVault error for " + ip + ": " + str(e))

            results[ip] = result

            # Update progress every IP for smooth animation
            self.root.after(0, lambda p=processed, t=total: self._update_progress(p, t))

        # Save results
        self._save_check_results(results)

        # Update UI
        self.root.after(0, lambda: self._check_all_complete(results))

    def _update_progress(self, processed, total):
        """Update progress bar and label during checking"""
        try:
            self.check_progress['value'] = processed
            pct = int((processed / total) * 100) if total > 0 else 0
            status_text = "Checking: " + str(processed) + "/" + str(total) + " (" + str(pct) + "%)"
            self.check_progress_label.config(text=status_text, fg='#00ff88')

            # Also update msg_status if available
            if hasattr(self, 'msg_status'):
                self.msg_status.config(text=status_text, fg='#ff6b35')
        except Exception as e:
            logger.error("Progress update error: " + str(e))

        # Log every 10 IPs to avoid spam
        if processed % 10 == 0 or processed == total:
            logger.info("Progress: " + str(processed) + "/" + str(total) + " (" + str(int((processed/total)*100)) + "%)")

    def _check_vt_api(self, ip):
        """Sjekk IP mot VirusTotal API"""
        api_key = self.config.get('virustotal_api_key', '')
        if not api_key:
            return None
        url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {'apikey': api_key, 'ip': ip}
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None

    def _check_abuse_api(self, ip):
        """Sjekk IP mot AbuseIPDB API"""
        api_key = self.config.get('abuseipdb_api_key', '')
        if not api_key:
            return None
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': api_key, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get('data', {})
        return None

    def _report_to_abuseipdb(self, ip):
        """Report IP to AbuseIPDB"""
        try:
            api_key = self.config.get('abuseipdb_api_key', '')
            if not api_key:
                return False
            url = "https://api.abuseipdb.com/api/v2/report"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            data = {
                'ip': ip,
                'categories': '18,22',  # Brute Force, SSH
                'comment': 'Reported by CYBER-ROR automated defense system'
            }
            response = requests.post(url, headers=headers, data=data, timeout=10)
            if response.status_code == 200:
                logger.info("Reported IP to AbuseIPDB: " + ip)
                return True
            else:
                logger.warning("AbuseIPDB report failed for " + ip + ": " + str(response.status_code))
                return False
        except Exception as e:
            logger.error("Error reporting to AbuseIPDB: " + str(e))
            return False

    def _save_check_results(self, results):
        """Lagre sjekkresultater til fil"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = DATA_DIR / ("check_all_results_" + timestamp + ".json")
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info("Resultater lagret til " + str(result_file))
        except Exception as e:
            logger.error("Error saving results: " + str(e))

    def _check_all_complete(self, results):
        """Vis resultater etter fullfoert sjekk"""
        total = len(results)
        vt_found = sum(1 for r in results.values() if r.get('vt'))
        abuse_found = sum(1 for r in results.values() if r.get('abuse'))
        gn_found = sum(1 for r in results.values() if r.get('gn'))
        av_found = sum(1 for r in results.values() if r.get('av'))

        msg = "Sjekk fullfoert! " + str(total) + " IP-er sjekket. "
        msg += "VT: " + str(vt_found) + " treff, "
        msg += "AbuseIPDB: " + str(abuse_found) + " treff, "
        msg += "GreyNoise: " + str(gn_found) + " treff, "
        msg += "AlienVault: " + str(av_found) + " treff. "
        msg += "Results saved in data folder."

        messagebox.showinfo("Check completed", msg)
        self.load_blocked_ips()  # Refresh the list

    def show_blocked_context_menu(self, event):
        # Get the item under cursor
        item = self.blocked_tree.identify_row(event.y)
        if item:
            self.blocked_tree.selection_set(item)
            self.blocked_tree.focus(item)

        menu = tk.Menu(self.root, tearoff=0, bg='#0d1b2a', fg='#ffffff', 
                      activebackground='#1b263b', activeforeground='#ff6b35')
        menu.add_command(label="Copy IP", command=self.copy_selected_ip)
        menu.add_separator()
        menu.add_command(label="Send message", command=self.select_blocked_ip)
        menu.add_command(label="Add to whitelist", command=self.add_to_whitelist)
        menu.add_command(label="Remove block", command=self.unblock_selected)
        menu.post(event.x_root, event.y_root)

    def copy_selected_ip(self):
        """Copy selected IP to clipboard"""
        selected = self.blocked_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select an IP first (click an IP in the list)")
            return
        try:
            item = self.blocked_tree.item(selected[0])
            values = item.get('values', [])
            if not values or len(values) == 0:
                messagebox.showwarning("Warning", "No IP data found")
                return
            ip = values[0]
            ip_str = str(ip).strip()
            if not ip_str:
                messagebox.showwarning("Warning", "No IP selected")
                return

            # Method 1: Tkinter clipboard
            self.root.clipboard_clear()
            self.root.clipboard_append(ip_str)
            self.root.update()

            # Method 2: Windows clipboard via ctypes (correct implementation)
            try:
                import ctypes
                from ctypes import wintypes

                # ANSI encode the string
                text = ip_str.encode('mbcs') + b'\0'

                # Open clipboard
                if ctypes.windll.user32.OpenClipboard(None):
                    ctypes.windll.user32.EmptyClipboard()

                    # Allocate global memory
                    GHND = 0x0042  # GMEM_MOVEABLE | GMEM_ZEROINIT
                    h_global = ctypes.windll.kernel32.GlobalAlloc(GHND, len(text))
                    if h_global:
                        # Lock and copy data
                        ptr = ctypes.windll.kernel32.GlobalLock(h_global)
                        if ptr:
                            ctypes.memmove(ptr, text, len(text))
                            ctypes.windll.kernel32.GlobalUnlock(h_global)
                        # Set clipboard data (CF_TEXT = 1)
                        ctypes.windll.user32.SetClipboardData(1, h_global)
                    ctypes.windll.user32.CloseClipboard()
            except Exception as e2:
                logger.warning("ctypes clipboard feil: " + str(e2))

            logger.info("IP kopiert: " + ip_str)
            messagebox.showinfo("Copied", "IP " + ip_str + " copied to clipboard!")

        except Exception as e:
            logger.error("Error copying IP: " + str(e))
            messagebox.showerror("Error", "Could not copy IP: " + str(e))

    def select_blocked_ip(self):
        selected = self.blocked_tree.selection()
        if selected:
            ip = self.blocked_tree.item(selected[0])['values'][0]
            self.msg_ip_entry.delete(0, tk.END)
            self.msg_ip_entry.insert(0, ip)
            self.msg_status.config(text="Selected IP: " + ip, fg='#00ff88')

    def unblock_selected(self):
        selected = self.blocked_tree.selection()
        if selected:
            ip = self.blocked_tree.item(selected[0])['values'][0]
            self.ip_blocker.unblock_ip(ip)
            self.load_blocked_ips()

    def log_event(self, ip, event_type, details=None):
        logger.info("Event: " + event_type + " from " + ip)

    def handle_incoming_reply(self, ip, message_type, data):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if ip not in self.ip_blocker.blocked_ips:
            return
        auto_reply = ""
        if hasattr(self, 'auto_reply_var') and self.auto_reply_var.get():
            reply_msg = self.auto_reply_msg.get()
            try:
                self.message_server.send_message(ip, reply_msg, "icmp")
                auto_reply = "Auto-reply sent"
            except Exception as e:
                auto_reply = "Auto-reply failed: " + str(e)
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
            logger.error("Error saving reply: " + str(e))
        self.root.after(0, lambda: self._add_reply_to_tree(reply_entry))
        logger.info("Incoming reply from " + ip + " (" + message_type + ")")

    def _add_reply_to_tree(self, entry):
        self.replies_tree.insert('', 0, values=(
            entry['timestamp'],
            entry['ip'],
            entry['type'],
            entry['data'][:50] + "..." if len(entry['data']) > 50 else entry['data'],
            entry['auto_reply']
        ))
        self.replies_status.config(text="New reply received!", fg='#00ff88')

    def on_closing(self):
        """Handle window closing - stop servers and save data"""
        try:
            self.message_server.stop()
            logger.info("CYBER-ROR GUI terminated")
        except Exception as e:
            logger.error("Error during shutdown: " + str(e))
        self.root.destroy()


def main():
    root = tk.Tk()
    app = CyberRorGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
