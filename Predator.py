import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time
import hashlib
import json
import psutil
import winsound
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import math
import sys
import subprocess
import sqlite3
import queue  
import yara
import winreg # Windows Kayıt Defteri (Registry) işlemleri için
import re
# --- ÇEVRİMDIŞI CİHAZ MARKALARI (MAC OUI) VERİTABANI ---
# Bu liste cihazların MAC adreslerinin ilk kısımlarına göre markalarını tanır.
# --- ÇEVRİMDIŞI CİHAZ MARKALARI (GENİŞLETİLMİŞ) ---
MAC_VENDORS = {
    "00-14-22": "Dell", "f8-ff-c2": "Apple", "60-f8-1d": "Apple", "cc-b8-a8": "Apple",
    "14-5a-05": "Apple", "bc-6c-21": "Apple", "e0-d4-64": "Samsung", "48-8d-36": "Samsung", 
    "00-1a-11": "Google", "00-50-56": "VMware", "08-00-27": "VirtualBox", 
    "b8-27-eb": "Raspberry Pi", "00-1e-10": "Cisco", "00-1a-2b": "Intel", 
    "18-c0-4d": "TP-Link", "c0-4a-00": "TP-Link", "d8-07-b6": "Asus", 
    "00-e0-4c": "Realtek (Genel PC)", "00-0e-c6": "Huawei", "00-25-df": "Airties", 
    "8c-59-73": "Airties", "48-f8-b3": "Airties", "00-a0-c5": "Zyxel", 
    "c8-6c-87": "Zyxel", "00-11-7a": "Vestel", "00-24-1d": "GIGABYTE", "b0-6e-bf": "Xiaomi"
}
# --- BİLDİRİM KÜTÜPHANESİ KONTROLÜ ---
try:
    from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False
    print("Sistem Uyarısı: 'win10toast' kütüphanesi bulunamadı. Windows bildirimleri kapalı.")

# --- SİSTEM AYARLARI ---
if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))

QUARANTINE_DIR = "Karantina_Merkezi"
LOG_DIR = "Tarama_Raporlari"
for folder in [QUARANTINE_DIR, LOG_DIR]:
    os.makedirs(folder, exist_ok=True)

# Görsel Stil Ayarları
BG_COLOR = "#2A3136"
SIDEBAR_COLOR = "#202529"
CARD_BG_COLOR = "#343B42"
TEXT_COLOR = "#D4D5D7"
ACCENT_COLOR = "#4DE7E9"
TITLE_COLOR = "#FFFFFF"

# --- BEYAZ & KARA LİSTELER ---
BLACK_LIST_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 
    "84c82835a5d21bbcf75a61706d8ab549",                                
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c", 
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745", 
    "1f2f01f2bc676dbbf93a30eb6a0a0fb0edfae78742bca1c3b1e3e78a2e1d71cb", 
    "d87e0ce3e9702ba0eb84ed57657d7b2a65b38edb37cb337d1217734bd48b488d", 
    "5b20677a28e579ed1e8f8553e198b9e6fbc1970b1fb1ea0a69a9bbaefc7edb2e", 
    "21ea5c43d2c9cf0e872951f224fa93433a1e4ba61b17a15deec1a392deec9483", 
    "1f2e1430030089a80e6080330026e6fb",                                
    "c5e933e144a99138ce3dc302b21b72e50cf604084f09d8fc6f54c935ee5c0eb7"  
]

SAFE_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp", ".heic", ".raw", ".stl", ".obj",
    ".mp4", ".mp3", ".wav", ".avi", ".mkv", ".mov", ".flac", ".m4a", ".aac",
    ".ttf", ".otf", ".woff", ".woff2",
    ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg", ".md", ".yaml", ".css"
]

TRUSTED_COMPANIES = [
    "microsoft corporation", "google llc", "google inc", "adobe systems",
    "adobe inc", "oracle corporation", "mozilla corporation", "mozilla foundation",
    "apple inc", "intel corporation", "advanced micro devices", "nvidia corporation",
    "valve corporation", "cisco systems"
]

SUSPICIOUS_PROCESS_NAMES = [
    "powershell.exe", "cmd.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", 
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "wmic.exe", "bitsadmin.exe", 
    "vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "schtasks.exe", "net.exe", "net1.exe", 
    "mimikatz.exe", "psexec.exe", "nc.exe", "netcat.exe" 
]

# --- YARA KURALLARI (TAM DONANIMLI) ---
YARA_KURALLARI_METNİ = """
rule Suspicious_PowerShell_Payload {
    strings:
        $s1 = "Invoke-Expression" ascii wide nocase
        $s2 = "Net.WebClient" ascii wide nocase
        $s3 = "DownloadString" ascii wide nocase
        $s4 = "-WindowStyle Hidden" ascii wide nocase
    condition: 2 of them
}

rule Ransomware_Note_Detected {
    strings:
        $r1 = "All your files have been encrypted" ascii wide nocase
        $r2 = "pay the ransom" ascii wide nocase
        $r3 = "bitcoin" ascii wide nocase
    condition: 2 of them
}

rule Suspicious_Keylogger_APIs {
    meta:
        description = "Klavye kancasi yakalayici"
    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "SetWindowsHookEx" ascii wide
        $api3 = "GetKeyboardState" ascii wide
        $api4 = "CallNextHookEx" ascii wide
    condition: 2 of them
}

rule Reverse_Shell_And_Backdoor {
    meta:
        description = "Olası Truva Atı (RAT)"
    strings:
        $net1 = "WSAStartup" ascii wide
        $net2 = "WSASocketA" ascii wide
        $net3 = "gethostbyname" ascii wide
        $cmd = "cmd.exe" ascii wide
    condition: ($cmd and 2 of ($net*))
}

rule Memory_Injection_Process_Hollowing {
    meta:
        description = "Virüsün kendini temiz bir programa enjekte etmesi"
    strings:
        $inj1 = "VirtualAllocEx" ascii wide
        $inj2 = "WriteProcessMemory" ascii wide
        $inj3 = "CreateRemoteThread" ascii wide
        $inj4 = "NtUnmapViewOfSection" ascii wide
    condition: 3 of them
}
"""

# --- ÇOKLU DİL (BILINGUAL) SÖZLÜĞÜ ---
TRANSLATIONS = {
    "tr": {
        "app_title": "PREDATOR XDR - ENTERPRISE SÜRÜMÜ",
        "status": "Durum",
        "security": "Güvenlik",
        "settings": "Ayarlar",
        "dashboard_title": "SİSTEM GÖSTERGE PANELİ",
        "total_threats": "Engellenen Tehditler",
        "cpu_usage": "CPU Kullanımı",
        "ram_usage": "RAM Kullanımı",
        "settings_title": "PREDATOR AYARLARI",
        "lang_select": "Uygulama Dili (Language):",
        "version": "Tarama Motoru Sürümü: v2.5.0 (Kurumsal YBS Sürümü)",
        "clear_db": "Veritabanı Loglarını Temizle",
        "sys_protected": "● SİSTEM KORUNUYOR",
        "full_scan_prog": "● TAM TARAMA DEVAM EDİYOR",
        "file_scan": "Dosya Taraması",
        "file_scan_desc": "Tek bir dosyayı analiz et",
        "folder_scan": "Klasör Taraması",
        "folder_scan_desc": "Belirli bir klasörü tara",
        "full_scan": "Tam Tarama",
        "full_scan_desc": "Derin sistem taraması",
        "quarantine": "Karantina",
        "quarantine_desc": "İzole edilenleri yönet",
        "analytics": "Analiz",
        "analytics_desc": "Güvenlik metrikleri",
        "persistence": "Kalıcılık",
        "persistence_desc": "Başlangıç ve Kayıt Defteri",
        "pc_boost": "PC Hızlandır",
        "pc_boost_desc": "Temel sistem optimizasyonu",
        "net_monitor": "Ağ İzleyici",
        "net_monitor_desc": "TCP/UDP trafik analizi",
        "warn_title": "Uyarı",
        "clear_db_msg": "Tüm tehdit geçmişi logları kalıcı olarak silinecek. Devam edilsin mi?",
        "success_title": "Başarılı",
        "db_cleared_msg": "Veritabanı başarıyla temizlendi.",
        "threat_alert_title": "🛡️ KRİTİK TEHDİT",
        "threat_alert_msg": "Zararlı yazılım tespit edildi:\n{file}",
        "quarantine_prompt": "{count} tehdit karantinaya taşınsın mı?",
        "net_active_conn": "Aktif Ağ Bağlantıları (Kurulu Oturumlar)",
        "net_app": "Uygulama",
        "net_local": "Yerel Adres",
        "net_remote": "Hedef (Uzak)",
        "net_status": "Durum",
        "no_data": "Henüz tehdit verisi kaydedilmedi.\nAnalizleri görmek için sisteminizi tarayın.",
        "history_title": "Tehdit Tespit Geçmişi",
        "risk_score": "Risk Skoru",
        "report_title": "PredatorXDR Sistem Analiz Raporu",
        "report_date": "Tarama Tarihi:",
        "report_status": "Durum:",
        "report_detected": "{count} Kritik Tehdit Tespit Edildi!",
        "report_path": "Zararlı Dosya Yolu",
        "report_type": "Tehdit Türü",
        "boost_alert": "Sistem optimize edildi.\nKazanılan Alan: {mb:.2f} MB",
        "log_scan_start": "Tarama başlatıldı: {file}",
        "log_scan_clean": "Tarama temiz. Tehdit bulunamadı.",
        "full_scan_prompt": "Sistem şu sürücüleri tarayacak: {drives}\nDevam edilsin mi?",
        "log_scan_complete": "Tarama tamamlandı. {count} dosya kontrol edildi. {threats} tehdit bulundu.",
        "log_quarantine_done": "İzolasyon tamamlandı. Tehditler Karantinaya taşındı.",
        "log_net_scan_done": "✅ Ağ taraması tamamlandı. {count} bağlantı listelendi.",
        "log_net_start": "🌐 Ağ izleme modülü başlatılıyor...",
        "log_boost_start": "🚀 Sistem optimizasyonu başlatılıyor...",
        "behavior_alert_title": "⚠️ DAVRANIŞSAL ALARM",
        "behavior_alert_msg": "Şüpheli işlem başlatıldı: {process}"
    },
    "en": {
        "app_title": "PREDATOR XDR - ENTERPRISE EDITION",
        "status": "Status",
        "security": "Security",
        "settings": "Settings",
        "dashboard_title": "SYSTEM DASHBOARD",
        "total_threats": "Total Threats Blocked",
        "cpu_usage": "CPU Usage",
        "ram_usage": "RAM Usage",
        "settings_title": "PREDATOR SETTINGS",
        "lang_select": "Application Language:",
        "version": "Scan Engine Version: v2.5.0 (Enterprise YBS Edition)",
        "clear_db": "Clear Database Logs",
        "sys_protected": "● SYSTEM PROTECTED",
        "full_scan_prog": "● FULL SCAN IN PROGRESS",
        "file_scan": "File Scan",
        "file_scan_desc": "Scan a single file",
        "folder_scan": "Folder Scan",
        "folder_scan_desc": "Scan specific folder",
        "full_scan": "Full Scan",
        "full_scan_desc": "Deep system scan",
        "quarantine": "Quarantine",
        "quarantine_desc": "Manage isolated threats",
        "analytics": "Analytics",
        "analytics_desc": "Security metrics",
        "persistence": "Persistence",
        "persistence_desc": "Startup & Registry",
        "pc_boost": "PC Boost",
        "pc_boost_desc": "Basic system optimization",
        "net_monitor": "Network Monitor",
        "net_monitor_desc": "TCP/UDP traffic analysis",
        "warn_title": "Warning",
        "clear_db_msg": "All threat history logs will be permanently deleted. Proceed?",
        "success_title": "Success",
        "db_cleared_msg": "Database cleared successfully.",
        "threat_alert_title": "🛡️ CRITICAL THREAT",
        "threat_alert_msg": "Malware detected:\n{file}",
        "quarantine_prompt": "Move {count} threats to quarantine?",
        "net_active_conn": "Active Network Connections (Established)",
        "net_app": "Application",
        "net_local": "Local Address",
        "net_remote": "Remote Address",
        "net_status": "Status",
        "no_data": "No threat data recorded yet.\nScan your system to see analytics.",
        "history_title": "Threat Detection History",
        "risk_score": "Risk Score",
        "report_title": "PredatorXDR System Analysis Report",
        "report_date": "Scan Date:",
        "report_status": "Status:",
        "report_detected": "{count} Critical Threats Detected!",
        "report_path": "Malicious File Path",
        "report_type": "Threat Type",
        "boost_alert": "System optimized.\nFreed Space: {mb:.2f} MB",
        "log_scan_start": "File analysis started: {file}",
        "log_scan_clean": "Scan clean: No threats found.",
        "full_scan_prompt": "System will scan: {drives}\nProceed?",
        "log_scan_complete": "Scan complete. {count} files checked. {threats} threats found.",
        "log_quarantine_done": "Isolation complete. Threats moved to Quarantine.",
        "log_net_scan_done": "✅ Network scan complete. {count} connections listed.",
        "log_net_start": "🌐 Starting network monitor module...",
        "log_boost_start": "🚀 Starting system optimization...",
        "behavior_alert_title": "⚠️ BEHAVIORAL ALERT",
        "behavior_alert_msg": "Suspicious process started: {process}"
    }
}

# --- VERİTABANI BAŞLATMA ---
def init_db():
    try:
        conn = sqlite3.connect("predator_data.db", check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS threat_logs 
                          (id INTEGER PRIMARY KEY, date TEXT, path TEXT, type TEXT, score INTEGER)''')
        conn.commit()
        return conn
    except Exception as e:
        print(f"Veritabanı hatası: {e}")
        return None

class PredatorXDR:
    def __init__(self, root):
        self.root = root
        self.current_lang = "tr" 
        self.root.title(self.t("app_title"))
        self.root.geometry("1150x800")
        self.root.configure(bg=BG_COLOR)
        
        self.db_conn = init_db() 
        self.stop_scan = False
        self.found_threats = []
        self.current_view_name = "Security"
        
        try:
            self.yara_motoru = yara.compile(source=YARA_KURALLARI_METNİ)
        except Exception as e:
            print(f"YARA Derleme Hatası: {e}")
            self.yara_motoru = None
            
        self.log_queue = queue.Queue()
        self.toaster = ToastNotifier() if TOAST_AVAILABLE else None
        
        self.setup_ui()
        self.process_log_queue()
        threading.Thread(target=self.live_behavior_monitor, daemon=True).start()

    def t(self, key):
        return TRANSLATIONS[self.current_lang].get(key, key)

    def setup_ui(self):
        self.sidebar_frame = tk.Frame(self.root, bg=SIDEBAR_COLOR, width=200)
        self.sidebar_frame.pack(side="left", fill="y")
        
        self.main_area = tk.Frame(self.root, bg=BG_COLOR)
        self.main_area.pack(side="right", fill="both", expand=True)
        
        self.setup_sidebar()
        self.show_view(self.current_view_name)

    def setup_sidebar(self):
        for w in self.sidebar_frame.winfo_children(): w.destroy()
        tk.Label(self.sidebar_frame, text="PREDATOR", fg=ACCENT_COLOR, bg=SIDEBAR_COLOR, font=("Orbitron", 18, "bold")).pack(pady=30)

        self.create_side_btn(self.sidebar_frame, "📈", self.t("status"), lambda: self.show_view("Status"), self.current_view_name == "Status")
        self.create_side_btn(self.sidebar_frame, "🛡️", self.t("security"), lambda: self.show_view("Security"), self.current_view_name == "Security")
        self.create_side_btn(self.sidebar_frame, "⚙️", self.t("settings"), lambda: self.show_view("Settings"), self.current_view_name == "Settings")

    def create_side_btn(self, parent, icon, text, cmd, active=False):
        btn = tk.Button(parent, text=f"{icon}  {text}", bg=SIDEBAR_COLOR, fg=TITLE_COLOR if active else TEXT_COLOR, 
                        font=("Segoe UI", 10), bd=0, padx=25, pady=10, anchor="w", relief="flat", command=cmd, 
                        activebackground=CARD_BG_COLOR, activeforeground=ACCENT_COLOR)
        btn.pack(fill="x")

    def show_view(self, view_name):
        self.current_view_name = view_name
        self.setup_sidebar() 
        for w in self.main_area.winfo_children(): w.destroy()
        
        if view_name == "Security": self.setup_security_grid()
        elif view_name == "Status": self.setup_status_view()
        elif view_name == "Settings": self.setup_settings_view()

    # --- STATUS VE SETTINGS ---
    def setup_status_view(self):
        container = tk.Frame(self.main_area, bg=BG_COLOR)
        container.pack(expand=True, fill="both", padx=40, pady=20)
        
        # --- BAŞLIK ---
        tk.Label(container, text=self.t("dashboard_title"), fg=TITLE_COLOR, bg=BG_COLOR, font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 20))
        
        # --- 1. BÖLÜM: TEMEL METRİKLER (4'LÜ KART) ---
        stats_frame = tk.Frame(container, bg=BG_COLOR)
        stats_frame.pack(fill="x")
        
        # Veritabanı sorguları (Son tehdit ve toplam tehdit)
        total_threats = 0
        last_threat_date = "Sistem Temiz"
        if self.db_conn:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM threat_logs")
            res = cursor.fetchone()
            total_threats = res[0] if res else 0
            
            cursor.execute("SELECT date FROM threat_logs ORDER BY id DESC LIMIT 1")
            res2 = cursor.fetchone()
            last_threat_date = res2[0] if res2 else "Tehdit Bulunamadı"

        cpu_val = psutil.cpu_percent()
        ram_val = psutil.virtual_memory().percent
        
        # Disk kullanımını hesapla (C: sürücüsü)
        try:
            disk_val = psutil.disk_usage(os.path.abspath(os.sep)).percent
        except:
            disk_val = 0

        self.create_dashboard_item(stats_frame, self.t("total_threats"), str(total_threats), "#ff3333")
        self.create_dashboard_item(stats_frame, self.t("cpu_usage"), f"%{cpu_val}", ACCENT_COLOR)
        self.create_dashboard_item(stats_frame, self.t("ram_usage"), f"%{ram_val}", ACCENT_COLOR)
        # Disk kırmızıya dönsün eğer %85'ten fazlaysa
        disk_color = "#ff3333" if disk_val > 85 else ACCENT_COLOR
        self.create_dashboard_item(stats_frame, "Disk Kullanımı", f"%{disk_val}", disk_color)

        # --- 2. BÖLÜM: DİNAMİK SAĞLIK VE DURUM KARTLARI ---
        info_frame = tk.Frame(container, bg=BG_COLOR)
        info_frame.pack(fill="x", pady=20)

        # Sistem Sağlık Mantığı
        if cpu_val < 75 and ram_val < 80:
            health_text = "SİSTEM STABİL VE GÜVENDE"
            health_color = "#00ff00"
        else:
            health_text = "YÜKSEK KAYNAK KULLANIMI"
            health_color = "#ffcc00"

        # Sol Kart: Sağlık
        health_card = tk.Frame(info_frame, bg=CARD_BG_COLOR, padx=20, pady=15)
        health_card.pack(side="left", fill="x", expand=True, padx=(10, 5))
        tk.Label(health_card, text="Genel Sağlık Durumu", fg=TEXT_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 10)).pack(anchor="w")
        tk.Label(health_card, text=health_text, fg=health_color, bg=CARD_BG_COLOR, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(5,0))

        # Sağ Kart: Son Tehdit
        db_card = tk.Frame(info_frame, bg=CARD_BG_COLOR, padx=20, pady=15)
        db_card.pack(side="right", fill="x", expand=True, padx=(5, 10))
        tk.Label(db_card, text="Son Tespit Edilen Tehdit Zamanı", fg=TEXT_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 10)).pack(anchor="w")
        tk.Label(db_card, text=last_threat_date, fg=TITLE_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(5,0))

        # --- 3. BÖLÜM: SİSTEM BİLGİ ÖZETİ ---
        sys_frame = tk.Frame(container, bg=CARD_BG_COLOR, padx=20, pady=20)
        sys_frame.pack(fill="both", expand=True, padx=10)

        tk.Label(sys_frame, text="XDR Operasyonel Bilgiler", fg=TITLE_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(0, 10))

        # Boot time (Sistemin ne zamandır açık olduğu)
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
        
        info_text = (
            f"🟢 Aktif Analiz Motorları : YARA İmza Motoru, Heuristic PE Analizi, Entropi Ölçümü\n\n"
            f"🟢 Ağ Dinleme Durumu     : TCP/UDP ve ARP Protokolleri İzleniyor\n\n"
            f"🟢 Arka Plan Koruması    : Process İzleyici (Davranışsal Analiz) Aktif\n\n"
            f"⏱️ Sistem Açılış Zamanı    : {boot_time}"
        )
        tk.Label(sys_frame, text=info_text, fg=TEXT_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 10), justify="left", spacing3=5).pack(anchor="w")

    def create_dashboard_item(self, parent, label, value, color):
        card = tk.Frame(parent, bg=CARD_BG_COLOR, padx=20, pady=20)
        card.pack(side="left", padx=10, expand=True, fill="x")
        tk.Label(card, text=label, fg=TEXT_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 10)).pack()
        tk.Label(card, text=value, fg=color, bg=CARD_BG_COLOR, font=("Segoe UI", 18, "bold")).pack(pady=(5,0))

    def setup_settings_view(self):
        container = tk.Frame(self.main_area, bg=BG_COLOR)
        container.pack(expand=True, fill="both", padx=40, pady=20)
        
        tk.Label(container, text=self.t("settings_title"), fg=TITLE_COLOR, bg=BG_COLOR, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(container, text=self.t("version"), fg=TEXT_COLOR, bg=BG_COLOR).pack(anchor="w", pady=10)
        
        tk.Label(container, text=self.t("lang_select"), fg=TEXT_COLOR, bg=BG_COLOR, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(20, 5))
        self.lang_var = tk.StringVar(value="Türkçe" if self.current_lang == "tr" else "English")
        lang_dropdown = ttk.Combobox(container, textvariable=self.lang_var, values=["Türkçe", "English"], state="readonly", width=20)
        lang_dropdown.pack(anchor="w", pady=5)
        lang_dropdown.bind("<<ComboboxSelected>>", self.change_language)
        
        tk.Button(container, text=self.t("clear_db"), bg="#ff3333", fg="white", bd=0, padx=20, pady=10, 
                  font=("Segoe UI", 10, "bold"), cursor="hand2", command=self.clear_db_action).pack(anchor="w", pady=30)

    def change_language(self, event=None):
        selected = self.lang_var.get()
        new_lang = "tr" if selected == "Türkçe" else "en"
        if new_lang != self.current_lang:
            self.current_lang = new_lang
            self.root.title(self.t("app_title"))
            self.show_view("Settings") 

    def clear_db_action(self):
        if messagebox.askyesno(self.t("warn_title"), self.t("clear_db_msg")):
            if self.db_conn:
                cursor = self.db_conn.cursor()
                cursor.execute("DELETE FROM threat_logs")
                self.db_conn.commit()
                messagebox.showinfo(self.t("success_title"), self.t("db_cleared_msg"))
                self.show_view("Settings") 

    # --- SECURITY (ANA EKRAN) ---
    def setup_security_grid(self):
        container = tk.Frame(self.main_area, bg=BG_COLOR)
        container.pack(expand=True, fill="both", padx=40, pady=20)
        
        header = tk.Frame(container, bg=BG_COLOR)
        header.pack(fill="x", pady=(0, 20))
        self.status_lbl = tk.Label(header, text=self.t("sys_protected"), fg="#00ff00", bg=BG_COLOR, font=("Segoe UI", 12, "bold"))
        self.status_lbl.pack(side="left")

        grid_f = tk.Frame(container, bg=BG_COLOR)
        grid_f.pack(fill="both", expand=True)
        for i in range(3): grid_f.columnconfigure(i, weight=1)

        cards = [
            ("📄", self.t("file_scan"), self.t("file_scan_desc"), self.start_file_scan_thread),
            ("📁", self.t("folder_scan"), self.t("folder_scan_desc"), self.start_folder_scan_thread),
            ("☢", self.t("full_scan"), self.t("full_scan_desc"), self.start_full_scan_thread),
            ("🔏", self.t("quarantine"), self.t("quarantine_desc"), lambda: os.startfile(QUARANTINE_DIR)),
            ("📊", self.t("analytics"), self.t("analytics_desc"), self.show_analytics),
            ("🧱", self.t("persistence"), self.t("persistence_desc"), self.check_persistence),
            ("🚀", self.t("pc_boost"), self.t("pc_boost_desc"), self.run_pc_boost),
            ("🌐", self.t("net_monitor"), self.t("net_monitor_desc"), self.show_network_monitor),
        ]

        for i, (icon, title, desc, cmd) in enumerate(cards):
            row, col = i // 3, i % 3
            self.create_card(grid_f, row, col, icon, title, desc, cmd)

        self.terminal = tk.Text(container, bg="#1E2326", fg="#00ff00", font=("Consolas", 9), height=12, bd=0, padx=10, pady=10)
        self.terminal.pack(fill="x", pady=(20, 0))
        self.terminal.tag_config("critical", foreground="#ff3333", font=("Consolas", 9, "bold"))
        self.progress = ttk.Progressbar(self.main_area, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", side="bottom")

    def create_card(self, parent, r, c, icon, title, desc, cmd):
        card = tk.Frame(parent, bg=CARD_BG_COLOR, cursor="hand2")
        card.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")
        lbl_icon = tk.Label(card, text=icon, fg=ACCENT_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 24))
        lbl_icon.pack(pady=(15, 0))
        lbl_title = tk.Label(card, text=title, fg=TITLE_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 11, "bold"))
        lbl_title.pack()
        lbl_desc = tk.Label(card, text=desc, fg=TEXT_COLOR, bg=CARD_BG_COLOR, font=("Segoe UI", 8))
        lbl_desc.pack(pady=(0, 15))
        for widget in (card, lbl_icon, lbl_title, lbl_desc):
            widget.bind("<Button-1>", lambda e: cmd())

    # --- TARAMA MODÜLLERİ ---
    def start_file_scan_thread(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.stop_scan = False
            self.terminal.delete(1.0, tk.END)
            log_msg = self.t("log_scan_start").replace("{file}", os.path.basename(file_path))
            self.log(log_msg, "sys")
            threading.Thread(target=self.run_single_file_scan, args=(file_path,), daemon=True).start()

    def run_single_file_scan(self, path):
        self.root.after(0, lambda: self.progress.config(mode="indeterminate"))
        self.root.after(0, lambda: self.progress.start())
        res = self.analyze_file(path)
        self.root.after(0, lambda: self.progress.stop())
        self.root.after(0, lambda: self.progress.config(mode="determinate", value=100))
        
        if res:
            self.found_threats.append(res) 
            if self.found_threats: 
                self.generate_html_report()
                self.root.after(2000, self.cleanup)
            self.log(f"ALERT: {res['type']} detected in {os.path.basename(path)}", "critical")
            self.play_alert_sound()
            msg = self.t("threat_alert_msg").replace("{file}", os.path.basename(res['path']))
            self.show_windows_alert(self.t("threat_alert_title"), msg)
        else:
            self.log(self.t("log_scan_clean"), "sys")

    def start_folder_scan_thread(self):
        target = filedialog.askdirectory()
        if target:
            self.stop_scan = False
            self.found_threats = []
            self.terminal.delete(1.0, tk.END)
            threading.Thread(target=self.run_scanner, args=(target,), daemon=True).start()

    def start_full_scan_thread(self):
        drives = [p.mountpoint for p in psutil.disk_partitions() if 'fixed' in p.opts]
        prompt_msg = self.t("full_scan_prompt").replace("{drives}", str(drives))
        confirm = messagebox.askyesno(self.t("full_scan"), prompt_msg)
        if confirm:
            self.stop_scan = False
            self.found_threats = []
            self.terminal.delete(1.0, tk.END)
            self.status_lbl.config(text=self.t("full_scan_prog"), fg="#ffcc00")
            threading.Thread(target=lambda: [self.run_scanner(d) for d in drives], daemon=True).start()

    def run_scanner(self, target):
        self.log(f"Scanning directory: {target}", "sys")
        def file_generator():
            for r, _, fls in os.walk(target):
                for f in fls:
                    yield os.path.join(r, f)

        self.root.after(0, lambda: self.progress.config(mode="indeterminate"))
        self.root.after(0, lambda: self.progress.start())
        
        scanned_count = 0
        with ThreadPoolExecutor(max_workers=4) as ex:
            for res in ex.map(self.analyze_file, file_generator()):
                if self.stop_scan: break
                scanned_count += 1
                if res:
                    self.found_threats.append(res)
                    self.log(f"THREAT: {os.path.basename(res['path'])}", "critical")
                    self.play_alert_sound()
                    msg = self.t("threat_alert_msg").replace("{file}", os.path.basename(res['path']))
                    self.show_windows_alert(self.t("threat_alert_title"), msg)
                if scanned_count % 50 == 0:
                    self.root.update_idletasks()

        self.root.after(0, lambda: self.progress.stop())
        self.root.after(0, lambda: self.progress.config(mode="determinate", value=100))

        if not self.stop_scan:
            self.root.after(0, lambda: self.status_lbl.config(text=self.t("sys_protected"), fg="#00ff00"))
            log_msg = self.t("log_scan_complete").replace("{count}", str(scanned_count)).replace("{threats}", str(len(self.found_threats)))
            self.log(log_msg, "sys")
            if self.found_threats: 
                self.generate_html_report()
                self.root.after(2000, self.cleanup)

    # --- CORE ANALİZ VE VERİTABANI ---
    def save_threat_to_db(self, threat):
        if not self.db_conn: return
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("INSERT INTO threat_logs (date, path, type, score) VALUES (?, ?, ?, ?)",
                           (datetime.now().strftime("%Y-%m-%d %H:%M"), threat['path'], threat['type'], threat['score']))
            self.db_conn.commit()
        except Exception as e:
            self.log(f"DB Error: {e}", "sys")

    def analyze_file(self, path):
        if self.stop_scan: 
            return None 
        
        try:
            if any(path.lower().endswith(ext) for ext in SAFE_EXTENSIONS): 
                return None
            
            lower_path = path.lower()
            if "c:\\windows\\" in lower_path or "program files" in lower_path:
                return None

            f_hash = self.get_file_hash(path)
            if f_hash in BLACK_LIST_HASHES:
                threat = {"path": path, "score": 100, "type": "Malware.HashMatch"}
                self.save_threat_to_db(threat)
                return threat

            score = 0
            
            # --- UZANTI GİZLEME (SPOOFING) KONTROLÜ ---
            try:
                with open(path, "rb") as f:
                    header = f.read(2)
                    if header == b"MZ": 
                        if not path.lower().endswith((".exe", ".dll", ".sys", ".scr", ".bat", ".cmd")):
                            score += 85
                            self.log(f"SPOOFING UYARISI: Sahte uzantı tespit edildi! -> {path}", "critical")
            except:
                pass

            # --- PE ANALİZİ & PACKER KONTROLÜ ---
            try:
                import pefile
                pe = pefile.PE(path, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
                ])
                
                if hasattr(pe, 'FileInfo'):
                    for file_info_list in pe.FileInfo:
                        for file_info in file_info_list:
                            if hasattr(file_info, 'StringTable'):
                                for st in file_info.StringTable:
                                    for key, value in st.entries.items():
                                        if key == b'CompanyName':
                                            company_name = value.decode('utf-8', 'ignore').lower()
                                            if any(trusted in company_name for trusted in TRUSTED_COMPANIES):
                                                return None 
                
                if hasattr(pe, 'sections'):
                    for section in pe.sections:
                        sec_name = section.Name.replace(b'\x00', b'').decode('utf-8', 'ignore').lower()
                        if "upx" in sec_name or "aspack" in sec_name or "mpx" in sec_name or "themida" in sec_name:
                            score += 45
                            self.log(f"PACKER UYARISI: Gizlenmiş kod yapısı (Packer) tespit edildi!", "critical")

                suspicious_imports = [b"wininet.dll", b"wsock32.dll", b"advapi32.dll", b"urlmon.dll"]
                keylogger_apis = [b"getasynckeystate", b"setwindowshookexa", b"setwindowshookexw", b"getkeyboardstate", b"callnexthookex"]
                
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.lower() if entry.dll else b""
                        if dll_name in suspicious_imports:
                            score += 30
                        if dll_name == b"user32.dll":
                            for imp in entry.imports:
                                api_name = imp.name.lower() if imp.name else b""
                                if api_name in keylogger_apis:
                                    score += 40 
            except:
                pass 

            # --- ENTROPİ KONTROLÜ ---
            try:
                with open(path, "rb") as f:
                    content = f.read(1024 * 1024 * 2) 
                    if content:
                        entropy = -sum(p * math.log2(p) for p in (content.count(i)/len(content) for i in set(content)) if p > 0)
                        if entropy > 7.65: 
                            score += 35
            except:
                pass

            if score >= 65:
                threat_type = "Heuristic.Suspicious.Keylogger" if score >= 70 else "Heuristic.Suspicious"
                threat = {"path": path, "score": min(score, 100), "type": threat_type}
                self.save_threat_to_db(threat)
                return threat

            # --- YARA MOTORU ---
            try:
                if self.yara_motoru:
                    eslesmeler = self.yara_motoru.match(path)
                    if eslesmeler:
                        eslesen_kural = eslesmeler[0].rule
                        threat = {"path": path, "score": 95, "type": f"Yara.Match.{eslesen_kural}"}
                        self.save_threat_to_db(threat)
                        return threat
            except Exception as e:
                pass
            
            return None
        except Exception as e:
            return None

    # --- LOG VE YARDIMCILAR ---
    def log(self, msg, tag="sys"):
        self.log_queue.put((msg, tag))
        try:
            log_file = os.path.join(LOG_DIR, f"Predator_Log_{datetime.now().strftime('%Y-%m-%d')}.txt")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        except: pass

    def process_log_queue(self):
        try:
            while True:
                msg, tag = self.log_queue.get_nowait()
                try:
                    self.terminal.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n", tag)
                    self.terminal.see(tk.END)
                except: pass
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_log_queue)

    def get_file_hash(self, path):
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""): sha.update(chunk)
            return sha.hexdigest()
        except: return None

    def play_alert_sound(self):
        try: winsound.PlaySound("SystemHand", winsound.SND_ALIAS)
        except: pass

    def show_windows_alert(self, title, message):
        if not TOAST_AVAILABLE or not self.toaster: return
        try: self.toaster.show_toast(title, message, icon_path=None, duration=5, threaded=True)
        except Exception as e: self.log(f"Bildirim Hatası: {e}", "sys")

    def check_persistence(self):
        self.log("Sistem Kalıcılık (Persistence) Noktaları Analiz Ediliyor...", "sys")
        
        # Zararlıların sıkça saklandığı şüpheli klasör yolları
        suspicious_paths = ["appdata\\roaming", "appdata\\local\\temp", "programdata", "users\\public"]
        # Başlangıçta çalışması şüpheli olan script uzantıları
        suspicious_extensions = [".bat", ".vbs", ".ps1", ".cmd", ".js"]
        
        anomalies_found = []
        
        # 1. KAYIT DEFTERİ (REGISTRY) ANOMALİ KONTROLÜ
        try:
            # HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            for i in range(1024):
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    val_lower = value.lower()
                    
                    is_suspicious = False
                    
                    # Yol kontrolü
                    if any(sp in val_lower for sp in suspicious_paths):
                        is_suspicious = True
                        
                    # Uzantı kontrolü
                    if any(val_lower.endswith(ext) or f"{ext} " in val_lower or f'"{ext}"' in val_lower for ext in suspicious_extensions):
                        is_suspicious = True
                        
                    if is_suspicious:
                        anomalies_found.append(f"Kayıt Defteri: {name}")
                        self.log(f"⚠️ ŞÜPHELİ BAŞLANGIÇ KAYDI: [{name}] -> {value}", "critical")
                    else:
                        # Temiz olanları sadece bilgi olarak basıyoruz
                        self.log(f"Güvenli Başlangıç Kaydı: {name}", "sys")
                except OSError:
                    break # Okunacak başka değer kalmadı
            winreg.CloseKey(key)
        except Exception as e:
            self.log(f"Kayıt defteri okunamadı (Yetki veya erişim hatası): {e}", "sys")

        try:
            self.log("Zamanlanmış görevler taranıyor...", "sys")
            
            task_cmd = 'schtasks /query /fo CSV'
            task_res = subprocess.run(task_cmd, capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
            
            for line in task_res.split('\n'):
                line_lower = line.lower()
                
                if "appdata" in line_lower or "temp\\" in line_lower or "powershell.exe" in line_lower:
                    
                    task_name = line.split(',')[0].replace('"', '')
                    if task_name and "TaskName" not in task_name:
                        anomalies_found.append(f"Zamanlanmış Görev: {task_name}")
                        self.log(f"⚠️ ŞÜPHELİ ZAMANLANMIŞ GÖREV: {task_name}", "critical")
        except Exception as e:
            pass

        # 3. SONUÇ VE BİLDİRİM EKRANI
        if anomalies_found:
            msg = f"Sistem başlangıcına gizlenmiş {len(anomalies_found)} şüpheli kayıt tespit edildi!\nTerminali (Log) inceleyin."
            self.show_windows_alert("⚠️ KALICILIK (PERSISTENCE) ALARMI", msg)
            self.log(f"Kalıcılık Analizi Tamamlandı: {len(anomalies_found)} TEHDİT BULUNDU!", "critical")
        else:
            self.log("✅ Kalıcılık denetimi temiz. Şüpheli başlangıç veya görev kaydı bulunamadı.", "sys")
            self.show_windows_alert("Güvenlik Denetimi", "Sistem başlangıcında şüpheli bir kayda rastlanmadı.")
        

    def run_pc_boost(self):
        self.log(self.t("log_boost_start"), "sys")
        threading.Thread(target=self._optimize_tasks, daemon=True).start()

    def _optimize_tasks(self):
        freed_space = 0
        temp_path = os.environ.get('TEMP')
        if temp_path:
            freed_space += self._clear_directory(temp_path)
        try: subprocess.run("ipconfig /flushdns", capture_output=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass
        local_app_data = os.environ.get('LOCALAPPDATA')
        if local_app_data:
            fivem_cache = os.path.join(local_app_data, "FiveM", "FiveM.app", "data", "cache")
            if os.path.exists(fivem_cache):
                freed_space += self._clear_directory(fivem_cache)
        freed_mb = freed_space / (1024 * 1024)
        msg = self.t("boost_alert").replace("{mb:.2f}", f"{freed_mb:.2f}")
        self.log(msg, "sys")
        self.show_windows_alert("🚀 PREDATOR XDR - BOOST", msg)

    def _clear_directory(self, folder_path):
        freed = 0
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    size = os.path.getsize(file_path)
                    os.remove(file_path)
                    freed += size
                except: pass 
        return freed        

    def show_analytics(self):
        win = tk.Toplevel(self.root)
        win.title(self.t("analytics"))
        win.geometry("1000x750") # 4 Grafik için pencereyi genişlettik
        win.configure(bg=BG_COLOR)

        if not self.db_conn:
            tk.Label(win, text="Database error.", fg=TEXT_COLOR, bg=BG_COLOR).pack(pady=50)
            return

        cursor = self.db_conn.cursor()

        # Verileri Çek
        cursor.execute("SELECT type, COUNT(*) FROM threat_logs GROUP BY type")
        type_data = cursor.fetchall()

        cursor.execute("SELECT date, score FROM threat_logs ORDER BY id DESC LIMIT 15")
        time_data = cursor.fetchall()
        
        cursor.execute("SELECT path, score FROM threat_logs")
        all_data = cursor.fetchall()

        if not all_data:
            empty_frame = tk.Frame(win, bg=BG_COLOR)
            empty_frame.pack(expand=True)
            tk.Label(empty_frame, text="📊", font=("Segoe UI", 48), fg=CARD_BG_COLOR, bg=BG_COLOR).pack()
            tk.Label(empty_frame, text=self.t("no_data"), fg=TEXT_COLOR, bg=BG_COLOR, font=("Segoe UI", 12)).pack(pady=10)
            return

        # --- DASHBOARD TASARIMI (4'LÜ GRID) ---
        fig = plt.figure(figsize=(12, 7), dpi=100)
        fig.patch.set_facecolor(BG_COLOR)

        # 1. SOL ÜST: TEHDİT TÜRÜ (DOUGHNUT)
        ax1 = plt.subplot(2, 2, 1) 
        types = [row[0].split('.')[-1] for row in type_data]
        counts = [row[1] for row in type_data]
        colors1 = ['#ff3333', '#ffcc00', '#4DE7E9', '#b366ff', '#ff6699']
        ax1.pie(counts, labels=types, autopct='%1.1f%%', startangle=90, 
                colors=colors1, textprops=dict(color=TEXT_COLOR, fontsize=8),
                wedgeprops=dict(width=0.4, edgecolor=BG_COLOR))
        ax1.set_title("Tehdit Türü Dağılımı", color=TITLE_COLOR, fontdict={'fontsize': 10, 'weight': 'bold'})

        # 2. SAĞ ÜST: RİSK ZAMAN ÇİZELGESİ (ALAN GRAFİĞİ)
        ax2 = plt.subplot(2, 2, 2)
        ax2.set_facecolor("#1E2326")
        dates = [row[0].split(" ")[1] for row in time_data][::-1] 
        scores = [row[1] for row in time_data][::-1]
        ax2.plot(dates, scores, color=ACCENT_COLOR, marker='o', linestyle='-', linewidth=2, markersize=5)
        ax2.fill_between(dates, scores, color=ACCENT_COLOR, alpha=0.1)
        ax2.set_title("Risk Skor Zaman Çizelgesi", color=TITLE_COLOR, fontdict={'fontsize': 10, 'weight': 'bold'})
        ax2.tick_params(axis='x', colors=TEXT_COLOR, labelsize=7, rotation=30)
        ax2.tick_params(axis='y', colors=TEXT_COLOR, labelsize=8)
        ax2.grid(color=BG_COLOR, linestyle='--', alpha=0.3)

        # 3. SOL ALT: HEDEFLENEN KONUMLAR (YATAY BAR GRAFİK)
        ax3 = plt.subplot(2, 2, 3)
        ax3.set_facecolor("#1E2326")
        from collections import Counter
        # Dosya yollarından en son klasör adını çekiyoruz (Örn: C:\...\Desktop\virus.exe -> Desktop)
        folders = [os.path.basename(os.path.dirname(row[0])) for row in all_data if os.path.dirname(row[0])]
        folder_counts = Counter(folders).most_common(5) # En çok virüs çıkan 5 klasör
        
        if folder_counts:
            f_names = [x[0] for x in folder_counts][::-1]
            f_vals = [x[1] for x in folder_counts][::-1]
            ax3.barh(f_names, f_vals, color='#ffcc00', height=0.5)
            ax3.set_title("En Çok Hedeflenen 5 Klasör", color=TITLE_COLOR, fontdict={'fontsize': 10, 'weight': 'bold'})
            ax3.tick_params(axis='x', colors=TEXT_COLOR, labelsize=8)
            ax3.tick_params(axis='y', colors=TEXT_COLOR, labelsize=8)
            ax3.grid(color=BG_COLOR, linestyle='--', alpha=0.3, axis='x')

        # 4. SAĞ ALT: TEHDİT SEVİYESİ ANALİZİ (DİKEY SÜTUN GRAFİK)
        ax4 = plt.subplot(2, 2, 4)
        ax4.set_facecolor("#1E2326")
        
        # Skorlara göre sınıflandırma işlemi
        critical = sum(1 for row in all_data if row[1] >= 90)
        high = sum(1 for row in all_data if 70 <= row[1] < 90)
        medium = sum(1 for row in all_data if row[1] < 70)
        
        sev_labels = ['Kritik (+90)', 'Yüksek (70-89)', 'Orta (<70)']
        sev_vals = [critical, high, medium]
        bar_colors = ['#ff3333', '#ffcc00', '#4DE7E9']
        
        ax4.bar(sev_labels, sev_vals, color=bar_colors, width=0.5)
        ax4.set_title("Tehdit Seviyesi Dağılımı", color=TITLE_COLOR, fontdict={'fontsize': 10, 'weight': 'bold'})
        ax4.tick_params(axis='x', colors=TEXT_COLOR, labelsize=8)
        ax4.tick_params(axis='y', colors=TEXT_COLOR, labelsize=8)
        ax4.grid(color=BG_COLOR, linestyle='--', alpha=0.3, axis='y')

        # Ekrana Gömme
        plt.tight_layout(pad=3.0) # Grafikler arası mesafe
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=20)

    def show_network_monitor(self):
        self.log(self.t("log_net_start"), "sys")
        net_win = tk.Toplevel(self.root)
        net_win.title(self.t("net_monitor"))
        net_win.geometry("900x500")
        net_win.configure(bg=BG_COLOR)
        
        # Sekmeli Yapı (Notebook) Oluşturma
        notebook = ttk.Notebook(net_win)
        notebook.pack(fill="both", expand=True, padx=20, pady=20)
        
        # --- 1. SEKME: AKTİF BAĞLANTILAR (Mevcut Olan) ---
        tab_connections = tk.Frame(notebook, bg=BG_COLOR)
        notebook.add(tab_connections, text="Aktif Oturumlar (TCP/UDP)")
        
        columns_conn = (self.t("net_app"), "PID", self.t("net_local"), self.t("net_remote"), self.t("net_status"))
        tree_conn = ttk.Treeview(tab_connections, columns=columns_conn, show="headings", height=15)
        for col in columns_conn:
            tree_conn.heading(col, text=col)
            tree_conn.column(col, width=150, anchor="center")
        tree_conn.column(self.t("net_app"), width=200, anchor="w") 
        tree_conn.pack(fill="both", expand=True, pady=10)
        
        # --- 2. SEKME: YEREL AĞ CİHAZLARI (Yeni Eklenen) ---
        tab_devices = tk.Frame(notebook, bg=BG_COLOR)
        notebook.add(tab_devices, text="Ağa Bağlı Cihazlar (LAN Scanner)")
        
        columns_dev = ("IP Adresi", "Fiziksel Adres (MAC)", "Cihaz Markası / Üretici", "Bağlantı Tipi")
        tree_dev = ttk.Treeview(tab_devices, columns=columns_dev, show="headings", height=15)
        for col in columns_dev:
            tree_dev.heading(col, text=col)
            tree_dev.column(col, width=200, anchor="center")
        tree_dev.pack(fill="both", expand=True, pady=10)
        
        # Her iki sekme için veri çekme işlemlerini arka planda başlat
        threading.Thread(target=self._fetch_network_data, args=(tree_conn,), daemon=True).start()
        threading.Thread(target=self._fetch_lan_devices, args=(tree_dev,), daemon=True).start()
    def _fetch_network_data(self, tree):
        try:
            connections = psutil.net_connections(kind='all') 
            count = 0
            for conn in connections:
                try:
                    pid = conn.pid
                    app_name = "Bilinmiyor"
                    if pid:
                        try: app_name = psutil.Process(pid).name()
                        except: pass
                    laddr = f"{conn.laddr[0]}:{conn.laddr[1]}" if conn.laddr else "-"
                    raddr = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else "-"
                    status = conn.status if conn.status else "BELİRSİZ"
                    self.root.after(0, lambda a=app_name, p=pid, l=laddr, r=raddr, s=status: tree.insert("", "end", values=(a, p, l, r, s)))
                    count += 1
                except Exception as item_err: continue
            msg = self.t("log_net_scan_done").replace("{count}", str(count))
            self.log(msg, "sys")
        except Exception as e:
            self.log(f"Ağ tarama hatası: {e}", "sys")
    def _fetch_lan_devices(self, tree):
        try:
            self.log("Ağa bağlı yerel cihazlar taranıyor (ARP İstihbaratı)...", "sys")
            arp_result = subprocess.run("arp -a", capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW).stdout
            
            pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)")
            matches = pattern.findall(arp_result)
            
            count = 0
            for match in matches:
                ip_addr, mac_addr, conn_type = match
                mac_addr_lower = mac_addr.lower()
                
                if ip_addr.endswith(".255") or ip_addr.startswith("224.") or ip_addr.startswith("239."):
                    continue
                if mac_addr_lower == "ff-ff-ff-ff-ff-ff":
                    continue

                # --- YENİ EKLENEN SİBER İSTİHBARAT MANTIĞI ---
                # MAC adresinin 2. karakterini alıyoruz (Örn: f8-... ise '8', x2-... ise '2')
                second_char = mac_addr_lower[1]
                
                # Eğer cihaz MAC Randomization (Gizlilik) kullanıyorsa:
                if second_char in ['2', '6', 'a', 'e']:
                    brand = "📱 Gizlenmiş Cihaz (Rastgele MAC / iOS-Android)"
                else:
                    # Normal bir cihazsa veritabanından bak
                    mac_prefix = mac_addr_lower[:8]
                    brand = MAC_VENDORS.get(mac_prefix, "Bilinmeyen / Diğer Üretici")
                
                if conn_type == "static" and count == 0:
                    brand = "💻 " + brand + " (Muhtemelen Senin Cihazın/Modem)"
                    
                self.root.after(0, lambda i=ip_addr, m=mac_addr, b=brand, t=conn_type: tree.insert("", "end", values=(i, m, b, t.capitalize())))
                count += 1
                
            self.log(f"Yerel Ağ (LAN) Taraması Tamamlandı. {count} cihaz tespit edildi.", "sys")
        except Exception as e:
            self.log(f"Cihaz tarama hatası: {e}", "sys")        
    def live_behavior_monitor(self):
        # Siber saldırganların sık kullandığı şüpheli komut satırı parametreleri
        suspicious_args = [
            "-windowstyle hidden", "-w hidden", # Pencereyi gizleyerek çalıştır
            "-ep bypass", "executionpolicy bypass", # Güvenlik politikalarını atla
            "-enc", "-encodedcommand",          # Base64 ile şifrelenmiş komut çalıştır
            "bypass", "hidden", "noninteractive"
        ]

        while True:
            # Sadece 'name' değil, işlemin çalıştırıldığı 'cmdline' (komut satırı) verisini de çekiyoruz
            for proc in psutil.process_iter(['name', 'cmdline']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ""
                    
                    # Eğer işlem bizim şüpheli listemizdeyse (örn: powershell.exe)
                    if proc_name in SUSPICIOUS_PROCESS_NAMES:
                        cmdline_list = proc.info.get('cmdline')
                        
                        if cmdline_list:
                            # Komut satırı argümanlarını tek bir metin haline getir ve küçült
                            cmdline_str = " ".join(cmdline_list).lower()
                            
                            # Komut satırında bizim belirlediğimiz şüpheli parametrelerden biri var mı kontrol et
                            if any(arg in cmdline_str for arg in suspicious_args):
                                alert_detail = f"{proc_name} (Gizli/Şüpheli Parametre)"
                                
                                # Terminale detayı logla (komutun ilk 100 karakterini görelim)
                                self.log(f"BEHAVIOR ALERT: {alert_detail} -> {cmdline_str[:100]}...", "critical")
                                
                                # Windows bildirimi gönder
                                msg = self.t("behavior_alert_msg").replace("{process}", alert_detail)
                                self.show_windows_alert(self.t("behavior_alert_title"), msg)
                                
                # Yetki eksikliği veya aniden kapanan işlemler için beklenen hataları yakala (çökmeyi engelle)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            time.sleep(15) # Sistemi yormamak için her döngüde 15 saniye bekle

    def generate_html_report(self):
        if not self.found_threats: return
        report_path = os.path.join(LOG_DIR, f"ScanReport_{int(time.time())}.html")
        absolute_path = os.path.abspath(report_path)
        
        detected_text = self.t("report_detected").replace("{count}", str(len(self.found_threats)))
        
        html_content = f"""
        <html>
        <head><meta charset="utf-8"><title>{self.t("report_title")}</title></head>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; padding: 40px;">
            <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                <h1 style="color: #d9534f; border-bottom: 2px solid #eee; padding-bottom: 10px;">🛡️ {self.t("report_title")}</h1>
                <p><b>{self.t("report_date")}</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><b>{self.t("report_status")}</b> <span style="color: #d9534f; font-weight: bold;">{detected_text}</span></p>
                <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                    <tr style="background-color: #202529; color: white; text-align: left;">
                        <th style="padding: 12px; border: 1px solid #ddd;">{self.t("report_path")}</th>
                        <th style="padding: 12px; border: 1px solid #ddd;">{self.t("report_type")}</th>
                        <th style="padding: 12px; border: 1px solid #ddd;">{self.t("risk_score")}</th>
                    </tr>
        """
        for t in self.found_threats:
            html_content += f"""
                    <tr style="background-color: #fff8f8;">
                        <td style="padding: 12px; border: 1px solid #ddd; font-family: Consolas, monospace; font-size: 12px;">{t['path']}</td>
                        <td style="padding: 12px; border: 1px solid #ddd; color: #d9534f; font-weight: bold;">{t['type']}</td>
                        <td style="padding: 12px; border: 1px solid #ddd; font-weight: bold;">{t['score']}/100</td>
                    </tr>
            """
        html_content += f"""
                </table>
                <p style="margin-top: 30px; font-size: 11px; color: #888; text-align: center;">
                    Bu rapor YBS Bitirme Projesi kapsamında <b>PredatorXDR</b> tarafından otomatik olarak oluşturulmuştur.
                </p>
            </div>
        </body>
        </html>
        """
        try:
            with open(absolute_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            import webbrowser
            webbrowser.open(f"file:///{absolute_path}")
            self.log(f"HTML Raporu oluşturuldu: {absolute_path}", "sys")
        except Exception as e:
            self.log(f"Rapor hatası: {e}", "sys")

    def cleanup(self):
        msg = self.t("quarantine_prompt").replace("{count}", str(len(self.found_threats)))
        if messagebox.askyesno(self.t("warn_title"), msg):
            for t in self.found_threats:
                try:
                    dest = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{os.path.basename(t['path'])}.vir")
                    shutil.move(t['path'], dest)
                except Exception as e:
                    self.log(f"Dosya taşınamadı (Kullanımda olabilir): {e}", "sys")
            self.log(self.t("log_quarantine_done"), "sys")
            self.found_threats = []

if __name__ == "__main__":
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    app = PredatorXDR(root)
    root.mainloop()