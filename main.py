#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                   CYBERSECURITY DASHBOARD v1.0                               ║
║              Moderne GUI für defensive Security-Tools                        ║
║                                                                              ║
║ Author: OLNgaming                                                            ║
║ Features: Ping, Port Scan, DNS Lookup, WHOIS, HTTP Headers, System Info      ║
║ Framework: CustomTkinter (Dark Mode GUI)                                     ║
║ Threading: Asynchrone Ausführung (GUI friert nicht ein)                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import socket
import subprocess
import platform
import sys
import re
import os
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from ipaddress import ip_address, AddressValueError

# ============================================================================
# KONFIGURATION
# ============================================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ============================================================================
# VALIDIERUNGS-FUNKTIONEN
# ============================================================================

def is_valid_ip(ip_string):
    """Validiert eine IPv4-Adresse."""
    pattern = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    return re.match(pattern, ip_string) is not None


def is_valid_domain(domain):
    """Validiert einen Domänennamen."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    return re.match(pattern, domain) is not None


def is_valid_url(url):
    """Validiert eine URL."""
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return re.match(url_pattern, url, re.IGNORECASE) is not None


def is_valid_target(target):
    """Validiert, ob ein String ein gültiges Ziel (IP, Domain oder URL) ist."""
    clean_target = target.replace("http://", "").replace("https://", "").split('/')[0]
    return (
        is_valid_ip(clean_target) or
        is_valid_domain(clean_target) or
        is_valid_url(target)
    )


# ============================================================================
# NETZWERK-TOOLS
# ============================================================================

class NetworkTools:
    """Sammlung aller Netzwerk- und Security-Tools."""

    @staticmethod
    def ping_host(target, log_func):
        """Führt einen Ping-Test durch."""
        log_func(f"Pinge {target}...", "INFO")
        
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "4", target]
        else:
            cmd = ["ping", "-c", "4", target]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            output = result.stdout if result.stdout else result.stderr
            log_func(output, "INFO")
            
            if result.returncode == 0:
                log_func(f"\n✓ {target} ist erreichbar!", "SUCCESS")
            else:
                log_func(f"\n✗ {target} ist nicht erreichbar.", "WARNING")
        
        except subprocess.TimeoutExpired:
            log_func(f"Timeout: Ping zu {target} hat zu lange gedauert.", "ERROR")
        except Exception as e:
            log_func(f"Fehler beim Ping: {str(e)}", "ERROR")

    @staticmethod
    def port_scan(target, log_func, ports=None):
        """Führt einen Port-Scan durch (Socket-basiert)."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        
        log_func(f"Starte Port-Scan auf {target}...", "INFO")
        log_func(f"Zu scannende Ports: {ports}\n", "INFO")
        
        open_ports = []
        
        try:
            ip = socket.gethostbyname(target)
            log_func(f"Aufgelöst: {target} -> {ip}", "INFO")
        except socket.gaierror:
            log_func(f"Fehler: Konnte {target} nicht auflösen.", "ERROR")
            return
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    log_func(f"Port {port}: OFFEN ✓", "SUCCESS")
                    open_ports.append(port)
                else:
                    log_func(f"Port {port}: GESCHLOSSEN", "INFO")
                
                sock.close()
            
            except Exception as e:
                log_func(f"Port {port}: Fehler - {str(e)}", "ERROR")
        
        log_func(f"\n{'='*40}", "INFO")
        log_func(f"Offene Ports: {open_ports if open_ports else 'Keine'}", "SUCCESS")
        log_func(f"{'='*40}", "INFO")

    @staticmethod
    def dns_lookup(target, log_func):
        """Führt DNS-Lookups durch (A, AAAA, Reverse DNS)."""
        log_func(f"DNS-Lookup für {target}...", "INFO")
        
        target = target.replace("http://", "").replace("https://", "").split('/')[0]
        
        try:
            # A-Record (IPv4)
            log_func(f"\nA-Records (IPv4):", "INFO")
            try:
                a_record = socket.getaddrinfo(target, None, socket.AF_INET)
                for item in set(a[4][0] for a in a_record):
                    log_func(f"  {item}", "SUCCESS")
            except Exception:
                log_func(f"  Keine A-Records gefunden.", "WARNING")
            
            # AAAA-Record (IPv6)
            log_func(f"\nAAAA-Records (IPv6):", "INFO")
            try:
                aaaa_record = socket.getaddrinfo(target, None, socket.AF_INET6)
                for item in set(a[4][0] for a in aaaa_record):
                    log_func(f"  {item}", "SUCCESS")
            except Exception:
                log_func(f"  Keine AAAA-Records gefunden.", "WARNING")
            
            # Reverse DNS
            log_func(f"\nReverse DNS-Lookup:", "INFO")
            try:
                ip_addr = ip_address(target)
                hostname = socket.gethostbyaddr(str(ip_addr))
                log_func(f"  Hostname: {hostname[0]}", "SUCCESS")
            except (AddressValueError, socket.herror):
                log_func(f"  Reverse DNS nicht direkt auflösbar oder Ziel ist eine Domain.", "INFO")
        
        except Exception as e:
            log_func(f"Fehler beim DNS-Lookup: {str(e)}", "ERROR")

    @staticmethod
    def whois_lookup(target, log_func):
        """Führt eine WHOIS-Abfrage via Port 43 durch."""
        target = target.replace("http://", "").replace("https://", "").split('/')[0]
        log_func(f"Starte WHOIS Abfrage für {target}...", "INFO")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("whois.iana.org", 43))
            s.send((target + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            log_func(response.decode("utf-8", errors="replace"), "INFO")
        except Exception as e:
            log_func(f"Fehler bei WHOIS-Abfrage: {str(e)}", "ERROR")

    @staticmethod
    def get_http_headers(target, log_func):
        """Liest HTTP/HTTPS Response Header aus."""
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
        
        log_func(f"Frage HTTP-Header ab von {target}...", "INFO")
        try:
            req = Request(target, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            with urlopen(req, timeout=5) as response:
                log_func(f"Status Code: {response.getcode()}", "SUCCESS")
                log_func("\nHeader:", "INFO")
                for key, val in response.info().items():
                    log_func(f"  {key}: {val}", "INFO")
        except HTTPError as e:
            log_func(f"HTTP Fehler: {e.code} - {e.reason}", "WARNING")
            log_func("\nHeader:", "INFO")
            for key, val in e.headers.items():
                log_func(f"  {key}: {val}", "INFO")
        except URLError as e:
            log_func(f"URL Fehler: {e.reason}", "ERROR")
        except Exception as e:
            log_func(f"Fehler beim Abrufen der Header: {str(e)}", "ERROR")

    @staticmethod
    def get_system_info(log_func):
        """Zeigt lokale Systeminformationen an."""
        log_func("Hole lokale Systeminformationen...", "INFO")
        log_func(f"Betriebssystem: {platform.system()} {platform.release()} ({platform.version()})", "SUCCESS")
        log_func(f"Architektur: {platform.machine()}", "INFO")
        log_func(f"Hostname: {socket.gethostname()}", "INFO")
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            log_func(f"Lokale IP: {local_ip}", "SUCCESS")
        except Exception:
            log_func("Lokale IP konnte nicht ermittelt werden.", "WARNING")


# ============================================================================
# GUI DASHBOARD
# ============================================================================

class DashboardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Cybersecurity Dashboard v1.0")
        self.geometry("900 x 650")

        # Grid Layout (2 Spalten: Navigation & Hauptbereich)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Seitenleiste
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="DEFENSIVE\nSECURITY", font=ctk.CTkFont(size=18, weight="bold"))
        self.logo_label.pack(padx=20, pady=(20, 20))

        # Haupt-Container
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # Eingabebereich
        self.target_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Ziel (IP, Domain oder URL eingeben)...", height=35)
        self.target_entry.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")

        # Aktions-Buttons Grid
        self.btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.btn_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        
        tools = [
            ("Ping Host", self.run_ping),
            ("Port Scan", self.run_portscan),
            ("DNS Lookup", self.run_dns),
            ("WHOIS", self.run_whois),
            ("HTTP Header", self.run_headers),
            ("System Info", self.run_sysinfo)
        ]

        for i, (name, cmd) in enumerate(tools):
            btn = ctk.CTkButton(self.btn_frame, text=name, command=cmd)
            btn.grid(row=i//3, column=i%3, padx=5, pady=5, sticky="ew")
            self.btn_frame.grid_columnconfigure(i%3, weight=1)

        # Ausgabe Console Textbereich
        self.console = scrolledtext.ScrolledText(self.main_frame, bg="#1e1e1e", fg="#dcdcdc", font=("Consolas", 10))
        self.console.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        # Config Console Tags
        self.console.tag_config("INFO", foreground="#00aaff")
        self.console.tag_config("SUCCESS", foreground="#00ffaa")
        self.console.tag_config("WARNING", foreground="#ffaa00")
        self.console.tag_config("ERROR", foreground="#ff5555")

    def log(self, text, tag="INFO"):
        """Schreibt formatierte Nachrichten synchron in das Log-Fenster."""
        self.console.insert(tk.END, f"{text}\n", tag)
        self.console.see(tk.END)

    def execute_threaded(self, func, needs_target=True):
        """Führt Funktionen in einem eigenen Thread aus, um GUI-Freeze zu verhindern."""
        target = self.target_entry.get().strip()
        if needs_target:
            if not target:
                messagebox.showwarning("Fehler", "Bitte gib ein gültiges Ziel ein!")
                return
            if not is_valid_target(target):
                messagebox.showerror("Fehler", f"'{target}' ist keine gültige IP, Domain oder URL.")
                return

        self.console.delete('1.0', tk.END)
        self.log(f"=== STARTE EXECUTION: {datetime.now().strftime('%H:%M:%S')} ===", "INFO")
        
        if needs_target:
            threading.Thread(target=func, args=(target, self.log), daemon=True).start()
        else:
            threading.Thread(target=func, args=(self.log,), daemon=True).start()

    # Callback-Wrapper für Buttons
    def run_ping(self): self.execute_threaded(NetworkTools.ping_host)
    def run_portscan(self): self.execute_threaded(NetworkTools.port_scan)
    def run_dns(self): self.execute_threaded(NetworkTools.dns_lookup)
    def run_whois(self): self.execute_threaded(NetworkTools.whois_lookup)
    def run_headers(self): self.execute_threaded(NetworkTools.get_http_headers)
    def run_sysinfo(self): self.execute_threaded(NetworkTools.get_system_info, needs_target=False)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    app = DashboardApp()
    app.mainloop()
