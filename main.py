#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    CYBERSECURITY DASHBOARD v1.0                              ║
║              Moderne GUI für defensive Security-Tools                         ║
║                                                                              ║
║  Author: OLNgaming                                                           ║
║  Features: Ping, Port Scan, DNS Lookup, WHOIS, HTTP Headers, System Info   ║
║  Framework: CustomTkinter (Dark Mode GUI)                                   ║
║  Threading: Asynchrone Ausführung (GUI friert nicht ein)                    ║
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
        
        # Kommando je nach Betriebssystem
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
        
        # Löse Hostname zu IP auf
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
        
        # Entferne http/https
        target = target.replace("http://", "").replace("https://", "").split('/')[0]
        
        try:
            # A-Record (IPv4)
            log_func(f"\nA-Records (IPv4):", "INFO")
            try:
                a_record = socket.getaddrinfo(target, None, socket.AF_INET)
                for item in a_record:
                    log_func(f"  {item[4][0]}", "SUCCESS")
            except:
                log_func(f"  Keine A-Records gefunden.", "WARNING")
            
            # AAAA-Record (IPv6)
            log_func(f"\nAAAA-Records (IPv6):", "INFO")
            try:
                aaaa_record = socket.getaddrinfo(target, None, socket.AF_INET6)
                for item in aaaa_record:
                    log_func(f"  {item[4][0]}", "SUCCESS")
            except:
                log_func(f"  Keine AAAA-Records gefunden.", "WARNING")
            
            # Reverse DNS
            log_func(f"\nReverse DNS-Lookup:", "INFO")
            try:
                try:
                    ip_addr = ip_address(target)
                    hostname = socket.gethostbyaddr(str(ip_addr))
                    log_func(f"  Hostname: {hostname[0]}", "SUCCESS")
                except (AddressValueError, socket.herror):
                    log_func(f"  Reverse DNS nicht verfügbar.", "INFO")
            except Exception as e:
                log_func(f"  Fehler: {str(e)}", "ERROR")
        
        except Exception as e:
            log_func(f"DNS