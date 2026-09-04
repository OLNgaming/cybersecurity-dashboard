"""
System Info Tool - Zeigt Systeminformationen des lokalen Computers
"""

import platform
import socket
import subprocess
import psutil
import os
from datetime import datetime


def get_system_info(log_func):
    """
    Gibt umfassende Systeminformationen aus.
    
    Args:
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    log_func(f"💾 Sammle Systeminformationen...", "INFO")
    log_func(f"\n{'='*60}", "INFO")
    log_func(f"SYSTEM INFORMATIONEN", "INFO")
    log_func(f"{'='*60}\n", "INFO")
    
    try:
        # --- BETRIEBSSYSTEM ---
        log_func(f"🖥️  Betriebssystem:", "INFO")
        log_func(f"  System: {platform.system()}", "SUCCESS")
        log_func(f"  Release: {platform.release()}", "SUCCESS")
        log_func(f"  Version: {platform.version()}", "SUCCESS")
        log_func(f"  Architektur: {platform.architecture()[0]}", "SUCCESS")
        log_func(f"  Prozessor: {platform.processor()}", "SUCCESS")
        
        # --- PYTHON ---
        log_func(f"\n🐍 Python:", "INFO")
        log_func(f"  Version: {platform.python_version()}", "SUCCESS")
        log_func(f"  Implementation: {platform.python_implementation()}", "SUCCESS")
        log_func(f"  Compiler: {platform.python_compiler()}", "SUCCESS")
        log_func(f"  Build: {platform.python_build()}", "SUCCESS")
        
        # --- HOSTNAME & NETZWERK ---
        log_func(f"\n🌐 Netzwerk:", "INFO")
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            log_func(f"  Hostname: {hostname}", "SUCCESS")
            log_func(f"  Lokale IPv4: {local_ip}", "SUCCESS")
            
            # Versuche IPv6 zu finden
            try:
                ipv6 = socket.gethostbyname(hostname)
                log_func(f"  Lokale IPv6: {ipv6}", "SUCCESS")
            except:
                pass
        
        except Exception as e:
            log_func(f"  Fehler beim Abrufen von Netzwerkinfo: {str(e)}", "ERROR")
        
        # --- CPU INFORMATIONEN ---
        log_func(f"\n⚙️  CPU-Informationen:", "INFO")
        try:
            cpu_count = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            cpu_freq = psutil.cpu_freq()
            cpu_percent = psutil.cpu_percent(interval=1)
            
            log_func(f"  Physische Kerne: {cpu_count}", "SUCCESS")
            log_func(f"  Logische Kerne: {cpu_count_logical}", "SUCCESS")
            if cpu_freq:
                log_func(f"  Frequenz: {cpu_freq.current:.2f} MHz", "SUCCESS")
            log_func(f"  Auslastung: {cpu_percent}%", "INFO")
        
        except Exception as e:
            log_func(f"  CPU-Info nicht verfügbar: {str(e)}", "WARNING")
        
        # --- SPEICHER ---
        log_func(f"\n💾 Speicher:", "INFO")
        try:
            ram = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            log_func(f"  RAM Gesamt: {ram.total / (1024**3):.2f} GB", "SUCCESS")
            log_func(f"  RAM Verfügbar: {ram.available / (1024**3):.2f} GB", "SUCCESS")
            log_func(f"  RAM Verwendet: {ram.used / (1024**3):.2f} GB ({ram.percent}%)", "INFO")
            log_func(f"  SWAP Gesamt: {swap.total / (1024**3):.2f} GB", "SUCCESS")
            log_func(f"  SWAP Verwendet: {swap.used / (1024**3):.2f} GB ({swap.percent}%)", "INFO")
        
        except Exception as e:
            log_func(f"  Speicher-Info nicht verfügbar: {str(e)}", "WARNING")
        
        # --- FESTPLATTE ---
        log_func(f"\n💿 Festplatte:", "INFO")
        try:
            disk = psutil.disk_usage('/')
            log_func(f"  Gesamt: {disk.total / (1024**3):.2f} GB", "SUCCESS")
            log_func(f"  Verwendet: {disk.used / (1024**3):.2f} GB ({disk.percent}%)", "INFO")
            log_func(f"  Frei: {disk.free / (1024**3):.2f} GB", "SUCCESS")
        
        except Exception as e:
            log_func(f"  Festplatte-Info nicht verfügbar: {str(e)}", "WARNING")
        
        # --- NETZWERK-INTERFACES ---
        log_func(f"\n📡 Netzwerk-Interfaces:", "INFO")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout[:1500]  # Erste 1500 Zeichen
                log_func(f"{output}", "INFO")
            else:
                result = subprocess.run(
                    ["ifconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout[:1500]
                log_func(f"{output}", "INFO")
        
        except Exception as e:
            log_func(f"  Netzwerk-Interface-Info nicht verfügbar: {str(e)}", "WARNING")
        
        # --- LAUFENDE PROZESSE ---
        log_func(f"\n⚡ Top Prozesse (nach CPU-Auslastung):", "INFO")
        try:
            processes = [(p.info['pid'], p.info['name'], p.info['cpu_percent']) 
                        for p in psutil.process_iter(['pid', 'name', 'cpu_percent'])]
            processes.sort(key=lambda x: x[2], reverse=True)
            
            for pid, name, cpu_percent in processes[:5]:
                log_func(f"  PID {pid}: {name} - {cpu_percent}% CPU", "INFO")
        
        except Exception as e:
            log_func(f"  Prozess-Info nicht verfügbar: {str(e)}", "WARNING")
        
        # --- BOOTING ---
        log_func(f"\n🔄 System Uptime:", "INFO")
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            hours, remainder = divmod(int(uptime.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            
            log_func(f"  Letzter Boot: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}", "SUCCESS")
            log_func(f"  Uptime: {hours}h {minutes}m {seconds}s", "SUCCESS")
        
        except Exception as e:
            log_func(f"  Uptime-Info nicht verfügbar: {str(e)}", "WARNING")
        
        # --- BENUTZER ---
        log_func(f"\n👤 Benutzer:", "INFO")
        try:
            user = os.getenv('USERNAME') or os.getenv('USER')
            log_func(f"  Aktueller Benutzer: {user}", "SUCCESS")
        
        except Exception as e:
            log_func(f"  Benutzer-Info nicht verfügbar: {str(e)}", "WARNING")
        
        log_func(f"\n{'='*60}", "SUCCESS")
        log_func(f"System-Informationen erfolgreich gesammelt", "SUCCESS")
        log_func(f"{'='*60}\n", "SUCCESS")
    
    except Exception as e:
        log_func(f"❌ Fehler beim Sammeln von Systeminformationen: {str(e)}", "ERROR")


def get_network_stats(log_func):
    """
    Zeigt Netzwerk-Statistiken an.
    
    Args:
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    log_func(f"📊 Netzwerk-Statistiken:", "INFO")
    log_func(f"\n{'='*60}", "INFO")
    
    try:
        net_stats = psutil.net_if_stats()
        
        for interface, stats in net_stats.items():
            log_func(f"\n🖇️  Interface: {interface}", "INFO")
            log_func(f"  Verfügbar: {'Ja' if stats.isup else 'Nein'}", "SUCCESS" if stats.isup else "WARNING")
            log_func(f"  MTU: {stats.mtu}", "INFO")
            log_func(f"  Geschwindigkeit: {stats.speed} Mbps", "INFO")
            
            net_io = psutil.net_io_counters(pernic=True)
            if interface in net_io:
                io = net_io[interface]
                log_func(f"  Bytes gesendet: {io.bytes_sent / (1024**2):.2f} MB", "INFO")
                log_func(f"  Bytes empfangen: {io.bytes_recv / (1024**2):.2f} MB", "INFO")
                log_func(f"  Pakete gesendet: {io.packets_sent}", "INFO")
                log_func(f"  Pakete empfangen: {io.packets_recv}", "INFO")
        
        log_func(f"\n{'='*60}", "INFO")
    
    except Exception as e:
        log_func(f"Fehler beim Abrufen von Netzwerk-Statistiken: {str(e)}", "ERROR")


def get_disk_usage(log_func):
    """
    Zeigt detaillierte Festplatten-Auslastung an.
    
    Args:
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    log_func(f"💿 Detaillierte Festplatten-Auslastung:", "INFO")
    log_func(f"\n{'='*60}", "INFO")
    
    try:
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            log_func(f"\n📂 {partition.device}", "INFO")
            log_func(f"  Mountpoint: {partition.mountpoint}", "INFO")
            log_func(f"  Dateisystem: {partition.fstype}", "INFO")
            
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                log_func(f"  Gesamt: {usage.total / (1024**3):.2f} GB", "SUCCESS")
                log_func(f"  Verwendet: {usage.used / (1024**3):.2f} GB ({usage.percent}%)", "INFO")
                log_func(f"  Frei: {usage.free / (1024**3):.2f} GB", "SUCCESS")
            except PermissionError:
                log_func(f"  ⚠️  Keine Berechtigung zum Auslesen", "WARNING")
        
        log_func(f"\n{'='*60}\n", "INFO")
    
    except Exception as e:
        log_func(f"Fehler beim Abrufen von Festplatten-Info: {str(e)}", "ERROR")
