"""
DNS Tool - DNS Lookups (A, AAAA, MX, Reverse DNS)
"""

import socket
from ipaddress import ip_address, AddressValueError


def dns_lookup(target, log_func):
    """
    Führt DNS-Lookups durch (A, AAAA, MX Records und Reverse DNS).
    
    Args:
        target (str): Domain oder IP-Adresse
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    log_func(f"🌐 DNS-Lookup für {target}...", "INFO")
    
    # Entferne http/https wenn vorhanden
    target = target.replace("http://", "").replace("https://", "").split('/')[0]
    
    log_func(f"\n{'='*60}", "INFO")
    log_func(f"Analysiere DNS-Einträge für: {target}", "INFO")
    log_func(f"{'='*60}\n", "INFO")
    
    try:
        # A-Record (IPv4)
        log_func(f"📍 A-Records (IPv4):", "INFO")
        try:
            a_record = socket.getaddrinfo(target, None, socket.AF_INET)
            found_a = False
            for item in a_record:
                log_func(f"  ✓ {item[4][0]}", "SUCCESS")
                found_a = True
            if not found_a:
                log_func(f"  ℹ️  Keine A-Records gefunden.", "WARNING")
        except Exception as e:
            log_func(f"  ❌ Fehler bei A-Record Abfrage: {str(e)}", "ERROR")
        
        # AAAA-Record (IPv6)
        log_func(f"\n📍 AAAA-Records (IPv6):", "INFO")
        try:
            aaaa_record = socket.getaddrinfo(target, None, socket.AF_INET6)
            found_aaaa = False
            for item in aaaa_record:
                log_func(f"  ✓ {item[4][0]}", "SUCCESS")
                found_aaaa = True
            if not found_aaaa:
                log_func(f"  ℹ️  Keine AAAA-Records gefunden.", "WARNING")
        except Exception as e:
            log_func(f"  ℹ️  IPv6 nicht verfügbar oder kein AAAA-Record.", "WARNING")
        
        # Reverse DNS Lookup
        log_func(f"\n📍 Reverse DNS-Lookup:", "INFO")
        try:
            try:
                # Versuche, die IP aufzulösen wenn target eine IP ist
                ip_addr = ip_address(target)
                hostname = socket.gethostbyaddr(str(ip_addr))
                log_func(f"  ✓ Hostname: {hostname[0]}", "SUCCESS")
                log_func(f"  ✓ Aliases: {hostname[1] if hostname[1] else 'Keine'}", "INFO")
                log_func(f"  ✓ IP-Adressen: {hostname[2]}", "INFO")
            except (AddressValueError, socket.herror):
                log_func(f"  ℹ️  Reverse DNS nicht verfügbar (target ist wahrscheinlich eine Domain).", "INFO")
        except Exception as e:
            log_func(f"  ⚠️  Fehler: {str(e)}", "WARNING")
        
        # Zusätzliche Informationen
        log_func(f"\n📋 Zusätzliche DNS-Informationen:", "INFO")
        try:
            fqdn = socket.getfqdn(target)
            log_func(f"  ✓ FQDN: {fqdn}", "SUCCESS")
        except:
            log_func(f"  ℹ️  FQDN konnte nicht ermittelt werden.", "WARNING")
        
        log_func(f"\n{'='*60}", "INFO")
        log_func(f"DNS-Lookup abgeschlossen.", "SUCCESS")
        log_func(f"{'='*60}\n", "INFO")
    
    except Exception as e:
        log_func(f"❌ DNS-Lookup fehlgeschlagen: {str(e)}", "ERROR")


def get_nameservers(target, log_func):
    """
    Versucht, die Nameserver für eine Domain zu finden.
    Benötigt das 'nslookup' oder 'dig' Tool.
    
    Args:
        target (str): Domain-Name
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    import subprocess
    import platform
    
    log_func(f"🔍 Suche Nameserver für {target}...", "INFO")
    
    try:
        if platform.system() == "Windows":
            cmd = ["nslookup", "-type=NS", target]
        else:
            cmd = ["dig", "+short", "NS", target]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.stdout:
            log_func(f"\n📡 Nameserver:\n{result.stdout}", "SUCCESS")
        else:
            log_func("Keine Nameserver-Informationen gefunden.", "WARNING")
    
    except FileNotFoundError:
        log_func("Tool nicht verfügbar (nslookup/dig).", "WARNING")
    except subprocess.TimeoutExpired:
        log_func("Timeout bei Nameserver-Abfrage.", "ERROR")
    except Exception as e:
        log_func(f"Fehler: {str(e)}", "ERROR")
