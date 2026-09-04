"""
Port Scan Tool - Socket-basierter Port-Scanner
"""

import socket


def port_scan(target, log_func, ports=None):
    """
    Führt einen Port-Scan auf häufig verwendeten Ports durch.
    Nutzt Python sockets (keine nmap erforderlich).
    
    Args:
        target (str): Ziel-IP oder Hostname
        log_func (callable): Funktion zum Ausgeben von Logs
        ports (list): Liste von zu scannenden Ports (Standard: häufige Ports)
    """
    if ports is None:
        # Häufig verwendete Ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    
    log_func(f"🔎 Starte Port-Scan auf {target}...", "INFO")
    log_func(f"📊 Zu scannende Ports: {ports}\n", "INFO")
    
    open_ports = []
    closed_ports = []
    
    # Löse Hostname zu IP auf
    try:
        ip = socket.gethostbyname(target)
        log_func(f"✓ Aufgelöst: {target} -> {ip}", "INFO")
    except socket.gaierror:
        log_func(f"❌ Fehler: Konnte {target} nicht auflösen.", "ERROR")
        return
    
    log_func(f"\n{'='*60}", "INFO")
    log_func(f"Scanne {len(ports)} Ports...\n", "INFO")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                log_func(f"Port {port:5d}: OFFEN ✓", "SUCCESS")
                open_ports.append(port)
            else:
                log_func(f"Port {port:5d}: GESCHLOSSEN", "INFO")
                closed_ports.append(port)
            
            sock.close()
        
        except Exception as e:
            log_func(f"Port {port:5d}: Fehler - {str(e)}", "ERROR")
    
    # Zusammenfassung
    log_func(f"\n{'='*60}", "INFO")
    log_func(f"📈 SCAN-ERGEBNISSE:", "INFO")
    log_func(f"{'='*60}", "INFO")
    log_func(f"Offene Ports ({len(open_ports)}): {open_ports if open_ports else 'Keine'}", "SUCCESS")
    log_func(f"Geschlossene Ports ({len(closed_ports)}): {len(closed_ports)}", "INFO")
    log_func(f"Gesamt gescannt: {len(ports)}", "INFO")
    log_func(f"{'='*60}\n", "INFO")
