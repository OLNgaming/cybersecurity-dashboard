"""
WHOIS Tool - WHOIS Lookups für IPs und Domains
"""

import subprocess
import socket


def whois_lookup(target, log_func):
    """
    Führt eine WHOIS-Abfrage durch (mit whois CLI-Tool).
    Benötigt das whois-Tool auf dem System.
    
    Args:
        target (str): IP-Adresse oder Domain
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    # Entferne http/https wenn vorhanden
    target = target.replace("http://", "").replace("https://", "").split('/')[0]
    
    log_func(f"🔗 WHOIS-Abfrage für {target}...", "INFO")
    log_func(f"\n{'='*60}", "INFO")
    log_func(f"Führe WHOIS-Lookup durch...", "INFO")
    log_func(f"{'='*60}\n", "INFO")
    
    try:
        # Überprüfe, ob whois-Tool verfügbar ist
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.stdout:
            output = result.stdout
            log_func(output, "INFO")
            log_func(f"\n{'='*60}", "INFO")
            log_func(f"WHOIS-Abfrage abgeschlossen.", "SUCCESS")
            log_func(f"{'='*60}\n", "INFO")
        else:
            log_func("ℹ️  Keine WHOIS-Daten verfügbar.", "WARNING")
    
    except FileNotFoundError:
        log_func(
            "❌ Fehler: 'whois' Tool nicht installiert.\n\n"
            "📖 Installationsanleitung:\n\n"
            "🪟 Windows:\n"
            "   - Option 1: choco install whois (via Chocolatey)\n"
            "   - Option 2: Download von http://www.nirsoft.net/whois.html\n"
            "   - Option 3: Nutze Online-WHOIS-Services\n\n"
            "🍎 macOS:\n"
            "   brew install whois\n\n"
            "🐧 Linux:\n"
            "   sudo apt-get install whois\n",
            "ERROR"
        )
    except subprocess.TimeoutExpired:
        log_func("⏱️  Timeout: WHOIS-Abfrage hat zu lange gedauert (>15s).", "ERROR")
    except Exception as e:
        log_func(f"❌ WHOIS-Abfrage fehlgeschlagen: {str(e)}", "ERROR")


def whois_bulk_lookup(targets, log_func):
    """
    Führt WHOIS-Abfragen für mehrere Ziele durch.
    
    Args:
        targets (list): Liste von IPs oder Domains
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    log_func(f"🔗 Starte Bulk-WHOIS-Abfrage für {len(targets)} Ziele...\n", "INFO")
    
    results = {}
    
    for target in targets:
        log_func(f"\n{'='*60}", "INFO")
        log_func(f"Abfrage: {target}", "INFO")
        log_func(f"{'='*60}", "INFO")
        
        try:
            result = subprocess.run(
                ["whois", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.stdout:
                # Extrahiere wichtige Informationen
                lines = result.stdout.split('\n')
                key_info = []
                
                for line in lines:
                    if any(keyword in line.lower() for keyword in 
                           ['registrar', 'registrant', 'organization', 'country', 
                            'netname', 'origin as', 'owner']):
                        key_info.append(line.strip())
                
                log_func(f"✓ Wichtige Informationen:\n", "SUCCESS")
                for info in key_info[:10]:  # Zeige max. 10 Zeilen
                    if info:
                        log_func(f"  {info}", "INFO")
                
                results[target] = "OK"
            else:
                log_func("ℹ️  Keine Daten gefunden.", "WARNING")
                results[target] = "NO DATA"
        
        except subprocess.TimeoutExpired:
            log_func(f"⏱️  Timeout für {target}", "ERROR")
            results[target] = "TIMEOUT"
        except FileNotFoundError:
            log_func("❌ whois Tool nicht verfügbar.", "ERROR")
            results[target] = "TOOL NOT FOUND"
        except Exception as e:
            log_func(f"❌ Fehler: {str(e)}", "ERROR")
            results[target] = "ERROR"
    
    # Zusammenfassung
    log_func(f"\n{'='*60}", "INFO")
    log_func(f"📊 ZUSAMMENFASSUNG:", "INFO")
    log_func(f"{'='*60}", "INFO")
    
    for target, status in results.items():
        status_icon = "✓" if status == "OK" else "✗"
        log_func(f"  {status_icon} {target}: {status}", "INFO" if status == "OK" else "WARNING")
    
    log_func(f"{'='*60}\n", "INFO")


def get_whois_info_parsed(target, log_func):
    """
    Holt und parst WHOIS-Informationen in ein strukturiertes Format.
    
    Args:
        target (str): IP-Adresse oder Domain
        log_func (callable): Funktion zum Ausgeben von Logs
    
    Returns:
        dict: Geparste WHOIS-Daten
    """
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        whois_data = {}
        current_section = None
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                whois_data[key] = value
        
        return whois_data
    
    except Exception as e:
        log_func(f"Fehler beim Parsen: {str(e)}", "ERROR")
        return {}
