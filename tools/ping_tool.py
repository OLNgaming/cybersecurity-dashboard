"""
Ping Tool - Erreichbarkeitsprüfung
"""

import subprocess
import platform


def ping_host(target, log_func):
    """
    Führt einen Ping-Test durch.
    
    Args:
        target (str): Ziel-IP oder Hostname
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    log_func(f"🔍 Pinge {target}...", "INFO")
    
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
