"""
HTTP Headers Tool - Holt und analysiert HTTP-Header von Websites
"""

import socket
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def get_http_headers(target, log_func):
    """
    Holt die HTTP-Header einer Website.
    
    Args:
        target (str): URL oder Hostname
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    # Stelle sicher, dass target eine vollständige URL ist
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    log_func(f"📋 Rufe HTTP-Header ab von {target}...", "INFO")
    log_func(f"\n{'='*60}", "INFO")
    
    try:
        request = Request(target)
        request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        with urlopen(request, timeout=10) as response:
            # Status Code
            log_func(f"🟢 Status Code: {response.status}", "SUCCESS")
            log_func(f"   Grund: {response.reason}\n", "INFO")
            
            # HTTP-Header
            log_func(f"📡 HTTP-Header:", "INFO")
            log_func(f"{'='*60}", "INFO")
            
            headers_dict = {}
            for header, value in response.headers.items():
                log_func(f"  {header}: {value}", "INFO")
                headers_dict[header] = value
            
            # Wichtige Header hervorheben
            log_func(f"\n{'='*60}", "INFO")
            log_func(f"⭐ Wichtige Sicherheits-Header:", "INFO")
            log_func(f"{'='*60}", "INFO")
            
            important_headers = {
                'Content-Type': 'Inhaltstyp',
                'Content-Length': 'Größe',
                'Server': 'Server-Software',
                'X-Frame-Options': 'Clickjacking-Schutz',
                'X-Content-Type-Options': 'MIME-Type-Sniffing Schutz',
                'Content-Security-Policy': 'CSP (Sicherheitspolicy)',
                'Strict-Transport-Security': 'HSTS (HTTPS-Only)',
                'Set-Cookie': 'Cookies',
                'WWW-Authenticate': 'Authentifizierung',
                'Cache-Control': 'Cache-Kontroll',
            }
            
            for header, description in important_headers.items():
                value = headers_dict.get(header, 'Nicht gesetzt')
                if value != 'Nicht gesetzt':
                    log_func(f"  ✓ {description}: {value}", "SUCCESS")
                else:
                    log_func(f"  ✗ {description}: {value}", "WARNING")
            
            # Server-Informationen
            log_func(f"\n{'='*60}", "INFO")
            log_func(f"🖥️  Server-Informationen:", "INFO")
            log_func(f"{'='*60}", "INFO")
            
            server = headers_dict.get('Server', 'Unbekannt')
            content_type = headers_dict.get('Content-Type', 'Unbekannt')
            content_length = headers_dict.get('Content-Length', 'Unbekannt')
            
            log_func(f"  Server: {server}", "INFO")
            log_func(f"  Content-Type: {content_type}", "INFO")
            log_func(f"  Content-Length: {content_length} Bytes", "INFO")
            
            # Sicherheitsbewertung
            log_func(f"\n{'='*60}", "INFO")
            log_func(f"🔒 Sicherheitsbewertung:", "INFO")
            log_func(f"{'='*60}", "INFO")
            
            security_score = 0
            max_score = 10
            
            if 'Strict-Transport-Security' in headers_dict:
                log_func(f"  ✓ HSTS aktiviert (HTTPS erzwungen)", "SUCCESS")
                security_score += 2
            else:
                log_func(f"  ✗ HSTS nicht aktiviert", "WARNING")
            
            if 'X-Content-Type-Options' in headers_dict:
                log_func(f"  ✓ MIME-Type-Sniffing Schutz aktiviert", "SUCCESS")
                security_score += 2
            else:
                log_func(f"  ✗ MIME-Type-Sniffing Schutz nicht aktiviert", "WARNING")
            
            if 'X-Frame-Options' in headers_dict:
                log_func(f"  ✓ Clickjacking-Schutz aktiviert", "SUCCESS")
                security_score += 2
            else:
                log_func(f"  ✗ Clickjacking-Schutz nicht aktiviert", "WARNING")
            
            if 'Content-Security-Policy' in headers_dict:
                log_func(f"  ✓ Content Security Policy (CSP) aktiviert", "SUCCESS")
                security_score += 2
            else:
                log_func(f"  ✗ Content Security Policy nicht aktiviert", "WARNING")
            
            if 'X-XSS-Protection' in headers_dict:
                log_func(f"  ✓ XSS-Schutz aktiviert", "SUCCESS")
                security_score += 1
            
            if 'Referrer-Policy' in headers_dict:
                log_func(f"  ✓ Referrer-Policy gesetzt", "SUCCESS")
                security_score += 1
            
            log_func(f"\n  📊 Sicherheitswert: {security_score}/{max_score}", "INFO")
            
            log_func(f"\n{'='*60}", "SUCCESS")
            log_func(f"HTTP-Header-Analyse abgeschlossen", "SUCCESS")
            log_func(f"{'='*60}\n", "SUCCESS")
    
    except HTTPError as e:
        log_func(f"❌ HTTP-Fehler {e.code}: {e.reason}", "WARNING")
        log_func(f"\nFehlerseite-Content (erste 500 Zeichen):\n", "INFO")
        try:
            error_content = e.read().decode('utf-8', errors='ignore')[:500]
            log_func(error_content, "INFO")
        except:
            pass
    
    except URLError as e:
        log_func(f"❌ URL-Fehler: {str(e)}", "ERROR")
    
    except socket.timeout:
        log_func("⏱️  Timeout: Anfrage hat zu lange gedauert (>10s).", "ERROR")
    
    except Exception as e:
        log_func(f"❌ Fehler beim Abrufen der Header: {str(e)}", "ERROR")


def check_security_headers(target, log_func):
    """
    Prüft speziell auf Sicherheits-Header.
    
    Args:
        target (str): URL oder Hostname
        log_func (callable): Funktion zum Ausgeben von Logs
    """
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    log_func(f"🔒 Prüfe Sicherheits-Header für {target}...", "INFO")
    log_func(f"\n{'='*60}", "INFO")
    
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'X-Frame-Options': 'X-Frame-Options',
        'X-XSS-Protection': 'X-XSS-Protection',
        'Content-Security-Policy': 'CSP',
        'Referrer-Policy': 'Referrer-Policy',
        'Permissions-Policy': 'Permissions-Policy',
    }
    
    try:
        request = Request(target)
        request.add_header('User-Agent', 'Mozilla/5.0')
        
        with urlopen(request, timeout=10) as response:
            headers_dict = dict(response.headers)
            
            log_func(f"\n✅ Gefundene Sicherheits-Header:", "INFO")
            found_count = 0
            
            for header, name in security_headers.items():
                if header in headers_dict:
                    log_func(f"  ✓ {name}: {headers_dict[header]}", "SUCCESS")
                    found_count += 1
                else:
                    log_func(f"  ✗ {name}: Nicht gesetzt", "WARNING")
            
            log_func(f"\n📊 Gesamt: {found_count}/{len(security_headers)} Header gesetzt", "INFO")
            log_func(f"{'='*60}\n", "INFO")
    
    except Exception as e:
        log_func(f"Fehler: {str(e)}", "ERROR")
