import ollama
import subprocess
import re
import os
import sys
import json
import base64
import argparse
import threading
import itertools
import time
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# =============================================================================
# LICENCE
# =============================================================================
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOzBX4u1OaASjNsPTwCr
E3Oq2odlpR/tFs6GP/g96VsWap19745/x8UoPxkL1/r5pHMSraxB6toUrzUKs+JY
XpIkiMQIPAwomTeJANI+nkL2nKpKRi8qfRqZDleXJlq3jZOPlOcesuQTF150dWFZ
og+ZJXd8zwvrt976xvyHrItQyDdQ+0wHTNdp1Aa+o4GSDrFd57ppBXfzUUpZvY2c
Tg/B/F4VjS0pZtU4w0jtspTTH5s2W6vAib2IUSns22xWiBxVOoV/FbSnsHTd4pOJ
eIRkAnNSWcvVZ/7RPV4I3Z/9mMm+JCiq0xvT6F3xRmh+9xzwTfGESGAB05iCXwt4
GQIDAQAB
-----END PUBLIC KEY-----"""

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))

def _b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")

def check_license():
    """Retourne (valid: bool, payload: dict|None, message: str)."""
    key_str = os.getenv("ORCHESTRATEUR_LICENSE", "").strip()
    if not key_str:
        key_file = os.path.expanduser("~/.orchestrateur/license.key")
        if os.path.exists(key_file):
            with open(key_file) as f:
                key_str = f.read().strip()
    if not key_str:
        return False, None, "Aucune licence trouvée."
    parts = key_str.split(".")
    if len(parts) != 2:
        return False, None, "Format de licence invalide."
    try:
        payload_b64, sig_b64 = parts
        payload_bytes = _b64url_decode(payload_b64)
        sig_bytes     = _b64url_decode(sig_b64)
        pub_key = serialization.load_pem_public_key(_PUBLIC_KEY_PEM, backend=default_backend())
        pub_key.verify(
            sig_bytes,
            payload_b64.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        payload = json.loads(payload_bytes)
        exp = payload.get("exp", 0)
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            exp_str = datetime.fromtimestamp(exp).strftime("%d/%m/%Y")
            return False, payload, f"Licence expirée le {exp_str}."
        seats = payload.get("seats", 1)
        seats_label = f"{seats} poste{'s' if seats > 1 else ''}"
        exp_str = datetime.fromtimestamp(payload.get("exp", 0)).strftime("%d/%m/%Y") if payload.get("exp") else "∞"
        return True, payload, f"Licence valide — {payload.get('email','?')} | {payload.get('tier','?').upper()} | {seats_label} | expire {exp_str}"
    except Exception:
        return False, None, "Licence corrompue ou signature invalide."

# =============================================================================
# CLI ARGUMENTS
# =============================================================================
parser = argparse.ArgumentParser(
    description="L'Orchestrateur — Agent IA de cybersécurité",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Exemples:
  python cyber_agent.py
  python cyber_agent.py --target example.com
  python cyber_agent.py --target example.com --full
  python cyber_agent.py --target example.com --quick
    """
)
parser.add_argument("--target",   "-t", help="Cible à analyser (domaine, IP, ou CIDR ex: 192.168.1.0/24)")
parser.add_argument("--full",     action="store_true", help="Scan complet (nikto, subdomains, CVE, WAF)")
parser.add_argument("--quick",    action="store_true", help="Scan rapide (ports, DNS, headers uniquement)")
parser.add_argument("--internal", action="store_true", help="Scan réseau interne (CIDR, SMB, vulnérabilités LAN)")
parser.add_argument("--iface",    default="", help="Interface réseau pour arp_scan (ex: eth0)")
args = parser.parse_args()

SCAN_MODE = "internal" if args.internal else "full" if args.full else "quick" if args.quick else "standard"

if args.full or args.internal:
    _valid, _lic, _msg = check_license()
    if not _valid:
        mode_flag = "--full" if args.full else "--internal"
        print(f"\n{'═'*58}")
        print(f"  FONCTIONNALITÉ PRO — Licence requise")
        print(f"{'═'*58}")
        print(f"\n  Le mode {mode_flag} nécessite une licence Pro.")
        print(f"  Raison : {_msg}")
        print(f"\n  Installez votre licence :")
        print(f"    cp votre_licence.key ~/.orchestrateur/license.key")
        print(f"  Ou via variable d'environnement :")
        print(f"    export ORCHESTRATEUR_LICENSE=<clé>")
        print(f"\n{'═'*58}\n")
        sys.exit(1)
    print(f"[✓] {_msg}")

# =============================================================================
# CONFIGURATION
# =============================================================================
MODEL_NAME         = "llama3.2:3b"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

_MODE_INSTRUCTIONS = {
    "quick":    "MODE RAPIDE : Lance uniquement whois, nmap, dig, http_header, redirect_check, ssl_check, email_security.",
    "standard": "MODE STANDARD : Lance whois, nmap, dig, http_header, redirect_check, ssl_check, cookie_audit, cors_check, http_methods, email_security, virustotal, abuseipdb, waf_detect, tech_detect.",
    "full":     "MODE COMPLET : Lance TOUS les outils disponibles : whois, nmap, dig, http_header, redirect_check, ssl_check, cookie_audit, cors_check, http_methods, email_security, virustotal, abuseipdb, waf_detect, tech_detect, subdomain_enum, cve_check, nikto, dir_scan.",
    "internal": "MODE RÉSEAU INTERNE : Commence par network_discover sur le subnet pour trouver les hôtes actifs, puis lance arp_scan, service_version et smb_scan sur chaque hôte découvert. Utilise vuln_scan sur les hôtes critiques. Focus sur : protocoles non chiffrés, SMB signing, partages exposés, services admin non protégés, credentials par défaut.",
}

SYSTEM_PROMPT = f"""Tu es L'Orchestrateur, un Expert Senior en Cybersécurité (Red Team, Blue Team, OSINT) et Consultant en Conformité Réglementaire.
Ton rôle est de mener des reconnaissances méthodiques et d'aligner les résultats avec les exigences légales (ISO 27001, NIS 2 et DORA).

{_MODE_INSTRUCTIONS[SCAN_MODE]}

RÈGLES DE RAISONNEMENT :
1. ACTIONS — FORMAT STRICT : Pour lancer un outil, écris EXACTEMENT sur une ligne dédiée, sans markdown :
   ACTION: nom_outil(argument)
   Exemples valides :
   ACTION: whois(example.com)
   ACTION: nmap(192.168.1.1)
   ACTION: http_header(https://example.com)
   ACTION: cookie_audit(https://example.com)
   Tu peux écrire plusieurs lignes ACTION: consécutives pour lancer plusieurs outils.
   INTERDIT : backticks, tirets, markdown, espace avant le ":", numérotation.
2. ANALYSE HOLISTIQUE : Pour chaque vulnérabilité, analyse-la sous le prisme de l'ISO 27001, NIS 2 et DORA.
3. GAP ANALYSIS : Identifie les manquements entre l'état actuel et les exigences légales.
4. PRIORISATION : Priorise selon la criticité du risque et les sanctions encourues.
5. SYNTHÈSE : Termine TOUJOURS par 'RAPPORT FINAL :' suivi d'une synthèse complète.
6. NIVEAUX DE RISQUE : Utilise UNIQUEMENT ces 4 labels : FAIBLE, MOYEN, ÉLEVÉ, CRITIQUE.

OUTILS DISPONIBLES :
- whois(domaine)              : informations WHOIS
- ping(cible)                 : test de connectivité
- nmap(cible)                 : scan de ports (accepte CIDR ex: 192.168.1.0/24)
- dig(domaine)                : résolution DNS
- http_header(url)            : en-têtes HTTP
- ssl_check(url)              : vérification SSL/TLS
- email_security(domaine)     : vérification SPF, DKIM, DMARC
- tech_detect(url)            : détection CMS/framework/serveur
- waf_detect(url)             : détection WAF/CDN
- subdomain_enum(domaine)     : énumération de sous-domaines [FULL]
- cve_check(service)          : recherche CVE (ex: "apache 2.4") [FULL]
- virustotal(cible)           : réputation VirusTotal
- abuseipdb(ip)               : score d'abus IP
- nikto(cible)                : scan de vulnérabilités web [FULL]
- dir_scan(url)               : scan de répertoires sensibles [FULL]
- sherlock(pseudo)            : OSINT réseaux sociaux
- cookie_audit(url)           : vérification flags sécurité cookies (HttpOnly, Secure, SameSite) [STANDARD/FULL]
- cors_check(url)             : test misconfiguration CORS (origine evil.com) [STANDARD/FULL]
- http_methods(url)           : méthodes HTTP autorisées (PUT, DELETE, TRACE) [STANDARD/FULL]
- redirect_check(url)         : vérification redirection HTTP→HTTPS et HSTS [STANDARD/FULL]
- network_discover(subnet)    : découverte des hôtes actifs sur un subnet CIDR [INTERNAL]
- arp_scan(subnet)            : scan ARP local pour hôtes actifs [INTERNAL]
- service_version(ip)         : détection versions services + OS (nmap -sV -O) [INTERNAL]
- smb_scan(ip)                : audit SMB : signing, partages, authentification [INTERNAL]
- vuln_scan(ip)               : scan de vulnérabilités NSE (EternalBlue, etc.) [INTERNAL]
"""

MEMORY      = [{"role": "system", "content": SYSTEM_PROMPT}]
SESSION_LOG = []

# =============================================================================
# SPINNER
# =============================================================================
class Spinner:
    def __init__(self, msg="Analyse en cours"):
        self.msg      = msg
        self._running = False
        self._thread  = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        for c in itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"):
            if not self._running:
                break
            print(f"\r{c} {self.msg}", end="", flush=True)
            time.sleep(0.1)
        print("\r" + " " * (len(self.msg) + 4) + "\r", end="", flush=True)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join()

# =============================================================================
# SÉCURITÉ
# =============================================================================
def clean_input(target):
    return re.sub(r"[^a-zA-Z0-9.\-_/:]", "", target)

# =============================================================================
# OUTILS SYSTÈME
# =============================================================================
def run_whois(target):
    t = clean_input(target)
    print(f"[*] Whois -> {t}...")
    try: return subprocess.check_output(["whois", t], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_ping(target):
    t = clean_input(target)
    print(f"[*] Ping -> {t}...")
    try: return subprocess.check_output(["ping", "-c", "1", t], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_nmap(target):
    t = clean_input(target)
    print(f"[*] Nmap -> {t}...")
    try: return subprocess.check_output(["nmap", "-F", t], stderr=subprocess.STDOUT, text=True, timeout=60)
    except Exception as e: return f"Erreur: {e}"

def run_dig(target):
    t = clean_input(target)
    print(f"[*] Dig -> {t}...")
    try: return subprocess.check_output(["dig", t, "ANY"], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_http_header(target):
    t = clean_input(target)
    print(f"[*] HTTP Headers -> {t}...")
    try:
        url = t if t.startswith("http") else f"https://{t}"
        # Follow redirects to get final headers, capture cookies too
        return subprocess.check_output(
            ["curl", "-sI", "-L", "--max-redirs", "5", url],
            stderr=subprocess.STDOUT, text=True, timeout=15
        )
    except Exception as e: return f"Erreur: {e}"

def run_ssl_check(target):
    t = clean_input(target)
    print(f"[*] SSL/TLS -> {t}...")
    try:
        host = t.replace("http://", "").replace("https://", "").split('/')[0]
        return subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host],
            stderr=subprocess.STDOUT, text=True, timeout=15
        )[:1500]
    except Exception as e: return f"Erreur SSL: {e}"

def run_nikto(target):
    t = clean_input(target)
    print(f"[*] Nikto -> {t}...")
    try: return subprocess.check_output(["nikto", "-h", t, "-T5"], stderr=subprocess.STDOUT, text=True, timeout=300)
    except Exception as e: return f"Erreur Nikto: {e}"

def run_dir_scan(target):
    t = clean_input(target)
    print(f"[*] Dir Scan -> {t}...")
    dirs = [
        "admin", "login", "wp-admin", "wp-login.php", "wp-config.php",
        ".env", ".git/config", ".git/HEAD", ".htaccess", ".DS_Store",
        "backup", "backup.zip", "backup.sql", "db.sql",
        "phpmyadmin", "pma", "myadmin",
        "config.php", "config.js", "config.json", "settings.php",
        "phpinfo.php", "info.php", "test.php", "debug.php",
        "api/v1", "api/v2", "api/swagger.json", "swagger.json",
        "swagger-ui.html", "api-docs", "openapi.json",
        "composer.json", "package.json",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "xmlrpc.php", "server-status", "server-info",
        ".well-known/security.txt",
    ]
    found, missing_security_txt = [], True
    url = t if t.startswith("http") else f"https://{t}"
    for d in dirs:
        try:
            code = subprocess.check_output(
                ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{url}/{d}"],
                text=True, timeout=5
            )
            if code in ("200", "301", "302"):
                tag = f"[{code}]"
                found.append(f"{url}/{d} {tag}")
            if d == ".well-known/security.txt" and code == "200":
                missing_security_txt = False
        except: continue
    if missing_security_txt:
        found.append("security.txt: ABSENT (/.well-known/security.txt)")
    return "\n".join(found) if found else "Aucun répertoire sensible trouvé."

def run_sherlock(username):
    u = clean_input(username)
    print(f"[*] Sherlock -> {u}...")
    try: return subprocess.check_output(["sherlock", u, "--timeout", "5"], stderr=subprocess.STDOUT, text=True, timeout=300)
    except Exception as e: return f"Erreur Sherlock: {e}"

def run_cookie_audit(target):
    t = clean_input(target)
    print(f"[*] Cookie Audit -> {t}...")
    try:
        url = t if t.startswith("http") else f"https://{t}"
        result = subprocess.check_output(
            ["curl", "-sI", "-L", "--max-redirs", "5", url],
            text=True, timeout=15
        )
        cookies, issues = [], []
        for line in result.split('\n'):
            if line.lower().startswith("set-cookie:"):
                cookies.append(line.strip())
                c = line.lower()
                if "httponly" not in c: issues.append(f"MISSING HttpOnly: {line.strip()[:100]}")
                if "secure"   not in c: issues.append(f"MISSING Secure: {line.strip()[:100]}")
                if "samesite" not in c: issues.append(f"MISSING SameSite: {line.strip()[:100]}")
        if not cookies:
            return "Aucun cookie Set-Cookie trouvé dans la réponse."
        return "\n".join(cookies[:8]) + ("\n\n[ISSUES]\n" + "\n".join(issues) if issues else "\n[OK] Tous les flags présents.")
    except Exception as e: return f"Erreur cookie_audit: {e}"

def run_cors_check(target):
    t = clean_input(target)
    print(f"[*] CORS Check -> {t}...")
    try:
        url = t if t.startswith("http") else f"https://{t}"
        result = subprocess.check_output(
            ["curl", "-sI", "-H", "Origin: https://evil.com", "-H", "Access-Control-Request-Method: GET", url],
            text=True, timeout=15
        )
        cors = [l.strip() for l in result.split('\n') if l.lower().startswith("access-control-")]
        if not cors:
            return "Aucun header CORS retourné (Access-Control-* absent)."
        return "\n".join(cors)
    except Exception as e: return f"Erreur cors_check: {e}"

def run_http_methods(target):
    t = clean_input(target)
    print(f"[*] HTTP Methods -> {t}...")
    try:
        url = t if t.startswith("http") else f"https://{t}"
        result = subprocess.check_output(
            ["curl", "-sI", "-X", "OPTIONS", url],
            text=True, timeout=15
        )
        for line in result.split('\n'):
            if line.lower().startswith("allow:") or line.lower().startswith("access-control-allow-methods:"):
                return line.strip()
        # Try TRACE directly
        trace = subprocess.check_output(
            ["curl", "-sI", "-X", "TRACE", url],
            text=True, timeout=10
        )
        first_line = trace.split('\n')[0].strip()
        if "200" in first_line:
            return f"TRACE: 200 OK — TRACE activé (vulnérable XST)\n{first_line}"
        return f"Allow: header absent — OPTIONS: {trace.split(chr(10))[0].strip()}"
    except Exception as e: return f"Erreur http_methods: {e}"

def run_redirect_check(target):
    t = clean_input(target)
    print(f"[*] Redirect Check -> {t}...")
    host = t.replace("https://","").replace("http://","").split('/')[0]
    results = []
    try:
        # Check HTTP→HTTPS redirect
        r = subprocess.check_output(
            ["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", f"http://{host}"],
            text=True, timeout=10
        )
        code, redir = (r.split(" ", 1) + [""])[:2]
        if code in ("301","302","307","308") and "https" in redir.lower():
            results.append(f"HTTP→HTTPS: OK (redirect {code} vers {redir.strip()})")
        elif code == "200":
            results.append(f"HTTP→HTTPS: ABSENT — HTTP répond 200 sans redirection vers HTTPS")
        else:
            results.append(f"HTTP→HTTPS: code {code}, redirect: {redir.strip()}")
        # Check HSTS preload
        r2 = subprocess.check_output(
            ["curl", "-sI", f"https://{host}"],
            text=True, timeout=10
        )
        hsts = next((l.strip() for l in r2.split('\n') if "strict-transport-security" in l.lower()), None)
        results.append(f"HSTS: {hsts if hsts else 'ABSENT ⚠️'}")
    except Exception as e:
        results.append(f"Erreur redirect_check: {e}")
    return "\n".join(results)

def run_network_discover(subnet):
    t = clean_input(subnet)
    print(f"[*] Network Discover -> {t}...")
    try:
        return subprocess.check_output(["nmap", "-sn", "-T4", t], stderr=subprocess.STDOUT, text=True, timeout=120)
    except Exception as e:
        return f"Erreur network_discover: {e}"

def run_arp_scan(subnet):
    t = clean_input(subnet)
    iface = args.iface or ""
    print(f"[*] ARP Scan -> {t}...")
    try:
        cmd = ["arp-scan", "--localnet"]
        if iface:
            cmd += ["-I", iface]
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=30)
    except FileNotFoundError:
        try:
            cmd = ["nmap", "-sn", "-PR", "-T4", t]
            return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=60)
        except Exception as e:
            return f"Erreur arp_scan (arp-scan non installé): {e}"
    except Exception as e:
        return f"Erreur arp_scan: {e}"

def run_service_version(target):
    t = clean_input(target)
    print(f"[*] Service Version -> {t}...")
    try:
        return subprocess.check_output(
            ["nmap", "-sV", "-O", "--top-ports", "200", "-T4", t],
            stderr=subprocess.STDOUT, text=True, timeout=180
        )
    except Exception as e:
        return f"Erreur service_version: {e}"

def run_smb_scan(target):
    t = clean_input(target)
    print(f"[*] SMB Scan -> {t}...")
    try:
        return subprocess.check_output(
            ["nmap", "-p", "139,445", "-T4",
             "--script", "smb-security-mode,smb2-security-mode,smb-enum-shares,smb-vuln-ms17-010,smb-vuln-ms08-067",
             t],
            stderr=subprocess.STDOUT, text=True, timeout=120
        )
    except Exception as e:
        return f"Erreur smb_scan: {e}"

def run_vuln_scan(target):
    t = clean_input(target)
    print(f"[*] Vuln Scan (NSE) -> {t}...")
    try:
        return subprocess.check_output(
            ["nmap", "-sV", "--script", "vuln", "-T4", "--open", t],
            stderr=subprocess.STDOUT, text=True, timeout=300
        )
    except Exception as e:
        return f"Erreur vuln_scan: {e}"

def run_email_security(domain):
    d = clean_input(domain)
    print(f"[*] Email Security (SPF/DKIM/DMARC) -> {d}...")
    results = []
    try:
        spf = subprocess.check_output(["dig", "+short", "TXT", d], text=True, timeout=10)
        spf_r = [l for l in spf.split('\n') if 'v=spf1' in l]
        results.append(f"SPF: {spf_r[0].strip() if spf_r else 'ABSENT ⚠️'}")

        dmarc = subprocess.check_output(["dig", "+short", "TXT", f"_dmarc.{d}"], text=True, timeout=10)
        dmarc_r = [l for l in dmarc.split('\n') if 'v=DMARC1' in l]
        results.append(f"DMARC: {dmarc_r[0].strip() if dmarc_r else 'ABSENT ⚠️'}")

        dkim_found = False
        for selector in ["default", "google", "k1", "mail", "dkim"]:
            try:
                dkim = subprocess.check_output(
                    ["dig", "+short", "TXT", f"{selector}._domainkey.{d}"],
                    text=True, timeout=5
                ).strip()
                if dkim:
                    results.append(f"DKIM ({selector}): {dkim[:80]}")
                    dkim_found = True
                    break
            except: continue
        if not dkim_found:
            results.append("DKIM: Non détecté")
    except Exception as e:
        return f"Erreur email_security: {e}"
    return "\n".join(results)

def run_tech_detect(target):
    t = clean_input(target)
    print(f"[*] Tech Detect -> {t}...")
    try:
        return subprocess.check_output(["whatweb", "-a", "3", t], stderr=subprocess.STDOUT, text=True, timeout=30)
    except FileNotFoundError:
        try:
            url = t if t.startswith("http") else f"https://{t}"
            result = subprocess.check_output(["curl", "-sI", url], text=True, timeout=15)
            techs = []
            for line in result.split('\n'):
                if line.lower().startswith("server:"):    techs.append(line.strip())
                if line.lower().startswith("x-powered-by:"): techs.append(line.strip())
                if "wordpress" in line.lower():           techs.append("CMS: WordPress")
                if "drupal"    in line.lower():           techs.append("CMS: Drupal")
                if "joomla"    in line.lower():           techs.append("CMS: Joomla")
            return "\n".join(dict.fromkeys(techs)) if techs else "Technologies non identifiées."
        except Exception as e:
            return f"Erreur tech_detect: {e}"
    except Exception as e:
        return f"Erreur whatweb: {e}"

def run_waf_detect(target):
    t = clean_input(target)
    print(f"[*] WAF Detect -> {t}...")
    try:
        return subprocess.check_output(["wafw00f", t], stderr=subprocess.STDOUT, text=True, timeout=30)
    except FileNotFoundError:
        try:
            url = t if t.startswith("http") else f"https://{t}"
            result = subprocess.check_output(["curl", "-sI", url], text=True, timeout=15)
            waf_map = {
                "cf-ray":        "Cloudflare",
                "x-sucuri-id":   "Sucuri",
                "x-cache":       "CDN/Cache",
                "x-varnish":     "Varnish",
                "x-amz-cf-id":   "AWS CloudFront",
                "x-fastly":      "Fastly",
                "x-akamai":      "Akamai",
            }
            detected = [name for header, name in waf_map.items() if header in result.lower()]
            return f"WAF/CDN détecté : {', '.join(set(detected))}" if detected else "Aucun WAF/CDN détecté."
        except Exception as e:
            return f"Erreur waf_detect: {e}"
    except Exception as e:
        return f"Erreur wafw00f: {e}"

def run_subdomain_enum(domain):
    d = clean_input(domain)
    print(f"[*] Subdomain Enum -> {d}...")
    wordlist = ["www","mail","ftp","remote","blog","webmail","server","ns1","ns2",
                "smtp","secure","vpn","m","shop","api","dev","staging","admin",
                "portal","intranet","app","web","cdn","static","media","auth"]
    found = []
    for sub in wordlist:
        try:
            result = subprocess.check_output(
                ["dig", "+short", f"{sub}.{d}"],
                stderr=subprocess.DEVNULL, text=True, timeout=5
            ).strip()
            if result:
                found.append(f"{sub}.{d} → {result.split()[0]}")
        except: continue
    return "\n".join(found) if found else f"Aucun sous-domaine trouvé pour {d}."

def run_cve_check(service_query):
    s = service_query.strip()
    print(f"[*] CVE Check -> {s}...")
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": s, "resultsPerPage": 5},
            timeout=20
        )
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            if not vulns:
                return f"Aucun CVE trouvé pour '{s}'."
            results = []
            for v in vulns:
                cve     = v.get("cve", {})
                cve_id  = cve.get("id", "?")
                desc    = cve.get("descriptions", [{}])[0].get("value", "")[:150]
                metrics = cve.get("metrics", {})
                score   = "?"
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", "?")
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", "?")
                results.append(f"{cve_id} (CVSS {score}) — {desc}")
            return "\n".join(results)
        return f"CVE API: HTTP {r.status_code}"
    except Exception as e:
        return f"Erreur CVE: {e}"

# =============================================================================
# OUTILS API EXTERNE
# =============================================================================
def run_virustotal(target):
    t = clean_input(target)
    print(f"[*] VirusTotal -> {t}...")
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal: VIRUSTOTAL_API_KEY non configurée."
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{t}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=15
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return (f"VirusTotal [{t}]: Malicious={stats.get('malicious',0)}, "
                    f"Suspicious={stats.get('suspicious',0)}, Harmless={stats.get('harmless',0)}")
        return f"VirusTotal: HTTP {r.status_code}"
    except Exception as e:
        return f"Erreur VirusTotal: {e}"

def run_abuseipdb(target):
    t = clean_input(target)
    print(f"[*] AbuseIPDB -> {t}...")
    if not ABUSEIPDB_API_KEY:
        return "AbuseIPDB: ABUSEIPDB_API_KEY non configurée."
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": t, "maxAgeInDays": 90}, timeout=15
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return (f"AbuseIPDB [{t}]: Score={d.get('abuseConfidenceScore',0)}%, "
                    f"Reports={d.get('totalReports',0)}, Country={d.get('countryCode','?')}")
        return f"AbuseIPDB: HTTP {r.status_code}"
    except Exception as e:
        return f"Erreur AbuseIPDB: {e}"

TOOLS = {
    "whois":            run_whois,
    "ping":             run_ping,
    "nmap":             run_nmap,
    "dig":              run_dig,
    "http_header":      run_http_header,
    "ssl_check":        run_ssl_check,
    "email_security":   run_email_security,
    "tech_detect":      run_tech_detect,
    "waf_detect":       run_waf_detect,
    "subdomain_enum":   run_subdomain_enum,
    "cve_check":        run_cve_check,
    "virustotal":       run_virustotal,
    "abuseipdb":        run_abuseipdb,
    "nikto":            run_nikto,
    "dir_scan":         run_dir_scan,
    "sherlock":         run_sherlock,
    "cookie_audit":     run_cookie_audit,
    "cors_check":       run_cors_check,
    "http_methods":     run_http_methods,
    "redirect_check":   run_redirect_check,
    "network_discover": run_network_discover,
    "arp_scan":         run_arp_scan,
    "service_version":  run_service_version,
    "smb_scan":         run_smb_scan,
    "vuln_scan":        run_vuln_scan,
}

# =============================================================================
# MITRE ATT&CK MAPPING — parser déterministe (tous les outils)
# =============================================================================
_PORT_RULES = [
    {"port": "3389",  "technique": "T1021.001", "name": "Remote Desktop Protocol exposé",           "tactic": "Lateral Movement",  "severity": "HIGH"},
    {"port": "22",    "technique": "T1021.004", "name": "SSH exposé",                               "tactic": "Lateral Movement",  "severity": "MEDIUM"},
    {"port": "21",    "technique": "T1071.002", "name": "FTP en clair exposé",                       "tactic": "Command & Control", "severity": "HIGH"},
    {"port": "445",   "technique": "T1021.002", "name": "SMB exposé — risque ransomware",            "tactic": "Lateral Movement",  "severity": "CRITICAL"},
    {"port": "139",   "technique": "T1021.002", "name": "NetBIOS/SMB exposé",                        "tactic": "Lateral Movement",  "severity": "HIGH"},
    {"port": "23",    "technique": "T1021",     "name": "Telnet en clair exposé",                    "tactic": "Lateral Movement",  "severity": "CRITICAL"},
    {"port": "3306",  "technique": "T1190",     "name": "MySQL exposé",                              "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "5432",  "technique": "T1190",     "name": "PostgreSQL exposé",                         "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "27017", "technique": "T1190",     "name": "MongoDB exposé",                            "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "6379",  "technique": "T1190",     "name": "Redis exposé",                              "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "9200",  "technique": "T1190",     "name": "Elasticsearch exposé",                      "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "2375",  "technique": "T1190",     "name": "Docker API exposé (sans TLS)",              "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "5900",  "technique": "T1021.005", "name": "VNC exposé — accès bureau distant non chiffré","tactic": "Lateral Movement", "severity": "CRITICAL"},
    {"port": "5985",  "technique": "T1021.006", "name": "WinRM HTTP exposé",                         "tactic": "Lateral Movement",  "severity": "HIGH"},
    {"port": "5986",  "technique": "T1021.006", "name": "WinRM HTTPS exposé",                        "tactic": "Lateral Movement",  "severity": "HIGH"},
    {"port": "161",   "technique": "T1046",     "name": "SNMP exposé — community string possible",   "tactic": "Discovery",         "severity": "HIGH"},
    {"port": "623",   "technique": "T1190",     "name": "IPMI exposé — accès BMC sans auth possible", "tactic": "Initial Access",   "severity": "CRITICAL"},
    {"port": "502",   "technique": "T1190",     "name": "Modbus exposé (protocole ICS/SCADA)",        "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "47808", "technique": "T1190",     "name": "BACnet exposé (protocole ICS/SCADA)",        "tactic": "Initial Access",    "severity": "CRITICAL"},
    {"port": "4786",  "technique": "T1190",     "name": "Cisco Smart Install exposé — RCE sans auth", "tactic": "Initial Access",   "severity": "CRITICAL"},
    {"port": "1900",  "technique": "T1046",     "name": "UPnP exposé — découverte réseau activée",    "tactic": "Discovery",         "severity": "MEDIUM"},
    {"port": "631",   "technique": "T1046",     "name": "CUPS (impression) exposé",                  "tactic": "Discovery",         "severity": "LOW"},
    {"port": "2049",  "technique": "T1039",     "name": "NFS exposé — partage réseau sans auth",      "tactic": "Collection",        "severity": "CRITICAL"},
    {"port": "111",   "technique": "T1046",     "name": "RPC Portmapper exposé",                     "tactic": "Discovery",         "severity": "MEDIUM"},
    {"port": "512",   "technique": "T1021",     "name": "rexec exposé (service Unix obsolète)",       "tactic": "Lateral Movement",  "severity": "CRITICAL"},
    {"port": "513",   "technique": "T1021",     "name": "rlogin exposé (service Unix obsolète)",      "tactic": "Lateral Movement",  "severity": "CRITICAL"},
    {"port": "514",   "technique": "T1021",     "name": "rsh exposé (service Unix obsolète)",         "tactic": "Lateral Movement",  "severity": "CRITICAL"},
]
_KNOWN_PORTS    = {r["port"] for r in _PORT_RULES}
_WEB_PORTS_SKIP = {"80", "443", "8080", "8443"}

def _section(log_text, tool_name):
    m = re.search(rf"=== {tool_name} \(.*?\) ===\n(.*?)(?====|\Z)", log_text, re.DOTALL | re.IGNORECASE)
    return m.group(1) if m else None

def map_to_mitre(log_text):
    seen, findings = set(), []

    def add(uid, technique, name, tactic, severity, source="", evidence=""):
        if uid not in seen:
            seen.add(uid)
            findings.append({"technique": technique, "name": name, "tactic": tactic,
                             "severity": severity, "source": source, "evidence": evidence,
                             "_uid": uid})

    # ── NMAP : ports dangereux connus ────────────────────────────────────────
    for rule in _PORT_RULES:
        if f"{rule['port']}/tcp" in log_text:
            m = re.search(rf"{rule['port']}/tcp\s+\S+\s+\S+", log_text)
            add(rule["technique"], rule["technique"], rule["name"], rule["tactic"],
                rule["severity"], "Nmap", m.group(0) if m else f"{rule['port']}/tcp ouvert")

    # ── NMAP : autres ports ouverts (hors 80/443/8080/8443) ──────────────────
    for port, service in re.findall(r"(\d+)/tcp\s+open\s+(\S+)", log_text):
        if port not in _KNOWN_PORTS and port not in _WEB_PORTS_SKIP:
            m = re.search(rf"{port}/tcp\s+open\s+\S+", log_text)
            sev = "MEDIUM" if service in ("ftp","smtp","imap","pop3","telnet") else "LOW"
            add(f"T1046-{port}", "T1046", f"Port {port}/tcp ouvert ({service})", "Discovery",
                sev, "Nmap", m.group(0) if m else f"{port}/tcp open {service}")

    # ── HTTP HEADERS ─────────────────────────────────────────────────────────
    hdr = _section(log_text, "HTTP_HEADER")
    if hdr:
        h = hdr.lower()
        if "x-frame-options"           not in h: add("T1189",       "T1189",     "X-Frame-Options manquant",           "Initial Access",    "MEDIUM", "HTTP Headers", "X-Frame-Options: [absent]")
        if "strict-transport-security" not in h: add("T1557-hsts",  "T1557",     "HSTS manquant",                      "Credential Access", "MEDIUM", "HTTP Headers", "Strict-Transport-Security: [absent]")
        if "content-security-policy"   not in h: add("T1059-csp",   "T1059.007", "Content-Security-Policy manquant",   "Execution",         "MEDIUM", "HTTP Headers", "Content-Security-Policy: [absent]")
        if "x-content-type-options"    not in h: add("T1566-xcto",  "T1566",     "X-Content-Type-Options manquant",    "Defense Evasion",   "LOW",    "HTTP Headers", "X-Content-Type-Options: [absent]")
        if "referrer-policy"           not in h: add("T1003-refpol","T1003",     "Referrer-Policy manquant",           "Credential Access", "LOW",    "HTTP Headers", "Referrer-Policy: [absent]")
        if "permissions-policy"        not in h: add("T1003-perms", "T1003",     "Permissions-Policy manquant",        "Collection",        "LOW",    "HTTP Headers", "Permissions-Policy: [absent]")
        # CSP unsafe-inline / unsafe-eval — CSP présente mais trop permissive
        csp_val = re.search(r"content-security-policy:\s*([^\r\n]+)", hdr, re.IGNORECASE)
        if csp_val:
            cv = csp_val.group(1).lower()
            if "unsafe-inline" in cv or "unsafe-eval" in cv:
                add("T1059-csp-unsafe", "T1059.007", "CSP avec 'unsafe-inline' ou 'unsafe-eval' — XSS possible", "Execution", "MEDIUM", "HTTP Headers", csp_val.group(0)[:100])
        # Server version disclosure
        srv = re.search(r"server:\s*(\S[^\r\n]*)", hdr, re.IGNORECASE)
        if srv:
            sv = srv.group(1).strip()
            if re.search(r"apache|nginx|iis|php|lighttpd|tomcat|jetty|openresty", sv, re.IGNORECASE):
                add("T1190-srv", "T1190", f"Version serveur divulguée ({sv[:40]})", "Initial Access", "LOW", "HTTP Headers", f"Server: {sv[:80]}")
            if re.search(r"apache/2\.[0-3]\.|nginx/1\.[0-9]\b|php/[45]\.|iis/[5-8]\.", sv, re.IGNORECASE):
                add("T1190-srv-eol", "T1190", f"Version serveur obsolète ({sv[:40]})", "Initial Access", "MEDIUM", "HTTP Headers", f"Server: {sv[:80]}")
        # X-Powered-By disclosure
        xpb = re.search(r"x-powered-by:\s*(\S[^\r\n]*)", hdr, re.IGNORECASE)
        if xpb:
            add("T1190-xpb", "T1190", f"X-Powered-By divulgué ({xpb.group(1).strip()[:40]})", "Initial Access", "LOW", "HTTP Headers", f"X-Powered-By: {xpb.group(1).strip()[:80]}")

    # ── REDIRECT CHECK ───────────────────────────────────────────────────────
    redir = _section(log_text, "REDIRECT_CHECK")
    if redir:
        r = redir.lower()
        if "absent" in r and "http→https" in r:
            ev = next((l.strip() for l in redir.split('\n') if "absent" in l.lower()), "HTTP répond sans redirection HTTPS")
            add("T1557-noredir", "T1557", "Pas de redirection HTTP→HTTPS — credentials en clair possibles", "Credential Access", "HIGH", "Redirect Check", ev[:120])
        if "hsts: absent" in r:
            add("T1557-hsts-rd", "T1557", "HSTS absent (confirmé par redirect_check)", "Credential Access", "MEDIUM", "Redirect Check", "HSTS: ABSENT ⚠️")

    # ── CORS CHECK ───────────────────────────────────────────────────────────
    cors = _section(log_text, "CORS_CHECK")
    if cors:
        c = cors.lower()
        if "access-control-allow-origin" in c:
            origin_line = next((l.strip() for l in cors.split('\n') if "access-control-allow-origin" in l.lower()), "")
            if "*" in origin_line or "evil.com" in origin_line:
                add("T1190-cors", "T1190", "CORS misconfiguration — toute origine acceptée", "Initial Access", "HIGH", "CORS Check", origin_line[:120])
            elif origin_line:
                add("T1190-cors-origin", "T1190", "CORS origin reflection — vérifier la politique", "Initial Access", "MEDIUM", "CORS Check", origin_line[:120])
        if "access-control-allow-credentials: true" in c:
            add("T1539-cors-cred", "T1539", "CORS + credentials=true — cookies volables cross-origin", "Credential Access", "CRITICAL", "CORS Check", "Access-Control-Allow-Credentials: true")

    # ── COOKIE AUDIT ─────────────────────────────────────────────────────────
    cookie = _section(log_text, "COOKIE_AUDIT")
    if cookie and "set-cookie" in cookie.lower():
        ck = cookie.lower()
        if "missing httponly" in ck:
            ev = next((l.strip() for l in cookie.split('\n') if "MISSING HttpOnly" in l), "Cookie sans flag HttpOnly")
            add("T1539-httponly", "T1539", "Cookie sans HttpOnly — vol de session possible via XSS", "Credential Access", "HIGH", "Cookie Audit", ev[:120])
        if "missing secure" in ck:
            ev = next((l.strip() for l in cookie.split('\n') if "MISSING Secure" in l), "Cookie sans flag Secure")
            add("T1557-cookie-sec", "T1557", "Cookie sans flag Secure — transmis en HTTP en clair", "Credential Access", "HIGH", "Cookie Audit", ev[:120])
        if "missing samesite" in ck:
            ev = next((l.strip() for l in cookie.split('\n') if "MISSING SameSite" in l), "Cookie sans flag SameSite")
            add("T1185-samesite", "T1185", "Cookie sans SameSite — attaque CSRF possible", "Collection", "MEDIUM", "Cookie Audit", ev[:120])

    # ── HTTP METHODS ─────────────────────────────────────────────────────────
    methods = _section(log_text, "HTTP_METHODS")
    if methods:
        m = methods.lower()
        if "trace" in m and ("200" in m or "allow" in m):
            add("T1040-trace", "T1040", "Méthode TRACE activée — Cross-Site Tracing (XST) possible", "Credential Access", "MEDIUM", "HTTP Methods", methods.strip()[:120])
        if re.search(r'\bput\b', m) and "allow" in m:
            add("T1190-put", "T1190", "Méthode PUT autorisée — upload de fichiers possible", "Initial Access", "HIGH", "HTTP Methods", methods.strip()[:120])
        if re.search(r'\bdelete\b', m) and "allow" in m:
            add("T1190-delete", "T1190", "Méthode DELETE autorisée — suppression de ressources possible", "Impact", "MEDIUM", "HTTP Methods", methods.strip()[:120])

    # ── SSL / TLS ────────────────────────────────────────────────────────────
    ssl = _section(log_text, "SSL_CHECK")
    if ssl:
        s = ssl.lower()
        if "tlsv1 " in s or "tlsv1.0" in s:
            ev = next((l.strip() for l in ssl.split('\n') if 'tlsv1' in l.lower()), "TLSv1.0 détecté")
            add("T1557-tls10", "T1557", "TLS 1.0 activé (protocole obsolète)",    "Credential Access", "HIGH",     "SSL Check", ev)
        if "tlsv1.1" in s:
            ev = next((l.strip() for l in ssl.split('\n') if 'tlsv1.1' in l.lower()), "TLSv1.1 détecté")
            add("T1557-tls11", "T1557", "TLS 1.1 activé (protocole obsolète)",    "Credential Access", "MEDIUM",   "SSL Check", ev)
        if "self signed" in s:
            add("T1557-self",  "T1557", "Certificat SSL auto-signé",              "Credential Access", "HIGH",     "SSL Check", "verify error: self signed certificate")
        if "certificate verify failed" in s or ("expired" in s and "cert" in s):
            add("T1557-exp",   "T1557", "Certificat SSL expiré ou invalide",      "Credential Access", "CRITICAL", "SSL Check", "Certificate verify failed / expired")

    # ── EMAIL SECURITY ───────────────────────────────────────────────────────
    email = _section(log_text, "EMAIL_SECURITY")
    if email:
        e = email.lower()
        def _eline(kw): return next((l.strip() for l in email.split('\n') if kw.lower() in l.lower()), kw)
        if "spf: absent"        in e: add("T1598-spf",        "T1598", "SPF absent — usurpation email possible",    "Reconnaissance", "HIGH",   "Email Security", _eline("SPF:"))
        if "dmarc: absent"      in e: add("T1598-dmarc",      "T1598", "DMARC absent — phishing non bloqué",        "Reconnaissance", "HIGH",   "Email Security", _eline("DMARC:"))
        elif "p=none"           in e: add("T1598-dmarc-none", "T1598", "DMARC en mode surveillance seulement",      "Reconnaissance", "MEDIUM", "Email Security", _eline("DMARC:"))
        if "dkim: non détecté"  in e: add("T1598-dkim",       "T1598", "DKIM absent — intégrité email non vérifiée","Reconnaissance", "MEDIUM", "Email Security", "DKIM: Non détecté")

    # ── SUBDOMAIN ENUM ───────────────────────────────────────────────────────
    subs = _section(log_text, "SUBDOMAIN_ENUM")
    if subs:
        dev_l = [l for l in subs.split('\n') if re.search(r'\b(?:dev|staging|test|demo)\.', l)]
        adm_l = [l for l in subs.split('\n') if re.search(r'\b(?:admin|cpanel|panel|manager)\.', l)]
        ftp_l = [l for l in subs.split('\n') if re.search(r'\b(?:ftp|sftp)\.', l)]
        if dev_l: add("T1583-dev", "T1583",     "Environnement dev/staging exposé publiquement",  "Resource Development", "CRITICAL", "Subdomain Enum", dev_l[0].strip())
        if adm_l: add("T1583-adm", "T1583",     "Interface admin exposée via sous-domaine public", "Initial Access",      "CRITICAL", "Subdomain Enum", adm_l[0].strip())
        if ftp_l: add("T1583-ftp", "T1071.002", "Sous-domaine FTP exposé",                         "Command & Control",   "HIGH",     "Subdomain Enum", ftp_l[0].strip())

    # ── CVE CHECK ────────────────────────────────────────────────────────────
    cve_sec = _section(log_text, "CVE_CHECK")
    if cve_sec:
        for score_str in re.findall(r"CVSS\s+([\d.]+)", cve_sec):
            try:
                s = float(score_str)
                ev = next((l.strip() for l in cve_sec.split('\n') if score_str in l), f"CVSS {score_str}")[:100]
                if   s >= 9.0: add(f"T1190-cve9-{score_str}", "T1190", f"CVE critique (CVSS {score_str})", "Initial Access", "CRITICAL", "CVE Check", ev); break
                elif s >= 7.0: add(f"T1190-cve7-{score_str}", "T1190", f"CVE élevé (CVSS {score_str})",   "Initial Access", "HIGH",     "CVE Check", ev); break
                elif s >= 4.0: add(f"T1190-cve4-{score_str}", "T1190", f"CVE modéré (CVSS {score_str})",  "Initial Access", "MEDIUM",   "CVE Check", ev); break
            except: continue

    # ── VIRUSTOTAL ───────────────────────────────────────────────────────────
    vt_l = next((l.strip() for l in log_text.split('\n') if 'VirusTotal' in l and 'Malicious=' in l), "")
    m = re.search(r"Malicious=(\d+)", vt_l)
    if m and int(m.group(1)) > 0:
        add("T1583-vt",     "T1583", "Réputation malveillante VirusTotal",  "Resource Development", "CRITICAL", "VirusTotal", vt_l[:80])
    m = re.search(r"Suspicious=(\d+)", vt_l)
    if m and int(m.group(1)) > 0:
        add("T1583-vt-sus", "T1583", "Réputation suspecte VirusTotal",      "Resource Development", "HIGH",     "VirusTotal", vt_l[:80])

    # ── ABUSEIPDB ────────────────────────────────────────────────────────────
    ab_l = next((l.strip() for l in log_text.split('\n') if 'AbuseIPDB' in l and 'Score=' in l), "")
    m = re.search(r"Score=(\d+)%", ab_l) or re.search(r"abuseConfidenceScore[\":\s]+(\d+)", log_text)
    if m:
        sc = int(m.group(1))
        if   sc > 50: add("T1583-abuse-h", "T1583", f"IP à réputation abusive élevée ({sc}%)",  "Resource Development", "HIGH",   "AbuseIPDB", ab_l[:80])
        elif sc > 20: add("T1583-abuse-m", "T1583", f"IP à réputation abusive modérée ({sc}%)", "Resource Development", "MEDIUM", "AbuseIPDB", ab_l[:80])

    # ── DIR SCAN — fichiers sensibles spécifiques ────────────────────────────
    dirs2 = _section(log_text, "DIR_SCAN")
    if dirs2:
        def _dline(kw): return next((l.strip() for l in dirs2.split('\n') if kw in l), kw)
        if ".env [200"          in dirs2: add("T1552-env",   "T1552", "Fichier .env accessible publiquement",        "Credential Access", "CRITICAL", "Dir Scan", _dline(".env"))
        if ".git/config [200"   in dirs2 or ".git/HEAD [200" in dirs2:
            add("T1552-git",  "T1552", "Dépôt .git accessible publiquement",          "Credential Access", "CRITICAL", "Dir Scan", _dline(".git"))
        if "phpmyadmin [200"    in dirs2 or "/pma [200" in dirs2:
            add("T1190-pma",  "T1190", "phpMyAdmin exposé publiquement",               "Initial Access",    "CRITICAL", "Dir Scan", _dline("pma"))
        if "wp-admin [200"      in dirs2 or "admin [200" in dirs2:
            ev = next((l.strip() for l in dirs2.split('\n') if ('wp-admin' in l or '/admin' in l) and '200' in l), '/admin [200]')
            add("T1078-adm",  "T1078", "Interface d'administration web exposée",        "Initial Access",    "HIGH",     "Dir Scan", ev)
        if "wp-config.php [200" in dirs2:
            add("T1552-wpcfg","T1552", "wp-config.php exposé — credentials BDD",        "Credential Access", "CRITICAL", "Dir Scan", _dline("wp-config"))
        if "xmlrpc.php [200"    in dirs2:
            add("T1190-xmlrpc","T1190","xmlrpc.php exposé — brute force WordPress",     "Initial Access",    "HIGH",     "Dir Scan", _dline("xmlrpc"))
        if "phpinfo.php [200"   in dirs2 or "info.php [200" in dirs2:
            add("T1190-phpinfo","T1190","phpinfo() exposé — divulgation configuration", "Initial Access",    "HIGH",     "Dir Scan", _dline("phpinfo"))
        if "backup [200"        in dirs2 or "backup.zip [200" in dirs2 or "backup.sql [200" in dirs2:
            add("T1530-bak",  "T1530", "Répertoire/archive backup accessible",          "Collection",        "CRITICAL", "Dir Scan", _dline("backup"))
        if "swagger.json [200"  in dirs2 or "openapi.json [200" in dirs2 or "api-docs [200" in dirs2:
            add("T1190-api",  "T1190", "Documentation API exposée (Swagger/OpenAPI)",   "Initial Access",    "MEDIUM",   "Dir Scan", _dline("swagger"))
        if "composer.json [200" in dirs2 or "package.json [200" in dirs2:
            add("T1190-pkgjson","T1190","Fichier de dépendances exposé (composer/npm)",  "Initial Access",    "LOW",      "Dir Scan", _dline("composer"))
        if "server-status [200" in dirs2:
            add("T1190-srvstat","T1190","Apache server-status exposé — info processus", "Initial Access",    "MEDIUM",   "Dir Scan", _dline("server-status"))
        if "security.txt: ABSENT" in dirs2:
            add("T1003-sectxt","T1003","security.txt absent — pas de contact sécurité officiel","Reconnaissance","LOW",  "Dir Scan", "/.well-known/security.txt: ABSENT")

    # ── NIKTO — parsing granulaire ────────────────────────────────────────────
    nikto = _section(log_text, "NIKTO")
    if nikto and len(nikto.strip()) > 20 and not nikto.strip().lower().startswith("erreur"):
        n = nikto.lower()
        nikto_lines = [l.strip() for l in nikto.split('\n') if l.strip().startswith('+') and len(l.strip()) > 15]
        # SQL injection mentions
        sqli_l = [l for l in nikto_lines if any(k in l.lower() for k in ("sql", "inject", "sqli"))]
        if sqli_l: add("T1190-sqli", "T1190", "Potentielle injection SQL (Nikto)", "Initial Access", "CRITICAL", "Nikto", sqli_l[0][:120])
        # File upload
        upl_l = [l for l in nikto_lines if any(k in l.lower() for k in ("upload", "file upload", "multipart"))]
        if upl_l: add("T1190-upload", "T1190", "Upload de fichier détecté (Nikto)", "Initial Access", "HIGH", "Nikto", upl_l[0][:120])
        # Default credentials / passwords
        cred_l = [l for l in nikto_lines if any(k in l.lower() for k in ("default", "password", "admin:admin", "credential"))]
        if cred_l: add("T1078-nikto-cred", "T1078", "Credentials par défaut détectés (Nikto)", "Initial Access", "CRITICAL", "Nikto", cred_l[0][:120])
        # Directory indexing / listing
        idx_l = [l for l in nikto_lines if any(k in l.lower() for k in ("index of", "directory listing", "directory index"))]
        if idx_l: add("T1083-diridx", "T1083", "Directory listing activé (Nikto)", "Discovery", "MEDIUM", "Nikto", idx_l[0][:120])
        # Outdated software versions
        ver_l = [l for l in nikto_lines if any(k in l.lower() for k in ("outdated", "obsolete", "end-of-life", "eol", "no longer"))]
        if ver_l: add("T1190-nikto-eol", "T1190", "Logiciel obsolète détecté (Nikto)", "Initial Access", "HIGH", "Nikto", ver_l[0][:120])
        # Cross-site scripting mentions
        xss_l = [l for l in nikto_lines if any(k in l.lower() for k in ("xss", "cross-site scripting", "cross site"))]
        if xss_l: add("T1059-xss", "T1059.007", "Potentiel XSS détecté (Nikto)", "Execution", "HIGH", "Nikto", xss_l[0][:120])
        # CVE mentions in nikto
        cve_nikto = re.findall(r"CVE-\d{4}-\d+", nikto)[:2]
        for cve_n in cve_nikto:
            ev = next((l.strip() for l in nikto_lines if cve_n in l), cve_n)
            add(f"T1190-nikto-{cve_n}", "T1190", f"{cve_n} identifié par Nikto", "Initial Access", "HIGH", "Nikto", ev[:120])
        # Generic nikto finding if no specific match above
        if nikto_lines and not any(k in [f.get("source","") for f in findings] for k in ["Nikto"]):
            add("T1190-nikto", "T1190", "Vulnérabilités web détectées (Nikto)", "Initial Access", "MEDIUM", "Nikto", nikto_lines[0][:120])

    # ── WAF ──────────────────────────────────────────────────────────────────
    waf = _section(log_text, "WAF_DETECT")
    if waf and "aucun waf" in waf.lower():
        add("T1190-nowaf", "T1190", "Aucun WAF/CDN détecté", "Initial Access", "MEDIUM", "WAF Detect", "Aucun pare-feu applicatif web détecté")

    # ── NETWORK DISCOVER ─────────────────────────────────────────────────────
    nd = _section(log_text, "NETWORK_DISCOVER")
    if nd:
        hosts = re.findall(r"Nmap scan report for (.+)", nd)
        count = len(hosts)
        if count > 20:
            add("T1046-net-large", "T1046", f"Subnet large : {count} hôtes actifs découverts",
                "Discovery", "MEDIUM", "Network Discover", f"{count} hôtes trouvés sur le subnet")

    # ── SMB SCAN ─────────────────────────────────────────────────────────────
    smb = _section(log_text, "SMB_SCAN")
    if smb:
        s = smb.lower()
        # EternalBlue MS17-010
        if "ms17-010" in s and ("vulnerable" in s or "likely" in s):
            ev = next((l.strip() for l in smb.split('\n') if 'ms17-010' in l.lower()), "MS17-010 détecté")
            add("T1210-eb", "T1210", "EternalBlue (MS17-010) — RCE sans authentification", "Lateral Movement", "CRITICAL", "SMB Scan", ev[:120])
        # MS08-067 NetAPI
        if "ms08-067" in s and ("vulnerable" in s or "likely" in s):
            ev = next((l.strip() for l in smb.split('\n') if 'ms08-067' in l.lower()), "MS08-067 détecté")
            add("T1210-08067", "T1210", "MS08-067 NetAPI — RCE Windows XP/2003", "Lateral Movement", "CRITICAL", "SMB Scan", ev[:120])
        # SMB signing disabled
        if "message signing enabled but not required" in s or "signing: disabled" in s:
            ev = next((l.strip() for l in smb.split('\n') if 'sign' in l.lower()), "SMB signing non requis")
            add("T1557-smb", "T1557", "SMB Signing non requis — attaque Relay possible", "Credential Access", "HIGH", "SMB Scan", ev[:120])
        # Anonymous access
        if "anonymous" in s and ("access" in s or "allowed" in s):
            ev = next((l.strip() for l in smb.split('\n') if 'anonymous' in l.lower()), "Accès anonyme SMB")
            add("T1078-smb-anon", "T1078", "Accès anonyme SMB autorisé", "Initial Access", "CRITICAL", "SMB Scan", ev[:120])
        # Shared folders enumerated
        shares = re.findall(r"\\\\[^\s]+\\(\S+)", smb)
        if shares:
            ev = " | ".join(shares[:5])
            add("T1135-smb", "T1135", f"Partages réseau exposés : {', '.join(shares[:3])}", "Discovery", "MEDIUM", "SMB Scan", ev[:120])

    # ── SERVICE VERSION ───────────────────────────────────────────────────────
    svc = _section(log_text, "SERVICE_VERSION")
    if svc:
        sv = svc.lower()
        # Windows version obsolète
        for os_kw, sev, label in [
            ("windows server 2003", "CRITICAL", "Windows Server 2003 (EOL depuis 2015)"),
            ("windows xp",          "CRITICAL", "Windows XP (EOL depuis 2014)"),
            ("windows server 2008", "CRITICAL", "Windows Server 2008 (EOL depuis 2020)"),
            ("windows 7 ",          "CRITICAL", "Windows 7 (EOL depuis 2020)"),
            ("windows server 2012", "HIGH",     "Windows Server 2012 (EOL depuis 2023)"),
        ]:
            if os_kw in sv:
                ev = next((l.strip() for l in svc.split('\n') if os_kw.split()[1] in l.lower()), os_kw)
                add(f"T1190-os-{os_kw.replace(' ','_')}", "T1190", f"Système d'exploitation obsolète : {label}", "Initial Access", sev, "Service Version", ev[:120])
                break
        # Services obsolètes (versions connues vulnérables)
        for svc_kw, uid, name in [
            ("openssh 4.", "T1190-ssh4",  "OpenSSH 4.x (version obsolète, CVE multiples)"),
            ("openssh 5.", "T1190-ssh5",  "OpenSSH 5.x (version obsolète)"),
            ("apache/1.",  "T1190-ap1",   "Apache 1.x (EOL, CVE critiques)"),
            ("apache/2.2", "T1190-ap22",  "Apache 2.2 (EOL depuis 2017)"),
            ("nginx/0.",   "T1190-ng0",   "Nginx 0.x (version obsolète)"),
            ("iis/6",      "T1190-iis6",  "IIS 6.0 (Windows Server 2003, EOL)"),
            ("iis/7",      "T1190-iis7",  "IIS 7.x (Windows Server 2008, EOL)"),
        ]:
            if svc_kw in sv:
                ev = next((l.strip() for l in svc.split('\n') if svc_kw.split('/')[0] in l.lower()), svc_kw)
                add(uid, "T1190", name, "Initial Access", "HIGH", "Service Version", ev[:120])

    # ── VULN SCAN NSE ─────────────────────────────────────────────────────────
    vuln = _section(log_text, "VULN_SCAN")
    if vuln and len(vuln.strip()) > 20 and not vuln.strip().lower().startswith("erreur"):
        v = vuln.lower()
        if "ms17-010" in v and "vulnerable" in v:
            ev = next((l.strip() for l in vuln.split('\n') if 'ms17-010' in l.lower()), "EternalBlue confirmé")
            add("T1210-eb-vuln", "T1210", "EternalBlue MS17-010 CONFIRMÉ par NSE", "Lateral Movement", "CRITICAL", "Vuln Scan", ev[:120])
        if "ms08-067" in v and "vulnerable" in v:
            add("T1210-08-vuln", "T1210", "MS08-067 CONFIRMÉ par NSE", "Lateral Movement", "CRITICAL", "Vuln Scan", "MS08-067 confirmé par nmap NSE")
        # Extrait les premiers CVE trouvés
        cves = re.findall(r"CVE-\d{4}-\d+", vuln)[:3]
        if cves:
            ev = " | ".join(cves)
            add("T1190-nse-cve", "T1190", f"CVE détectés par NSE : {', '.join(cves)}", "Initial Access", "HIGH", "Vuln Scan", ev)

    return findings

# =============================================================================
# SCORE DE RISQUE
# =============================================================================
def compute_risk_score(sev_counts):
    score = (
        sev_counts.get("CRITICAL", 0) * 25 +
        sev_counts.get("HIGH",     0) * 15 +
        sev_counts.get("MEDIUM",   0) * 8  +
        sev_counts.get("LOW",      0) * 3
    )
    return min(score, 100)

def risk_label(score):
    if score >= 75: return "CRITIQUE", HexColor("#ef4444")
    if score >= 50: return "ÉLEVÉ",    HexColor("#f97316")
    if score >= 25: return "MOYEN",    HexColor("#eab308")
    return "FAIBLE", HexColor("#22c55e")

# =============================================================================
# PDF GENERATION
# =============================================================================
C = {
    "primary":  HexColor("#1a1a2e"),
    "accent":   HexColor("#6366f1"),
    "critical": HexColor("#ef4444"),
    "high":     HexColor("#f97316"),
    "medium":   HexColor("#eab308"),
    "low":      HexColor("#22c55e"),
    "text":     HexColor("#1e293b"),
    "muted":    HexColor("#64748b"),
    "bg":       HexColor("#f8fafc"),
    "border":   HexColor("#e2e8f0"),
}
SEV_COLOR = {"CRITICAL": C["critical"], "HIGH": C["high"], "MEDIUM": C["medium"], "LOW": C["low"]}

def _p(text, size=9, color=None, bold=False, align=TA_LEFT, font="Helvetica"):
    if bold: font += "-Bold"
    return Paragraph(str(text), ParagraphStyle(
        "x", fontSize=size, textColor=color or C["text"],
        alignment=align, fontName=font, leading=size * 1.45,
    ))

def count_severity(mitre_findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in mitre_findings:
        sev = f.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1
    return counts

def make_pie(sev_counts, size=70):
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    colors  = [C["critical"], C["high"], C["medium"], C["low"]]
    data    = [(sev_counts.get(l, 0), c) for l, c in zip(labels, colors) if sev_counts.get(l, 0) > 0]
    if not data:
        return None
    d   = Drawing(size, size)
    pie = Pie()
    pie.x, pie.y       = size * 0.05, size * 0.05
    pie.width          = size * 0.9
    pie.height         = size * 0.9
    pie.data           = [v for v, _ in data]
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = white
    for i, (_, col) in enumerate(data):
        pie.slices[i].fillColor = col
    d.add(pie)
    return d

def get_scope(session_log):
    scope = []
    for entry in session_log:
        m = re.match(r"=== (\w+) \((.*?)\) ===", entry)
        if m:
            scope.append(f"{m.group(1).capitalize():<18} → {m.group(2)}")
    return scope

def grc_from_findings(mitre_findings, sev_counts):
    recs = []
    if sev_counts.get("CRITICAL", 0) > 0:
        recs.append({"framework": "NIS 2",    "article": "Art. 21",  "control": "Sécurité des réseaux et SI",    "priority": "CRITICAL", "action": "Fermer immédiatement les ports critiques exposés. Déployer un pare-feu applicatif."})
    if any(r["technique"] in ("T1021.001","T1021.002","T1021.004") for r in mitre_findings):
        recs.append({"framework": "ISO 27001","article": "A.8.20",   "control": "Sécurité des réseaux",          "priority": "HIGH",     "action": "Restreindre les accès admin distants via VPN + MFA obligatoire."})
    if any(r["technique"] == "T1557" for r in mitre_findings):
        recs.append({"framework": "DORA",     "article": "Art. 9",   "control": "Sécurité des communications",   "priority": "HIGH",     "action": "Renouveler les certificats SSL/TLS. Activer HSTS (min. 1 an)."})
    if any(r["technique"] == "T1189" for r in mitre_findings):
        recs.append({"framework": "ISO 27001","article": "A.8.23",   "control": "Filtrage des accès web",        "priority": "MEDIUM",   "action": "Implémenter X-Frame-Options, CSP, HSTS, X-Content-Type-Options."})
    if any(r["technique"] == "T1598" for r in mitre_findings):
        recs.append({"framework": "ISO 27001","article": "A.5.14",   "control": "Authentification des emails",   "priority": "MEDIUM",   "action": "Configurer SPF, DKIM et DMARC pour prévenir le spoofing."})
    # ── Réseau interne ────────────────────────────────────────────────────────
    if any(r["technique"] == "T1210" or r["technique"].startswith("T1210-") for r in mitre_findings):
        recs.append({"framework": "NIS 2",    "article": "Art. 21",  "control": "Gestion des vulnérabilités",    "priority": "CRITICAL", "action": "Appliquer immédiatement les patchs MS17-010/MS08-067. Isoler les hôtes non patchables. Segmenter le réseau."})
    if any(r["technique"] == "T1557-smb" for r in mitre_findings):
        recs.append({"framework": "ISO 27001","article": "A.8.22",   "control": "Ségrégation des réseaux",       "priority": "HIGH",     "action": "Activer SMB Signing obligatoire via GPO sur tous les serveurs et contrôleurs de domaine."})
    if any(r["technique"] in ("T1021.005","T1021.006") for r in mitre_findings):
        recs.append({"framework": "ISO 27001","article": "A.8.20",   "control": "Accès distant sécurisé",        "priority": "HIGH",     "action": "Désactiver VNC/WinRM non autorisés. Centraliser les accès admin via jump server + MFA."})
    if any(r["technique"] in ("T1135","T1135-smb","T1039") for r in mitre_findings):
        recs.append({"framework": "ISO 27001","article": "A.8.3",    "control": "Gestion des accès aux médias",  "priority": "MEDIUM",   "action": "Auditer et restreindre les partages réseau. Appliquer le principe du moindre privilège."})
    if any("os-windows" in r.get("_uid","") for r in mitre_findings):
        recs.append({"framework": "NIS 2",    "article": "Art. 21",  "control": "Mises à jour de sécurité",      "priority": "CRITICAL", "action": "Migrer ou isoler immédiatement les systèmes en fin de vie (EOL). Aucun patch disponible."})
    if not recs:
        recs.append({"framework": "ISO 27001","article": "A.5.2",    "control": "Politique de sécurité",         "priority": "LOW",      "action": "Maintenir une surveillance continue et des audits réguliers."})
    return recs

# =============================================================================
# FINDING METADATA — impact + remédiation statiques par technique
# =============================================================================
FINDING_META = {
    "T1021.001": {"impact": "RDP exposé permet des attaques par force brute et l'exploitation de CVE critiques (BlueKeep, DejaBlue). Compromission directe du serveur possible.", "fix": "Fermer le port 3389 depuis Internet. Accès uniquement via VPN + MFA obligatoire.", "delay": "Immédiat"},
    "T1021.004": {"impact": "SSH exposé permet des attaques par force brute sur les credentials. Accès shell root possible si configuration laxiste.", "fix": "Désactiver l'auth par mot de passe (PasswordAuthentication no). Utiliser des clés SSH ED25519. Restreindre via firewall.", "delay": "48h"},
    "T1071.002": {"impact": "FTP transmet les données en clair (identifiants inclus). Vulnérable au sniffing réseau et aux attaques MITM.", "fix": "Désactiver FTP. Migrer vers SFTP (port 22). Fermer le port 21 au niveau firewall.", "delay": "Immédiat"},
    "T1021.002": {"impact": "SMB exposé sur Internet est directement exploitable par des ransomwares (WannaCry, NotPetya). Propagation latérale dans le réseau.", "fix": "Bloquer le port 445 au périmètre. SMB uniquement sur réseau interne ou via VPN.", "delay": "Immédiat"},
    "T1021":     {"impact": "Telnet transmet tout en clair. Protocole obsolète, compromission triviale par sniffing réseau.", "fix": "Désactiver le service Telnet immédiatement. Remplacer par SSH.", "delay": "Immédiat"},
    "T1190":     {"impact": "Service exposé directement sur Internet sans authentification réseau préalable. Exploitation directe possible.", "fix": "Fermer le port via firewall. Si nécessaire, restreindre aux IPs de confiance uniquement.", "delay": "Immédiat"},
    "T1046":     {"impact": "Port ouvert visible depuis Internet — élargit la surface d'attaque et peut révéler les versions des services.", "fix": "Fermer les ports non nécessaires. Mettre à jour les services exposés vers les dernières versions stables.", "delay": "30 jours"},
    "T1189":     {"impact": "Sans X-Frame-Options, le site peut être intégré dans un iframe malveillant. Permet des attaques Clickjacking qui piègent les utilisateurs.", "fix": "Ajouter dans la config serveur : X-Frame-Options: DENY (ou SAMEORIGIN si les iframes internes sont nécessaires).", "delay": "7 jours"},
    "T1557":     {"impact": "Configuration TLS faible. Les communications (credentials, sessions) peuvent être interceptées ou déchiffrées.", "fix": "Désactiver TLS 1.0 et 1.1. Activer HSTS (max-age=31536000). Utiliser uniquement TLS 1.2 et 1.3.", "delay": "7 jours"},
    "T1557-hsts": {"impact": "Sans HSTS, les connexions HTTP initiales peuvent être interceptées (downgrade attack). Les cookies de session sont exposés.", "fix": "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "delay": "7 jours"},
    "T1557-tls10": {"impact": "TLS 1.0 est vulnérable aux attaques POODLE et BEAST. Déprécié par PCI DSS depuis 2018.", "fix": "Désactiver TLS 1.0 et 1.1. Maintenir uniquement TLS 1.2 et TLS 1.3 dans la config serveur.", "delay": "7 jours"},
    "T1557-tls11": {"impact": "TLS 1.1 est considéré comme obsolète depuis 2021 (RFC 8996). Vulnérabilités de downgrade connues.", "fix": "Désactiver TLS 1.1. Maintenir uniquement TLS 1.2 et TLS 1.3.", "delay": "7 jours"},
    "T1557-self": {"impact": "Un certificat auto-signé n'établit pas de confiance vérifiable. Le navigateur affiche une alerte bloquante.", "fix": "Obtenir un certificat signé par une CA reconnue. Let's Encrypt est gratuit et automatisable.", "delay": "7 jours"},
    "T1557-exp":  {"impact": "Certificat SSL expiré — connexions HTTPS non sécurisées. Perte de confiance immédiate et risque de MITM.", "fix": "Renouveler immédiatement le certificat. Automatiser avec certbot (certbot renew --cron).", "delay": "Immédiat"},
    "T1059.007":  {"impact": "Sans CSP, le site est vulnérable aux attaques XSS. Un attaquant peut injecter du JavaScript malveillant pour voler des sessions.", "fix": "Définir une CSP stricte : Content-Security-Policy: default-src 'self'; script-src 'self'.", "delay": "30 jours"},
    "T1059-csp":  {"impact": "Sans CSP, le site est vulnérable aux attaques XSS. Un attaquant peut injecter du JavaScript malveillant pour voler des sessions.", "fix": "Définir une CSP stricte : Content-Security-Policy: default-src 'self'; script-src 'self'.", "delay": "30 jours"},
    "T1566":      {"impact": "Sans X-Content-Type-Options, le navigateur peut interpréter des fichiers uploadés comme du code exécutable (MIME sniffing).", "fix": "Ajouter : X-Content-Type-Options: nosniff dans les réponses HTTP.", "delay": "7 jours"},
    "T1566-xcto": {"impact": "Sans X-Content-Type-Options, le navigateur peut interpréter des fichiers uploadés comme du code exécutable (MIME sniffing).", "fix": "Ajouter : X-Content-Type-Options: nosniff dans les réponses HTTP.", "delay": "7 jours"},
    "T1598":      {"impact": "Sans SPF/DKIM/DMARC, n'importe qui peut envoyer des emails au nom de votre domaine. Vecteur de phishing direct.", "fix": "1) SPF : TXT v=spf1 include:... -all  2) DMARC : _dmarc avec p=reject  3) DKIM : configurer le sélecteur.", "delay": "7 jours"},
    "T1598-spf":  {"impact": "Sans SPF, des serveurs tiers peuvent envoyer des emails en usurpant votre domaine. Vecteur phishing privilégié.", "fix": "Créer un enregistrement DNS TXT : v=spf1 include:[provider] -all", "delay": "7 jours"},
    "T1598-dmarc": {"impact": "Sans DMARC, les emails non autorisés ne sont pas rejetés même si SPF/DKIM échouent.", "fix": "Créer _dmarc.[domaine] TXT : v=DMARC1; p=reject; rua=mailto:dmarc@[domaine]", "delay": "7 jours"},
    "T1598-dmarc-none": {"impact": "DMARC en mode p=none ne bloque rien — configuration en surveillance uniquement, sans protection réelle.", "fix": "Passer progressivement de p=none à p=quarantine puis p=reject après analyse des rapports.", "delay": "30 jours"},
    "T1598-dkim": {"impact": "Sans DKIM, l'authenticité des emails ne peut pas être vérifiée. Les emails peuvent être altérés sans détection.", "fix": "Générer une paire de clés RSA 2048 bits. Configurer le sélecteur dans le MTA et publier la clé publique en DNS.", "delay": "30 jours"},
    "T1583":      {"impact": "Sous-domaine ou infrastructure exposée. Ces environnements ont souvent des credentials par défaut et moins de sécurité.", "fix": "Restreindre l'accès via VPN ou IP whitelist. Supprimer les DNS des sous-domaines inutilisés.", "delay": "Immédiat"},
    "T1583-dev":  {"impact": "Environnement de développement accessible depuis Internet. Souvent moins sécurisé, credentials partagés, pas de supervision.", "fix": "Désactiver le DNS public du sous-domaine dev/staging. Accès uniquement via VPN.", "delay": "Immédiat"},
    "T1583-adm":  {"impact": "Interface d'administration accessible publiquement. Cible privilégiée pour force brute et exploitation.", "fix": "Restreindre l'accès admin à des IPs de confiance. Ajouter MFA obligatoire.", "delay": "Immédiat"},
    "T1552":      {"impact": "Fichier de configuration accessible publiquement pouvant contenir credentials, clés API, chaînes de connexion BDD.", "fix": "Supprimer immédiatement. Révoquer TOUS les credentials potentiellement exposés.", "delay": "Immédiat"},
    "T1552-env":  {"impact": "Fichier .env exposé — contient typiquement les secrets d'application : BDD, clés API, tokens.", "fix": "Supprimer le fichier du serveur. Révoquer tous les secrets. Règle nginx/apache : deny all pour /.env", "delay": "Immédiat"},
    "T1552-git":  {"impact": "Dépôt Git exposé — permet de reconstruire l'historique complet du code, y compris les credentials commités.", "fix": "Bloquer l'accès à /.git via config serveur. Auditer l'historique Git pour les secrets exposés.", "delay": "Immédiat"},
    "T1078":      {"impact": "Interface d'administration web exposée sans restriction. Attaques par force brute peuvent compromettre le compte admin.", "fix": "Restreindre l'accès via IP whitelist. Activer MFA. Changer l'URL d'admin par défaut.", "delay": "48h"},
    "T1078-adm":  {"impact": "Interface d'administration web exposée (panel admin ou wp-admin). Cible directe pour les attaques automatisées.", "fix": "Restreindre l'accès via IP whitelist. Activer MFA. Changer l'URL d'administration.", "delay": "48h"},
    "T1530":      {"impact": "Répertoire de sauvegarde accessible — peut contenir des archives BDD, code source, ou configurations.", "fix": "Déplacer les backups hors de la racine web. Bloquer l'accès direct aux répertoires de backup.", "delay": "Immédiat"},
    "T1530-bak":  {"impact": "Répertoire backup accessible — potentiellement des archives BDD ou fichiers de config.", "fix": "Déplacer les backups hors du webroot. Restreindre via config serveur web.", "delay": "Immédiat"},
    # ── WEB EXTERNE ──────────────────────────────────────────────────────────
    "T1003-refpol": {"impact": "Sans Referrer-Policy, l'URL complète (avec tokens, IDs) est envoyée aux sites tiers lors des clics sortants.", "fix": "Ajouter : Referrer-Policy: strict-origin-when-cross-origin dans les headers HTTP.", "delay": "7 jours"},
    "T1003-perms":  {"impact": "Sans Permissions-Policy, le navigateur peut accéder à la caméra, micro et géolocalisation sans restriction explicite.", "fix": "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()", "delay": "7 jours"},
    "T1003-sectxt": {"impact": "Sans security.txt, les chercheurs en sécurité n'ont pas de canal officiel pour signaler les vulnérabilités.", "fix": "Créer /.well-known/security.txt avec contact, encryption, expires. Voir securitytxt.org.", "delay": "30 jours"},
    "T1059-csp-unsafe": {"impact": "CSP avec 'unsafe-inline' ou 'unsafe-eval' annule la protection contre XSS. La politique est présente mais inefficace.", "fix": "Remplacer 'unsafe-inline' par des nonces CSP dynamiques. Supprimer 'unsafe-eval'.", "delay": "30 jours"},
    "T1059-xss":    {"impact": "Injection de code JavaScript côté client. Permet le vol de cookies, la redirection, et l'exécution de code arbitraire.", "fix": "Encoder toutes les sorties HTML. Implémenter une CSP stricte. Valider les entrées côté serveur.", "delay": "48h"},
    "T1190-srv":    {"impact": "La version du serveur est divulguée en clair. Permet aux attaquants de cibler des CVE spécifiques à cette version.", "fix": "Masquer la version : ServerTokens Prod (Apache) ou server_tokens off (Nginx).", "delay": "7 jours"},
    "T1190-xpb":    {"impact": "X-Powered-By révèle le langage/framework utilisé et sa version, facilitant le ciblage CVE.", "fix": "Supprimer X-Powered-By : header always unset X-Powered-By (Apache) ou php_flag expose_php off.", "delay": "7 jours"},
    "T1190-cors":   {"impact": "CORS avec wildcard (*) ou origine malveillante acceptée permet à tout site d'effectuer des requêtes authentifiées.", "fix": "Définir une whitelist explicite d'origines. Ne jamais utiliser * avec credentials=true.", "delay": "48h"},
    "T1190-cors-origin": {"impact": "Le serveur reflète l'origine de la requête — comportement à vérifier pour prévenir les attaques CORS.", "fix": "Vérifier que l'Access-Control-Allow-Origin est strictement validé côté serveur avec une whitelist.", "delay": "7 jours"},
    "T1539-cors-cred": {"impact": "CORS + Allow-Credentials: true avec origine trop permissive : un attaquant peut voler des cookies ou tokens via un site malveillant.", "fix": "Restreindre strictement l'origine autorisée. Ne jamais combiner Access-Control-Allow-Origin: * avec credentials.", "delay": "Immédiat"},
    "T1539-httponly": {"impact": "Cookie sans HttpOnly accessible via document.cookie. En cas de XSS, les sessions peuvent être volées en une ligne de JavaScript.", "fix": "Ajouter HttpOnly à tous les cookies de session : Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict", "delay": "48h"},
    "T1557-cookie-sec": {"impact": "Cookie transmis sur HTTP non chiffré. Interceptable par sniffing réseau (cafés, aéroports, réseaux inconnus).", "fix": "Ajouter le flag Secure à tous les cookies sensibles. Forcer HTTPS avec HSTS.", "delay": "48h"},
    "T1185-samesite": {"impact": "Cookie sans SameSite : attaque CSRF possible — un site malveillant peut déclencher des actions à la place de l'utilisateur.", "fix": "Ajouter SameSite=Strict (ou Lax pour les cookies moins critiques). Valider le CSRF token côté serveur.", "delay": "7 jours"},
    "T1557-noredir": {"impact": "Le site répond en HTTP sans redirection vers HTTPS. Les credentials saisis sur des pages mixtes circulent en clair.", "fix": "Configurer une redirection 301 HTTP→HTTPS au niveau serveur/load balancer. Activer HSTS ensuite.", "delay": "48h"},
    "T1040-trace":  {"impact": "TRACE permet à un attaquant de lire les headers HTTP envoyés par le navigateur, y compris les cookies (Cross-Site Tracing).", "fix": "Désactiver TRACE : TraceEnable off (Apache) ou dans le bloc server {} de Nginx.", "delay": "7 jours"},
    "T1190-put":    {"impact": "Méthode PUT autorisée — upload de fichiers possible directement sur le serveur sans authentification.", "fix": "Désactiver les méthodes HTTP inutiles. Conserver uniquement GET, POST, HEAD.", "delay": "Immédiat"},
    "T1190-delete": {"impact": "Méthode DELETE autorisée — suppression de ressources possible par un attaquant non authentifié.", "fix": "Désactiver DELETE dans la configuration serveur. Valider l'authentification pour toute méthode destructive.", "delay": "Immédiat"},
    "T1190-xmlrpc": {"impact": "xmlrpc.php permet des attaques brute-force amplifiées (1000 tentatives en 1 requête) et l'exploitation de CVE WordPress.", "fix": "Désactiver xmlrpc.php via .htaccess ou config Nginx si non utilisé par des plugins.", "delay": "48h"},
    "T1190-phpinfo": {"impact": "phpinfo() expose la configuration PHP complète : chemins serveur, extensions, variables d'environnement, clés de session.", "fix": "Supprimer phpinfo.php et info.php des environnements de production immédiatement.", "delay": "Immédiat"},
    "T1190-api":    {"impact": "Documentation API publique expose tous les endpoints, paramètres et types de données — roadmap complète pour un attaquant.", "fix": "Protéger /swagger.json et /api-docs derrière une authentification en production.", "delay": "48h"},
    "T1190-pkgjson": {"impact": "composer.json ou package.json expose la liste des dépendances et leurs versions — facilite le ciblage de CVE.", "fix": "Bloquer l'accès aux fichiers de manifeste via config serveur web.", "delay": "7 jours"},
    "T1190-srvstat": {"impact": "Apache server-status révèle les processus actifs, IPs clientes, requêtes en cours — information opérationnelle sensible.", "fix": "Désactiver ExtendedStatus ou restreindre server-status à 127.0.0.1.", "delay": "7 jours"},
    "T1190-sqli":   {"impact": "Injection SQL potentielle : extraction de la base de données, authentification bypass, ou exécution de commandes OS.", "fix": "Utiliser des requêtes paramétrées (PDO, prepared statements). Valider et encoder toutes les entrées.", "delay": "Immédiat"},
    "T1190-upload": {"impact": "Upload de fichiers non sécurisé : possible upload de webshell permettant exécution de code arbitraire sur le serveur.", "fix": "Valider le type MIME côté serveur. Stocker les uploads hors du webroot. Scanner les fichiers uploadés.", "delay": "Immédiat"},
    "T1078-nikto-cred": {"impact": "Credentials par défaut détectés — accès immédiat sans effort pour un attaquant connaissant les valeurs par défaut.", "fix": "Changer immédiatement tous les mots de passe par défaut. Appliquer une politique de mots de passe forts.", "delay": "Immédiat"},
    "T1083-diridx": {"impact": "Directory listing révèle la structure complète du serveur web — fichiers de config, backups, scripts exposés.", "fix": "Désactiver l'indexation : Options -Indexes (Apache) ou autoindex off (Nginx).", "delay": "48h"},
    "T1190-nikto-eol": {"impact": "Logiciel en fin de vie sans correctifs de sécurité — vulnérabilités connues non corrigées.", "fix": "Mettre à jour vers la dernière version stable supportée. Prévoir un plan de migration.", "delay": "30 jours"},
    "T1552-wpcfg":  {"impact": "wp-config.php exposé contient les credentials BDD, les clés secrètes WordPress et la configuration complète.", "fix": "Déplacer wp-config.php un niveau au-dessus du webroot. Règle deny : location ~* /wp-config.php { deny all; }", "delay": "Immédiat"},
    "T1190-nowaf": {"impact": "Sans WAF, les requêtes malveillantes (SQLi, XSS, LFI) atteignent directement le serveur applicatif.", "fix": "Déployer un WAF (Cloudflare Free, AWS WAF, ou ModSecurity + OWASP CRS).", "delay": "30 jours"},
    "T1190-nikto": {"impact": "Nikto a identifié des vulnérabilités web. Voir evidence pour les détails.", "fix": "Analyser chaque finding Nikto individuellement. Appliquer les patches et mises à jour correspondants.", "delay": "30 jours"},
    "T1190-pma":  {"impact": "phpMyAdmin exposé donne accès direct à la base de données via une interface web.", "fix": "Restreindre l'accès phpMyAdmin à des IPs de confiance ou le déplacer hors du webroot.", "delay": "Immédiat"},
    "T1190-srv":  {"impact": "Version serveur obsolète exposée — des CVE publics peuvent être directement applicables.", "fix": "Mettre à jour le serveur web vers la dernière version stable. Masquer la version (ServerTokens Prod).", "delay": "30 jours"},
    # ── RÉSEAU INTERNE ────────────────────────────────────────────────────────
    "T1021.005":  {"impact": "VNC transmet le bureau distant avec un chiffrement faible ou nul. Accès graphique complet à la machine.", "fix": "Désactiver VNC. Remplacer par RDP via VPN avec MFA, ou SSH tunneling pour Linux.", "delay": "Immédiat"},
    "T1021.006":  {"impact": "WinRM permet l'exécution de commandes PowerShell à distance. Compromission complète du système si credentials volés.", "fix": "Désactiver WinRM si non utilisé. Si nécessaire, restreindre via GPO aux administrateurs + MFA.", "delay": "48h"},
    "T1210":      {"impact": "Vulnérabilité d'exécution de code à distance sans authentification. Compromission immédiate et propagation ransomware.", "fix": "Appliquer le patch MS17-010 immédiatement (KB4012212). Isoler l'hôte si non patchable.", "delay": "Immédiat"},
    "T1210-eb":   {"impact": "EternalBlue permet un RCE sans credentials sur Windows non patchés. Vecteur principal de propagation WannaCry/NotPetya.", "fix": "Appliquer KB4012212 (MS17-010) immédiatement. Bloquer SMB (port 445) au niveau réseau entre segments.", "delay": "Immédiat"},
    "T1210-eb-vuln": {"impact": "EternalBlue CONFIRMÉ — compromission totale du système possible sans aucune interaction utilisateur.", "fix": "URGENT : Isoler immédiatement l'hôte du réseau. Appliquer KB4012212. Vérifier les autres machines du segment.", "delay": "Immédiat"},
    "T1210-08067": {"impact": "MS08-067 permet RCE sur Windows XP/Server 2003 sans authentification. Système EOL depuis 2015.", "fix": "Retirer immédiatement ces systèmes du réseau. Migration vers OS supportés obligatoire.", "delay": "Immédiat"},
    "T1557-smb":  {"impact": "SMB Signing non requis : attaque NTLM Relay possible. Un attaquant peut usurper des sessions sans connaître les mots de passe.", "fix": "Activer SMB Signing obligatoire via GPO : Microsoft network server - Digitally sign communications (always): Enabled.", "delay": "48h"},
    "T1078-smb-anon": {"impact": "Accès SMB anonyme autorisé : un attaquant peut énumérer les partages, utilisateurs et politiques sans credentials.", "fix": "Désactiver l'accès anonyme SMB. Paramètre : Network access: Shares that can be accessed anonymously → vide.", "delay": "Immédiat"},
    "T1135":      {"impact": "Partages réseau exposés visibles depuis le segment. Possibilité d'accéder à des fichiers sensibles sans authentification forte.", "fix": "Auditer tous les partages. Supprimer les partages inutiles. Appliquer des permissions minimales.", "delay": "30 jours"},
    "T1135-smb":  {"impact": "Partages SMB exposés — données potentiellement accessibles sans authentification forte sur le réseau interne.", "fix": "Revoir les permissions de chaque partage. Activer l'audit des accès aux partages (Event ID 5140).", "delay": "30 jours"},
    "T1039":      {"impact": "Partage NFS sans authentification : montage possible depuis n'importe quel hôte du réseau.", "fix": "Restreindre les exports NFS (/etc/exports) aux IPs de confiance uniquement. Activer Kerberos auth.", "delay": "Immédiat"},
    "T1046-net-large": {"impact": "Surface réseau large exposée. Un grand nombre d'hôtes augmente le risque de compromission via un seul maillon faible.", "fix": "Segmenter le réseau (VLAN). Limiter les communications inter-segments via firewall interne (Zero Trust).", "delay": "30 jours"},
    "T1190-os-windows_server_2003": {"impact": "Windows Server 2003 EOL — aucun patch de sécurité depuis 2015. Centaines de CVE non corrigées.", "fix": "Migration urgente vers Windows Server 2022. Si non possible, isolation réseau immédiate.", "delay": "Immédiat"},
    "T1190-os-windows_xp":  {"impact": "Windows XP EOL depuis 2014. Vulnérable à EternalBlue, MS08-067 et des centaines de CVE non corrigées.", "fix": "Retirer du réseau ou isoler dans un VLAN dédié sans accès Internet. Migration obligatoire.", "delay": "Immédiat"},
    "T1190-os-windows_server_2008": {"impact": "Windows Server 2008 EOL depuis janvier 2020. Patch Tuesday arrêté — vulnérabilités non corrigées s'accumulent.", "fix": "Migrer vers Windows Server 2019/2022. ESU payant disponible mais limité.", "delay": "Immédiat"},
    "T1190-os-windows_7_": {"impact": "Windows 7 EOL depuis janvier 2020. Vulnérable aux exploits SMB modernes.", "fix": "Migrer vers Windows 10/11 ou retirer du réseau d'entreprise.", "delay": "Immédiat"},
    "T1190-os-windows_server_2012": {"impact": "Windows Server 2012 EOL depuis octobre 2023. Support de sécurité terminé.", "fix": "Migrer vers Windows Server 2022. Des mises à jour de sécurité étendues (ESU) sont disponibles.", "delay": "48h"},
    "T1190-nse-cve": {"impact": "CVE actives détectées par scan NSE. Ces vulnérabilités sont exploitables avec des outils publics.", "fix": "Appliquer les correctifs correspondants via Windows Update ou mise à jour des services concernés.", "delay": "48h"},
}

# =============================================================================
# TOPOLOGIE RÉSEAU INTERNE — parsing + dessin
# =============================================================================

_DEVICE_CFG = {
    "router":         {"color": "#4338ca", "label": "ROUTEUR/GW"},
    "switch":         {"color": "#7c3aed", "label": "SWITCH/AP"},
    "server_linux":   {"color": "#0284c7", "label": "SERV.LINUX"},
    "server_windows": {"color": "#1d4ed8", "label": "SERV.WIN"},
    "server":         {"color": "#0369a1", "label": "SERVEUR"},
    "workstation":    {"color": "#059669", "label": "POSTE"},
    "printer":        {"color": "#b45309", "label": "IMPRIMANTE"},
    "camera":         {"color": "#b91c1c", "label": "CAMERA"},
    "host":           {"color": "#475569", "label": "HOTE"},
    "unknown":        {"color": "#94a3b8", "label": "INCONNU"},
}

_TYPE_ORDER = [
    "router","switch",
    "server_linux","server_windows","server",
    "workstation",
    "printer","camera",
    "host","unknown",
]


def _classify_device(host):
    ip       = host.get("ip", "")
    os_str   = host.get("os", "").lower()
    ports    = host.get("ports", [])
    hostname = host.get("hostname", "").lower()
    pnums    = {p.split("/")[0] for p in ports}
    last_oct = ip.split(".")[-1] if "." in ip else "0"

    if last_oct in ("1", "254") or any(k in hostname for k in
       ("router","gateway","gw","fw","firewall","pfsense","opnsense")):
        return "router"
    if any(k in hostname for k in
       ("switch","sw-","ap-","unifi","ubnt","cisco","netgear","mikrotik","dlink","tplink","tp-link")):
        return "switch"
    if "9100" in pnums or "515" in pnums:
        return "printer"
    if any(k in hostname for k in ("print","hp","canon","epson","brother","xerox","ricoh","lexmark","konica")):
        return "printer"
    if "554" in pnums:
        return "camera"
    if any(k in hostname for k in ("cam","nvr","dvr","hikvision","dahua","axis","hanwha")):
        return "camera"
    if "windows" in os_str and "server" in os_str:
        return "server_windows"
    if any(k in os_str for k in ("linux","ubuntu","debian","centos","fedora","redhat","rhel")):
        return "server_linux"
    if "windows" in os_str:
        return "workstation"
    if len(ports) >= 3 or any(p in pnums for p in
       ("80","443","22","8080","8443","3306","5432","27017","25","143","110")):
        return "server"
    if ports:
        return "host"
    return "unknown"


def _parse_hosts_from_log(log_text):
    """Extrait les hôtes depuis network_discover, arp_scan et service_version."""
    hosts = {}

    def _add(ip, hostname=""):
        hosts.setdefault(ip, {"ip": ip, "hostname": hostname, "os": "", "ports": [], "type": "unknown"})
        if hostname and not hosts[ip]["hostname"]:
            hosts[ip]["hostname"] = hostname

    # ── network_discover ─────────────────────────────────────────────────────
    nd = _section(log_text, "NETWORK_DISCOVER") or ""
    for line in nd.split("\n"):
        m = re.search(r"Nmap scan report for (\S+?)(?:\s+\(([\d.]+)\))?$", line)
        if m:
            raw, ip2 = m.group(1), m.group(2)
            ip = ip2 or (raw if re.match(r"[\d.]+$", raw) else None)
            if ip:
                _add(ip, raw if ip2 else "")

    # ── arp_scan ─────────────────────────────────────────────────────────────
    arp = _section(log_text, "ARP_SCAN") or ""
    for line in arp.split("\n"):
        m = re.match(r"([\d.]+)\s+([0-9a-fA-F:]+)\s*(.*)", line.strip())
        if m and re.match(r"\d+\.\d+\.\d+\.\d+$", m.group(1)):
            _add(m.group(1), m.group(3).strip()[:25])

    # ── service_version (une entrée par hôte, plusieurs possibles) ───────────
    for _, sv_block in re.findall(
        r"=== SERVICE_VERSION \(.*?\) ===\n()(.*?)(?====|\Z)",
        log_text, re.DOTALL | re.IGNORECASE
    ):
        _parse_sv_block(sv_block, hosts)

    # fallback: single _section
    sv_single = _section(log_text, "SERVICE_VERSION")
    if sv_single:
        _parse_sv_block(sv_single, hosts)

    for h in hosts.values():
        h["type"] = _classify_device(h)

    return hosts


def _parse_sv_block(block, hosts):
    cur = None
    for line in block.split("\n"):
        m = re.search(r"Nmap scan report for (\S+?)(?:\s+\(([\d.]+)\))?$", line)
        if m:
            raw, ip2 = m.group(1), m.group(2)
            ip = ip2 or (raw if re.match(r"[\d.]+$", raw) else None)
            if ip:
                cur = ip
                hosts.setdefault(ip, {"ip": ip, "hostname": raw if ip2 else "",
                                       "os": "", "ports": [], "type": "unknown"})
        if cur:
            om = re.search(r"OS details:\s*(.+)", line)
            if om and not hosts[cur]["os"]:
                hosts[cur]["os"] = om.group(1).strip()[:60]
            pm = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if pm:
                entry = f"{pm.group(1)}/{pm.group(2)}"
                if entry not in hosts[cur]["ports"]:
                    hosts[cur]["ports"].append(entry)


def draw_network_map(hosts_dict, W_pt):
    """Retourne un ReportLab Drawing représentant la topologie réseau interne."""
    from reportlab.graphics.shapes import Drawing, Rect, String, Line
    from reportlab.lib.colors import HexColor, white

    if not hosts_dict:
        return None

    hosts = list(hosts_dict.values())

    # Dimensions des nœuds (points)
    NW, NH   = 88, 52    # largeur / hauteur nœud
    HGAP     = 6         # espacement horizontal
    VGAP     = 20        # espace entre lignes (pour les connecteurs)
    HDR_H    = 14        # hauteur de la bande colorée du type
    TOP_M    = 26        # marge titre
    BOT_M    = 18        # marge légende

    max_per_row = max(1, int((W_pt - 20) / (NW + HGAP)))

    # Regrouper par type
    grouped = {t: [] for t in _TYPE_ORDER}
    for h in hosts:
        grouped[h["type"]].append(h)

    rows = []  # liste de (type, [hosts])
    for t in _TYPE_ORDER:
        chunk = grouped[t]
        if not chunk:
            continue
        for i in range(0, len(chunk), max_per_row):
            rows.append((t, chunk[i:i+max_per_row]))

    if not rows:
        return None

    n_rows    = len(rows)
    drawing_h = TOP_M + n_rows * NH + (n_rows - 1) * VGAP + BOT_M + 8

    d = Drawing(W_pt, drawing_h)

    # Fond
    d.add(Rect(0, 0, W_pt, drawing_h,
               fillColor=HexColor("#f8fafc"),
               strokeColor=HexColor("#e2e8f0"), strokeWidth=0.5))

    # Titre
    n_h = len(hosts)
    d.add(String(W_pt / 2, drawing_h - 14,
                 f"TOPOLOGIE RESEAU INTERNE  —  {n_h} hote{'s' if n_h > 1 else ''} decouvert{'s' if n_h > 1 else ''}",
                 fontSize=8, fontName="Helvetica-Bold",
                 fillColor=HexColor("#1e293b"), textAnchor="middle"))

    # Ligne de backbone verticale centrale
    bx = W_pt / 2
    if n_rows > 1:
        top_cy = drawing_h - TOP_M - NH / 2
        bot_cy = drawing_h - TOP_M - (n_rows - 1) * (NH + VGAP) - NH / 2
        d.add(Line(bx, top_cy, bx, bot_cy,
                   strokeColor=HexColor("#cbd5e1"), strokeWidth=1.5,
                   strokeDashArray=[5, 3]))

    # Dessiner chaque ligne
    for row_idx, (row_type, row_hosts) in enumerate(rows):
        cfg = _DEVICE_CFG.get(row_type, _DEVICE_CFG["unknown"])
        fg  = HexColor(cfg["color"])

        n_col      = len(row_hosts)
        row_total  = n_col * NW + (n_col - 1) * HGAP
        row_x0     = (W_pt - row_total) / 2

        # y du bas du nœud (coords RL, bas = 0)
        y_bot    = drawing_h - TOP_M - (row_idx + 1) * NH - row_idx * VGAP
        y_center = y_bot + NH / 2

        for col_idx, host in enumerate(row_hosts):
            x  = row_x0 + col_idx * (NW + HGAP)
            xc = x + NW / 2

            # Connecteur horizontal vers le backbone
            if abs(xc - bx) > 4:
                d.add(Line(bx, y_center, xc, y_center,
                           strokeColor=HexColor("#cbd5e1"), strokeWidth=0.8))

            # Corps du nœud
            d.add(Rect(x, y_bot, NW, NH,
                       fillColor=HexColor("#ffffff"),
                       strokeColor=fg, strokeWidth=1.2))

            # Bande colorée de type (haut du nœud)
            d.add(Rect(x, y_bot + NH - HDR_H, NW, HDR_H,
                       fillColor=fg, strokeColor=None))

            # Label type
            d.add(String(xc, y_bot + NH - HDR_H + 3,
                         cfg["label"],
                         fontSize=6, fontName="Helvetica-Bold",
                         fillColor=white, textAnchor="middle"))

            # Adresse IP
            d.add(String(xc, y_bot + NH - HDR_H - 13,
                         host["ip"],
                         fontSize=8.5, fontName="Helvetica-Bold",
                         fillColor=HexColor("#1e293b"), textAnchor="middle"))

            # Hostname
            hn = (host.get("hostname") or "")[:20]
            if hn:
                d.add(String(xc, y_bot + NH - HDR_H - 24,
                             hn,
                             fontSize=6, fontName="Helvetica",
                             fillColor=HexColor("#64748b"), textAnchor="middle"))

            # OS court
            os_full = host.get("os", "").lower()
            os_map = [("windows server 2022","WinSrv 2022"),
                      ("windows server 2019","WinSrv 2019"),
                      ("windows server 2016","WinSrv 2016"),
                      ("windows server 2012","WinSrv 2012"),
                      ("windows server 2008","WinSrv 2008"),
                      ("windows server",     "WinServer"),
                      ("windows 10",         "Windows 10"),
                      ("windows 11",         "Windows 11"),
                      ("windows",            "Windows"),
                      ("ubuntu",             "Ubuntu"),
                      ("debian",             "Debian"),
                      ("centos",             "CentOS"),
                      ("fedora",             "Fedora"),
                      ("redhat","RHEL"),("rhel","RHEL"),
                      ("linux",              "Linux")]
            os_short = next((v for k, v in os_map if k in os_full), "")
            if os_short:
                d.add(String(xc, y_bot + NH - HDR_H - 34,
                             os_short,
                             fontSize=5.5, fontName="Helvetica",
                             fillColor=HexColor("#94a3b8"), textAnchor="middle"))

            # Ports ouverts (bas de la fiche)
            ports_str = ", ".join(p.split("/")[0] for p in host.get("ports", [])[:5])
            if ports_str:
                d.add(String(xc, y_bot + 3,
                             f"ports: {ports_str}",
                             fontSize=5.5, fontName="Courier",
                             fillColor=HexColor("#475569"), textAnchor="middle"))

    # Légende (bas du dessin)
    present_types = [t for t in _TYPE_ORDER if grouped[t]]
    leg_item_w    = 70
    leg_x0        = max(8, (W_pt - len(present_types) * leg_item_w) / 2)
    for i, t in enumerate(present_types):
        cfg = _DEVICE_CFG[t]
        lx  = leg_x0 + i * leg_item_w
        if lx + 60 > W_pt:
            break
        d.add(Rect(lx, 5, 8, 8, fillColor=HexColor(cfg["color"]), strokeColor=None))
        d.add(String(lx + 11, 6, cfg["label"],
                     fontSize=5.5, fontName="Helvetica",
                     fillColor=HexColor("#475569"), textAnchor="start"))

    return d


def esc(s):
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def get_executive_summary(target, mitre_findings):
    """Appel LLM ciblé — narrative executive 3 phrases, basée uniquement sur les findings confirmés."""
    if not mitre_findings:
        return (f"L'audit automatisé de {target} n'a révélé aucune vulnérabilité critique "
                f"détectable par les outils utilisés. La surface d'attaque exposée semble limitée. "
                f"Une analyse manuelle approfondie est recommandée pour confirmer ces résultats.")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top = sorted(mitre_findings, key=lambda x: sev_order.get(x["severity"], 4))[:8]
    findings_list = "\n".join(f"- [{f['severity']}] {f['name']}" for f in top)
    prompt = (
        f"Voici les vulnérabilités confirmées par scan automatisé sur {target} :\n\n"
        f"{findings_list}\n\n"
        f"En 3 phrases concises en français pour un DSI non-technique :\n"
        f"1. Niveau de risque global et menace principale.\n"
        f"2. Impact métier des 2 findings les plus critiques.\n"
        f"3. Urgence et prochaine action prioritaire.\n\n"
        f"RÈGLE ABSOLUE : Mentionne UNIQUEMENT les éléments de la liste ci-dessus. "
        f"Aucune technologie, outil ou vulnérabilité non listé."
    )
    try:
        sp = Spinner("Synthèse executive...")
        sp.start()
        resp = ollama.chat(model=MODEL_NAME, messages=[
            {"role": "system", "content": "Tu es un expert cybersécurité senior. Réponds en exactement 3 phrases, sans markdown, directement."},
            {"role": "user",   "content": prompt},
        ])
        sp.stop()
        return re.sub(r'\*+', '', resp["message"]["content"]).strip()
    except:
        crit = sum(1 for f in mitre_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in mitre_findings if f["severity"] == "HIGH")
        top1 = top[0]["name"] if top else "vulnérabilité critique"
        return (f"L'audit de {target} révèle {len(mitre_findings)} vulnérabilités "
                f"({crit} critiques, {high} élevées). "
                f"La menace principale identifiée : {top1}. "
                f"Une action corrective immédiate est requise.")

def _finding_card(f, W):
    """Fiche de vulnérabilité : header coloré + evidence + impact + remédiation."""
    sev    = f.get("severity", "LOW")
    col    = SEV_COLOR.get(sev, C["muted"])
    uid    = f.get("_uid", f["technique"])
    meta   = FINDING_META.get(uid, FINDING_META.get(f["technique"], {}))
    ev     = f.get("evidence", "").strip()
    impact = meta.get("impact", "")
    fix    = meta.get("fix", "")
    delay  = meta.get("delay", "")

    rows, ts = [], []
    # Row 0 — header
    rows.append([
        _p(sev, 8, white, bold=True, align=TA_CENTER),
        _p(f"<b>{esc(f['name'])}</b>", 9, C["text"]),
        _p(f"<font color='#6366f1'>{f['technique']}</font>  <font color='#94a3b8' size='7'>{f.get('source','')}</font>", 8, align=TA_RIGHT),
    ])
    ts += [("BACKGROUND",(0,0),(0,0), col),
           ("BACKGROUND",(1,0),(2,0), C["bg"]),
           ("LINEBELOW", (0,0),(-1,0), 0.5, C["border"])]
    # Row 1 — evidence
    if ev:
        rows.append([_p("Evidence", 7, C["muted"], bold=True),
                     _p(esc(ev[:130]), 7, C["muted"], font="Courier"),
                     _p("", 7)])
        ts += [("BACKGROUND",(0,len(rows)-1),(-1,len(rows)-1), HexColor("#f1f5f9")),
               ("LINEBELOW", (0,len(rows)-1),(-1,len(rows)-1), 0.3, C["border"])]
    # Row 2 — impact
    if impact:
        rows.append([_p("Impact", 7, C["muted"], bold=True), _p(esc(impact), 8), _p("", 7)])
        ts.append(("LINEBELOW", (0,len(rows)-1),(-1,len(rows)-1), 0.3, HexColor("#f0f4f8")))
    # Row 3 — fix
    if fix:
        fix_txt = f"{esc(fix)}"
        if delay: fix_txt += f"  <font color='#64748b' size='7'>→ {esc(delay)}</font>"
        rows.append([_p("Remédiation", 7, C["muted"], bold=True), _p(fix_txt, 8), _p("", 7)])

    ts += [("BOX",         (0,0),(-1,-1), 1,   C["border"]),
           ("PADDING",     (0,0),(-1,-1), 5),
           ("LEFTPADDING", (1,0),(1,-1),  8),
           ("VALIGN",      (0,0),(-1,-1), "TOP"),
           ("VALIGN",      (0,0),(0,-1),  "MIDDLE"),
           ("SPAN",        (1,0),(2,0))]
    # Actually can't span with 3-col easily — use colWidths instead
    tbl = Table(rows, colWidths=[20*mm, W - 38*mm, 18*mm])
    tbl.setStyle(TableStyle(ts))
    return [tbl, Spacer(1, 3*mm)]

def save_pdf_report(target):
    log_text   = "\n".join(SESSION_LOG)
    mitre      = map_to_mitre(log_text)
    sev_counts = count_severity(mitre)          # 100% déterministe, pas de LLM
    grc        = grc_from_findings(mitre, sev_counts)
    risk_score = compute_risk_score(sev_counts)
    risk_lbl, risk_color = risk_label(risk_score)
    scope      = get_scope(SESSION_LOG)
    narrative  = get_executive_summary(target, mitre)

    fname = f"report_{re.sub(r'[^a-zA-Z0-9_]','_',target)}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    W     = A4[0] - 30*mm
    doc   = SimpleDocTemplate(fname, pagesize=A4,
                               leftMargin=15*mm, rightMargin=15*mm,
                               topMargin=18*mm,  bottomMargin=18*mm)
    story = []

    def section_title(title):
        return [Spacer(1, 5*mm),
                _p(title, 12, C["primary"], bold=True),
                HRFlowable(width="100%", thickness=2, color=C["accent"]),
                Spacer(1, 3*mm)]

    # ── 1. Header ────────────────────────────────────────────────────────────
    hdr = Table([[
        _p("<b>ORCHESTRATEUR</b><br/><font size='8'>Rapport d'Audit de Sécurité</font>", 16, white),
        _p(f"<font size='8'>Cible : <b>{esc(target)}</b></font><br/>"
           f"<font size='7'>Date  : {datetime.now().strftime('%d/%m/%Y %H:%M')}</font><br/>"
           f"<font size='7'>Mode  : {SCAN_MODE.upper()}</font><br/>"
           f"<font size='7' color='#94a3b8'>CONFIDENTIEL — Usage autorisé uniquement</font>",
           8, white, align=TA_RIGHT),
    ]], colWidths=[W*0.55, W*0.45])
    hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1), C["primary"]),
                              ("PADDING",   (0,0),(-1,-1), 12),
                              ("VALIGN",    (0,0),(-1,-1), "MIDDLE")]))
    story += [hdr, Spacer(1, 5*mm)]

    # ── 2. Résumé Exécutif ───────────────────────────────────────────────────
    story += section_title("Résumé Exécutif")

    exec_tbl = Table([[
        _p(f"<b>{sev_counts['CRITICAL']}</b><br/>CRITIQUE", 10, white, bold=True, align=TA_CENTER),
        _p(f"<b>{sev_counts['HIGH']}</b><br/>ÉLEVÉ",        10, white, bold=True, align=TA_CENTER),
        _p(f"<b>{sev_counts['MEDIUM']}</b><br/>MOYEN",      10, white, bold=True, align=TA_CENTER),
        _p(f"<b>{sev_counts['LOW']}</b><br/>FAIBLE",        10, white, bold=True, align=TA_CENTER),
        _p(f"<b>{risk_score}/100</b><br/>Score de risque",  10, white, bold=True, align=TA_CENTER),
    ]], colWidths=[W/5]*5, rowHeights=[16*mm])
    exec_tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,0), C["critical"]),
        ("BACKGROUND",(1,0),(1,0), C["high"]),
        ("BACKGROUND",(2,0),(2,0), C["medium"]),
        ("BACKGROUND",(3,0),(3,0), C["low"]),
        ("BACKGROUND",(4,0),(4,0), risk_color),
        ("ALIGN", (0,0),(-1,-1), "CENTER"),
        ("VALIGN",(0,0),(-1,-1), "MIDDLE"),
    ]))
    story.append(exec_tbl)
    story.append(Spacer(1, 4*mm))
    story.append(_p(narrative, 9, C["text"]))
    story.append(Spacer(1, 4*mm))

    # Actions immédiates — top 3 critiques/élevées
    urgent = [f for f in sorted(mitre, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],4))
              if f["severity"] in ("CRITICAL","HIGH")][:3]
    if urgent:
        story += section_title("Actions Immédiates")
        for i, f in enumerate(urgent, 1):
            meta = FINDING_META.get(f.get("_uid",""), FINDING_META.get(f["technique"], {}))
            fix_short = meta.get("fix","Voir fiche détaillée.")[:70]
            row = Table([[
                _p(f"<b>{i}</b>", 9, white, bold=True, align=TA_CENTER),
                _p(f"<b>{esc(f['name'])}</b>  —  <font size='7' color='#475569'>{esc(fix_short)}…</font>", 8),
            ]], colWidths=[8*mm, W-8*mm],
            style=[("BACKGROUND",(0,0),(0,0), SEV_COLOR.get(f["severity"], C["muted"])),
                   ("BACKGROUND",(1,0),(1,0), C["bg"]),
                   ("PADDING",(0,0),(-1,-1),5),
                   ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                   ("BOX",(0,0),(-1,-1),.5,C["border"])])
            story += [row, Spacer(1, 1.5*mm)]
        story.append(Spacer(1, 4*mm))

    # ── 3. Périmètre & Outils ────────────────────────────────────────────────
    if scope:
        story += section_title("Périmètre & Outils Utilisés")
        scope_rows = [[_p("Outil", 8, white, bold=True), _p("Cible analysée", 8, white, bold=True)]]
        for s in scope:
            parts = s.split("→", 1)
            scope_rows.append([_p(parts[0].strip(), 8), _p(parts[1].strip() if len(parts)>1 else "", 8)])
        st = Table(scope_rows, colWidths=[W*0.3, W*0.7])
        st.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0), C["primary"]),
                                 ("ROWBACKGROUNDS",(0,1),(-1,-1),[C["bg"],white]),
                                 ("GRID",(0,0),(-1,-1),.5,C["border"]),
                                 ("PADDING",(0,0),(-1,-1),5)]))
        story += [st, Spacer(1, 4*mm)]

    # ── 4. Topologie Réseau (mode internal uniquement) ───────────────────────
    if SCAN_MODE == "internal":
        hosts_dict = _parse_hosts_from_log(log_text)
        if hosts_dict:
            story += section_title(f"Topologie Réseau — {len(hosts_dict)} hôte{'s' if len(hosts_dict) > 1 else ''} découvert{'s' if len(hosts_dict) > 1 else ''}")
            topo = draw_network_map(hosts_dict, W)
            if topo:
                story += [topo, Spacer(1, 4*mm)]
            # Inventaire détaillé (table)
            inv_rows = [[_p("IP",8,white,bold=True), _p("Type",8,white,bold=True),
                         _p("Hostname",8,white,bold=True), _p("OS",8,white,bold=True),
                         _p("Ports ouverts",8,white,bold=True)]]
            for h in sorted(hosts_dict.values(),
                            key=lambda x: [int(o) for o in x["ip"].split(".") if o.isdigit()]):
                cfg = _DEVICE_CFG.get(h["type"], _DEVICE_CFG["unknown"])
                inv_rows.append([
                    _p(h["ip"], 8, C["accent"]),
                    _p(cfg["label"], 7, HexColor(cfg["color"]), bold=True),
                    _p(h.get("hostname","—")[:30], 8),
                    _p(h.get("os","—")[:35], 7, C["muted"]),
                    _p(", ".join(p.split("/")[0] for p in h.get("ports",[])[:8]) or "—", 7, C["muted"]),
                ])
            it = Table(inv_rows, colWidths=[W*.15, W*.15, W*.22, W*.26, W*.22])
            it.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), C["primary"]),
                ("ROWBACKGROUNDS",(0,1),(-1,-1), [C["bg"], white]),
                ("GRID",(0,0),(-1,-1), .5, C["border"]),
                ("PADDING",(0,0),(-1,-1), 5),
                ("VALIGN",(0,0),(-1,-1), "MIDDLE"),
            ]))
            story += [it, Spacer(1, 4*mm)]

    # ── 5. Vulnérabilités Détectées (fiches) ─────────────────────────────────
    if mitre:
        story += section_title(f"Vulnérabilités Détectées ({len(mitre)})")
        for f in sorted(mitre, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],4)):
            story += _finding_card(f, W)
        story.append(Spacer(1, 2*mm))

    # ── 5. Mapping MITRE ATT&CK ──────────────────────────────────────────────
    if mitre:
        story += section_title("Mapping MITRE ATT&CK")
        rows = [[_p("Technique",8,white,bold=True,align=TA_CENTER),
                 _p("Nom",8,white,bold=True),
                 _p("Tactique",8,white,bold=True),
                 _p("Source",8,white,bold=True),
                 _p("Sévérité",8,white,bold=True,align=TA_CENTER)]]
        for f in mitre:
            rows.append([_p(f["technique"],8,C["accent"],align=TA_CENTER),
                         _p(f["name"],8),
                         _p(f["tactic"],8),
                         _p(f.get("source","—"),8,C["muted"]),
                         _p(f["severity"],7,white,bold=True,align=TA_CENTER)])
        mt = Table(rows, colWidths=[W*.14, W*.34, W*.23, W*.15, W*.14])
        ts = [("BACKGROUND",(0,0),(-1,0),C["primary"]),
              ("ROWBACKGROUNDS",(0,1),(-1,-1),[C["bg"],white]),
              ("GRID",(0,0),(-1,-1),.5,C["border"]),
              ("PADDING",(0,0),(-1,-1),5),
              ("VALIGN",(0,0),(-1,-1),"MIDDLE")]
        for i, f in enumerate(mitre, 1):
            ts.append(("BACKGROUND",(4,i),(4,i),SEV_COLOR.get(f["severity"],C["muted"])))
        mt.setStyle(TableStyle(ts))
        story += [mt, Spacer(1, 4*mm)]

    # ── 6. Recommandations GRC ───────────────────────────────────────────────
    story += section_title("Recommandations GRC — ISO 27001 / NIS 2 / DORA")
    GRC_DELAY = {"CRITICAL": "Immédiat", "HIGH": "48h", "MEDIUM": "30 jours", "LOW": "90 jours"}
    grows = [[_p("Framework",8,white,bold=True,align=TA_CENTER),
              _p("Contrôle",8,white,bold=True),
              _p("Priorité",8,white,bold=True,align=TA_CENTER),
              _p("Action recommandée",8,white,bold=True),
              _p("Délai",8,white,bold=True,align=TA_CENTER)]]
    for rec in grc:
        grows.append([
            _p(f"<b>{rec['framework']}</b><br/>{rec['article']}", 8, C["accent"], align=TA_CENTER),
            _p(rec["control"], 8),
            _p(rec["priority"], 7, white, bold=True, align=TA_CENTER),
            _p(rec["action"], 8),
            _p(GRC_DELAY.get(rec["priority"],"30 jours"), 7, C["muted"], align=TA_CENTER),
        ])
    gt = Table(grows, colWidths=[W*.12, W*.23, W*.10, W*.43, W*.12])
    gts = [("BACKGROUND",(0,0),(-1,0),C["primary"]),
           ("ROWBACKGROUNDS",(0,1),(-1,-1),[C["bg"],white]),
           ("GRID",(0,0),(-1,-1),.5,C["border"]),
           ("PADDING",(0,0),(-1,-1),5),
           ("VALIGN",(0,0),(-1,-1),"TOP")]
    for i, rec in enumerate(grc, 1):
        gts.append(("BACKGROUND",(2,i),(2,i),SEV_COLOR.get(rec["priority"],C["muted"])))
    gt.setStyle(TableStyle(gts))
    story += [gt, Spacer(1, 4*mm)]

    # ── 7. Footer ────────────────────────────────────────────────────────────
    story += [HRFlowable(width="100%", thickness=.5, color=C["border"]), Spacer(1, 2*mm),
              _p(f"Orchestrateur — Rapport généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} — "
                 f"Audit automatisé — Pour usage autorisé uniquement.", 7, C["muted"], align=TA_CENTER)]

    doc.build(story)
    print(f"\n[+] Rapport PDF : {fname}")
    return fname

# =============================================================================
# LOGIQUE AGENT
# =============================================================================
def chat_with_agent(user_input):
    global MEMORY, SESSION_LOG
    MEMORY.append({"role": "user", "content": user_input})
    spinner = Spinner("L'Orchestrateur analyse...")

    for _ in range(15):
        try:
            spinner.start()
            response = ollama.chat(model=MODEL_NAME, messages=MEMORY)
            spinner.stop()
            text = response["message"]["content"]
            print(f"\n🤖 L'Orchestrateur:\n{text}")

            if "RAPPORT" in text.upper() or "CONCLUSION" in text.upper():
                m = re.search(r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})', user_input)
                target = m.group(1) if m else user_input.split()[-1].strip()
                save_pdf_report(target)
                break

            # Primary: "ACTION: tool(arg)" or "ACTION : tool(arg)"
            actions = re.findall(r"ACTION\s*:\s*(\w+)\((.*?)\)", text)
            # Fallback: LLM used backtick format `tool(arg)` — extract known tools
            if not actions:
                seen_k: set = set()
                for tool_name, arg in re.findall(r"`(\w+)\(([^)`]*)\)`", text):
                    if tool_name in TOOLS:
                        k = f"{tool_name}|{arg}"
                        if k not in seen_k:
                            seen_k.add(k)
                            actions.append((tool_name, arg))
            if actions:
                MEMORY.append({"role": "assistant", "content": text})
                for tool_name, tool_arg in actions:
                    tool_arg = tool_arg.strip()
                    if tool_name in TOOLS:
                        result = TOOLS[tool_name](tool_arg)
                        SESSION_LOG.append(f"=== {tool_name.upper()} ({tool_arg}) ===\n{result}")
                        MEMORY.append({"role": "user", "content": f"RÉSULTAT {tool_name.upper()} :\n{result}"})
                    else:
                        MEMORY.append({"role": "user", "content": f"Erreur : outil '{tool_name}' inconnu."})
            else:
                break

        except Exception as e:
            spinner.stop()
            print(f"Erreur : {e}")
            break

# =============================================================================
# ENTRY POINT
# =============================================================================
print("\n╔══════════════════════════════════════════╗")
print("║    L'ORCHESTRATEUR — Cyber Agent CLI     ║")
print(f"║    Mode : {SCAN_MODE.upper():<10}  Red/Blue + GRC    ║")
print("╚══════════════════════════════════════════╝\n")

if args.target:
    if SCAN_MODE == "internal":
        query = (f"Audit de sécurité du réseau interne {args.target}. "
                 f"Lance network_discover({args.target}) pour découvrir les hôtes, "
                 f"puis pour chaque hôte actif : service_version, smb_scan. "
                 f"Lance vuln_scan sur les hôtes avec SMB ouvert. "
                 f"Génère ensuite le rapport complet.")
    else:
        query = f"Analyse complète de la sécurité de {args.target}"
    print(f"❓ Mission : {query}")
    chat_with_agent(query)
else:
    while True:
        query = input("❓ Mission (ou 'exit') : ")
        if query.lower() == "exit":
            break
        chat_with_agent(query)
        MEMORY      = [{"role": "system", "content": SYSTEM_PROMPT}]
        SESSION_LOG = []
