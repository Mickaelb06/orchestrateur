import ollama
import subprocess
import re
import os
import requests
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor, white
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# =============================================================================
# CONFIGURATION
# =============================================================================
MODEL_NAME = "gemma4:31b-cloud"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

SYSTEM_PROMPT = """Tu es L'Orchestrateur, un Expert Senior en Cybersécurité (Red Team, Blue Team, OSINT) et Consultant en Conformité Réglementaire.
Ton rôle est de mener des reconnaissances méthodiques et d'aligner les résultats avec les exigences légales (ISO 27001, NIS 2 et DORA).

RÈGLES DE RAISONNEMENT :
1. ACTION : Utilise ACTION: outil(argument) pour agir. Tu peux lancer plusieurs actions.
2. ANALYSE HOLISTIQUE : Pour chaque vulnérabilité, analyse-la sous le prisme de l'ISO 27001, NIS 2 et DORA.
3. GAP ANALYSIS : Identifie les manquements entre l'état actuel et les exigences légales.
4. PRIORISATION : Priorise selon la criticité du risque et les sanctions encourues (ex: obligations DORA/NIS 2).
5. SYNTHÈSE : Termine TOUJOURS ton analyse par 'RAPPORT FINAL :' suivi d'une synthèse complète.

OUTILS DISPONIBLES :
- whois(domaine)        : informations WHOIS
- ping(cible)           : test de connectivité
- nmap(cible)           : scan de ports
- dig(domaine)          : résolution DNS
- http_header(url)      : en-têtes HTTP
- ssl_check(url)        : vérification SSL/TLS
- nikto(cible)          : scan de vulnérabilités web
- dir_scan(url)         : scan de répertoires sensibles
- sherlock(pseudo)      : OSINT réseaux sociaux
- virustotal(cible)     : réputation VirusTotal (domaine ou IP)
- abuseipdb(ip)         : score d'abus IP
"""

MEMORY      = [{"role": "system", "content": SYSTEM_PROMPT}]
SESSION_LOG = []

# =============================================================================
# SÉCURITÉ : Nettoyage des entrées (Anti-Injection)
# =============================================================================
def clean_input(target):
    return re.sub(r"[^a-zA-Z0-9.\-/_]", "", target)

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
        url = t if t.startswith("http") else f"http://{t}"
        return subprocess.check_output(["curl", "-I", url], stderr=subprocess.STDOUT, text=True, timeout=15)
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
    dirs = ["admin", "login", ".env", ".git/config", "backup", "phpmyadmin", "config.php", "wp-admin"]
    found = []
    url = t if t.startswith("http") else f"http://{t}"
    for d in dirs:
        try:
            code = subprocess.check_output(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"{url}/{d}"],
                text=True, timeout=5
            )
            if code == "200":
                found.append(f"{url}/{d} [200 OK]")
        except: continue
    return "\n".join(found) if found else "Aucun répertoire sensible trouvé."

def run_sherlock(username):
    u = clean_input(username)
    print(f"[*] Sherlock -> {u}...")
    try: return subprocess.check_output(["sherlock", u, "--timeout", "5"], stderr=subprocess.STDOUT, text=True, timeout=300)
    except Exception as e: return f"Erreur Sherlock: {e}"

# =============================================================================
# OUTILS API EXTERNE
# =============================================================================
def run_virustotal(target):
    t = clean_input(target)
    print(f"[*] VirusTotal -> {t}...")
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal: clé VIRUSTOTAL_API_KEY non configurée (export VIRUSTOTAL_API_KEY=...)."
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{t}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15
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
        return "AbuseIPDB: clé ABUSEIPDB_API_KEY non configurée (export ABUSEIPDB_API_KEY=...)."
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": t, "maxAgeInDays": 90},
            timeout=15
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return (f"AbuseIPDB [{t}]: Score={d.get('abuseConfidenceScore',0)}%, "
                    f"Reports={d.get('totalReports',0)}, Country={d.get('countryCode','?')}")
        return f"AbuseIPDB: HTTP {r.status_code}"
    except Exception as e:
        return f"Erreur AbuseIPDB: {e}"

TOOLS = {
    "whois": run_whois,       "ping": run_ping,         "nmap": run_nmap,
    "dig": run_dig,           "http_header": run_http_header,
    "ssl_check": run_ssl_check, "nikto": run_nikto,
    "dir_scan": run_dir_scan, "sherlock": run_sherlock,
    "virustotal": run_virustotal, "abuseipdb": run_abuseipdb,
}

# =============================================================================
# MITRE ATT&CK MAPPING
# =============================================================================
MITRE_RULES = [
    {"port": "3389", "technique": "T1021.001", "name": "Remote Desktop Protocol",    "tactic": "Lateral Movement",      "severity": "HIGH"},
    {"port": "22",   "technique": "T1021.004", "name": "SSH Remote Services",         "tactic": "Lateral Movement",      "severity": "MEDIUM"},
    {"port": "21",   "technique": "T1071.002", "name": "FTP Protocol",               "tactic": "Command & Control",     "severity": "HIGH"},
    {"port": "445",  "technique": "T1021.002", "name": "SMB/Windows Admin Shares",   "tactic": "Lateral Movement",      "severity": "CRITICAL"},
    {"port": "23",   "technique": "T1021",     "name": "Telnet Remote Services",      "tactic": "Lateral Movement",      "severity": "CRITICAL"},
    {"port": "3306", "technique": "T1190",     "name": "MySQL Database Exposed",      "tactic": "Initial Access",        "severity": "CRITICAL"},
    {"port": "5432", "technique": "T1190",     "name": "PostgreSQL Exposed",          "tactic": "Initial Access",        "severity": "CRITICAL"},
    {"port": "27017","technique": "T1190",     "name": "MongoDB Exposed",             "tactic": "Initial Access",        "severity": "CRITICAL"},
    {"port": "6379", "technique": "T1190",     "name": "Redis Exposed",               "tactic": "Initial Access",        "severity": "CRITICAL"},
    {"keyword": "X-Frame-Options",         "technique": "T1189", "name": "Drive-by Compromise (missing header)",  "tactic": "Initial Access",    "severity": "MEDIUM", "missing": True},
    {"keyword": "Strict-Transport-Security","technique": "T1557", "name": "HSTS Missing",                         "tactic": "Credential Access", "severity": "MEDIUM", "missing": True},
    {"keyword": "Malicious=",              "technique": "T1583", "name": "Malicious Infrastructure (VirusTotal)", "tactic": "Resource Development","severity": "CRITICAL"},
    {"keyword": "Score=",                  "technique": "T1583", "name": "IP Abuse Score (AbuseIPDB)",            "tactic": "Resource Development","severity": "HIGH"},
]

def map_to_mitre(log_text):
    seen, findings = set(), []
    for rule in MITRE_RULES:
        if "port" in rule:
            if f"{rule['port']}/tcp" in log_text:
                if rule["technique"] not in seen:
                    seen.add(rule["technique"]); findings.append(rule)
        elif rule.get("missing"):
            if rule["keyword"] not in log_text:
                if rule["technique"] not in seen:
                    seen.add(rule["technique"]); findings.append(rule)
        elif "keyword" in rule:
            if rule["keyword"] in log_text:
                if rule["technique"] not in seen:
                    seen.add(rule["technique"]); findings.append(rule)
    return findings

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
    style = ParagraphStyle("x", fontSize=size, textColor=color or C["text"],
                           alignment=align, fontName=font, leading=size*1.4)
    return Paragraph(str(text), style)

def count_severity(text):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for w in text.upper().split():
        if w in counts:
            counts[w] += 1
    return counts

def grc_from_findings(mitre_findings, sev_counts):
    recs = []
    if sev_counts.get("CRITICAL", 0) > 0:
        recs.append({"framework": "NIS 2", "article": "Art. 21",
                     "control": "Sécurité des réseaux et SI",
                     "priority": "CRITICAL",
                     "action": "Fermer immédiatement les ports critiques exposés. Déployer un pare-feu applicatif."})
    if any(r["technique"] in ("T1021.001","T1021.002","T1021.004") for r in mitre_findings):
        recs.append({"framework": "ISO 27001", "article": "A.8.20",
                     "control": "Sécurité des réseaux",
                     "priority": "HIGH",
                     "action": "Restreindre les accès admin distants via VPN + MFA obligatoire."})
    if any(r["technique"] == "T1557" for r in mitre_findings):
        recs.append({"framework": "DORA", "article": "Art. 9",
                     "control": "Sécurité des communications",
                     "priority": "HIGH",
                     "action": "Renouveler les certificats SSL/TLS. Activer HSTS (min. 1 an)."})
    if any(r["technique"] == "T1189" for r in mitre_findings):
        recs.append({"framework": "ISO 27001", "article": "A.8.23",
                     "control": "Filtrage des accès web",
                     "priority": "MEDIUM",
                     "action": "Ajouter les en-têtes HTTP : X-Frame-Options, CSP, HSTS, X-Content-Type-Options."})
    if not recs:
        recs.append({"framework": "ISO 27001", "article": "A.5.2",
                     "control": "Politique de sécurité",
                     "priority": "LOW",
                     "action": "Mettre en place une surveillance continue et des audits réguliers."})
    return recs

def save_pdf_report(target, ai_analysis):
    log_text   = "\n".join(SESSION_LOG)
    mitre      = map_to_mitre(log_text)
    sev_counts = count_severity(log_text + " " + ai_analysis)
    grc        = grc_from_findings(mitre, sev_counts)

    fname = f"report_{re.sub(r'[^a-zA-Z0-9_]', '_', target)}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    W     = A4[0] - 30*mm

    doc   = SimpleDocTemplate(fname, pagesize=A4,
                               leftMargin=15*mm, rightMargin=15*mm,
                               topMargin=15*mm, bottomMargin=15*mm)
    story = []

    # ── Header ──────────────────────────────────────────────────────────────
    hdr = Table([[
        _p("ORCHESTRATEUR", 18, white, bold=True),
        _p(f"Rapport Cybersécurité<br/>{datetime.now().strftime('%d/%m/%Y %H:%M')}",
           8, white, align=TA_RIGHT),
    ]], colWidths=[W*0.6, W*0.4])
    hdr.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C["primary"]),
        ("PADDING",    (0,0), (-1,-1), 10),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
    ]))
    story += [hdr, Spacer(1, 4*mm),
              _p(f"Cible : <b>{target}</b>", 13),
              Spacer(1, 2*mm),
              HRFlowable(width="100%", thickness=1, color=C["border"]),
              Spacer(1, 4*mm)]

    # ── Severity summary ────────────────────────────────────────────────────
    story.append(_p("Résumé Exécutif", 12, bold=True))
    story.append(Spacer(1, 2*mm))
    sev_row = [[
        _p(f"<b>{sev_counts['CRITICAL']}</b><br/>CRITIQUE", 8, white, align=TA_CENTER),
        _p(f"<b>{sev_counts['HIGH']}</b><br/>ÉLEVÉ",        8, white, align=TA_CENTER),
        _p(f"<b>{sev_counts['MEDIUM']}</b><br/>MOYEN",      8, white, align=TA_CENTER),
        _p(f"<b>{sev_counts['LOW']}</b><br/>FAIBLE",        8, white, align=TA_CENTER),
    ]]
    sev_tbl = Table(sev_row, colWidths=[W/4]*4, rowHeights=[16*mm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), C["critical"]),
        ("BACKGROUND", (1,0), (1,0), C["high"]),
        ("BACKGROUND", (2,0), (2,0), C["medium"]),
        ("BACKGROUND", (3,0), (3,0), C["low"]),
        ("ALIGN",  (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    story += [sev_tbl, Spacer(1, 6*mm)]

    # ── AI Analysis ─────────────────────────────────────────────────────────
    story.append(_p("Analyse & Recommandations IA", 12, bold=True))
    story.append(Spacer(1, 2*mm))
    clean = ai_analysis.replace("*","").replace("#","").replace("<","&lt;").replace(">","&gt;")
    for line in clean.split("\n"):
        if line.strip():
            story.append(_p(line.strip(), 9))
    story += [Spacer(1, 5*mm), HRFlowable(width="100%", thickness=1, color=C["border"]), Spacer(1, 4*mm)]

    # ── MITRE ATT&CK ────────────────────────────────────────────────────────
    if mitre:
        story.append(_p("MITRE ATT&CK — Techniques Détectées", 12, bold=True))
        story.append(Spacer(1, 2*mm))
        rows = [[_p("Technique",8,white,bold=True,align=TA_CENTER),
                 _p("Nom",8,white,bold=True),
                 _p("Tactique",8,white,bold=True),
                 _p("Sévérité",8,white,bold=True,align=TA_CENTER)]]
        for f in mitre:
            rows.append([
                _p(f["technique"], 8, C["accent"], align=TA_CENTER),
                _p(f["name"], 8),
                _p(f["tactic"], 8),
                _p(f["severity"], 7, white, bold=True, align=TA_CENTER),
            ])
        mt = Table(rows, colWidths=[W*.15, W*.40, W*.28, W*.17])
        ts = [("BACKGROUND",(0,0),(-1,0),C["primary"]),
              ("ROWBACKGROUNDS",(0,1),(-1,-1),[C["bg"],white]),
              ("GRID",(0,0),(-1,-1),.5,C["border"]),
              ("PADDING",(0,0),(-1,-1),5),
              ("VALIGN",(0,0),(-1,-1),"MIDDLE")]
        for i,f in enumerate(mitre,1):
            ts.append(("BACKGROUND",(3,i),(3,i), SEV_COLOR.get(f["severity"], C["muted"])))
        mt.setStyle(TableStyle(ts))
        story += [mt, Spacer(1, 6*mm),
                  HRFlowable(width="100%", thickness=1, color=C["border"]), Spacer(1, 4*mm)]

    # ── GRC Recommendations ─────────────────────────────────────────────────
    story.append(_p("Recommandations GRC — ISO 27001 / NIS 2 / DORA", 12, bold=True))
    story.append(Spacer(1, 2*mm))
    grows = [[_p("Framework",8,white,bold=True,align=TA_CENTER),
              _p("Contrôle",8,white,bold=True),
              _p("Priorité",8,white,bold=True,align=TA_CENTER),
              _p("Action recommandée",8,white,bold=True)]]
    for rec in grc:
        grows.append([
            _p(f"<b>{rec['framework']}</b><br/>{rec['article']}", 8, C["accent"], align=TA_CENTER),
            _p(rec["control"], 8),
            _p(rec["priority"], 7, white, bold=True, align=TA_CENTER),
            _p(rec["action"], 8),
        ])
    gt = Table(grows, colWidths=[W*.13, W*.27, W*.12, W*.48])
    gts = [("BACKGROUND",(0,0),(-1,0),C["primary"]),
           ("ROWBACKGROUNDS",(0,1),(-1,-1),[C["bg"],white]),
           ("GRID",(0,0),(-1,-1),.5,C["border"]),
           ("PADDING",(0,0),(-1,-1),5),
           ("VALIGN",(0,0),(-1,-1),"TOP")]
    for i,rec in enumerate(grc,1):
        gts.append(("BACKGROUND",(2,i),(2,i), SEV_COLOR.get(rec["priority"], C["muted"])))
    gt.setStyle(TableStyle(gts))
    story += [gt, Spacer(1, 6*mm),
              HRFlowable(width="100%", thickness=1, color=C["border"]), Spacer(1, 4*mm)]

    # ── Technical evidence ───────────────────────────────────────────────────
    story.append(_p("Preuves Techniques", 12, bold=True))
    story.append(Spacer(1, 2*mm))
    mono = ParagraphStyle("mono", fontSize=7, fontName="Courier",
                          textColor=C["text"], leading=10, spaceAfter=1)
    for entry in SESSION_LOG:
        for line in entry.split("\n")[:25]:
            if line.strip():
                safe = line.replace("<","&lt;").replace(">","&gt;")
                story.append(Paragraph(safe, mono))
        story.append(Spacer(1, 3*mm))

    # ── Footer ──────────────────────────────────────────────────────────────
    story += [HRFlowable(width="100%", thickness=.5, color=C["border"]), Spacer(1, 2*mm),
              _p("Généré par Orchestrateur — Pour usage autorisé uniquement.", 7, C["muted"], align=TA_CENTER)]

    doc.build(story)
    print(f"\n[+] Rapport PDF : {fname}")
    return fname

# =============================================================================
# LOGIQUE AGENT
# =============================================================================
def chat_with_agent(user_input):
    global MEMORY, SESSION_LOG
    MEMORY.append({"role": "user", "content": user_input})

    for _ in range(15):
        try:
            response = ollama.chat(model=MODEL_NAME, messages=MEMORY)
            text     = response["message"]["content"]
            print(f"\n🤖 L'Orchestrateur: {text}")

            if "RAPPORT" in text.upper() or "CONCLUSION" in text.upper():
                analysis = text.split("RAPPORT FINAL :")[-1].strip() if "RAPPORT FINAL :" in text else text
                target   = user_input.split()[-1].strip()
                save_pdf_report(target, analysis)
                break

            actions = re.findall(r"ACTION:\s*(\w+)\((.*?)\)", text)
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
            print(f"Erreur : {e}")
            break

# =============================================================================
# ENTRY POINT
# =============================================================================
print("\n╔══════════════════════════════════════════╗")
print("║    L'ORCHESTRATEUR — Cyber Agent CLI     ║")
print("║    Red/Blue Team + MITRE + GRC           ║")
print("╚══════════════════════════════════════════╝\n")

while True:
    query = input("❓ Mission (ou 'exit') : ")
    if query.lower() == "exit":
        break
    chat_with_agent(query)
    MEMORY      = [{"role": "system", "content": SYSTEM_PROMPT}]
    SESSION_LOG = []
