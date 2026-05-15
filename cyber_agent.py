import ollama
import subprocess
import re
from datetime import datetime

# =============================================================================
# 1. CONFIGURATION & MÉMOIRE
# =============================================================================
MODEL_NAME = "gemma4:31b-cloud" 

# System Prompt Hybride : Technique + Conformité (ISO/NIS2/DORA)
SYSTEM_PROMPT = """Tu es L'Orchestrateur, un Expert Senior en Cybersécurité (Red Team, Blue Team, OSINT) et Consultant en Conformité Réglementaire.
Ton rôle est de mener des reconnaissances méthodiques et d'aligner les résultats avec les exigences légales (ISO 27001, NIS 2 et DORA).

RÈGLES DE RAISONNEMENT :
1. ACTION : Utilise ACTION: outil(argument) pour agir. Tu peux lancer plusieurs actions.
2. ANALYSE HOLISTIQUE : Pour chaque vulnérabilité, analyse-la sous le prisme de l'ISO 27001, NIS 2 et DORA.
3. GAP ANALYSIS : Identifie les manquements entre l'état actuel et les exigences légales.
4. PRIORISATION : Priorise selon la criticité du risque et les sanctions encourues (ex: obligations DORA/NIS 2).
5. SYNTHÈSE : Termine TOUJOURS ton analyse par 'RAPPORT FINAL :' suivi d'une synthèse complète.

OUTILS :
- whois(domaine), ping(cible), nmap(cible), dig(domaine), http_header(url), ssl_check(url), nikto(cible), dir_scan(url), sherlock(pseudo)
"""

MEMORY = [{"role": "system", "content": SYSTEM_PROMPT}]
SESSION_LOG = []

# =============================================================================
# 2. SÉCURITÉ : Nettoyage des entrées (Anti-Injection)
# =============================================================================

def clean_input(target):
    """Supprime les caractères dangereux pour empêcher l'injection de commandes."""
    # On n'autorise que les lettres, chiffres, points, tirets et slashs
    return re.sub(r"[^a-zA-Z0-9.\-/_]", "", target)

# =============================================================================
# 3. DÉFINITION DES OUTILS
# =============================================================================

def run_whois(target):
    t = clean_input(target)
    print(f"[*] Whois -> {t}..."); 
    try: return subprocess.check_output(["whois", t], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_ping(target):
    t = clean_input(target)
    print(f"[*] Ping -> {t}..."); 
    try: return subprocess.check_output(["ping", "-c", "1", t], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_nmap(target):
    t = clean_input(target)
    print(f"[*] Nmap Scanning -> {t}..."); 
    try: return subprocess.check_output(["nmap", "-F", t], stderr=subprocess.STDOUT, text=True, timeout=60)
    except Exception as e: return f"Erreur: {e}"

def run_dig(target):
    t = clean_input(target)
    print(f"[*] Dig DNS -> {t}..."); 
    try: return subprocess.check_output(["dig", t, "ANY"], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_http_header(target):
    t = clean_input(target)
    print(f"[*] HTTP Headers -> {t}..."); 
    try:
        url = t if t.startswith("http") else f"http://{t}"
        return subprocess.check_output(["curl", "-I", url], stderr=subprocess.STDOUT, text=True, timeout=15)
    except Exception as e: return f"Erreur: {e}"

def run_ssl_check(target):
    t = clean_input(target)
    print(f"[*] Analyse SSL/TLS -> {t}...")
    try:
        url = t.replace("http://", "").replace("https://", "").split('/')[0]
        return subprocess.check_output(["openssl", "s_client", "-connect", f"{url}:443", "-servername", url], stderr=subprocess.STDOUT, text=True, timeout=15)[:1000]
    except Exception as e: return f"Erreur SSL: {e}"

def run_nikto(target):
    t = clean_input(target)
    print(f"[*] Nikto Vulnerability Scan -> {t}...")
    try: return subprocess.check_output(["nikto", "-h", t, "-T5"], stderr=subprocess.STDOUT, text=True, timeout=300)
    except Exception as e: return f"Erreur Nikto: {e}"

def run_dir_scan(target):
    t = clean_input(target)
    print(f"[*] Dir Scan -> {t}...")
    common_dirs = ["admin", "login", ".env", ".git/config", "backup", "phpmyadmin", "config.php", "wp-admin"]
    found = []
    url = t if t.startswith("http") else f"http://{t}"
    for d in common_dirs:
        try:
            res = subprocess.check_output(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"{url}/{d}"], text=True, timeout=5)
            if res == "200": found.append(f"{url}/{d} [200 OK]")
        except: continue
    return "\n".join(found) if found else "Aucun répertoire sensible trouvé."

def run_sherlock(username):
    u = clean_input(username)
    print(f"[*] Sherlock OSINT -> {u}...")
    try: return subprocess.check_output(["sherlock", u, "--timeout", "5"], stderr=subprocess.STDOUT, text=True, timeout=300)
    except Exception as e: return f"Erreur Sherlock: {e}"

TOOLS = {
    "whois": run_whois, "ping": run_ping, "nmap": run_nmap, 
    "dig": run_dig, "http_header": run_http_header, 
    "ssl_check": run_ssl_check, "nikto": run_nikto, 
    "dir_scan": run_dir_scan, "sherlock": run_sherlock
}

# =============================================================================
# 4. RAPPORT & LOGIQUE
# =============================================================================

def save_report(target, ai_analysis):
    filename = f"report_{target.replace('.', '_')}.txt"
    header = f"==========================================================\nRAPPORT DE CYBERSÉCURITÉ PROFESSIONNEL\n==========================================================\nDATE : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nCIBLE : {target}\n----------------------------------------------------------\n"
    evidence = "\n\n--- PREUVES TECHNIQUES BRUTES ---\n"
    for entry in SESSION_LOG:
        evidence += f"\n{entry}\n{'-'*40}"
    analysis = f"\n\n--- ANALYSE STRATÉGIQUE & CONFORMITÉ (ISO/NIS2/DORA) ---\n\n{ai_analysis}"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(header + evidence + analysis + "\n\n==========================================================")
    print(f"\n[+] Rapport sauvegardé : {filename}")

def chat_with_agent(user_input):
    global MEMORY, SESSION_LOG
    MEMORY.append({"role": "user", "content": user_input})

    for i in range(15):
        try:
            response = ollama.chat(model=MODEL_NAME, messages=MEMORY)
            text = response['message']['content']
            print(f"\n🤖 L'Orchestrateur: {text}")

            if "RAPPORT" in text.upper() or "CONCLUSION" in text.upper():
                report_content = text.split("RAPPORT FINAL :")[-1].strip() if "RAPPORT FINAL :" in text else text
                target_guess = user_input.split()[-1].replace(" ", "").strip()
                save_report(target_guess, report_content)
                break

            actions = re.findall(r"ACTION:\s*(\w+)\((.*?)\)", text)
            if actions:
                MEMORY.append({"role": "assistant", "content": text})
                for tool_name, tool_arg in actions:
                    tool_arg = tool_arg.strip()
                    if tool_name in TOOLS:
                        result = TOOLS[tool_name](tool_arg)
                        SESSION_LOG.append(f"Outil: {tool_name} | Cible: {tool_arg}\nRésultat:\n{result}")
                        MEMORY.append({"role": "user", "content": f"RÉSULTAT {tool_name} : \n{result}"})
                    else:
                        MEMORY.append({"role": "user", "content": f"Erreur : Outil {tool_name} inconnu."})
            else:
                break
        except Exception as e:
            print(f"Erreur : {e}"); break

print("\n--- L'Orchestrateur (Sécurisé & Consultant) activé ---")
while True:
    query = input("\n❓ Mission (ou 'exit') : ")
    if query.lower() == 'exit': break
    chat_with_agent(query)