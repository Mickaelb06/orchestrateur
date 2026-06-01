# L'Orchestrateur

**Agent IA d'audit de sécurité — Automatisez vos reconnaissances, générez des rapports PDF professionnels.**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![AI](https://img.shields.io/badge/LLM-Gemma%204-orange?style=flat-square)
![License](https://img.shields.io/badge/Licence-Pro%20299€%2Fan-green?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ed?style=flat-square)

---

## Ce que ça fait

Vous donnez un domaine ou une IP. L'Orchestrateur lance automatiquement la suite d'outils adaptée, analyse les résultats et génère un **rapport PDF professionnel** avec mapping MITRE ATT&CK et recommandations ISO 27001 / NIS 2 / DORA.

```
Input  : python cyber_agent.py --target client.fr --full
Output : report_client_fr_20260601.pdf  (2-5 pages, prêt à livrer)
```

Temps moyen : **8-15 minutes** contre 3-4 heures en manuel.

---

## Modes de scan

| Mode | Commande | Outils lancés | Licence |
|------|----------|---------------|---------|
| **Standard** | `--target domain.fr` | whois, nmap, dig, headers, SSL, cookies, CORS, WAF, VirusTotal | Gratuit |
| **Rapide** | `--quick` | whois, nmap, dig, headers, SSL, email security | Gratuit |
| **Complet** | `--full` | Tous les outils + Nikto, subdomain enum, CVE check, dir scan | **Pro** |
| **Réseau interne** | `--internal` | Network discover, ARP scan, SMB audit, vuln scan, topologie réseau | **Pro** |

---

## Rapport PDF généré

Chaque rapport inclut :

- **Résumé exécutif** — synthèse 3 phrases pour le RSSI / DSI
- **Périmètre & outils** — liste des outils exécutés + cibles
- **Topologie réseau** *(mode internal)* — graphique des hôtes avec classification automatique (routeur, serveur, poste, imprimante, caméra...)
- **Vulnérabilités détectées** — classées CRITIQUE / ÉLEVÉ / MOYEN / FAIBLE
- **Mapping MITRE ATT&CK** — techniques associées à chaque finding
- **Recommandations GRC** — actions correctives alignées ISO 27001, NIS 2, DORA

---

## Outils intégrés

### OSINT & Reconnaissance
- `whois` — informations registrar, dates d'expiration
- `dig` — enregistrements DNS (A, MX, TXT, NS)
- `subdomain_enum` — énumération de sous-domaines [FULL]
- `sherlock` — OSINT réseaux sociaux

### Infrastructure
- `nmap` — scan de ports et services (supporte CIDR)
- `ssl_check` — certificat, protocoles, cipher suites
- `email_security` — SPF, DKIM, DMARC

### Web & Vulnérabilités
- `http_header` — headers de sécurité manquants
- `cookie_audit` — flags HttpOnly, Secure, SameSite
- `cors_check` — misconfiguration CORS
- `http_methods` — méthodes dangereuses (PUT, DELETE, TRACE)
- `redirect_check` — redirection HTTP→HTTPS + HSTS
- `waf_detect` — détection WAF/CDN
- `tech_detect` — CMS, framework, serveur web
- `virustotal` — réputation domaine/IP
- `abuseipdb` — score d'abus IP
- `nikto` — scan de vulnérabilités web [FULL]
- `dir_scan` — fichiers sensibles exposés (.env, .git, admin) [FULL]
- `cve_check` — CVE connues sur les services détectés [FULL]

### Réseau interne [PRO]
- `network_discover` — découverte des hôtes actifs sur un subnet
- `arp_scan` — scan ARP local
- `service_version` — détection OS et versions de services (nmap -sV -O)
- `smb_scan` — audit SMB : signing, partages, authentification
- `vuln_scan` — vulnérabilités NSE (EternalBlue, MS17-010...)

---

## Installation

### Prérequis système

```bash
# Debian / Ubuntu
sudo apt install nmap bind-utils curl whois nikto git -y

# Fedora / RHEL
sudo dnf install nmap bind-utils curl whois nikto git -y
```

### Ollama + modèle

```bash
# Installer Ollama : https://ollama.com
ollama pull gemma4:31b-cloud
```

### Python

```bash
git clone https://github.com/Mickaelb06/orchestrateur.git
cd orchestrateur
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Docker (recommandé)

```bash
docker build -t orchestrateur .
docker run -it --network=host orchestrateur
```

---

## Utilisation

```bash
# Scan standard (gratuit)
python cyber_agent.py --target example.com

# Scan rapide
python cyber_agent.py --target example.com --quick

# Scan complet — rapport PDF détaillé [PRO]
python cyber_agent.py --target example.com --full

# Audit réseau interne — topologie + SMB + vulns [PRO]
python cyber_agent.py --target 192.168.1.0/24 --internal

# Spécifier l'interface réseau pour l'ARP scan
python cyber_agent.py --target 192.168.1.0/24 --internal --iface eth0
```

### Variables d'environnement (optionnel)

```bash
export VIRUSTOTAL_API_KEY=votre_clé
export ABUSEIPDB_API_KEY=votre_clé
export ORCHESTRATEUR_LICENSE=votre_licence   # alternative au fichier
```

---

## Licence Pro

Les modes `--full` et `--internal` nécessitent une licence.

| | **Early Adopter** | **Standard** | **Équipe** |
|---|---|---|---|
| **Prix** | ~~299€~~ **199€/an** | 299€/an | 699€/an (5 postes) |
| Scan complet `--full` | ✅ | ✅ | ✅ |
| Réseau interne `--internal` | ✅ | ✅ | ✅ |
| Rapport PDF complet | ✅ | ✅ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ | ✅ |
| Topologie réseau | ✅ | ✅ | ✅ |

### Installer votre licence

```bash
mkdir -p ~/.orchestrateur
echo "VOTRE_CLE_LICENCE" > ~/.orchestrateur/license.key
```

---

## Architecture technique

```
LLM (Gemma 4 via Ollama)
       ↓  ReAct loop
  ACTION: tool(target)
       ↓
  Tool Runner  →  whois / nmap / nikto / ...
       ↓
  SESSION_LOG  →  Parsing & analyse
       ↓
  PDF Generator  →  ReportLab + MITRE mapping
       ↓
  report_target_date.pdf
```

L'agent suit un cycle **ReAct (Reason + Act)** : il planifie, lance les outils, observe les sorties, pivote si nécessaire, puis synthétise en rapport final.

---

## Avertissement éthique

Cet outil est conçu exclusivement pour des **audits autorisés**. Ne scannez que des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite. L'utilisation sur des systèmes tiers sans autorisation est illégale (Code pénal art. 323-1).
