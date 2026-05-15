# 🛡️ L'Orchestrateur

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Agent-red) ![AI](https://img.shields.io/badge/AI-Gemma-blue) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![License](https://img.shields.io/badge/License-GPLv3-green)

**L'Orchestrateur** est un framework d'automatisation de la reconnaissance et de l'audit de sécurité basé sur l'intelligence artificielle. Il ne se contente pas de scanner des cibles : il pilote une suite d'outils offensifs et OSINT pour transformer des données brutes en intelligence stratégique et en conseils de conformité.

---

## 🧠 Intelligence & Architecture

L'agent utilise un cycle de raisonnement **ReAct (Reason + Act)** pour orchestrer ses actions :

1. **Analyse de la Mission** $\rightarrow$ Décomposition de l'objectif en étapes tactiques.
2. **Orchestration** $\rightarrow$ Sélection et lancement des outils adaptés (ex: `Nmap` $\rightarrow$ `Nikto`).
3. **Observation** $\rightarrow$ Interprétation des sorties techniques brutes.
4. **Pivotement** $\rightarrow$ Ajustement de la stratégie en fonction des découvertes.
5. **Synthèse** $\rightarrow$ Génération d'un rapport final incluant une analyse de conformité.

---

## ⚖️ Expertise en Conformité (GRC)

Au-delà de la technique, L'Orchestrateur agit comme un consultant en cybersécurité. Chaque vulnérabilité détectée est analysée sous le prisme des référentiels suivants :
- **ISO 27001** : Standard international de gestion de la sécurité.
- **NIS 2** : Directive européenne sur la cybersécurité des entités essentielles.
- **DORA** : Règlement sur la résilience opérationnelle numérique du secteur financier.

---

## 🛠️ Suite d'Outils Intégrés

### 🔍 Module OSINT & Renseignement
- **Identité numérique** : `whois` et `dig` (DNS ANY/MX).
- **Traque Sociale** : `Sherlock` (Recherche de pseudos multi-plateformes).
- **Infrastructure Mail** : `mail_hunt` (Identification des serveurs MX).

### 📡 Analyse d'Infrastructure
- **Scanning Actif** : `nmap` (Scan rapide des ports et services).
- **Vérification de Flux** : `ping` (Diagnostic de connectivité).
- **Audit SSL/TLS** : `ssl_check` via OpenSSL.

### 🌐 Audit Web & Vulnérabilités
- **Analyse de Surface** : `http_header` (Identification des serveurs).
- **Scan de Failles** : `Nikto` (Détection de vulnérabilités connues).
- **Fuzzing de Répertoires** : `dir_scan` (Découverte de fichiers sensibles : `.env`, `.git`).

---

## 🚀 Déploiement via Docker (Recommandé)

La méthode Docker est la plus stable car elle installe automatiquement tous les outils système nécessaires dans un environnement isolé.

### 1. Pré-requis
- **Docker** installé sur votre machine.
- **Ollama** installé sur l'hôte avec le modèle requis :
  ```bash
  ollama pull gemma4:31b-cloud

### 2. Construction et Lancement

# Cloner le dépôt
git clone https://github.com/Mickaelb06/orchestrateur.git
cd orchestrateur

# Construire l'image Docker
docker build -t l-orchestrateur .

# Lancer l'agent (le flag --network=host est crucial pour communiquer avec Ollama)
docker run -it --network=host l-orchestrateur

⚙️ Installation Manuelle (Alternative)
# Dépendances Système (Fedora)
sudo dnf install nmap bind-utils curl whois iputils nikto git perl -y

### 3. Environnement Python
python3 -m venv venv_cyber
source venv_cyber/bin/activate
pip install ollama

### Lancement
python cyber_agent.py

📜 Licence & Éthique

Ce projet est distribué sous licence GPLv3. 

Avertissement : L'utilisation de cet outil sur des systèmes sans autorisation explicite est strictement interdite et illégale. L'Orchestrateur est conçu exclusivement pour l'éducation et le pentesting éthique.