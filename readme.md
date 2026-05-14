# 🛡️ L'Orchestrateur

**L'Orchestrateur** est un agent d'intelligence artificielle spécialisé en cybersécurité, conçu pour automatiser la phase de reconnaissance et d'audit de sécurité. Plutôt que de lancer des outils manuellement, l'utilisateur délègue la mission à l'IA qui planifie, exécute et analyse les résultats pour produire un rapport stratégique.

## 🎯 Concept
L'objectif de l'outil est de transformer des flux de données techniques bruts en intelligence exploitable. L'IA ne se contente pas de lancer des commandes ; elle **raisonne** sur les résultats pour décider de l'étape suivante.

## 🚀 Capacités de l'Agent
L'Orchestrateur pilote une suite d'outils professionnels :

### 🔍 Reconnaissance OSINT & DNS
- **Whois** : Identification du propriétaire et des dates d'enregistrement.
- **Dig** : Analyse approfondie des enregistrements DNS.
- **Sherlock** : Traque des pseudonymes sur les réseaux sociaux.
- **Mail Hunt** : Identification des serveurs de messagerie (MX).

### 📡 Analyse Réseau & Infrastructure
- **Nmap** : Scan de ports et identification des services.
- **Ping** : Vérification de la disponibilité des cibles.
- **SSL Check** : Analyse de la validité et de la sécurité des certificats TLS/SSL.

### 🌐 Audit Web & Vulnérabilités
- **Nikto** : Scan de vulnérabilités serveurs et fichiers sensibles.
- **Dir Scan** : Fuzzing de répertoires pour découvrir des fichiers cachés (`.env`, `/admin`).
- **HTTP Headers** : Analyse des signatures serveurs et technologies utilisées.

## 🧠 Fonctionnement Technique
L'agent repose sur une architecture de boucle de raisonnement :
1. **Analyse de la mission** $\rightarrow$ Planification des outils nécessaires.
2. **Exécution** $\rightarrow$ Appel des outils système via Python.
3. **Observation** $\rightarrow$ Lecture et analyse des résultats bruts.
4. **Synthèse** $\rightarrow$ Génération d'un rapport final détaillé avec preuves techniques.

## 🛠️ Installation rapide
### Dépendances Système (Fedora)
```bash
sudo dnf install nmap bind-utils curl whois iputils nikto -y

Installation Python

python3 -m venv venv_cyber
source venv_cyber/bin/activate
pip install ollama
 
 
Lancement

     Installer Ollama et le modèle : ollama pull gemma4:31b-cloud
     Lancer l'agent : python cyber_agent.py

⚠️ Avertissement Légal

Cet outil est développé dans un cadre éducatif. L'utilisation de cet agent sur des cibles sans autorisation est strictement interdite et illégale.