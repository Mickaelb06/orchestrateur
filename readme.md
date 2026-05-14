# 🛡️ L'Orchestrateur

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Agent-red) ![AI](https://img.shields.io/badge/AI-Gemma-blue) ![License](https://img.shields.io/badge/License-GPLv3-green)

**L'Orchestrateur** est un framework d'automatisation de la reconnaissance et de l'audit de sécurité basé sur l'intelligence artificielle. Contrairement aux outils de scan classiques, il utilise un LLM pour piloter une suite d'outils de sécurité, analyser les résultats en temps réel et élaborer une stratégie d'audit complète.

---

## 🧠 L'Architecture de l'Agent

L'agent ne se contente pas d'exécuter des commandes ; il suit un cycle de réflexion appelé **ReAct (Reason + Act)** :

1. **Analyse de la Mission** : L'IA décompose l'objectif utilisateur en étapes techniques.
2. **Orchestration** : Elle sélectionne l'outil le plus adapté (ex: `Nmap` pour les ports, `Sherlock` pour l'OSINT).
3. **Observation** : L'agent lit la sortie brute de l'outil et l'interprète.
4. **Pivotement** : En fonction du résultat, l'IA ajuste sa stratégie (ex: si un port est ouvert, elle lance automatiquement `Nikto` ou un `dir_scan`).
5. **Synthèse** : Génération d'un rapport final structuré avec preuves techniques brutes et analyse stratégique.

---

## 🛠️ Capacités Techniques

### 🔍 Module OSINT & Renseignement
- **Identité numérique** : `whois` (propriété) et `dig` (enregistrements DNS ANY/MX).
- **Traque Sociale** : Intégration de `Sherlock` pour la recherche de pseudonymes sur les réseaux sociaux.
- **Infrastructure Mail** : `mail_hunt` pour identifier les serveurs de messagerie.

### 📡 Analyse d'Infrastructure
- **Scanning Actif** : `nmap` (scan rapide des ports communs et services).
- **Vérification de Flux** : `ping` pour le diagnostic de connectivité.
- **Audit SSL/TLS** : `ssl_check` via OpenSSL pour analyser la chaîne de confiance et la validité des certificats.

### 🌐 Audit Web & Vulnérabilités
- **Analyse de Surface** : `http_header` pour identifier les technologies serveurs et versions.
- **Scan de Failles** : `Nikto` pour la détection de vulnérabilités connues et fichiers sensibles.
- **Fuzzing de Répertoires** : `dir_scan` pour la découverte de dossiers cachés (`.env`, `.git`, `/admin`).

---

## 📋 Exemples de Missions

L'agent peut gérer des requêtes complexes et multi-étapes :
> *"Analyse la cible colib-ri.com : vérifie si elle est active, identifie le propriétaire, scanne les ports ouverts, et cherche des répertoires sensibles. Une fois terminé, rédige un rapport final détaillé."*

---

## ⚙️ Installation & Déploiement

### 1. Dépendances Système (Fedora)
```bash
sudo dnf install nmap bind-utils curl whois iputils nikto -y

### 2. Environnement Python
python3 -m venv venv_cyber
source venv_cyber/bin/activate
pip install ollama

### 3. Lancement
Modèle requis : ollama pull gemma4:31b-cloud (ou tout autre modèle Gemma compatible)
Exécution : python cyber_agent.py

📜 Licence & Éthique

Ce projet est distribué sous licence GPLv3. 

Avertissement : L'utilisation de cet outil sur des systèmes sans autorisation explicite est strictement interdite et illégale. L'Orchestrateur est conçu exclusivement pour l'éducation et le pentesting éthique. L'auteur décline toute responsabilité quant à l'usage abusif de cet outil.
