# 🛡️ L'Orchestrateur

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Agent-red) ![AI](https://img.shields.io/badge/AI-Gemma-blue) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![License](https://img.shields.io/badge/License-GPLv3-green)

**L'Orchestrateur** est un framework d'automatisation de la reconnaissance et de l'audit de sécurité basé sur l'intelligence artificielle. Conçu pour les professionnels de la cybersécurité, il ne se contente pas de scanner des cibles : il **pilote** une suite d'outils offensifs et OSINT pour transformer des données brutes en intelligence stratégique.

---

## 🧠 Intelligence & Architecture

L'agent repose sur une architecture de raisonnement **ReAct (Reason + Act)**. Au lieu d'exécuter un script linéaire, l'IA analyse la cible et adapte sa stratégie en temps réel :

1. **Analyse de la Mission** $\rightarrow$ Décomposition de l'objectif en étapes tactiques.
2. **Orchestration** $\rightarrow$ Sélection et lancement des outils adaptés (ex: `Nmap` $\rightarrow$ `Nikto`).
3. **Observation** $\rightarrow$ Interprétation des sorties techniques brutes.
4. **Pivotement** $\rightarrow$ Ajustement de la stratégie en fonction des découvertes.
5. **Synthèse** $\rightarrow$ Génération d'un rapport final structuré avec preuves techniques.

---

## 🛠️ Suite d'Outils Intégrés

L'Orchestrateur pilote un arsenal complet divisé en trois modules :

### 🔍 Module OSINT & Renseignement
- **Identité Numérique** : `whois` et `dig` (DNS ANY/MX).
- **Traque Sociale** : Intégration de `Sherlock` pour la recherche de pseudos multi-plateformes.
- **Infrastructure Mail** : `mail_hunt` pour identifier les serveurs de messagerie.

### 📡 Analyse d'Infrastructure
- **Scanning Actif** : `nmap` (scan rapide des ports et services).
- **Vérification de Flux** : `ping` pour le diagnostic de connectivité.
- **Audit SSL/TLS** : `ssl_check` via OpenSSL pour analyser la validité des certificats.

### 🌐 Audit Web & Vulnérabilités
- **Analyse de Surface** : `http_header` pour identifier les technologies serveurs.
- **Scan de Failles** : `Nikto` pour la détection de vulnérabilités et fichiers sensibles.
- **Fuzzing de Répertoires** : `dir_scan` pour découvrir des dossiers cachés (`.env`, `.git`, `/admin`).

---

## 🚀 Déploiement Rapide via Docker

Pour garantir une portabilité totale et éviter les conflits de dépendances, **L'Orchestrateur** est entièrement conteneurisé.

### 1. Pré-requis
- **Docker** installé sur votre machine.
- **Ollama** installé et lancé sur l'hôte avec le modèle requis :
  ```bash
  ollama pull gemma4:31b-cloud