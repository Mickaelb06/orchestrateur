
***

### 2. Le fichier `Dockerfile` (Version Finale)

Voici le fichier optimisé pour être robuste et inclure toutes les dépendances.

```dockerfile
# Image Python officielle et légère
FROM python:3.11-slim

# Installation des dépendances système
# On installe perl pour Nikto et ca-certificates pour les requêtes HTTPS
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    curl \
    whois \
    iputils-ping \
    git \
    perl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Installation manuelle de Nikto (car non présent dans les dépôts Debian slim)
RUN git clone https://github.com/Sullo/nikto.git /tmp/nikto && \
    cp /tmp/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto && \
    rm -rf /tmp/nikto

# Configuration du dossier de travail
WORKDIR /app

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

# Lancement de l'agent
CMD ["python", "cyber_agent.py"]