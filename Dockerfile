# On utilise une image Python officielle et légère
FROM python:3.11-slim

# On installe les dépendances système disponibles
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    curl \
    whois \
    iputils-ping \
    git \
    perl \
    && rm -rf /var/lib/apt/lists/*

# --- INSTALLATION MANUELLE DE NIKTO ---
# On clone Nikto et on le place dans /usr/local/bin pour qu'il soit accessible partout
RUN git clone https://github.com/Sullo/nikto.git /tmp/nikto && \
    cp /tmp/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto && \
    rm -rf /tmp/nikto
# ---------------------------------------

# On crée le dossier de travail
WORKDIR /app

# On installe les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# On copie tout le reste du code
COPY . .

# On lance l'agent
CMD ["python", "cyber_agent.py"]
