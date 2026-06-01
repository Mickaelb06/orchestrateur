#!/bin/bash
set -e

source venv/bin/activate

echo ""
echo "════════════════════════════════════════════════"
echo "  BUILD — L'Orchestrateur"
echo "════════════════════════════════════════════════"

# Compilation
echo ""
echo "[1/3] Compilation Nuitka..."
python -m nuitka \
    --onefile \
    --output-dir=dist \
    --output-filename=orchestrateur \
    cyber_agent.py

echo "[2/3] Préparation du livrable..."

# Dossier de livraison
VERSION=$(date +"%Y%m%d")
PACKAGE_DIR="dist/orchestrateur_${VERSION}"
mkdir -p "$PACKAGE_DIR"

# Binaire
cp dist/orchestrateur "$PACKAGE_DIR/orchestrateur"
chmod +x "$PACKAGE_DIR/orchestrateur"

# Instructions d'installation
cat > "$PACKAGE_DIR/INSTALL.txt" << 'EOF'
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  L'Orchestrateur — Guide d'installation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PRÉREQUIS SYSTÈME
  sudo apt install nmap whois nikto curl -y   # Debian/Ubuntu
  sudo dnf install nmap whois nikto curl -y   # Fedora/RHEL

OLLAMA (moteur IA local)
  1. Installez Ollama : https://ollama.com
  2. Téléchargez le modèle :
     ollama pull gemma4:31b-cloud

LICENCE
  mkdir -p ~/.orchestrateur
  echo "VOTRE_CLE_LICENCE" > ~/.orchestrateur/license.key

UTILISATION
  chmod +x orchestrateur

  # Scan standard
  ./orchestrateur --target example.com

  # Scan rapide
  ./orchestrateur --target example.com --quick

  # Scan complet [PRO]
  ./orchestrateur --target example.com --full

  # Réseau interne [PRO]
  ./orchestrateur --target 192.168.1.0/24 --internal

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF

# ZIP
echo "[3/3] Création du ZIP..."
cd dist
zip -r "orchestrateur_${VERSION}.zip" "orchestrateur_${VERSION}/" -q
cd ..

echo ""
echo "════════════════════════════════════════════════"
echo "  Livrable prêt :"
echo "  dist/orchestrateur_${VERSION}.zip"
ls -lh "dist/orchestrateur_${VERSION}.zip"
echo "════════════════════════════════════════════════"
echo ""
