#!/usr/bin/env bash
# ============================================
# XSS FRAMEWORK ULTIME v2.0 — Lancement rapide
# ============================================

set -e

# Couleurs
GREEN='\033[92m'; CYAN='\033[96m'; NC='\033[0m'

# Vérifier le venv
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
elif [ -d "venv" ]; then
    VENV_DIR="venv"
else
    echo -e "\033[91m[X]\033[0m Aucun venv trouvé. Lance d'abord ./install.sh"
    exit 1
fi

# Activer le venv
source "$VENV_DIR/bin/activate"

# Trouver le fichier principal
MAIN_FILE=""
for f in xss_framework.py xss_framework_ultime.py; do
    if [ -f "$f" ]; then
        MAIN_FILE="$f"
        break
    fi
done

if [ -z "$MAIN_FILE" ]; then
    echo -e "\033[91m[X]\033[0m Fichier xss_framework.py introuvable."
    exit 1
fi

# Lancer
echo -e "${GREEN}[OK]${NC} Lancement de XSS Framework..."
echo ""
python3 "$MAIN_FILE"