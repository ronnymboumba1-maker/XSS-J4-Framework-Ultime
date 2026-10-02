#!/bin/bash
# ============================================
# XSS FRAMEWORK ULTIME — Installateur
# Auteur : Jathniel
# Crée et active un venv Python, installe les dépendances
# ============================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo "[*] XSS FRAMEWORK ULTIME — Installation par Jathniel"
echo ""

# 1. Vérifie Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 introuvable. Installe-le : sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

# 2. Crée le venv s'il n'existe pas
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Création du venv dans $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "[*] Venv existant détecté."
fi

# 3. Active le venv et installe les dépendances
echo "[*] Activation du venv et installation des dépendances..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r "$SCRIPT_DIR/requirements.txt"

# 4. Crée un lanceur qui active le venv automatiquement
cat > "$SCRIPT_DIR/run.sh" << 'EOF'
#!/bin/bash
# Lanceur XSS FRAMEWORK ULTIME — active le venv automatiquement
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
python3 "$SCRIPT_DIR/xss_framework_ultime.py"
EOF
chmod +x "$SCRIPT_DIR/run.sh"

echo ""
echo "[+] Installation terminée."
echo "[+] Pour lancer le framework :"
echo "      ./run.sh"
echo "    ou manuellement :"
echo "      source venv/bin/activate && python3 xss_framework_ultime.py"