#!/usr/bin/env bash
# ============================================
# XSS FRAMEWORK ULTIME v2.0 — Installation
# ============================================

set -e

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[X]${NC} $1"; }

echo ""
cat << "EOF"

  ██╗  ██╗███████╗███████╗
  ██║ ██╔╝██╔════╝██╔════╝   XSS FRAMEWORK ULTIME v2.0
  █████╔╝ ███████╗███████╗   ─── Installation ───
  ██╔═██╗ ╚════██║╚════██║   
  ██║  ██╗███████║███████║   
  ╚═╝  ╚═╝╚══════╝╚══════╝   
        by JATHNIEL

EOF
echo ""

# 1. Python
log "Vérification de Python..."
if ! command -v python3 &> /dev/null; then
    err "Python3 manquant. Installation..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
else
    ok "Python3 : $(python3 --version 2>&1 | awk '{print $2}')"
fi

# 2. venv
log "Vérification de venv..."
if ! python3 -c "import venv" &> /dev/null; then
    sudo apt install -y python3-venv
fi
ok "venv disponible"

# 3. Créer/activer le venv
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
    warn "Dossier '.venv' détecté, réutilisation..."
elif [ -d "venv" ]; then
    VENV_DIR="venv"
    warn "Dossier 'venv' détecté, réutilisation..."
else
    VENV_DIR=".venv"
    log "Création du venv dans '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    ok "Venv créé"
fi

log "Activation de ./$VENV_DIR ..."
source "$VENV_DIR/bin/activate"
ok "Python actif : $(which python3)"

# 4. pip
log "Mise à jour de pip..."
python3 -m pip install --upgrade pip setuptools wheel 2>&1 | tail -1
ok "pip à jour"

# 5. Dépendances
log "Installation des dépendances..."
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt
    ok "Dépendances installées"
else
    warn "requirements.txt absent, installation manuelle..."
    python3 -m pip install requests rich flask urllib3
    ok "Dépendances installées manuellement"
fi

# 6. Vérification
log "Vérification des imports..."
python3 -c "
import sys
ok = True
try:
    import requests; print('  requests:', requests.__version__)
except: print('  requests: MANQUANT'); ok = False
try:
    import rich; print('  rich: OK')
except: print('  rich: MANQUANT'); ok = False
try:
    import flask; print('  flask:', flask.__version__)
except: print('  flask: MANQUANT'); ok = False
sys.exit(0 if ok else 1)
" && ok "Tous les imports OK" || warn "Certains imports manquants"

# 7. Dossiers
log "Préparation des dossiers..."
mkdir -p c2_files
ok "Dossier 'c2_files/' prêt"

# 8. Fichier principal
MAIN_FILE=""
for f in xss_framework.py xss_framework_ultime.py; do
    if [ -f "$f" ]; then
        MAIN_FILE="$f"
        break
    fi
done

if [ -n "$MAIN_FILE" ]; then
    ok "Fichier principal : $MAIN_FILE"
else
    warn "Aucun fichier xss_framework.py détecté"
fi

# 9. Résumé
echo ""
echo -e "${GREEN}========================================================${NC}"
echo -e "${GREEN}  INSTALLATION TERMINÉE${NC}"
echo -e "${GREEN}========================================================${NC}"
echo ""
echo -e "  ${BOLD}Prochaines étapes :${NC}"
echo ""
echo -e "  1. Activer le venv :"
echo -e "     ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo ""
echo -e "  2. Lancer le framework :"
if [ -n "$MAIN_FILE" ]; then
    echo -e "     ${CYAN}python3 $MAIN_FILE${NC}"
else
    echo -e "     ${CYAN}python3 xss_framework.py${NC}"
fi
echo ""
echo -e "  3. Pour un lancement rapide :"
echo -e "     ${CYAN}./run.sh${NC}"
echo ""
echo -e "  ${YELLOW}Rappel légal :${NC}"
echo -e "     Usage éducatif / CTF / pentest AUTORISÉ uniquement."
echo ""
echo -e "${GREEN}========================================================${NC}"
echo ""