#!/bin/bash
# Installation XSS Framework Ultime

echo "[*] Installation des dépendances..."
pip install -r requirements.txt

echo "[*] Rendu du script exécutable..."
chmod +x xss_framework_ultime.py

echo "[*] Installation terminée."
echo "[*] Lance : python3 xss_framework_ultime.py"