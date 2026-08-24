# 🚀 XSS FRAMEWORK ULTIME - PERSISTANCE EDITION

## Framework complet d'exploitation XSS avec persistance

### 📌 Description

XSS FRAMEWORK ULTIME est un outil complet de test de sécurité XSS qui permet de scanner, exploiter et maintenir des vulnérabilités XSS dans un cadre éducatif et légal. Il intègre des fonctionnalités de persistance, de téléchargement/upload de fichiers, et de XSS stocké.

### ✨ Fonctionnalités

#### 🔍 Scan
- Détection automatique des vulnérabilités XSS
- Scan des paramètres GET/POST
- Détection des XSS réfléchis et stockés
- 50+ payloads de test

#### 💥 Exploitation
- 🍪 **Vol de cookies** : Capture des cookies de session
- 🎣 **Phishing** : Injection de formulaire de phishing
- 🎨 **Défiguration** : Modification du contenu de la page
- ⌨️ **Keylogger** : Capture des frappes clavier
- 🔄 **Redirection** : Vers des sites malveillants
- 📡 **Beacon** : Surveillance continue des victimes
- 🔄 **Session persistante** : Maintien des sessions actives

#### 📥 Téléchargement
- **Site → Moi** : Téléchargement de fichiers depuis le site vulnérable
- **Moi → Site** : Upload de fichiers sur le site vulnérable
- **Forcé** : Téléchargement forcé sur la machine de la victime

#### 🔄 Persistance
- ✅ Réinjection automatique des payloads supprimés
- ✅ Vérification toutes les minutes
- ✅ Suivi des exécutions
- ✅ Activation/Désactivation par bouton
- ✅ Stockage en base de données SQLite

#### 💾 XSS Stocké
- Détection automatique
- Exploitation des formulaires
- Injection de payloads persistants

#### 📊 Données capturées
- Cookies de session
- Identifiants (phishing)
- Frappes clavier (keylogger)
- Informations de navigation (beacon)
- Fichiers téléchargés

### 🚀 Installation

```bash
# 1. Cloner le dépôt
git clone https://github.com/votre-compte/xss-framework.git
cd xss-framework

# 2. Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/WSL
# ou
venv\Scripts\activate     # Windows

# 3. Installer les dépendances
pip install -r requirements.txt
```

🎯 Utilisation

```bash
# Lancer l'interface
python3 xss_framework.py
```

📊 Interface

```
┌─────────────────────────────────────────────────────────────────┐
│  🚀 XSS FRAMEWORK ULTIME - PERSISTANCE - JATHNIEL EDITION      │
├─────────────────────────────────────────────────────────────────┤
│  🔍 Scan  │  💥 Exploitation  │  🔄 Persistance  │  📥 Téléchargement  │
│  📤 Upload │  💾 XSS Stocké    │  📊 Données      │  📟 Console         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  📊 Vulnérabilités                                        │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │  id - <script>alert(1)</script>...                   │ │ │
│  │  │  page - <img src=x onerror=alert(1)>                 │ │ │
│  │  └──────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  📋 Détails                                               │ │
│  │  Paramètre: id                                            │ │
│  │  Payload: <script>alert(1)</script>                       │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  [🔍 Scanner]  [🍪 Vol de cookies]  [🎣 Phishing]              │
│  [🎨 Défiguration]  [⌨️ Keylogger]  [📥 Télécharger]          │
│                                                                  │
│  🖥️ Serveur de capture: [🚀 Démarrer]  [🛑 Arrêter]          │
│                                                                  │
│  🔄 Persistance: [▶️ Démarrer]  [⏹️ Arrêter]                  │
│  Statut: 🟢 ACTIVE                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

🎮 Commandes et Actions

Action Description Commande/Bouton
Scanner Détecte les vulnérabilités XSS "🔍 Scanner"
Vol de cookies Capture les cookies de session "🍪 Vol de cookies"
Phishing Injecte un formulaire de phishing "🎣 Phishing"
Défiguration Modifie le contenu de la page "🎨 Défiguration"
Keylogger Capture les frappes clavier "⌨️ Keylogger"
Téléchargement Télécharge un fichier du site "📥 Télécharger"
Upload Upload un fichier sur le site "📤 Upload"
Persistance Maintient les payloads actifs "▶️ Démarrer"
XSS Stocké Teste et exploite le XSS stocké "🔍 Tester"

📋 Exemple de session

```bash
# 1. Scanner le site
🔍 Scan de https://example.com/page?id=1
🚨 XSS trouvé sur paramètre: id

# 2. Démarrer le serveur de capture
🖥️ Serveur démarré sur le port 8080

# 3. Activer la persistance
🔄 Persistance ACTIVÉE

# 4. Injecter un payload
🍪 Injection de vol de cookies effectuée
🔄 Payload réinjecté sur la page

# 5. Télécharger un fichier
📥 Téléchargement de /etc/passwd initié
✅ Fichier téléchargé

# 6. Upload un webshell
📤 Upload de shell.php vers /var/www/html/shell.php
✅ Webshell uploadé

# 7. Désactiver la persistance
🔄 Persistance DÉSACTIVÉE
```