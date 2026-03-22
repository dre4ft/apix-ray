# APIX-Ray 🔍

**APIX-Ray** est un agent de pentest API autonome et intelligent avec interface web moderne. Il découvre automatiquement les vulnérabilités dans les APIs en utilisant des LLM (Ollama local ou services distants) pour générer et analyser des cas de test sophistiqués.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![MongoDB](https://img.shields.io/badge/MongoDB-8.2+-green.svg)](https://mongodb.com)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

---

## 📋 Table des matières

- [🎯 Aperçu](#-aperçu)
- [✨ Fonctionnalités](#-fonctionnalités)
- [🏗️ Architecture](#️-architecture)
- [⚡ Démarrage rapide](#-démarrage-rapide)
- [📦 Installation](#-installation)
- [🚀 Utilisation](#-utilisation)
- [🌐 Interface Web](#-interface-web)
- [🗄️ Stockage des Schémas](#️-stockage-des-schémas)
- [🧪 Tests](#-tests)
- [📁 Structure du projet](#-structure-du-projet)
- [🛠️ Développement](#️-développement)
- [📊 Roadmap](#-roadmap)
- [📄 Licence](#-licence)

---

## 🎯 Aperçu

APIX-Ray automatise le pentest d'APIs REST en combinant intelligence artificielle et analyse automatisée :

1. **📋 Découverte d'endpoints** : Parse automatiquement les spécifications OpenAPI/Swagger
2. **🧠 Génération de tests IA** : Utilise des LLM pour créer des scénarios d'attaque sophistiqués
3. **⚡ Exécution parallèle** : Tests asynchrones avec contrôle de débit
4. **🔍 Analyse intelligente** : Détection automatique de vulnérabilités et anomalies
5. **📊 Rapports détaillés** : Findings exportés en Markdown avec recommandations

### 🎯 Vulnérabilités testées
- **IDOR** (Insecure Direct Object References)
- **Broken Access Control**
- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Command Injection**
- **Rate Limiting Bypass**
- **Authentication Bypass**

### 📚 Playbooks de sécurité
APIX-Ray utilise un système de **playbooks** extensibles pour définir les méthodologies de test pour chaque type de vulnérabilité :

- **Playbooks prédéfinis** : SQL Injection, XSS, IDOR, etc.
- **Création personnalisée** : Interface web pour ajouter de nouveaux playbooks
- **Méthodologies structurées** : Reconnaissance, phases de test, règles de validation
- **Stockage persistant** : Playbooks sauvegardés en base MongoDB

---

## ✨ Fonctionnalités

### 🤖 Intelligence Artificielle
- **Support multi-LLM** : Ollama (local), OpenAI, Anthropic, etc.
- **Génération contextuelle** : Tests adaptés aux spécifications API
- **Analyse sémantique** : Détection d'anomalies comportementales

### 🌐 Interface Web Moderne
- **Dashboard temps réel** : Suivi des scans en cours
- **Gestion des schémas** : Upload et gestion des spécifications OAS
- **Historique des scans** : Logs et résultats détaillés
- **API REST complète** : Intégration possible avec autres outils

### 🗄️ Stockage Persistant
- **MongoDB intégré** : Stockage des schémas et résultats
- **Support JSON/YAML** : Parsing automatique des spécifications
- **Historique complet** : Traçabilité des tests et findings

### 🧪 Environnement de Test
- **API Mock vulnérable** : Tests contrôlés avec vraies vulnérabilités
- **Tests unitaires** : Couverture complète des composants
- **Validation automatique** : Scripts de vérification système

---

## 🏗️ Architecture

APIX-Ray utilise une architecture de microservices avec séparation des responsabilités :

```
apix-ray/
├── src/                    # Code source principal
│   ├── main.py            # Point d'entrée CLI
│   ├── pentest_agent.py   # Orchestrateur principal
│   ├── llm_client.py      # Client LLM (Litellm)
│   ├── ollama_client.py   # Client Ollama local
│   ├── request_manager.py # Gestion HTTP asynchrone
│   ├── endpoint_discovery.py # Parsing OAS
│   ├── test_generator.py  # Génération de tests IA
│   ├── response_analyzer.py # Analyse des réponses
│   ├── report_generator.py # Génération de rapports
│   └── wrapper.py         # Wrapper d'exécution
├── web_app/               # Interface web et APIs
│   ├── api_gateway.py    # 🌐 Gateway API (port 8080)
│   ├── schema_api.py     # 📋 API gestion schémas (port 8081)
│   ├── scan_api.py       # 🔍 API gestion scans (port 8082)
│   ├── bridge.py         # Pont vers la logique métier
│   ├── static/           # Assets frontend (HTML/CSS/JS)
│   ├── web_serveur.py    # 🖥️ Serveur web Flask (port 8800)
│   └── start_services.sh # 🚀 Script de démarrage
├── storage/               # Système de stockage
│   ├── db.py             # Interface MongoDB
│   └── README.md         # Documentation stockage
├── mock/                  # Environnement de test
│   ├── mock_api.py       # API vulnérable simulée
│   └── mock_oas.json     # Spécification de test
├── test_storage.py        # Tests du stockage
├── test_schemas.py       # Tests des schémas
├── check_mongodb.sh      # Script de diagnostic
└── requirements.txt      # Dépendances Python
```

### 🏛️ Architecture des Services

```
┌─────────────────┐    ┌─────────────────┐
│   🌐 Frontend   │────│ 🖥️ Web Server  │
│   (Port 8800)   │    │   (Flask)       │
└─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐
│  🌐 API Gateway │◄───┤   📱 Clients    │
│   (Port 8080)   │    │                 │
└─────────────────┘    └─────────────────┘
        │
        ├─────────────────┐
        │                 │
        ▼                 ▼
┌─────────────────┐ ┌─────────────────┐
│ 📋 Schema API   │ │ 🔍 Scan API     │
│  (Port 8081)    │ │  (Port 8082)    │
└─────────────────┘ └─────────────────┘
        │                 │
        └─────────────────┘
                │
                ▼
        ┌─────────────────┐
        │   🗄️ MongoDB    │
        │   (Port 27017)  │
        └─────────────────┘
```

**API Gateway** : Point d'entrée unique qui route les requêtes vers les services appropriés
- `/schemas/*` → Schema API
- `/start_scan`, `/scan_*` → Scan API
- `/health` → Health check de la gateway

**Schema API** : Gestion complète des schémas OpenAPI/Swagger
- Stockage en base MongoDB
- Upload, récupération, suppression
- Validation des formats OAS

**Scan API** : Orchestration des scans de sécurité
- Lancement et monitoring des scans
- Gestion des sessions de test
- Logs et résultats en temps réel

---

## ⚡ Démarrage rapide

### Prérequis
- **Python 3.10+**
- **MongoDB** (installé automatiquement avec le script)
- **Git**

### Installation en 3 commandes

```bash
# 1. Cloner et installer
git clone <repository-url>
cd apix-ray
pip install -r requirements.txt

# 2. Installer et démarrer MongoDB
./check_mongodb.sh  # Installe et configure MongoDB automatiquement

# 3. Lancer tous les services
cd web_app && ./start_services.sh
```

**🎉 L'application est accessible sur http://localhost:8800**

### Architecture des services
- **🌐 Interface Web** : http://localhost:8800 (Flask)
- **🚪 API Gateway** : http://localhost:8080 (FastAPI)
- **📋 Schema API** : http://localhost:8081 (FastAPI)
- **🔍 Scan API** : http://localhost:8082 (FastAPI)
- **🗄️ MongoDB** : localhost:27017

### Premier test
1. Ouvrez http://localhost:8800 dans votre navigateur
2. Allez dans l'onglet "Schemas" et uploadez un schéma OAS
3. Retournez à "Dashboard" et lancez un scan de sécurité
4. Visualisez les résultats en temps réel !

---

## 📦 Installation détaillée

### 1. Dépendances système
```bash
# macOS avec Homebrew
brew install mongodb-community python@3.12

# Ubuntu/Debian
sudo apt update
sudo apt install mongodb python3.10 python3-pip
```

### 2. Environnement virtuel
```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

### 3. Configuration MongoDB
```bash
# Installation automatique
./check_mongodb.sh

# Ou manuellement
brew tap mongodb/brew
brew install mongodb-community
brew services start mongodb-community
```

### 4. Variables d'environnement
Créez un fichier `.env` :
```env
# Configuration LLM (optionnel - Ollama par défaut)
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL=qwen2.5-coder:latest

# MongoDB (optionnel - localhost par défaut)
MONGO_URL=mongodb://localhost:27017
```

---

## 🚀 Utilisation

### Interface Web (Recommandé)
```bash
cd web_app
python api.py
# Accès : http://localhost:8080
```

### Ligne de commande
```bash
cd src
python main.py
```

### API Mock pour les tests
```bash
cd mock
python mock_api.py
# API vulnérable sur http://localhost:8000
```

---

## 🌐 Interface Web

### Dashboard Principal
- **📊 Vue d'ensemble** : Scans actifs, métriques, historique
- **📋 Gestion des schémas** : Upload, liste, suppression des spécifications OAS
- **🎯 Lancement de scans** : Configuration et exécution des pentests
- **📈 Suivi temps réel** : Logs, progression, résultats intermédiaires

### API REST
```bash
# Schémas
GET    /schemas           # Lister les schémas
POST   /schemas           # Uploader un schéma (multipart/form-data)
DELETE /schemas/{id}      # Supprimer un schéma

# Scans
POST   /start_scan        # Lancer un scan
GET    /scan_logs/{id}    # Logs du scan
GET    /scan_results/{id} # Résultats du scan
POST   /stop_scan/{id}    # Arrêter un scan

# Utilitaires
GET    /health           # État du système
GET    /llm/models       # Modèles LLM disponibles
```

### Exemple d'utilisation
```javascript
// Lancer un scan
const response = await fetch('/start_scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target_url: 'http://api.example.com',
    llm_type: 'ollama',
    model: 'qwen2.5-coder:latest',
    vulnerabilities: ['SQLi', 'XSS', 'IDOR']
  })
});
```

---

## 📚 Gestion des Playbooks

### Vue d'ensemble des playbooks
L'onglet **"Playbooks"** permet de consulter et gérer les méthodologies de test de sécurité :

- **📖 Consultation** : Visualiser les playbooks existants avec leur méthodologie
- **➕ Création** : Ajouter de nouveaux playbooks personnalisés
- **🔧 Modification** : Éditer les playbooks existants
- **🗑️ Suppression** : Supprimer les playbooks inutiles

### Structure d'un playbook
Chaque playbook définit une méthodologie complète de test :

```json
{
  "description": "Description de la vulnérabilité",
  "methodology": {
    "reconnaissance": ["Étapes de reconnaissance"],
    "testing_phases": [
      {
        "phase": "Nom de la phase",
        "description": "Description détaillée",
        "payloads": ["payload1", "payload2"],
        "target_parameters": ["param1", "param2"],
        "http_methods": ["GET", "POST"],
        "success_indicators": ["indicateur1", "indicateur2"]
      }
    ],
    "validation_rules": ["Règles de validation"]
  },
  "severity": "high|medium|low|critical|info",
  "cvss_base_score": 8.5,
  "enabled": true
}
```

### API Playbooks
```bash
# Lister tous les playbooks
GET /playbooks/

# Obtenir un playbook spécifique
GET /playbooks/{vulnerability_type}

# Créer un nouveau playbook
POST /playbooks/
Content-Type: application/json
{
  "vulnerability_type": "New Vulnerability",
  "playbook": {...}
}

# Modifier un playbook
PUT /playbooks/{vulnerability_type}

# Supprimer un playbook
DELETE /playbooks/{vulnerability_type}

# Générer des payloads intelligents
POST /playbooks/generate_payloads
{
  "vulnerability_type": "SQL Injection",
  "endpoint_info": {"method": "GET", "path": "/users"}
}
```

---

## 🗄️ Stockage des Schémas

### Base de données MongoDB
- **Collection** : `apixray_storage.json_objects`
- **Format** : Documents JSON avec métadonnées
- **Taille max** : 16MB par document (limite MongoDB)

### Gestion des schémas
```bash
# Upload d'un schéma
curl -X POST http://localhost:8080/schemas \
  -F "file=@api_spec.yaml"

# Liste des schémas
curl http://localhost:8080/schemas

# Suppression
curl -X DELETE http://localhost:8080/schemas/{schema_id}
```

### Structure des données
```json
{
  "_id": "uuid-generated",
  "filename": "api.yaml",
  "content_type": "application/yaml",
  "schema": {
    "openapi": "3.0.0",
    "info": {"title": "My API", "version": "1.0.0"},
    "paths": {...}
  },
  "created_at": "2026-03-17T..."
}
```

---

## 🧪 Tests et validation

### Tests automatisés
```bash
# Tests du stockage
python test_storage.py

# Tests des schémas
python test_schemas.py

# Tests unitaires
python -m unittest discover test/
```

### Diagnostic système
```bash
# Vérification complète MongoDB
./check_mongodb.sh

# Status détaillé
mongosh --eval "db.serverStatus()"
```

### API Mock pour développement
```bash
cd mock
python mock_api.py
# Swagger UI : http://localhost:8000/docs
```

---

## 📁 Structure détaillée du projet

### `src/` - Cœur de l'application
- **`pentest_agent.py`** : Orchestrateur principal du pentest
- **`llm_client.py`** / **`ollama_client.py`** : Clients LLM avec interface unifiée
- **`request_manager.py`** : Gestion HTTP asynchrone avec retry et timeout
- **`endpoint_discovery.py`** : Parsing intelligent des spécifications OAS
- **`test_generator.py`** : Génération de payloads malveillants via IA
- **`response_analyzer.py`** : Analyse comportementale des réponses
- **`report_generator.py`** : Compilation des findings en rapports structurés

### `web_app/` - Interface utilisateur
- **`api.py`** : API REST FastAPI avec CORS et validation
- **`bridge.py`** : Couche d'abstraction pour l'exécution asynchrone
- **`static/`** : Interface web responsive (HTML5/CSS3/JavaScript)

### `storage/` - Persistance des données
- **`db.py`** : Interface MongoDB avec Motor (async)
- **Support JSON/YAML** : Parsing automatique des schémas OAS

### `mock/` - Environnement de test
- **`mock_api.py`** : API FastAPI avec vulnérabilités simulées
- **`mock_oas.json`** : Spécification OpenAPI de test

---

## 🛠️ Développement

### Ajouter une nouvelle vulnérabilité
1. **Via l'interface web** : Utiliser l'onglet "Playbooks" pour créer un nouveau playbook
2. **Via API** : POST vers `/playbooks/` avec la structure JSON du playbook
3. **Programmatiquement** :
   - Étendre `VULNERABILITY_TYPES` dans `pentest_agent.py`
   - Ajouter la logique de génération dans `test_generator.py`
   - Implémenter la détection dans `response_analyzer.py`

### Support d'un nouveau LLM
1. Créer une classe héritant de `BaseLLMClient`
2. Implémenter `chat_completion()` et `close()`
3. Ajouter dans `web_app/api.py` et l'interface

### Débogage avancé
```python
# Logs détaillés
import logging
logging.basicConfig(level=logging.DEBUG)

# Profiling des requêtes
# Utiliser httpx avec instrumentation
```

### Contribution
1. Fork le projet
2. Créer une branche feature
3. Tests unitaires pour les nouvelles fonctionnalités
4. Pull request avec description détaillée

---

## 📊 Roadmap

### ✅ Implémenté
- [x] Agent pentest autonome avec IA
- [x] Support multi-LLM (Ollama, OpenAI, etc.)
- [x] Interface web moderne
- [x] Stockage persistant MongoDB
- [x] API REST complète
- [x] Environnement de test mock
- [x] Tests automatisés

### 🚧 En cours
- [ ] Intégration MCP (Model Context Protocol)
- [ ] Authentification et autorisation
- [ ] Export de rapports PDF/JSON
- [ ] Intégration CI/CD

### 🔮 Planifié
- [ ] Édition avancée des playbooks (interface complète)
- [ ] Templates de playbooks prédéfinis
- [ ] Validation automatique des playbooks
- [ ] Interface mobile
- [ ] Support GraphQL
- [ ] Machine Learning pour détection avancée
- [ ] Intégration avec outils de sécurité existants

---

## 📄 Licence

**GNU General Public License v3.0**

Ce projet est open-source. Voir [LICENSE](LICENSE) pour les détails.

---

## 👤 Auteur

**Romain Travail**

- GitHub: [@romain-travail](https://github.com/romain-travail)
- LinkedIn: [Romain Travail](https://linkedin.com/in/romain-travail)

---

## 💬 Support et contribution

### Issues et bugs
- [GitHub Issues](../../issues) pour les rapports de bug
- [Discussions](../../discussions) pour les questions générales

### Documentation
- [Wiki](../../wiki) pour les guides détaillés
- [API Docs](http://localhost:8080/docs) une fois l'app lancée

---

## 🎉 Remerciements

- **FastAPI** pour le framework web exceptionnel
- **MongoDB** pour la base de données robuste
- **Ollama** pour le support LLM local
- **OpenAI/Litellm** pour l'accès aux modèles avancés

---

**Bon pentest sécurisé ! 🚀🔒**

---
*Dernière mise à jour : Mars 2026*
