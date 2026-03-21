#!/bin/bash

# Script de vérification de MongoDB et du système de stockage
# Usage: ./check_mongodb.sh

echo "🔍 Vérification du système MongoDB et stockage..."
echo "=================================================="

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages colorés
print_status() {
    local status=$1
    local message=$2
    case $status in
        "OK")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "$message"
            ;;
    esac
}

# 1. Vérifier si MongoDB est installé
echo ""
print_status "INFO" "1. Vérification de l'installation MongoDB..."
if command -v mongod &> /dev/null; then
    print_status "OK" "MongoDB est installé"
    mongod --version | head -1
else
    print_status "ERROR" "MongoDB n'est pas installé"
    echo "  Installation: brew tap mongodb/brew && brew install mongodb-community"
    exit 1
fi

# 2. Vérifier si le service est démarré
echo ""
print_status "INFO" "2. Vérification du service MongoDB..."
SERVICE_STATUS=$(brew services list | grep mongodb-community | awk '{print $2}')
if [ "$SERVICE_STATUS" = "started" ]; then
    print_status "OK" "Service MongoDB démarré"
else
    print_status "ERROR" "Service MongoDB non démarré"
    echo "  Démarrage: brew services start mongodb/brew/mongodb-community"
    exit 1
fi

# 3. Vérifier la connectivité
echo ""
print_status "INFO" "3. Test de connectivité MongoDB..."
if mongosh --eval "db.stats()" --quiet | grep -q "ok.*1"; then
    print_status "OK" "Connexion MongoDB réussie"
else
    print_status "ERROR" "Impossible de se connecter à MongoDB"
    exit 1
fi

# 4. Vérifier le port 27017
echo ""
print_status "INFO" "4. Vérification du port 27017..."
if lsof -i :27017 &> /dev/null; then
    print_status "OK" "Port 27017 ouvert et écouté"
else
    print_status "WARNING" "Port 27017 non détecté (mais connexion OK)"
fi

# 5. Test du module de stockage Python
echo ""
print_status "INFO" "5. Test du module de stockage Python..."
if python3 -c "
import sys
sys.path.append('storage')
try:
    from db import storage_db
    print('✅ Module de stockage importé')
except ImportError as e:
    print(f'❌ Erreur d\'import: {e}')
    sys.exit(1)
" 2>/dev/null; then
    print_status "OK" "Module de stockage Python OK"
else
    print_status "ERROR" "Problème avec le module Python"
    exit 1
fi

# 6. Test fonctionnel complet
echo ""
print_status "INFO" "6. Test fonctionnel complet..."
if python3 storage/test_storage.py 2>/dev/null | grep -q "All tests passed"; then
    print_status "OK" "Tests fonctionnels réussis"
else
    print_status "ERROR" "Échec des tests fonctionnels"
    echo "  Détails: python3 test_storage.py"
    exit 1
fi

# 7. Informations système
echo ""
print_status "INFO" "7. Informations système..."
echo "  📊 Base de données: apixray_storage"
echo "  📁 Collection: json_objects"
echo "  📏 Taille max objet: 16MB (limite MongoDB)"
echo "  🔗 URL: mongodb://localhost:27017"

# Statistiques MongoDB
echo ""
print_status "INFO" "8. Statistiques MongoDB..."
mongosh --eval "
db = db.getSiblingDB('apixray_storage');
print('📊 Collections:', db.getCollectionNames().length);
print('📦 Documents:', db.json_objects.countDocuments());
print('💾 Taille DB:', (db.stats().dataSize / 1024 / 1024).toFixed(2), 'MB');
" --quiet 2>/dev/null || print_status "WARNING" "Impossible de récupérer les stats détaillées"

echo ""
print_status "OK" "🎉 Vérification terminée - Tout fonctionne !"
echo ""
echo "💡 Commandes utiles:"
echo "  • Arrêter MongoDB: brew services stop mongodb/brew/mongodb-community"
echo "  • Redémarrer: brew services restart mongodb/brew/mongodb-community"
echo "  • Logs: brew services logs mongodb/brew/mongodb-community"
echo "  • Console MongoDB: mongosh"