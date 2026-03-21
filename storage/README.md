# APIX-Ray Schema Storage

Ce dossier contient le système de stockage pour les schémas OAS (OpenAPI/Swagger) utilisés par l'agent de pentest.

## Technologies utilisées
- **MongoDB** : Base de données NoSQL pour stocker les schémas
- **Motor** : Driver asynchrone MongoDB pour Python
- **PyYAML** : Parsing des fichiers YAML

## API Endpoints

### Lister les schémas OAS
```http
GET /schemas
```

**Réponse :**
```json
{
  "schemas": [
    {
      "id": "uuid-generated",
      "title": "API Title",
      "version": "1.0.0"
    }
  ]
}
```

### Uploader un schéma OAS
```http
POST /schemas
Content-Type: multipart/form-data

file: [fichier .json ou .yaml]
```

**Réponse :**
```json
{
  "schema_id": "uuid-generated",
  "filename": "api.yaml",
  "title": "API Title",
  "message": "Schema uploaded and stored successfully."
}
```

### Supprimer un schéma OAS
```http
DELETE /schemas/{schema_id}
```

**Réponse :**
```json
{
  "message": "Schema deleted successfully"
}
```

## Format des données stockées
Chaque schéma est stocké sous forme de document MongoDB :
```json
{
  "_id": "uuid-generated",
  "filename": "api.yaml",
  "content_type": "application/yaml",
  "schema": {
    "openapi": "3.0.0",
    "info": {...},
    "paths": {...}
  },
  "created_at": "2026-03-17T..."
}
```

## Utilisation dans le code
```python
from storage.db import storage_db

# Stocker un schéma
schema_id = await storage_db.store_json({
    "filename": "api.yaml",
    "content_type": "application/yaml",
    "schema": oas_document
})

# Récupérer un schéma
data = await storage_db.get_json(schema_id)
schema = data["schema"]
```

## Tests
```bash
# Test du stockage
python test_schemas.py

# Vérification complète MongoDB
./check_mongodb.sh
```