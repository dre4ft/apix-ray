import json
import yaml
from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os
import sys

# Add storage path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'storage'))
from db import storage_db



# ===== SCHEMA ROUTER =====
schema_router = APIRouter(prefix="/schemas", tags=["schemas"])

@schema_router.get("")
async def get_schemas():
    """Liste les schémas OAS stockés."""
    try:
        schemas = await storage_db.list_objects(limit=1000)
        # Filtrer pour ne garder que les schémas OAS (ceux qui contiennent du YAML/JSON OAS)
        oas_schemas = []
        for schema_id in schemas:
            schema_data = await storage_db.get_json(schema_id)
            if schema_data and isinstance(schema_data, dict):
                schema = schema_data.get("schema", {})
                if "openapi" in schema or "swagger" in schema:
                    oas_schemas.append({
                        "id": schema_id,
                        "title": schema.get("info", {}).get("title", f"Schema {schema_id}"),
                        "version": schema.get("info", {}).get("version", "unknown")
                    })
        return JSONResponse(status_code=200, content={"schemas": oas_schemas})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@schema_router.get("/{schema_id}")
async def get_schema(schema_id: str):
    """Récupère un schéma OAS spécifique par son ID."""
    try:
        schema_data = await storage_db.get_json(schema_id)
        if not schema_data:
            return JSONResponse(status_code=404, content={"error": "Schema not found"})
        return JSONResponse(status_code=200, content={"schema": schema_data})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@schema_router.post("")
async def add_schema(file: UploadFile = File(...)):
    """Upload et stocke un schéma OAS dans la base de données."""
    try:
        # Lire le contenu du fichier
        content = await file.read()
        content_str = content.decode("utf-8")

        # Parser le JSON/YAML
        try:
            schema_data = json.loads(content_str)
        except json.JSONDecodeError:
            # Essayer YAML si JSON échoue
            try:
                schema_data = yaml.safe_load(content_str)
            except ImportError:
                return JSONResponse(status_code=400, content={"error": "YAML support not available. Install PyYAML."})
            except Exception:
                return JSONResponse(status_code=400, content={"error": "Invalid JSON or YAML format"})

        # Vérifier que c'est bien un schéma OAS
        if not isinstance(schema_data, dict) or ("openapi" not in schema_data and "swagger" not in schema_data):
            return JSONResponse(status_code=400, content={"error": "Not a valid OpenAPI/Swagger schema"})

        # Stocker dans MongoDB
        schema_id = await storage_db.store_json({
            "filename": file.filename,
            "content_type": file.content_type,
            "schema": schema_data
        })

        return JSONResponse(status_code=201, content={
            "schema_id": schema_id,
            "filename": file.filename,
            "title": schema_data.get("info", {}).get("title", file.filename),
            "message": "Schema uploaded and stored successfully."
        })

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@schema_router.delete("/{schema_id}")
async def delete_schema(schema_id: str):
    """Supprime un schéma OAS de la base de données."""
    try:
        deleted = await storage_db.delete_json(schema_id)
        if not deleted:
            return JSONResponse(status_code=404, content={"error": "Schema not found"})
        return JSONResponse(status_code=200, content={"message": "Schema deleted successfully"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
