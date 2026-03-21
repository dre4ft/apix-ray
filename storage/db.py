import motor.motor_asyncio
import os
from typing import Dict, Any, Optional
import uuid
from datetime import datetime

# Configuration MongoDB
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DATABASE_NAME = "apixray_storage"
COLLECTION_NAME = "json_objects"
REPORTS_COLLECTION = "scan_reports"

class StorageDB:
    def __init__(self):
        self.client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
        self.db = self.client[DATABASE_NAME]
        self.collection = self.db[COLLECTION_NAME]
        self.reports_collection = self.db[REPORTS_COLLECTION]

    async def store_json(self, data: Dict[str, Any], object_id: Optional[str] = None) -> str:
        """Stocke un objet JSON et retourne son ID."""
        if object_id is None:
            object_id = str(uuid.uuid4())

        document = {
            "_id": object_id,
            "data": data,
            "created_at": datetime.utcnow()
        }

        await self.collection.insert_one(document)
        return object_id

    async def get_json(self, object_id: str) -> Optional[Dict[str, Any]]:
        """Récupère un objet JSON par son ID."""
        document = await self.collection.find_one({"_id": object_id})
        if document:
            return document["data"]
        return None

    async def delete_json(self, object_id: str) -> bool:
        """Supprime un objet JSON par son ID."""
        result = await self.collection.delete_one({"_id": object_id})
        return result.deleted_count > 0

    async def list_objects(self, limit: int = 100) -> list:
        """Liste les IDs des objets stockés."""
        cursor = self.collection.find({}, {"_id": 1}).limit(limit)
        return [doc["_id"] async for doc in cursor]

    # Méthodes pour les rapports de scan
    async def store_scan_report(self, scan_id: str, report_data: Dict[str, Any]) -> bool:
        """Stocke un rapport de scan complet."""
        document = {
            "_id": scan_id,
            "scan_id": scan_id,
            "report_markdown": report_data.get("report", ""),
            "status": report_data.get("status", "unknown"),
            "vulnerabilities_found": report_data.get("vulnerabilities_found", []),
            "metrics": report_data.get("metrics", {}),
            "target_url": report_data.get("target_url", ""),
            "llm_type": report_data.get("llm_type", ""),
            "llm_model": report_data.get("llm_model", ""),
            "vulnerabilities_tested": report_data.get("vulnerabilities_tested", []),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        try:
            await self.reports_collection.replace_one(
                {"_id": scan_id},
                document,
                upsert=True
            )
            return True
        except Exception as e:
            print(f"Error storing scan report: {e}")
            return False

    async def get_scan_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Récupère un rapport de scan par son ID."""
        document = await self.reports_collection.find_one({"_id": scan_id})
        if document:
            return {
                "scan_id": document["scan_id"],
                "report": document["report_markdown"],
                "status": document["status"],
                "vulnerabilities_found": document["vulnerabilities_found"],
                "metrics": document["metrics"],
                "target_url": document["target_url"],
                "llm_type": document["llm_type"],
                "llm_model": document["llm_model"],
                "vulnerabilities_tested": document["vulnerabilities_tested"],
                "created_at": document["created_at"],
                "updated_at": document["updated_at"]
            }
        return None

    async def list_scan_reports(self, limit: int = 50) -> list:
        """Liste les rapports de scan disponibles."""
        cursor = self.reports_collection.find(
            {},
            {
                "_id": 1,
                "scan_id": 1,
                "status": 1,
                "target_url": 1,
                "created_at": 1,
                "vulnerabilities_found": {"$size": "$vulnerabilities_found"}
            }
        ).sort("created_at", -1).limit(limit)

        reports = []
        async for doc in cursor:
            reports.append({
                "scan_id": doc["_id"],
                "status": doc["status"],
                "target_url": doc["target_url"],
                "created_at": doc["created_at"],
                "vulnerabilities_count": doc.get("vulnerabilities_found", 0)
            })
        return reports

# Instance globale
storage_db = StorageDB()