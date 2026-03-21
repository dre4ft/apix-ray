import motor.motor_asyncio
import os
from typing import Dict, Any, Optional
import uuid
from datetime import datetime

# Configuration MongoDB
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DATABASE_NAME = "apixray_storage"
COLLECTION_NAME = "json_objects"

class StorageDB:
    def __init__(self):
        self.client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
        self.db = self.client[DATABASE_NAME]
        self.collection = self.db[COLLECTION_NAME]

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

# Instance globale
storage_db = StorageDB()