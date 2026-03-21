#!/usr/bin/env python3
"""
Test script for MongoDB storage functionality.
"""
import asyncio
import sys
import os
from db import storage_db

async def test_storage():
    print("🧪 Testing MongoDB storage...")

    # Test data
    test_data = {
        "name": "test_object",
        "data": "x" * 1000,  # 1KB of data
        "metadata": {
            "size": 1000,
            "type": "test"
        }
    }

    print("📤 Storing test data...")
    object_id = await storage_db.store_json(test_data)
    print(f"✅ Stored with ID: {object_id}")

    print("📥 Retrieving data...")
    retrieved = await storage_db.get_json(object_id)
    if retrieved:
        print("✅ Data retrieved successfully")
        print(f"   Name: {retrieved['name']}")
        print(f"   Data length: {len(retrieved['data'])}")
    else:
        print("❌ Failed to retrieve data")

    print("📋 Listing objects...")
    objects = await storage_db.list_objects(limit=10)
    print(f"✅ Found {len(objects)} objects: {objects}")

    print("🗑️  Cleaning up...")
    deleted = await storage_db.delete_json(object_id)
    print(f"✅ Deleted: {deleted}")

    print("🎉 All tests passed!")

if __name__ == "__main__":
    asyncio.run(test_storage())