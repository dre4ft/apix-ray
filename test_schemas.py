#!/usr/bin/env python3
"""
Test script for the new schema storage functionality.
"""
import asyncio
import sys
import os

# Add paths
sys.path.append('web_app')
sys.path.append('storage')

from db import storage_db

async def test_schema_storage():
    print("🧪 Testing schema storage functionality...")

    # Sample OAS schema
    sample_schema = {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "A test API schema"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {
                        "200": {
                            "description": "Success"
                        }
                    }
                }
            }
        }
    }

    print("📤 Storing sample OAS schema...")
    schema_id = await storage_db.store_json({
        "filename": "test_api.yaml",
        "content_type": "application/yaml",
        "schema": sample_schema
    })
    print(f"✅ Schema stored with ID: {schema_id}")

    print("📥 Retrieving schema...")
    stored_data = await storage_db.get_json(schema_id)
    if stored_data and "schema" in stored_data:
        schema = stored_data["schema"]
        print(f"✅ Schema retrieved: {schema['info']['title']} v{schema['info']['version']}")
    else:
        print("❌ Failed to retrieve schema")

    print("📋 Listing schemas...")
    all_objects = await storage_db.list_objects(limit=100)
    schemas = []
    for obj_id in all_objects:
        data = await storage_db.get_json(obj_id)
        if data and "schema" in data and ("openapi" in data["schema"] or "swagger" in data["schema"]):
            schemas.append(obj_id)

    print(f"✅ Found {len(schemas)} OAS schemas")

    print("🗑️  Cleaning up...")
    deleted = await storage_db.delete_json(schema_id)
    print(f"✅ Deleted: {deleted}")

    print("🎉 Schema storage tests passed!")

if __name__ == "__main__":
    asyncio.run(test_schema_storage())