from fastapi import FastAPI, APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import bridge
import os
import sys
import json
import yaml

# Add storage path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'storage'))
from db import storage_db

# Add storage path
sys.path.append(os.path.join(os.path.dirname(__file__), 'apis'))
from schema_api import schema_router
from scan_api import scan_router
from playbook_api import playbook_router

# Create the main FastAPI app
app = FastAPI(
    title="APIX-Ray API",
    description="API pour contrôler et monitorer le pentest agent avec gestion des schémas",
    version="1.0.0"
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8800", "http://127.0.0.1:8800"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ===== MAIN APP =====
# Include routers
app.include_router(schema_router)
app.include_router(scan_router)
app.include_router(playbook_router)

@app.get("/health")
def health_check():
    return JSONResponse(status_code=200, content={"status": "healthy"})

if __name__ == "__main__":
    import uvicorn
    import os

    # Enable auto-reload in development
    reload_enabled = os.getenv("API_RELOAD", "true").lower() == "true"

    if reload_enabled:
        # Use import string for reload to work properly
        uvicorn.run(
            "api:app",
            host="127.0.0.1",
            port=8080,
            reload=True,
            reload_dirs=[".", "../src", "../playbooks"]
        )
    else:
        # Use app object directly when reload is disabled
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=8080,
            reload=False
        )
