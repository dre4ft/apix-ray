"""
Playbook API endpoints
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from typing import List, Dict, Any
import sys
import os

# Add paths
playbooks_path = os.path.join(os.path.dirname(__file__), '..', '..', 'playbooks')
storage_path = os.path.join(os.path.dirname(__file__), '..', '..', 'storage')
sys.path.append(playbooks_path)
sys.path.append(storage_path)

from playbooks import playbook_manager
from db import storage_db

# Create router
playbook_router = APIRouter(prefix="/playbooks", tags=["playbooks"])

@playbook_router.get("/")
async def get_all_playbooks():
    """Get all available playbooks"""
    try:
        # Ensure playbooks are initialized
        await playbook_manager.ensure_initialized()

        playbooks = {}
        for vuln_type in playbook_manager.get_available_vulnerabilities():
            playbook = playbook_manager.get_playbook(vuln_type)
            if playbook:
                # Return simplified version without full methodology for overview
                playbooks[vuln_type] = {
                    "description": playbook.get("description", ""),
                    "severity": playbook.get("severity", "low"),
                    "cvss_base_score": playbook.get("cvss_base_score", 0),
                    "enabled": playbook.get("enabled", True)
                }

        return JSONResponse(status_code=200, content={"playbooks": playbooks})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to get playbooks: {str(e)}"})

@playbook_router.get("/vulnerabilities")
async def get_available_vulnerabilities():
    """Get list of available vulnerability types for testing"""
    try:
        await playbook_manager.ensure_initialized()
        vulnerabilities = playbook_manager.get_available_vulnerabilities()
        return JSONResponse(status_code=200, content={"vulnerabilities": vulnerabilities})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to get vulnerabilities: {str(e)}"})

@playbook_router.get("/{vulnerability_type}")
async def get_playbook(vulnerability_type: str):
    """Get detailed playbook for a specific vulnerability type"""
    try:
        await playbook_manager.ensure_initialized()
        playbook = playbook_manager.get_playbook(vulnerability_type)
        if not playbook:
            return JSONResponse(status_code=404, content={"error": "Playbook not found"})

        return JSONResponse(status_code=200, content={"playbook": playbook})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to get playbook: {str(e)}"})

@playbook_router.get("/{vulnerability_type}/methodology")
async def get_vulnerability_methodology(vulnerability_type: str):
    """Get testing methodology for a vulnerability type"""
    try:
        await playbook_manager.ensure_initialized()
        methodology = playbook_manager.get_methodology_for_vulnerability(vulnerability_type)
        if not methodology:
            return JSONResponse(status_code=404, content={"error": "Methodology not found"})

        return JSONResponse(status_code=200, content={"methodology": methodology})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to get methodology: {str(e)}"})

@playbook_router.post("/generate_payloads")
async def generate_smart_payloads(request: Dict[str, Any]):
    """Generate smart payloads for a vulnerability type based on endpoint info"""
    try:
        print(f"DEBUG: Received request: {request}")
        await playbook_manager.ensure_initialized()
        vulnerability_type = request.get("vulnerability_type")
        endpoint_info = request.get("endpoint_info", {})
        print(f"DEBUG: vulnerability_type={vulnerability_type}, endpoint_info={endpoint_info}")

        if not vulnerability_type:
            return JSONResponse(status_code=400, content={"error": "vulnerability_type is required"})

        payloads = await playbook_manager.generate_smart_payloads(vulnerability_type, endpoint_info)
        return JSONResponse(status_code=200, content={"payloads": payloads})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to generate payloads: {str(e)}"})

@playbook_router.post("/validate_response")
async def validate_response(request: Dict[str, Any]):
    """Validate API response for vulnerability indicators"""
    try:
        await playbook_manager.ensure_initialized()
        response = request.get("response", {})
        vulnerability_type = request.get("vulnerability_type")
        phase = request.get("phase", "")

        if not vulnerability_type:
            return JSONResponse(status_code=400, content={"error": "vulnerability_type is required"})

        validation = await playbook_manager.validate_response_for_vulnerability(response, vulnerability_type, phase)
        return JSONResponse(status_code=200, content={"validation": validation})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to validate response: {str(e)}"})

@playbook_router.post("/")
async def create_playbook(request: Dict[str, Any]):
    """Create a new playbook"""
    try:
        vulnerability_type = request.get("vulnerability_type")
        playbook_data = request.get("playbook")

        if not vulnerability_type or not playbook_data:
            return JSONResponse(status_code=400, content={"error": "vulnerability_type and playbook are required"})

        await playbook_manager.ensure_initialized()

        # Check if playbook already exists
        existing = playbook_manager.get_playbook(vulnerability_type)
        if existing:
            return JSONResponse(status_code=409, content={"error": f"Playbook for {vulnerability_type} already exists"})

        # Validate playbook structure
        required_fields = ["description", "methodology", "severity"]
        for field in required_fields:
            if field not in playbook_data:
                return JSONResponse(status_code=400, content={"error": f"Missing required field: {field}"})

        # Store in database
        success = await storage_db.store_playbook(vulnerability_type, playbook_data)
        if success:
            # Update local cache
            playbook_manager.playbooks[vulnerability_type] = playbook_data
            return JSONResponse(status_code=201, content={"message": f"Playbook for {vulnerability_type} created successfully"})
        else:
            return JSONResponse(status_code=500, content={"error": "Failed to store playbook in database"})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to create playbook: {str(e)}"})

@playbook_router.put("/{vulnerability_type}")
async def update_playbook(vulnerability_type: str, request: Dict[str, Any]):
    """Update an existing playbook"""
    try:
        playbook_data = request.get("playbook")

        if not playbook_data:
            return JSONResponse(status_code=400, content={"error": "playbook data is required"})

        await playbook_manager.ensure_initialized()

        # Check if playbook exists
        existing = playbook_manager.get_playbook(vulnerability_type)
        if not existing:
            return JSONResponse(status_code=404, content={"error": f"Playbook for {vulnerability_type} not found"})

        # Validate playbook structure
        required_fields = ["description", "methodology", "severity"]
        for field in required_fields:
            if field not in playbook_data:
                return JSONResponse(status_code=400, content={"error": f"Missing required field: {field}"})

        # Store updated playbook in database
        success = await storage_db.store_playbook(vulnerability_type, playbook_data)
        if success:
            # Update local cache
            playbook_manager.playbooks[vulnerability_type] = playbook_data
            return JSONResponse(status_code=200, content={"message": f"Playbook for {vulnerability_type} updated successfully"})
        else:
            return JSONResponse(status_code=500, content={"error": "Failed to update playbook in database"})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to update playbook: {str(e)}"})

@playbook_router.delete("/{vulnerability_type}")
async def delete_playbook(vulnerability_type: str):
    """Delete a playbook"""
    try:
        await playbook_manager.ensure_initialized()

        # Check if playbook exists
        existing = playbook_manager.get_playbook(vulnerability_type)
        if not existing:
            return JSONResponse(status_code=404, content={"error": f"Playbook for {vulnerability_type} not found"})

        # Delete from database
        success = await storage_db.delete_playbook(vulnerability_type)
        if success:
            # Update local cache
            if vulnerability_type in playbook_manager.playbooks:
                del playbook_manager.playbooks[vulnerability_type]
            return JSONResponse(status_code=200, content={"message": f"Playbook for {vulnerability_type} deleted successfully"})
        else:
            return JSONResponse(status_code=500, content={"error": "Failed to delete playbook from database"})

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to delete playbook: {str(e)}"})