from fastapi import FastAPI, APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from typing import List, Dict, Any
import bridge
import os
import sys
import json
import yaml
import asyncio
from scan_sessions import scan_sessions, scan_ws_clients, scan_log_watchers, broadcast_scan_update

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'storage'))
from db import storage_db

# ===== SCAN ROUTER =====
scan_router = APIRouter(prefix="", tags=["scans"])

def get_log_file_path(scan_id: str) -> str:
    """Retourne le chemin de fichier log correspondant au scan_id."""
    candidates = [
        os.path.join(os.path.dirname(__file__), '..', 'log', f'pentest_run_{scan_id}.log'),
        os.path.join(os.path.dirname(__file__), '..', '..', 'log', f'pentest_run_{scan_id}.log'),
        os.path.join(os.path.dirname(__file__), '..', 'logs', f'pentest_run_{scan_id}.log'),
        os.path.join(os.path.dirname(__file__), '..', '..', 'logs', f'pentest_run_{scan_id}.log')
    ]
    for path in candidates:
        normalized = os.path.normpath(path)
        if os.path.exists(normalized):
            return normalized
    # Fallback vers le premier emplacement attendu
    return os.path.normpath(candidates[0])


def load_scan_logs_from_file(scan_id: str) -> list[str]:
    """Lit et retourne les lignes de logs à partir du fichier avec scan_id"""
    path = get_log_file_path(scan_id)
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except Exception:
        return []





async def scan_log_watcher(scan_id: str):
    log_path = get_log_file_path(scan_id)
    offset = 0
    last_progress = 0
    last_status = "running"
    last_results_count = 0

    while scan_id in scan_sessions and scan_sessions[scan_id].get("status") not in ("completed", "failed", "stopped", "error"):
        session = scan_sessions[scan_id]
        current_progress = session.get("progress", 0)
        current_status = session.get("status", "running")
        current_results_count = len(session.get("results", []))

        # Vérifier si il y a des changements dans les logs
        log_updated = False
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8') as f:
                    f.seek(offset)
                    new_text = f.read()
                    offset = f.tell()

                lines = [line for line in new_text.splitlines() if line.strip()]
                if lines:
                    log_updated = True
                    # Mise à jour mémoire aussi si nécessaire
                    session.setdefault("logs", []).extend(lines)
            except Exception:
                pass

        # Si logs mis à jour ou statut/progress/résultats changé, envoyer une mise à jour complète
        if log_updated or current_progress != last_progress or current_status != last_status or current_results_count != last_results_count:
            file_logs = load_scan_logs_from_file(scan_id)
            logs = file_logs if file_logs else session.get("logs", [])
            results = session.get("results", [])
            
            # Get metrics from session (updated by results_callback)
            metrics = {
                "endpoints_discovered": session.get("endpoints_discovered", 0),
                "tests_generated": session.get("tests_generated", 0),
                "requests_executed": session.get("requests_executed", 0),
                "vulnerabilities_found": session.get("vulnerabilities_found", 0),
                "high_severity": session.get("high_severity", 0),
                "medium_severity": session.get("medium_severity", 0),
                "low_severity": session.get("low_severity", 0),
                "critical_severity": session.get("critical_severity", 0),
                "info_severity": session.get("info_severity", 0),
                "scan_time_seconds": session.get("scan_time_seconds", 0),
                "avg_response_time_ms": session.get("avg_response_time_ms", 0),
                "success_rate_percent": session.get("success_rate_percent", 0)
            }

            await broadcast_scan_update(scan_id, {
                "type": "scan_update",
                "status": current_status,
                "progress": metrics.get("progress", current_progress),
                "target_url": session.get("target_url"),
                "logs": logs,
                "results": results,
                "metrics": metrics
            })

            last_progress = current_progress
            last_status = current_status
            last_results_count = current_results_count

        await asyncio.sleep(1)


class ScanRequest(BaseModel):
    target_url: str
    llm_type: str = "ollama"
    model: str = "qwen2.5-coder:latest"
    schema_id: str  # Changé de oas_name à schema_id
    vulnerabilities: list = ["IDOR", "Broken Access Control", "SQL injection", "XSS", "Command Injection"]
    use_mcp: bool = False
    request_limits: Dict[str, Any] = {
        "global_max_requests": 100,
        "per_vulnerability_max": 25,
        "adaptive_enabled": True,
        "relevance_threshold": 0.7,
        "evolution_factor": 1.2
    }

@scan_router.post("/start_scan")
async def start_scan(scan_request: ScanRequest):
    scan_id = bridge.generate_scan_id()
    log_file_path = get_log_file_path(str(scan_id))
    scan_sessions[str(scan_id)] = {
        "status": "running",
        "target_url": scan_request.target_url,
        "llm_type": scan_request.llm_type,
        "schema_id": scan_request.schema_id,
        "vulnerabilities": scan_request.vulnerabilities,
        "logs": ["Scan initialized..."],
        "results": [],
        "progress": 0,
        "log_file": log_file_path
    }
    bridge.start_scan(scan_id=scan_id, llm_type=scan_request.llm_type, model=scan_request.model, target_url=scan_request.target_url, schema_id=scan_request.schema_id, vulnerability_types_to_test=scan_request.vulnerabilities, use_mcp=scan_request.use_mcp, request_limits=scan_request.request_limits)

    # Lancer un watcher de fichier de log qui envoie des événements en temps réel via WS
    watcher_task = asyncio.create_task(scan_log_watcher(str(scan_id)))
    scan_log_watchers[str(scan_id)] = watcher_task

    return JSONResponse(status_code=200, content={
        "scan_id": str(scan_id),
        "message": "Scan started successfully."
    })

@scan_router.post("/stop_scan/{scan_id}")
async def stop_scan(scan_id: str):
    if scan_id not in scan_sessions:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})
    scan_sessions[scan_id]["status"] = "stopped"
    stopped = await bridge.stop_scan(scan_id=scan_id)

    # Arrêter le watcher de log au besoin
    watcher_task = scan_log_watchers.pop(scan_id, None)
    if watcher_task:
        watcher_task.cancel()

    return JSONResponse(status_code=200, content={
        "scan_id": scan_id,
        "message": "Scan stopped successfully." if stopped else "Scan was not running."
    })

@scan_router.websocket("/ws/scan/{scan_id}")
async def websocket_scan(scan_id: str, websocket: WebSocket):
    await websocket.accept()
    scan_ws_clients.setdefault(scan_id, set()).add(websocket)

    # __send initial state__ (pour le dashboard) 
    if scan_id in scan_sessions:
        session = scan_sessions[scan_id]
        await websocket.send_json({
            "type": "init",
            "status": session.get("status", "unknown"),
            "progress": session.get("progress", 0),
            "target_url": session.get("target_url"),
            "logs": session.get("logs", []),
            "results": session.get("results", [])
        })

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        scan_ws_clients.get(scan_id, set()).discard(websocket)

@scan_router.get("/scan_status/{scan_id}")
def get_scan_status(scan_id: str):
    if scan_id not in scan_sessions:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})
    return JSONResponse(status_code=200, content={
        "scan_id": scan_id,
        "status": scan_sessions[scan_id]["status"],
        "progress": scan_sessions[scan_id]["progress"],
        "target_url": scan_sessions[scan_id]["target_url"]
    })

@scan_router.get("/scan_logs/{scan_id}")
def get_scan_logs(scan_id: str):
    if scan_id not in scan_sessions:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})

    # Lecture du fichier de log lié au scan (priorité sur le contenu mémoire)
    file_logs = load_scan_logs_from_file(scan_id)
    if file_logs:
        logs = file_logs
    else:
        logs = scan_sessions[scan_id].get("logs", [])

    return JSONResponse(status_code=200, content={
        "logs": logs,
        "progress": scan_sessions[scan_id].get("progress", 0),
        "status": scan_sessions[scan_id].get("status", "unknown")
    })

@scan_router.post("/update_scan_results/{scan_id}")
async def update_scan_results(scan_id: str, results: List[Dict[str, Any]] = None, metrics: Dict[str, Any] = None):
    """Update scan results and metrics in real-time"""
    if scan_id not in scan_sessions:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})

    # Update results if provided
    if results is not None:
        scan_sessions[scan_id]["results"] = results
        # Update progress based on results
        scan_sessions[scan_id]["progress"] = min(90, 10 + len(results) * 2)

    # Update metrics if provided
    if metrics is not None:
        # Handle special fields
        if "status" in metrics:
            scan_sessions[scan_id]["status"] = metrics["status"]
        if "progress" in metrics:
            scan_sessions[scan_id]["progress"] = metrics["progress"]

        # Update other metrics
        for key, value in metrics.items():
            if key not in ["status", "progress"]:  # Already handled above
                scan_sessions[scan_id][key] = value

    # Create payload for WebSocket broadcast
    payload = {
        "type": "scan_update",
        "scan_id": scan_id,
        "results": scan_sessions[scan_id].get("results", []),
        "progress": scan_sessions[scan_id].get("progress", 0),
        "status": scan_sessions[scan_id].get("status", "running"),
        "metrics": metrics or {}
    }

    # Broadcast update via WebSocket
    asyncio.create_task(broadcast_scan_update(scan_id, payload))

    return JSONResponse(status_code=200, content={"status": "updated"})

@scan_router.get("/scan_results/{scan_id}")
def get_scan_results(scan_id: str):
    if scan_id not in scan_sessions:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})
    return JSONResponse(status_code=200, content={
        "results": scan_sessions[scan_id]["results"],
        "status": scan_sessions[scan_id]["status"]
    })

@scan_router.get("/scan_overview/{scan_id}")
def get_scan_overview(scan_id: str):
    """Renvoie en une seule requête status+logs+results pour diminuer la charge"""
    if scan_id not in scan_sessions:
        return JSONResponse(status_code=404, content={"error": "Scan not found"})

    session = scan_sessions[scan_id]
    # Si le fichier log existe, charge-le
    file_logs = load_scan_logs_from_file(scan_id)
    logs = file_logs if file_logs else session.get("logs", [])

    return JSONResponse(status_code=200, content={
        "status": session.get("status", "unknown"),
        "progress": session.get("progress", 0),
        "target_url": session.get("target_url"),
        "logs": logs,
        "results": session.get("results", []),
        "metrics": {
            "endpoints_discovered": session.get("endpoints_discovered", 0),
            "tests_generated": session.get("tests_generated", 0),
            "high_severity": len([r for r in session.get("results", []) if r.get("severity") == "high"]),
            "medium_severity": len([r for r in session.get("results", []) if r.get("severity") == "medium"])
        }
    })


@scan_router.get("/llm/models")
async def get_llm_models():
    """Retourne les modèles LLM disponibles pour chaque type."""
    try:
        models = {
            "ollama": [
                "llama2",
                "qwen2.5",
                "qwen2.5-coder:latest",
                "codellama",
                "mistral"
            ],
            "litellm": [
                "gpt-3.5-turbo",
                "gpt-4",
                "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307"
            ],
            "xai": [
                "grok-3",
                "grok-3-mini",
                "grok-4-1-fast-non-reasoning",
                "grok-4.20-0309-reasoning"
            ],
        }
        return {"models": models}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to get LLM models: {str(e)}"})

@scan_router.get("/scan_history")
async def get_scan_history(limit: int = 20):
    """Récupérer l'historique des scans passés"""
    try:
        scans = await storage_db.list_scan_reports(limit)
        return JSONResponse(status_code=200, content={"scans": scans})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to get scan history: {str(e)}"})

@scan_router.get("/get_report/{scan_id}")
async def get_scan_report(scan_id: str):
    """Récupérer le rapport complet d'un scan au format Markdown"""
    try:
        print(f"DEBUG: Attempting to get report for scan {scan_id}")

        # Essayer d'abord de récupérer depuis MongoDB
        report_data = await storage_db.get_scan_report(scan_id)
        print(f"DEBUG: Database query result: {report_data is not None}")

        if report_data:
            report_content = report_data.get("report", "")
            print(f"DEBUG: Report content length: {len(report_content)}")
            print(f"DEBUG: Report preview: {report_content[:100]}..." if report_content else "Report content is empty!")

            # Retourner le rapport au format Markdown
            return Response(
                content=report_content,
                media_type="text/markdown",
                headers={"Content-Disposition": f"attachment; filename=apix-ray-report-{scan_id}.md"}
            )

        # Fallback vers les sessions en mémoire si pas trouvé en DB
        if scan_id not in scan_sessions:
            return JSONResponse(status_code=404, content={"error": "Scan not found"})

        session = scan_sessions[scan_id]
        report = session.get("report", "")

        if not report:
            return JSONResponse(status_code=404, content={"error": "Report not available"})

        # Retourner le rapport au format Markdown
        return Response(
            content=report,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=apix-ray-report-{scan_id}.md"}
        )

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to retrieve report: {str(e)}"})

@scan_router.get("/list_reports")
async def list_scan_reports(limit: int = 20):
    """Lister les rapports de scan disponibles"""
    try:
        reports = await storage_db.list_scan_reports(limit)
        return JSONResponse(status_code=200, content={"reports": reports})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Failed to list reports: {str(e)}"})