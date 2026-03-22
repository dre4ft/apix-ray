import os
import sys
import asyncio
from typing import Dict
import uuid_utils
src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
sys.path.insert(0, src_path)


from wrapper import main_pentest_run
from wrapper import generate_scan_id as scan_id_generator
from apis.scan_sessions import scan_sessions, broadcast_scan_update

# Import de la base de données
storage_path = os.path.join(os.path.dirname(__file__), '..', 'storage')
sys.path.append(storage_path)
from db import storage_db

# Fonction pour diffuser les mises à jour de scan (évite l'import circulaire)
async def broadcast_scan_error(scan_id: str, error_message: str):
    """Diffuse une erreur de scan via WebSocket si disponible"""
    try:
        await broadcast_scan_update(scan_id, {
            "type": "scan_update",
            "status": "error",
            "error": error_message,
            "progress": 0,
            "logs": [f"Scan failed: {error_message}"],
            "results": []
        })
    except ImportError:
        # Si l'import échoue, on ne peut pas diffuser
        pass

# Tracker des tâches asyncio pour chaque scan
scan_tasks: Dict[str, asyncio.Task] = {}


def generate_scan_id():
    return scan_id_generator()


def start_scan(scan_id: uuid_utils.UUID, llm_type: str = "ollama", model: str = "qwen2.5-coder:latest", target_url: str = "http://example.com/api", schema_id: str = None, litellm_url: str = None, auth: str = None, vulnerability_types_to_test: list = None, use_mcp: bool = False, request_limits: Dict = None):
    async def run_scan():
        try:
            result = await main_pentest_run(
                scan_id=scan_id,
                llm_type=llm_type,
                model=model,
                target_url=target_url,
                auth=auth,
                schema_id=schema_id,  # Changé de oas_name à schema_id
                vulnerability_types_to_test=vulnerability_types_to_test,
                use_mcp=use_mcp,
                request_limits=request_limits,
            )

            # Mettre à jour la session avec les résultats finaux
            scan_id_str = str(scan_id)
            if scan_id_str in scan_sessions:
                scan_sessions[scan_id_str]["status"] = result.get("status", "completed")
                scan_sessions[scan_id_str]["results"] = result.get("vulnerabilities_found", [])
                scan_sessions[scan_id_str]["report"] = result.get("report", "")
                scan_sessions[scan_id_str]["progress"] = 100

                # Debug logging
                report_content = result.get("report", "")
                print(f"DEBUG: Storing report for scan {scan_id_str}")
                print(f"DEBUG: Report length: {len(report_content)} characters")
                print(f"DEBUG: Report preview: {report_content[:200]}..." if report_content else "Report is empty!")

                # Stocker le rapport complet dans MongoDB
                report_data = {
                    "scan_id": scan_id_str,
                    "report": report_content,
                    "status": result.get("status", "completed"),
                    "vulnerabilities_found": result.get("vulnerabilities_found", []),
                    "target_url": scan_sessions[scan_id_str].get("target_url", ""),
                    "llm_type": scan_sessions[scan_id_str].get("llm_type", ""),
                    "vulnerabilities_tested": scan_sessions[scan_id_str].get("vulnerabilities", [])
                }

                # Ajouter les métriques si disponibles
                if "endpoints_discovered" in scan_sessions[scan_id_str]:
                    report_data["metrics"] = {
                        "endpoints_discovered": scan_sessions[scan_id_str].get("endpoints_discovered", 0),
                        "tests_generated": scan_sessions[scan_id_str].get("tests_generated", 0),
                        "requests_executed": scan_sessions[scan_id_str].get("requests_executed", 0),
                        "vulnerabilities_found": len(result.get("vulnerabilities_found", [])),
                        "high_severity": scan_sessions[scan_id_str].get("high_severity", 0),
                        "medium_severity": scan_sessions[scan_id_str].get("medium_severity", 0),
                        "low_severity": scan_sessions[scan_id_str].get("low_severity", 0),
                        "critical_severity": scan_sessions[scan_id_str].get("critical_severity", 0),
                        "info_severity": scan_sessions[scan_id_str].get("info_severity", 0),
                        "scan_time_seconds": scan_sessions[scan_id_str].get("scan_time_seconds", 0),
                        "avg_response_time_ms": scan_sessions[scan_id_str].get("avg_response_time_ms", 0),
                        "success_rate_percent": scan_sessions[scan_id_str].get("success_rate_percent", 0)
                    }

                success = await storage_db.store_scan_report(scan_id_str, report_data)
                print(f"DEBUG: Database storage result: {success}")
                if not success:
                    print("ERROR: Failed to store scan report in database!")
                else:
                    print(f"SUCCESS: Scan report stored for scan {scan_id_str}")

        except asyncio.CancelledError:
            # Gestion propre de l'annulation
            print(f"Scan {scan_id} cancelled.")
            scan_id_str = str(scan_id)
            if scan_id_str in scan_sessions:
                scan_sessions[scan_id_str]["status"] = "cancelled"
                scan_sessions[scan_id_str]["error"] = "Scan was cancelled"
            raise
        except Exception as e:
            # Gestion des erreurs générales
            print(f"Scan {scan_id} failed with error: {e}")
            scan_id_str = str(scan_id)
            if scan_id_str in scan_sessions:
                scan_sessions[scan_id_str]["status"] = "error"
                scan_sessions[scan_id_str]["error"] = str(e)
                scan_sessions[scan_id_str]["progress"] = 0
            # Diffuser l'erreur immédiatement via WebSocket
            await broadcast_scan_error(scan_id_str, str(e))

    # Créer et lancer la tâche en arrière-plan
    task = asyncio.create_task(run_scan())
    scan_tasks[str(scan_id)] = task


async def stop_scan(scan_id: str):
    """Annule la tâche asyncio pour arrêter le scan."""
    task = scan_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
        try:
            await task  # Attendre que la tâche se termine proprement
        except asyncio.CancelledError:
            pass
        return True
    return False


if __name__ == "__main__":
    print("Available OAS schemas: Use the /schemas API endpoint to list stored schemas")
    
    # Example usage of start_scan
    #scan_result = start_scan(type="ollama", model="qwen2.5-coder:latest", target_url="http://example.com/api", oas_name="oas.yaml")
    #print("Scan Result:", scan_result)