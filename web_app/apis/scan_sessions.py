# Module pour gérer les sessions de scan
# Évite les importations circulaires entre scan_api.py et bridge.py

from typing import Dict, Any
import asyncio

# Dictionnaire de sessions pour tracker les scans
scan_sessions: Dict[str, Dict[str, Any]] = {}

# WebSocket clients par scan id
scan_ws_clients: Dict[str, set] = {}

# Tâches de surveillance de fichiers de log par scan id
scan_log_watchers: Dict[str, Any] = {}


async def broadcast_scan_update(scan_id: str, payload: Dict[str, Any]):
    """Broadcast scan updates via WebSocket"""
    clients = scan_ws_clients.get(scan_id, set())
    for client in list(clients):
        try:
            await client.send_json(payload)
        except Exception:
            clients.discard(client)
    scan_ws_clients[scan_id] = clients