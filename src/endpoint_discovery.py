import yaml
import json
import logging
import re
import os
import sys
import asyncio
from typing import List, Dict, Any

# Add storage path for database access
storage_path = os.path.join(os.path.dirname(__file__), '..', 'storage')
sys.path.append(storage_path)
try:
    from db import storage_db
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    logger.warning("Database module not available, schema loading from DB disabled")

# Assurez-vous que le logging est configuré dans votre application principale ou ici
logger =  logging.getLogger(__name__)

class OASLoadError(Exception):
    """Exception personnalisée pour les erreurs lors du chargement d'un document OAS local."""
    pass

class OASParseError(Exception):
    """Exception personnalisée pour les erreurs lors du parsing d'un document OAS."""
    pass

class EndpointExtractionError(Exception):
    """Exception personnalisée pour les erreurs lors de l'extraction des endpoints."""
    pass

class EndpointInspectionError(Exception):
    """Exception personnalisée pour les erreurs lors de l'extraction des endpoints."""
    pass


def load_oas_document_from_local_file(oas_file_path: str) -> Dict[str, Any]:
    """
    Charge un document OpenAPI (Swagger) depuis un chemin de fichier local ou un ID de base de données.

    Args:
        oas_file_path (str): Chemin d'accès au fichier local du document OAS ou ID du schéma en base.

    Returns:
        Dict[str, Any]: Le contenu du document OAS parsé en dictionnaire Python.

    Raises:
        OASLoadError: Si le fichier n'est pas trouvé, ne peut pas être lu, ou si le parsing échoue.
    """
    # Check if it's a UUID (schema ID from database)
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    if uuid_pattern.match(oas_file_path) and DB_AVAILABLE:
        logger.info(f"Loading OAS document from database with ID: {oas_file_path}")
        try:
            # Run async database call in sync context
            async def get_schema():
                return await storage_db.get_json(oas_file_path)
            
            schema_data = asyncio.run(get_schema())
            
            if not schema_data:
                raise OASLoadError(f"Schema not found in database: {oas_file_path}")
            
            # Extract the actual schema content
            if isinstance(schema_data, dict) and 'schema' in schema_data:
                return schema_data['schema']
            else:
                raise OASLoadError(f"Invalid schema format in database for ID: {oas_file_path}")
        except Exception as e:
            raise OASLoadError(f"Error loading schema from database {oas_file_path}: {e}") from e

    # Otherwise, load from file as before
    logger.info(f"Attempting to load OAS document from local file: {oas_file_path}")
    content = None
    try:
        with open(oas_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        logger.info(f"Successfully read OAS document from local file: {oas_file_path}")

        if not content:
            raise OASLoadError("OAS file is empty.")

        # Déterminer le format et parser
        if oas_file_path.lower().endswith(('.yaml', '.yml')):
            try:
                return yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise OASParseError(f"Error parsing YAML document from {oas_file_path}: {e}") from e
        elif oas_file_path.lower().endswith('.json'):
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                raise OASParseError(f"Error parsing JSON document from {oas_file_path}: {e}") from e
        else:
            # Essayer de deviner si ce n'est pas une extension claire
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                try:
                    return yaml.safe_load(content)
                except yaml.YAMLError as e:
                    raise OASParseError(f"Could not parse file {oas_file_path} as JSON or YAML: {e}") from e

    except FileNotFoundError:
        raise OASLoadError(f"OAS file not found at: {oas_file_path}") from None
    except IOError as e:
        raise OASLoadError(f"Error reading OAS file {oas_file_path}: {e}") from e
    except OASParseError:
        raise # Propager les erreurs de parsing
    except Exception as e:
        # Capture toute autre exception inattendue
        raise OASLoadError(f"An unexpected error occurred while loading OAS from {oas_file_path}: {e}") from e


def discover_endpoints_from_oas(oas_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extrait la liste des endpoints (chemins et méthodes) à partir d'un document OpenAPI parsé.

    Args:
        oas_document (Dict[str, Any]): Le dictionnaire représentant le document OAS.

    Returns:
        List[Dict[str, Any]]: Une liste de dictionnaires, où chaque dictionnaire décrit un endpoint.
                               Ex: {'path': '/users/{id}', 'method': 'GET', 'operationId': 'getUser', ...}

    Raises:
        EndpointExtractionError: Si la structure du document OAS est inattendue ou si des données clés manquent.
    """
    endpoints = []
    if not isinstance(oas_document, dict):
        raise EndpointExtractionError("Invalid OAS document format. Expected a dictionary.")

    paths = oas_document.get("paths")
    if not paths or not isinstance(paths, dict):
        logger.warning("No 'paths' section found in the OAS document or 'paths' is not a dictionary. No endpoints to discover.")
        return []

    logger.info(f"Found {len(paths)} paths in the OAS document.")

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            logger.warning(f"Skipping invalid path item for path '{path}'. Expected a dictionary.")
            continue

        for method, operation in path_item.items():
            if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head", "trace"):
                if not isinstance(operation, dict):
                    logger.warning(f"Skipping invalid operation for path '{path}', method '{method}'. Expected a dictionary.")
                    continue

                endpoint_info = {
                    "path": path,
                    "method": method.upper(),
                    "operationId": operation.get("operationId"),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "tags": operation.get("tags", []),
                }
                endpoints.append(endpoint_info)
                logger.debug(f"Discovered endpoint: {method.upper()} {path}")

    logger.info(f"Successfully discovered {len(endpoints)} endpoints.")
    return endpoints


def inspect_endpoint_details(
    oas_document: Dict[str, Any],
    path: str,
    method: str
) -> Dict[str, Any]:
    """
    Inspecte un endpoint spécifique à partir d'un document OpenAPI parsé et retourne ses détails.

    Args:
        oas_document (Dict[str, Any]): Le document OAS parsé.
        path (str): Le chemin de l'endpoint à inspecter (e.g., "/users/{id}").
        method (str): La méthode HTTP de l'endpoint (e.g., "GET", "POST"). Case-insensitive.

    Returns:
        Dict[str, Any]: Un dictionnaire structuré contenant les détails de l'opération.
                        Ex: {'path': ..., 'method': ..., 'summary': ..., 'parameters': [...], 
                             'requestBody': {...}, 'responses': {...}}

    Raises:
        EndpointInspectionError: Si le path, la méthode, ou la structure attendue ne sont pas trouvés.
    """
    if not isinstance(oas_document, dict):
        raise EndpointInspectionError("Invalid OAS document format provided.")

    paths = oas_document.get("paths")
    if not paths or not isinstance(paths, dict):
        raise EndpointInspectionError("OAS document does not contain a valid 'paths' section.")

    normalized_method = method.lower()
    path_item = paths.get(path)

    if not path_item or not isinstance(path_item, dict):
        raise EndpointInspectionError(f"Path '{path}' not found in the OAS document.")

    operation = path_item.get(normalized_method)
    if not operation or not isinstance(operation, dict):
        raise EndpointInspectionError(f"Method '{method.upper()}' not found for path '{path}' in the OAS document.")

    logger.info(f"Inspecting details for endpoint: {method.upper()} {path}")

    # --- Extraction des détails pertinents ---
    details = {
        "path": path,
        "method": normalized_method.upper(),
        "summary": operation.get("summary", ""),
        "description": operation.get("description", ""),
        "operationId": operation.get("operationId"),
        "tags": operation.get("tags", []),
        "parameters": [],
        "requestBody": None,
        "responses": {}
    }

    # Extraction des paramètres
    parameters = operation.get("parameters", [])
    if isinstance(parameters, list):
        for param in parameters:
            if isinstance(param, dict):
                param_details = {
                    "name": param.get("name"),
                    "in": param.get("in"),
                    "description": param.get("description", ""),
                    "required": param.get("required", False),
                    "schema": param.get("schema", {}) # Le schéma complet du paramètre
                }
                # On met à null les valeurs non trouvées pour plus de clarté
                if param_details["name"] is None: param_details["name"] = "N/A"
                if param_details["in"] is None: param_details["in"] = "N/A"
                
                details["parameters"].append(param_details)
    else:
        logger.warning(f"Unexpected format for 'parameters' in {method.upper()} {path}. Expected a list, got {type(parameters)}.")

    # Extraction du requestBody
    request_body = operation.get("requestBody")
    if request_body and isinstance(request_body, dict):
        rq_body_details = {
            "description": request_body.get("description", ""),
            "required": request_body.get("required", False),
            "content": request_body.get("content", {}), # Garder le contenu brut pour l'instant
        }
        details["requestBody"] = rq_body_details
    
    # Extraction des responses
    responses = operation.get("responses")
    if responses and isinstance(responses, dict):
        for status_code, response_info in responses.items():
            if isinstance(response_info, dict):
                details["responses"][status_code] = {
                    "description": response_info.get("description", ""),
                    "content": response_info.get("content", {}), # Garder le contenu brut
                    # On pourrait explorer plus en détail les schemas ici si nécessaire
                }
    else:
        logger.warning(f"No 'responses' section found for {method.upper()} {path}.")

    logger.info(f"Successfully extracted details for {method.upper()} {path}.")
    return details

# --- Example Usage (for testing or main.py) ---
# if __name__ == "__main__":
#     import os
#     # Assurez-vous qu'un fichier OAS local existe pour tester.
#     # Par exemple, utilisez le dummy_content créé dans l'exemple précédent.
#     local_oas_file_path = "temp_oas/swagger.json" # Ou un autre chemin valide
#
#     if not os.path.exists(local_oas_file_path):
#         print(f"Error: Test file '{local_oas_file_path}' not found. Please create it or update the path.")
#     else:
#         try:
#             oas_doc = load_oas_document_from_local_file(local_oas_file_path)
#             
#             # Exemple 1: Inspecter un endpoint existant
#             print("\n--- Inspecting endpoint /users/{id} (GET) ---")
#             try:
#                 user_details = inspect_endpoint_details(oas_doc, "/users/{id}", "GET")
#                 print(f"Summary: {user_details['summary']}")
#                 print(f"Parameters found: {len(user_details['parameters'])}")
#                 if user_details['parameters']:
#                     print(f"  First param: Name='{user_details['parameters'][0].get('name')}', In='{user_details['parameters'][0].get('in')}', Required={user_details['parameters'][0].get('required')}")
#                 print(f"Request Body present: {'Yes' if user_details['requestBody'] else 'No'}")
#                 print(f"Responses defined: {list(user_details['responses'].keys())}")
#             except EndpointInspectionError as e:
#                 print(f"Error inspecting endpoint: {e}")
#
#             # Exemple 2: Inspecter un autre endpoint
#             print("\n--- Inspecting endpoint /login (POST) ---")
#             try:
#                 login_details = inspect_endpoint_details(oas_doc, "/login", "post") # Test case-insensitivity
#                 print(f"Summary: {login_details['summary']}")
#                 print(f"Request Body required: {login_details['requestBody']['required'] if login_details['requestBody'] else 'N/A'}")
#                 if login_details['requestBody'] and login_details['requestBody']['content']:
#                     print(f"  Content types: {list(login_details['requestBody']['content'].keys())}")
#             except EndpointInspectionError as e:
#                 print(f"Error inspecting endpoint: {e}")
#
#             # Exemple 3: Tenter d'inspecter un endpoint inexistant
#             print("\n--- Inspecting non-existent endpoint /admin (GET) ---")
#             try:
#                 inspect_endpoint_details(oas_doc, "/admin", "GET")
#             except EndpointInspectionError as e:
#                 print(f"Caught expected error: {e}")
#
#             # Exemple 4: Tenter d'inspecter une méthode inexistante pour un path existant
#             print("\n--- Inspecting non-existent method for /users/{id} (POST) ---")
#             try:
#                 inspect_endpoint_details(oas_doc, "/users/{id}", "POST")
#             except EndpointInspectionError as e:
#                 print(f"Caught expected error: {e}")
#
#         except OASLoadError as e:
#             print(f"Error loading OAS for testing inspection: {e}")
#         except Exception as e:
#             print(f"An unexpected error occurred during inspection testing: {e}")