import httpx
import logging
import time
from typing import List, Dict, Any, Optional, Union, Tuple
from urllib.parse import urljoin
import time

AUTH = "n5AkcyNrxQg0PD2MYGGQWLBWfbfLUs3m7OkWzhXsrI5SgoWjAUkj6X"

# Configuration basique du logging (peut être gérée de manière plus globale plus tard)
logger = logging.getLogger(__name__)

class HttpRequestManager:
    """
    Un gestionnaire de requêtes HTTP asynchrone pour envoyer des requêtes REST.
    Supporte les retries pour les erreurs réseau et serveur.
    """
    def __init__(self, default_timeout: float = 30.0, max_retries: int = 3, retry_delay: float = 1.0, base_url: str = "", auth : str = ""):
        """
        Initialise le HttpRequestManager.

        Args:
            default_timeout (float): Timeout par défaut en secondes pour chaque requête.
            max_retries (int): Nombre maximum de tentatives automatiques en cas d'échec.
            retry_delay (float): Délai en secondes entre chaque tentative (peut être implémenté avec backoff exponentiel).
            base_url (str): Une URL de base optionnelle pour joindre les URLs relatives.
        """
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.auth = auth

        self.headers = {
            "User-Agent": "API-Pentest-Agent/1.0", # Un User-Agent personnalisé
            "Accept": "*/*" # Pour être permissif
        }

        # Add Authorization header only if auth is provided
        if self.auth:
            self.headers["Authorization"] = f"Bearer {self.auth}"

        self.httpx_client = httpx.AsyncClient(
            timeout=self.default_timeout,
            headers=self.headers,
            verify=False,
            # httpx gère les retries automatiquement avec `follow_redirects=True` et `limits`
            # Pour une gestion manuelle plus fine, nous déactivons ceci et gérons nous-mêmes.
            follow_redirects=False, 
            limits=httpx.Limits(max_keepalive_connections=None, max_connections=None) # Illimité pour l'instant
        )
        logger.info(f"HttpRequestManager initialized with timeout={self.default_timeout}s, retries={self.max_retries}, delay={self.retry_delay}s, base_url='{self.base_url}'")

    async def _send_request_internal(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                                   params: Optional[Dict[str, Any]] = None, json: Optional[Any] = None,
                                   data: Optional[Union[Dict[str, str], str]] = None, files: Optional[Dict[str, Any]] = None,
                                   auth: Optional[Union[Tuple[str, str], Any]] = None, timeout: Optional[float] = None) -> httpx.Response:
        """
        Méthode interne pour envoyer une requête unique avec gestion des retries.
        """
        request_timeout = timeout if timeout is not None else self.default_timeout
        
        full_url = urljoin(self.base_url, url) # Joindre l'URL de base si nécessaire

        combined_headers = self.headers.copy()
        if headers:

            if headers.get("Authorization"): headers.pop("Authorization")
            combined_headers.update(headers)

        logger.debug(f"Attempting to send {method.upper()} request to {full_url} with timeout={request_timeout}s")

        try:
            response = await self.httpx_client.request(
                method=method.upper(),
                url=full_url,
                headers=combined_headers,
                params=params,
                json=json,
                data=data,
                files=files,
                auth=auth,
                timeout=request_timeout,
            )
            return response
        except httpx.TimeoutException as e:
            logger.warning(f"Timeout during {method.upper()} request to {full_url}: {e}")
            raise e
        except httpx.RequestError as e:
            logger.warning(f"Request error during {method.upper()} request to {full_url}: {e}")
            raise e
        except Exception as e:
            logger.error(f"Unexpected error during request to {full_url}: {e}")
            raise e

    async def send_request(self, request_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Envoie une requête HTTP basée sur un dictionnaire de détails. Gère les retries.

        Args:
            request_details (Dict[str, Any]): Dictionnaire décrivant la requête.
                Ex: {"method": "GET", "url": "/users", "headers": {...}, "params": {...}}

        Returns:
            Dict[str, Any]: Dictionnaire contenant les détails de la requête envoyée et la réponse.
                            Format: {"request": {...}, "response": {"status_code": ..., "headers": ..., "body": ..., "elapsed_time": ...}, "error": ...}
        """
        method = request_details.get("method", "GET").upper()
        url = request_details.get("url")
        if not url:
            return {"error": {"message": "URL is required for sending a request."}}
        
        headers = request_details.get("headers")
        params = request_details.get("params")
        json_payload = request_details.get("json")
        data_payload = request_details.get("data")
        files_payload = request_details.get("files")
        auth_details = request_details.get("auth")
        request_timeout = request_details.get("timeout") # Timeout spécifique pour cette requête

        # Nettoyer les chargements potentiels multiples (priorité json > data > files)
        if json_payload is not None: data_payload = None
        if json_payload is None and data_payload is not None: files_payload = None

        req_sent = {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "json": json_payload,
            "data": data_payload,
            "files": files_payload,
            "auth": auth_details,
            "timeout": request_timeout
        }

        response_data = {} # Pour stocker les informations de la réponse ou de l'erreur
        
        for attempt in range(self.max_retries + 1):
            try:
                # Utiliser le client httpx pour l'appel réel
                start_time = time.time()
                response = await self._send_request_internal(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_payload,
                    data=data_payload,
                    files=files_payload,
                    auth=auth_details,
                    timeout=request_timeout
                )
                end_time = time.time()
                elapsed_time = round(end_time - start_time, 4)

                # Traitement de la réponse
                response_body = None
                try:
                    # Essaye de décoder en JSON, sinon prend le texte brut
                    response_body = response.json()
                except httpx.DecodingError:
                    response_body = response.text
                except Exception: # Catch any other potential decoding issues
                    response_body = response.text

                response_data = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response_body,
                    "elapsed_time": elapsed_time
                }
                
                # Si la réponse est un succès, sortir de la boucle de retry
                if 200 <= response.status_code < 400: # Inclure les redirections comme succès pour l'instant
                    logger.info(f"Request successful: {method} {urljoin(self.base_url, url)} -> {response.status_code} in {elapsed_time}s")
                    to_print_data = response_data.copy()
                    to_print_data["body"] = str(to_print_data["body"])[:100]
                    logger.info({"request": req_sent, "response": to_print_data})
                    return {"request": request_details, "response": response_data}

                
                # Si échec mais pas retryable, sortir et rapporter l'erreur
                elif 400 <= response.status_code < 500:
                    logger.warning(f"Client error: {method} {urljoin(self.base_url, url)} -> {response.status_code}. No retries for 4xx errors.")
                    response_data["error_message"] = f"Client Error: {response.status_code}"
                    to_print_data = response_data.copy()
                    to_print_data["body"] = str(to_print_data["body"])[:100]
                    logger.info({"request": req_sent, "response": to_print_data})
                    return {"request": request_details, "response": response_data}

                # Si erreur serveur (5xx), on continue si on a encore des retries
                elif 500 <= response.status_code < 600:
                    logger.warning(f"Server error: {method} {urljoin(self.base_url, url)} -> {response.status_code}. Attempt {attempt + 1}/{self.max_retries + 1}")
                    response_data["error_message"] = f"Server Error: {response.status_code}"
                    # Continuer la boucle, le delay sera appliqué plus bas
                
            except (httpx.TimeoutException, httpx.RequestError) as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries + 1}): {method} {urljoin(self.base_url, url)} -> {e}")
                response_data["error_message"] = f"Request failed: {e}"
                # Continuer la boucle pour retry
            except Exception as e:
                logger.error(f"Unexpected error during request (attempt {attempt + 1}/{self.max_retries + 1}): {method} {urljoin(self.base_url, url)} -> {e}")
                response_data["error_message"] = f"Unexpected error: {e}"
                # Pour les erreurs inattendues, on peut choisir de retry ou non
                # Ici, on arrête après la première exception inattendue pour être prudent
                return {"request": request_details, "response": response_data}

            # Si on est ici, c'est qu'il faut retry (erreur serveur ou réseau)
            if attempt < self.max_retries:
                delay = self.retry_delay * (2 ** attempt) # Backoff exponentiel simple
                logger.info(f"Retrying in {delay:.2f} seconds...")
                time.sleep(delay)

        # Si toutes les tentatives ont échoué
        logger.error(f"Request failed after {self.max_retries + 1} attempts: {method} {urljoin(self.base_url, url)}")
        return {"request": request_details, "response": response_data} # Retourne les dernières info / erreur

    async def close(self):
        """
        Ferme proprement le client httpx.
        """
        await self.httpx_client.aclose()
        logger.info("HttpRequestManager closed.")

# --- Exemple d'utilisation (peut être mis dans main.py ou un script de test) ---
# async def main_test_request_manager():
#     manager = HttpRequestManager(base_url="https://httpbin.org", max_retries=2, retry_delay=0.5)
#
#     # Test GET
#     get_req_details = {"method": "GET", "url": "/get", "params": {"param1": "value1", "param2": "value2"}}
#     get_result = await manager.send_request(get_req_details)
#     print("--- GET Request Result ---")
#     print(get_result)
#     print("\n")
#
#     # Test POST avec JSON
#     post_json_req_details = {
#         "method": "POST",
#         "url": "/post",
#         "headers": {"X-Custom-Header": "Test"},
#         "json": {"key1": "value1", "nested": {"k": "v"}}
#     }
#     post_json_result = await manager.send_request(post_json_req_details)
#     print("--- POST JSON Request Result ---")
#     print(post_json_result)
#     print("\n")
#
#     # Test POST avec form-data
#     post_data_req_details = {
#         "method": "POST",
#         "url": "/post",
#         "data": {"field1": "value_a", "field2": "value_b"}
#     }
#     post_data_result = await manager.send_request(post_data_req_details)
#     print("--- POST Form-data Request Result ---")
#     print(post_data_result)
#     print("\n")
#
#     # Test avec authentification Basic Auth
#     auth_req_details = {
#         "method": "GET",
#         "url": "/basic-auth/user/password",
#         "auth": ("user", "password")
#     }
#     auth_result = await manager.send_request(auth_req_details)
#     print("--- Basic Auth Request Result ---")
#     print(auth_result)
#     print("\n")
#
#     # Test d'un timeout (ATTENTION: httpbin.org/delay/x prend x secondes)
#     # timeout_req_details = {"method": "GET", "url": "/delay/5", "timeout": 2.0}
#     # timeout_result = await manager.send_request(timeout_req_details)
#     # print("--- Timeout Request Result ---")
#     # print(timeout_result)
#     # print("\n")
#
#     # Test d'une erreur 500 pour vérifier le retry
#     # error_500_req_details = {"method": "GET", "url": "/status/500"}
#     # error_500_result = await manager.send_request(error_500_req_details)
#     # print("--- 500 Error Retry Result ---")
#     # print(error_500_result)
#     # print("\n")
#
#     await manager.close()
#
# if __name__ == "__main__":
#     import asyncio
#     asyncio.run(main_test_request_manager())
