import httpx
import logging
import os
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional

# Configuration basique du logging
logger = logging.getLogger(__name__)
load_dotenv() 

class XAIAPIClient:
    """
    Un client Python pour interagir avec l'API xAI.
    """

    def __init__(self, model_name: str, api_key: Optional[str] = None):
        """
        Initialise le client XAIAPIClient.

        Args:
            model_name (str): Le nom du modèle LLM à utiliser (ex: "grok-2").
            api_key (Optional[str]): Clé d'API xAI. Si None, récupérée depuis XAI_API_KEY.
        """
        self.model_name = model_name
        self.api_key = api_key or os.getenv("API_KEY")  # Utilise la clé du .env

        if not self.api_key:
            raise ValueError("XAI API key is required. Set API_KEY in .env file.")

        self.api_url = "https://api.x.ai/v1"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        # Utilisation d'un client asynchrone
        self.httpx_client = httpx.AsyncClient(
            timeout=30.0,
            headers=self.headers,
            verify=True,
        )
        logging.info(f"XAIAPIClient initialized for model '{self.model_name}'")

    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.7, max_tokens: int = 1000, stream: bool = False) -> Dict[str, Any]:
        """
        Réalise une complétion de chat via l'API xAI.

        Args:
            messages (List[Dict[str, str]]): Liste des messages de la conversation.
            temperature (float): Contrôle la créativité de la réponse.
            max_tokens (int): Nombre maximum de tokens à générer.
            stream (bool): Si True, active le streaming (non implémenté).

        Returns:
            Dict[str, Any]: Le résultat de la complétion de chat ou un dictionnaire d'erreur.
        """
        completions_url = f"{self.api_url}/chat/completions"

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream,
        }

        logging.info(f"Sending chat completion request to xAI with model {self.model_name}")

        try:
            response = await self.httpx_client.post(completions_url, json=payload)
            response.raise_for_status()

            if stream:
                logging.warning("Streaming is enabled but not fully implemented.")
                try:
                    return response.json()
                except Exception:
                    return {"error": {"message": "Failed to decode streaming response"}}
            else:
                return response.json()

        except httpx.HTTPStatusError as e:
            logging.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
            return {"error": {
                "message": f"HTTP error during chat completion: {e}",
                "status_code": e.response.status_code,
                "response_body": e.response.text
            }}
        except httpx.RequestError as e:
            logging.error(f"Network error occurred: {e}")
            return {"error": {
                "message": f"Network or request error during chat completion: {e}",
                "request_url": str(e.request.url)
            }}
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return {"error": {"message": f"An unexpected error occurred: {e}"}}

    async def list_models(self) -> List[str]:
        """
        Liste les modèles disponibles via l'API xAI.

        Returns:
            List[str]: Liste des noms de modèles disponibles.
        """
        models_url = f"{self.api_url}/models"

        try:
            response = await self.httpx_client.get(models_url)
            response.raise_for_status()
            data = response.json()

            # Extraire les noms de modèles de la réponse
            models = []
            if "data" in data:
                models = [model["id"] for model in data["data"] if "id" in model]

            return models

        except Exception as e:
            logging.error(f"Failed to list models: {e}")
            return []

    async def close(self):
        """Ferme proprement le client httpx."""
        await self.httpx_client.aclose()
    
    