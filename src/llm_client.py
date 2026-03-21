import httpx
import logging
from typing import List, Dict, Any, Optional

# Configuration basique du logging
logger = logging.getLogger(__name__)

class LitellmAPIClient:
    """
    Un client Python pour interagir avec une API LLM compatible OpenAI
    hébergée via Litellm.
    """
    def __init__(self, api_url: str, model_name: str, api_key: Optional[str] = None):
        """
        Initialise le client LitellmAPIClient.

        Args:
            api_url (str): L'URL de base de votre endpoint Litellm (ex: "http://localhost:8000").
            model_name (str): Le nom du modèle LLM à utiliser (ex: "gpt-3.5-turbo").
            api_key (Optional[str]): Clé d'API si votre endpoint Litellm en requiert une.
        """
        # Assure que l'URL de base ne se termine pas par un slash pour une concaténation propre
        self.api_url = api_url.rstrip('/')
        self.model_name = model_name
        self.api_key = api_key

        self.headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            # Assumption: API Key is expected in Authorization header as Bearer token
            # Adjust if your Litellm setup expects a different header (e.g., X-Api-Key)
            self.headers["x-litellm-api-key"] = self.api_key

        # Utilisation d'un client asynchrone pour de meilleures performances
        # Il est géré de manière à être fermé proprement.
        self.httpx_client = httpx.AsyncClient(
            timeout=30.0,  # Timeout par défaut, configurable plus tard
            headers=self.headers,
            verify=False,
        )
        logging.info(f"LitellmAPIClient initialized for model '{self.model_name}' at {self.api_url}")

    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.7, max_tokens: int = 1000, stream: bool = False) -> Dict[str, Any]:
        """
        Réalise une complétion de chat via l'API Litellm.

        Args:
            messages (List[Dict[str, str]]): Liste des messages de la conversation.
                                             Ex: [{"role": "system", "content": "..."}]
            temperature (float): Contrôle la créativité de la réponse.
            max_tokens (int): Nombre maximum de tokens à générer.
            stream (bool): Si True, active le streaming de la réponse (non implémenté en détail ici).

        Returns:
            Dict[str, Any]: Le résultat de la complétion de chat ou un dictionnaire d'erreur.
        """
        completions_url = f"{self.api_url}/v1/chat/completions"
        
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream, # Pour le moment, on ne traite pas le stream en tant que tel
        }

        logging.info(f"Sending chat completion request to {completions_url} with model {self.model_name}")

        try:
            response = await self.httpx_client.post(completions_url, json=payload, headers=self.headers)
            response.raise_for_status()  # Lève une exception pour les codes d'erreur HTTP (4xx, 5xx)
            
            if stream:
                # Gérer le cas du streaming si nécessaire. Pour l'instant, on retourne le dernier chunk ou une indication.
                # Une implémentation complète du streaming nécessiterait de lire response.aiter_bytes() ou response.aiter_lines()
                logging.warning("Streaming is enabled but not fully implemented in this basic client. Returning raw response text might be needed.")
                # Pour simplifier, on traite la réponse comme non-streamée ici.
                # Dans une application réelle, il faudrait parcourir le générateur.
                try:
                    return response.json() # Tente de parser si ce n'est pas un stream
                except httpx.DecodingError:
                    logging.error("Could not decode stream response as JSON.")
                    return {"error": {"message": "Failed to decode streaming response as JSON.", "status_code": response.status_code, "response_body": await response.text()}}

            else:
                return response.json()

        except httpx.HTTPStatusError as e:
            logging.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text} for URL {e.request.url}")
            return {"error": {
                "message": f"HTTP error during chat completion: {e}",
                "status_code": e.response.status_code,
                "response_body": e.response.text
            }}
        except httpx.RequestError as e:
            logging.error(f"An error occurred while requesting {e.request.url!r}: {e}")
            return {"error": {
                "message": f"Network or request error during chat completion: {e}",
                "request_url": str(e.request.url)
            }}
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return {"error": {"message": f"An unexpected error occurred: {e}"}}

    async def close(self):
        """
        Ferme proprement le client httpx.
        """
        await self.httpx_client.aclose()
        logging.info("LitellmAPIClient closed.")

# --- Exemple d'utilisation (peut être mis dans main.py ou un script de test) ---
# async def main_test():
#     # Assurez-vous que ces valeurs sont définies dans votre .env et chargées
#     import os
#     from dotenv import load_dotenv
#
#     load_dotenv()
#
#     llm_url = os.getenv("LLM_API_ENDPOINT")
#     llm_model = os.getenv("LLM_MODEL_NAME")
#     llm_key = os.getenv("LLM_API_KEY") # Peut être None
#
#     if not llm_url or not llm_model:
#         print("Erreur: LLM_API_ENDPOINT et LLM_MODEL_NAME doivent être définis dans le fichier .env")
#         return
#
#     client = LitellmAPIClient(api_url=llm_url, model_name=llm_model, api_key=llm_key)
#
#     messages = [
#         {"role": "system", "content": "You are a helpful assistant."},
#         {"role": "user", "content": "Quelle est la capitale de la France ?"}
#     ]
#
#     completion_result = await client.chat_completion(messages=messages)
#
#     if "error" in completion_result:
#         print(f"Erreur lors de l'appel LLM : {completion_result['error']['message']}")
#     else:
#         print("Réponse LLM :")
#         # Pour une réponse non-streaming, le contenu est généralement dans choices[0]['message']['content']
#         if "choices" in completion_result and completion_result["choices"]:
#             print(completion_result["choices"][0]["message"]["content"])
#         else:
#             print(completion_result) # Afficher la structure complète si pas de choix attendu
#
#     await client.close()
#
# if __name__ == "__main__":
#     import asyncio
#     asyncio.run(main_test())
