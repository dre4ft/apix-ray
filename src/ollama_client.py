from ollama import AsyncClient
import logging
from typing import List, Dict, Any, Optional

class OllamaAPIClient:
    """Un client Python pour interagir avec une API Ollama locale.

    Cette classe reprend le même fonctionnement que `LitellmAPIClient` (dans `llm_client.py`) afin
d'offrir une interface similaire pour appeler un serveur Ollama local.
    """

    def __init__(self, model_name: str):
        """Initialise le client OllamaAPIClient.

        Args:
            api_url (str): L'URL de base de votre endpoint Ollama (ex: "http://localhost:11434").
            model_name (str): Le nom du modèle LLM à utiliser (ex: "llama2").
            api_key (Optional[str]): Clé d'API si votre endpoint Ollama en requiert une.
        """
        # Assure que l'URL de base ne se termine pas par un slash pour une concaténation propre
        self.model_name = model_name
        self.ollama_client = AsyncClient()
        logging.info(f"OllamaAPIClient initialized for model '{self.model_name}'")

    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.7, max_tokens: int = 1000, stream: bool = False) -> Dict[str, Any]:
        """Réalise une complétion de chat via l'API Ollama.

        Args:
            messages (List[Dict[str, str]]): Liste des messages de la conversation.
                                             Ex: [{"role": "system", "content": "..."}]
            temperature (float): Contrôle la créativité de la réponse.
            max_tokens (int): Nombre maximum de tokens à générer.
            stream (bool): Si True, active le streaming de la réponse (non implémenté en détail ici).

        Returns:
            Dict[str, Any]: Le résultat de la complétion de chat ou un dictionnaire d'erreur.
        """
        logging.info(f"Sending chat completion request to ollama with model {self.model_name}")

        try:
            response = await self.ollama_client.chat(model=self.model_name, messages=messages)

        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return {"error": {"message": f"An unexpected error occurred: {e}"}}
        
        return response['message']['content'] #if "content" in response else response

    async def close(self):
        """Ferme proprement le client httpx."""
        #await self.ollama_client.aclose()
        logging.info("OllamaAPIClient closed.")

