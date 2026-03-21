import asyncio
import os
import logging
from dotenv import load_dotenv
import json
from wrapper import main_pentest_run, generate_scan_id

AUTH = "fE6ls27vaXPABGBXnFZiGEW6IEs7FZmm4vJxU4fGS6Z3bSk4VA1dli"




async def main():
    """
    Fonction principale pour lancer le processus de pentest agent.
    Charge la configuration, initialise les clients et l'agent, exécute le pentest, puis ferme les clients.
    """

    """load_dotenv()

    llm_api_endpoint = os.getenv("LLM_API_ENDPOINT")
    llm_model_name = os.getenv("LLM_MODEL_NAME")
    llm_api_key = os.getenv("LLM_API_KEY")
    if not llm_api_endpoint or not llm_model_name:
        logging.error("Environment variables LLM_API_ENDPOINT and LLM_MODEL_NAME must be set in your .env file.")
        return"""

    # Les informations de l'API cible à tester
    api_target_base_url = "http://127.0.0.1:9000"
    oas_file_path =  "../mock/mock_oas.json"

    max_concurrent_requests =  5
    

    vulnerability_types_to_test = ["IDOR", "Broken Access Control", "SQL injection", "XSS", "Command Injection"]
    scan_id = generate_scan_id()
    result = await main_pentest_run(scan_id=scan_id, llm_type="ollama", model="qwen2.5-coder:latest", target_url=api_target_base_url, schema_id=None, oas_name=oas_file_path, vulnerability_types_to_test=vulnerability_types_to_test)
    return result 

if __name__ == "__main__":
    logging.info("Starting the main pentest execution script...")
    final_result = asyncio.run(main())
    logging.info("Main pentest execution script finished.")

