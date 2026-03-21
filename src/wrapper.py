import asyncio
import os
import logging
import sys
import json
from dotenv import load_dotenv
from pentest_agent import PentestAgent, AgentInitializationError
from mcp_agent import MCPPentestAgent
from llm_client import LitellmAPIClient
from ollama_client import OllamaAPIClient
from xai_client import XAIAPIClient
from request_manager import HttpRequestManager
import uuid_utils

# Add storage path for database access
storage_path = os.path.join(os.path.dirname(__file__), '..', 'storage')
sys.path.append(storage_path)
from db import storage_db





def generate_scan_id():
    return uuid_utils.uuid4()


async def main_pentest_run(scan_id : uuid_utils.UUID, llm_type:str = "ollama", model : str = "qwen2.5-coder:latest", target_url: str = "http://example.com/api", schema_id: str = None, oas_name: str = "oas.yaml", litellm_url: str = None, vulnerability_types_to_test: list = None, auth: str = None, use_mcp: bool = False, request_limits: dict = None):
    """
    Fonction principale pour lancer le processus de pentest agent.
    Charge la configuration, initialise les clients et l'agent, exécute le pentest, puis ferme les clients.
    """
    
    # Créer le répertoire log s'il n'existe pas (chemin racine)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    log_dir = os.path.join(project_root, 'log')
    os.makedirs(log_dir, exist_ok=True)

    # Configuration du logging pour cette session
    logger = logging.getLogger()  # Logger root
    logger.setLevel(logging.INFO)

    # Supprimer les handlers existants pour éviter les doublons
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Créer un handler pour le fichier
    log_file = os.path.join(log_dir, f"pentest_run_{scan_id}.log")
    file_handler = logging.FileHandler(log_file, mode='w')
    file_handler.setLevel(logging.INFO)
    
    # Créer un formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    
    # Ajouter le handler au logger root
    logger.addHandler(file_handler)
    
    if llm_type not in ["ollama", "litellm", "xai"]:
        logging.error("Invalid type specified. Expected 'ollama', 'litellm', or 'xai'.")
        raise ValueError("Invalid type specified. Expected 'ollama', 'litellm', or 'xai'.")

    if type == "litellm":
        load_dotenv()

        llm_api_endpoint = os.getenv("LLM_API_ENDPOINT")
        llm_model_name = os.getenv("LLM_MODEL_NAME")
        llm_api_key = os.getenv("LLM_API_KEY")
        if not llm_api_endpoint or not llm_model_name:
            logging.error("Environment variables LLM_API_ENDPOINT and LLM_MODEL_NAME must be set in your .env file.")
            return

    # Les informations de l'API cible à tester
    api_target_base_url = target_url

    # Charger OAS depuis la base de données si schema_id disponible, sinon charger depuis fichier local (histoire de rétrocompatibilité)
    oas_content = None
    if schema_id:
        logging.info(f"Loading OAS schema from database with ID: {schema_id}")
        try:
            schema_data = await storage_db.get_json(schema_id)
            if not schema_data or "schema" not in schema_data:
                logging.error(f"Schema with ID '{schema_id}' not found in database or invalid format")
                return
            oas_content = schema_data["schema"]

            # S'assurer que c'est un dictionnaire (au cas où c'est stocké comme string JSON)
            if isinstance(oas_content, str):
                try:
                    oas_content = json.loads(oas_content)
                except json.JSONDecodeError:
                    logging.error(f"Schema content is a string but not valid JSON for ID '{schema_id}'")
                    return

            if not isinstance(oas_content, dict):
                logging.error(f"Schema content is not a dictionary for ID '{schema_id}'")
                return

            logging.info("OAS schema loaded successfully from database")
        except Exception as e:
            logging.error(f"Failed to load OAS schema from database: {e}")
            return
    else:
        logging.info(f"No schema_id provided, falling back to local OAS file: {oas_name}")
        if not os.path.exists(oas_name):
            logging.error(f"OAS file specified ('{oas_name}') not found.")
            return
        with open(oas_name, 'r', encoding='utf-8') as f:
            raw_content = f.read()
        try:
            oas_content = json.loads(raw_content)
        except json.JSONDecodeError:
            try:
                oas_content = yaml.safe_load(raw_content)
            except Exception as e:
                logging.error(f"Error parsing local OAS file {oas_name}: {e}")
                return

    # Fonction callback pour mettre à jour les résultats en temps réel
    async def update_scan_results(results, metrics=None):
        # Faire un appel HTTP vers l'API web pour mettre à jour les résultats
        try:
            import httpx

            # URL de l'API web (adapter selon la configuration)
            api_base_url = "http://localhost:8080"  # TODO: rendre configurable
            update_url = f"{api_base_url}/update_scan_results/{scan_id}"

            async with httpx.AsyncClient() as client:
                payload = {}
                if results is not None:
                    payload["results"] = results
                if metrics is not None:
                    payload["metrics"] = metrics

                response = await client.post(update_url, json=payload, timeout=5.0)

                if response.status_code != 200:
                    logging.warning(f"Failed to update scan results via API: HTTP {response.status_code}")
                else:
                    logging.debug(f"Successfully updated scan results for {scan_id}")

        except ImportError as e:
            # Ignore les erreurs d'importation circulaire pendant l'initialisation
            if "circular import" in str(e).lower() or "partially initialized" in str(e).lower():
                logging.debug("Ignoring circular import error during initialization")
            else:
                logging.warning(f"Failed to update scan results in real-time: {e}")
        except Exception as e:
            logging.warning(f"Failed to update scan results in real-time: {e}")

    max_concurrent_requests =  5

    # Dynamic request limits configuration (use passed limits or defaults)
    if request_limits is None:
        request_limits = {
            "global_max_requests": 100,  # Maximum total requests for the scan
            "per_vulnerability_max": 25,  # Maximum requests per vulnerability type
            "adaptive_enabled": True,  # Enable adaptive request generation
            "relevance_threshold": 0.7,  # Minimum relevance score for endpoints
            "evolution_factor": 1.2  # How much to increase requests based on findings
        }

    vulnerability_types_to_test = ["IDOR", "Broken Access Control", "SQL injection", "XSS", "Command Injection"] if not vulnerability_types_to_test else vulnerability_types_to_test
    logging.info(f"Vulnerability types not specified, using default: {vulnerability_types_to_test}")


    # --- 2. Initialisation des Clients ---
    try:
        logging.info("Initializing LLM client...")
        if llm_type == "ollama":
            llm_client = OllamaAPIClient(model_name=model)
        elif llm_type == "xai":
            llm_client = XAIAPIClient(model_name=model)
        else:  # litellm
            llm_client = LitellmAPIClient(
                api_url=llm_api_endpoint, 
                model_name=llm_model_name, 
                api_key=llm_api_key
            )
        
        logging.info("Initializing HTTP request manager...")

        req_manager = HttpRequestManager(
            base_url=api_target_base_url,
            max_retries=2,
            retry_delay=0.5,
            default_timeout=30.0,
            auth=auth
        )
        logging.info("Base clients initialized.")

    except Exception as e:
        logging.error(f"Failed to initialize base clients: {e}")
        return

    # --- 4. Initialisation du Pentest Agent ---
    agent_type = "MCP" if use_mcp else "Legacy"
    logging.info(f"Initializing {agent_type} PentestAgent...")
    try:
        if use_mcp:
            agent = MCPPentestAgent(
                scan_id=scan_id,
                llm_client=llm_client,
                oas_content=oas_content,
                api_base_url=api_target_base_url,
                max_concurrent_requests=max_concurrent_requests,
                results_callback=update_scan_results,
                auth=auth,
                request_limits=request_limits
            )
            await agent.initialize()  # MCP agent needs async initialization
        else:
            agent = PentestAgent(
                scan_id=scan_id,
                llm_client=llm_client,
                request_manager=req_manager,
                oas_content=oas_content,  # Passer le contenu OAS au lieu du chemin du fichier
                api_base_url=api_target_base_url,
                max_concurrent_requests=max_concurrent_requests,
                results_callback=update_scan_results  # Callback pour mises à jour temps réel
            )
        logging.info(f"{agent_type} PentestAgent initialized successfully.")

    except AgentInitializationError as e:
        logging.error(f"Agent Initialization Failed: {e}")
        return # Arrêter si l'initialisation échoue

    # --- 5. Lancement du Processus de Pentest ---
    logging.info(f"--- Starting {agent_type} Pentest Agent run for API: {api_target_base_url} ---")
    try:
        # Lancer l'agent pour exécuter la génération des tests et leur exécution
        if use_mcp:
            run_result = await agent.run_pentest_workflow(vulnerability_types=vulnerability_types_to_test)
        else:
            run_result = await agent.run(vulnerability_types_to_test=vulnerability_types_to_test)
        print(f"\n--- {agent_type} Pentest Run Summary ---")
        print(f"Status: {run_result.get('status')}")
        print(f"Vulnerabilities found: {run_result.get('vulnerabilities_found', 'N/A')}")
        print("---------------------------\n")

    except asyncio.CancelledError:
        logging.info("Pentest run was cancelled.")
        run_result = {"status": "cancelled", "vulnerabilities_found": len(agent.vulnerabilities_found)}
        raise  # Re-raise to propagate cancellation

    except Exception as e:
        logging.error(f"An error occurred during the Pentest Agent run: {e}")
        # Attraper les erreurs potentielles pendant l'exécution du run
        run_result = {"status": "error_during_run", "error": str(e)}

    # --- 6. Fermeture des Clients ---
    finally:
        # Assurez-vous de toujours fermer les clients, même en cas d'erreur
        logging.info("Shutting down agent and clients...")
        await agent.close()
        logging.info("Agent and clients shut down.")

    return run_result # Retourner le résultat final de l'exécution



