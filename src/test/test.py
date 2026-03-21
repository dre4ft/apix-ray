# Fichier : test_analysis_batch.py

import asyncio
import json
import random
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()

llm_api_endpoint = os.getenv("LLM_API_ENDPOINT")
llm_model_name = os.getenv("LLM_MODEL_NAME")
llm_api_key = os.getenv("LLM_API_KEY")

# --- Imports des modules nécessaires ---

from llm_client import LitellmAPIClient
# Importer ReportGenerator depuis votre structure de projet
from report_generator import ReportGenerator, ReportGenerationError 
from pentest_agent import ResponseAnalyzer
class AgentInitializationError(Exception): pass
class TestGenerationError(Exception): pass
class OASLoadError(Exception): pass
class EndpointExtractionError(Exception): pass
class EndpointInspectionError(Exception): pass
class ResponseAnalysisError(Exception): pass # Déjà défini dans le mock LLM

class MockHttpRequestManager:
    def __init__(self, *args, **kwargs): print("INFO: MockHttpRequestManager initialized.")
    async def send_request(self, request_detail: Dict[str, Any]) -> Dict[str, Any]:
        # print(f"  Simulating send_request for: {request_detail.get('method')} {request_detail.get('url')}")
        await asyncio.sleep(0.001) 
        return {
            "request": request_detail,
            "response": {
                "status_code": random.choice([200, 200, 200, 404, 403, 500]), 
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"message": f"Simulated data for {request_detail.get('url')}"}),
                "elapsed_time": random.uniform(0.005, 0.05)
            }
        }

# --- CLASSE PENTEST AGENT MODIFIÉE POUR LE TEST ---
class PentestAgent:
    def __init__(self, litellm_client, request_manager, oas_file_path: str, api_base_url: str, max_concurrent_requests: int = 10):
        self.litellm_client = litellm_client # Client LLM mocké
        self.request_manager = request_manager 
        self.oas_file_path = oas_file_path
        self.api_base_url = api_base_url

        self.discovered_endpoints_details = {} 
        self.test_requests_queue: List[Dict[str, Any]] = [] 
        
        self.executed_test_results: List[Dict[str, Any]] = [] 
        
        self.vulnerabilities_found: List[Dict[str, Any]] = [] 
        self.audit_log: List[str] = [] # Audit log pour le rapport

        self.response_analyzer = ResponseAnalyzer(self.litellm_client)
        # --- Initialiser le ReportGenerator avec le client LLM ---
        self.report_generator = ReportGenerator(self.litellm_client) 


    async def analyze_test_results(self, vulnerability_types_to_analyze: Optional[List[str]] = None):
        """
        Analyse les résultats des tests exécutés pour détecter les vulnérabilités (version batch).
        Injecte des données fictives pour les tests.
        """
        logging.info("Starting analysis of executed test results (using mocked data)...")

        if not self.executed_test_results:
            logging.warning("No executed test results provided (self.executed_test_results is empty).")
            return

        if vulnerability_types_to_analyze is None:
            vulnerability_types_to_analyze = ["SQL Injection", "XSS", "IDOR", "Broken Access Control", "Command Injection"]
            logging.info(f"Vulnerability types for analysis not specified, using default: {vulnerability_types_to_analyze}")
        
        found_vulnerabilities_count = 0

        # Filtrer les résultats valides une seule fois
        valid_results = [
            {"request": result.get('request'), "response": result.get('response'), "error": result.get('error'), "original_index": i}
            for i, result in enumerate(self.executed_test_results)
            if result.get('request') and result.get('response') is not None
        ]
        
        if not valid_results:
             logging.warning("No valid results found for batch analysis after filtering.")
             return

        # Créer une tâche d'analyse pour chaque type de vulnérabilité
        analysis_tasks = []
        for vul_type in vulnerability_types_to_analyze:
            logging.info(f"Preparing batch analysis for type: {vul_type}")
            
            batch_to_analyze = valid_results 
            
            task = self.response_analyzer.analyze_batch_results(
                batch_items=batch_to_analyze,
                vulnerability_type=vul_type
            )
            analysis_tasks.append(task)

        # Exécuter toutes les tâches d'analyse batch (une par type de vulnérabilité) en parallèle
        if analysis_tasks:
            logging.info(f"Executing {len(analysis_tasks)} batch analysis tasks concurrently...")
            batch_analyses_results = await asyncio.gather(*analysis_tasks)
            
            # Collecter les vulnérabilités détectées à partir des résultats des batches
            for type_analyses in batch_analyses_results: # type_analyses est une liste pour un type donné
                for analysis in type_analyses: # chaque 'analysis' est un dict de vulnérabilité détectée
                    self.vulnerabilities_found.append(analysis)
                    found_vulnerabilities_count += 1

        logging.info(f"Finished batch analysis. Found {found_vulnerabilities_count} potential vulnerabilities across all analyzed types.")
        # Audit log n'est pas simulé ici, donc pas d'ajout.

    async def run(self, vulnerability_types_to_test: Optional[List[str]] = None):
        """ Méthode simplifiée pour simuler le flux de run jusqu'à l'analyse et le rapport. """
        print("\n--- Running PentestAgent.run() (Simulated) ---")
        if vulnerability_types_to_test is None:
            vulnerability_types_to_test = ["SQL Injection", "XSS", "IDOR"] # Types par défaut pour le test
        
        # Phase 3: Analyse des résultats (c'est ce qu'on teste)
        await self.analyze_test_results(vulnerability_types_to_analyze=vulnerability_types_to_test)

        print(f"\n--- Analysis Complete ---")
        print(f"Vulnerabilities found: {len(self.vulnerabilities_found)}")
        print("------------------------\n")
        
        # --- PHASE 4 : Rapport et Finalisation ---
        print("--- Generating Report ---")
        api_details = {
            "api_base_url": self.api_base_url,
            "oas_file_path": self.oas_file_path
        }
        
        final_report = ""
        try:
            final_report = await self.report_generator.generate_report(
                discovered_vulnerabilities=self.vulnerabilities_found,
                api_details=api_details,
                audit_log=self.audit_log # Passer l'audit log pour info
            )
            
            # --- AJOUT : Enregistrement du rapport dans un fichier ---
            report_filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            try:
                with open(report_filename, "w", encoding="utf-8") as f:
                    f.write(final_report)
                logging.info(f"Report successfully saved to: {report_filename}")
                self.audit_log.append(f"Report saved to {report_filename}")
            except IOError as e:
                logging.error(f"Failed to save report to file {report_filename}: {e}")
                self.audit_log.append(f"Error saving report to file: {e}")
            # --- Fin de l'ajout ---

            print("\n--- Report Generated ---")
            print(final_report[:500] + "...\n" if len(final_report) > 500 else final_report) 
            print("------------------------\n")
            logging.info("Report generation complete.")
            self.audit_log.append("Report generation successfully completed.")
        except ReportGenerationError as e:
            logging.error(f"Failed to generate report: {e}")
            self.audit_log.append(f"Error generating report: {e}")
            final_status = "error_during_report_generation"


        return {"status": "analysis_and_report_complete", 
                "vulnerabilities_found": len(self.vulnerabilities_found),
                "report_preview": final_report[:500] + "..." if final_report else "No report generated."}

# --- Fonction principale pour exécuter le test ---
async def test_analysis_and_report():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # 1. Créer les données fictives pour executed_test_results
    mock_executed_results = []
    for i in range(15): 
        request_data = {
            "method": random.choice(["GET", "POST"]),
            "url": f"http://test.com/api/resource/{i}",
            "params": {"id": f"{i}' OR '1'='1" if i % 3 == 0 and i > 0 else f"{i}"},
            "headers": {"Authorization": "Bearer token"}
        }
        # Simuler des résultats : 80% succès, 20% erreur d'exécution
        if random.random() < 0.2: # Simuler erreur d'exécution
            result_data = {"request": request_data, "error": {"message": "Simulated network error"}}
        else: # Simuler succès
            result_data = {
                "request": request_data,
                "response": {
                    "status_code": random.choice([200, 200, 200, 404, 403, 500]),
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"data": f"Simulated data for result {i}"}),
                    "elapsed_time": random.uniform(0.05, 0.5)
                }
            }
            # Introduire un faux résultat qui semble vulnérable pour le mocked LLM
            if i % 4 == 0: # Tous les 4ème résultats simulés
                result_data["response"]["body"] = json.dumps({"message": "Access granted without proper check!"}) # Simule une réponse d'IDOR potentielle

        mock_executed_results.append(result_data)
    
    print(f"Generated {len(mock_executed_results)} mock executed test results.")

    # 2. Créer des instances mockées (LLM, RequestManager)
    # Le MockLitellmAPIClient est configuré avec des réponses prédéfinies pour les analyses batch et la reformulation.
    litellm_client = LitellmAPIClient(
            api_url=llm_api_endpoint, 
            model_name=llm_model_name, 
            api_key=llm_api_key
        )
    mock_request_manager = MockHttpRequestManager()

    # 3. Initialiser PentestAgent et injecter les résultats fictifs
    agent = PentestAgent(
        litellm_client=litellm_client,
        request_manager=mock_request_manager,
        oas_file_path="dummy/path/to/oas.yaml",
        api_base_url="http://mockapi.com/api/v1"
    )
    
    agent.executed_test_results = mock_executed_results
    print(f"Injected {len(agent.executed_test_results)} mock results into agent.")

    # 4. Appeler la méthode run (qui appelle analyze_test_results et puis generate_report)
    print("\n--- Testing PentestAgent.run() (simulating analysis and report) ---")
    
    # Spécifier les types de vulnérabilités pour l'analyse et le rapport
    vulnerability_types_to_test = ["IDOR", "SQL Injection", "XSS"] 
    
    run_result = await agent.run(vulnerability_types_to_test=vulnerability_types_to_test)

    print("\n--- Pentest Run Summary ---")
    print(f"Status: {run_result.get('status')}")
    print(f"Vulnerabilities found: {run_result.get('vulnerabilities_found')}")
    print("--------------------------\n")
    
    print("Analysis and Report simulation finished.")

if __name__ == "__main__":
    # Configuration du logging pour voir les logs du ResponseAnalyzer et ReportGenerator
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    print("Starting batch analysis and report test script...")
    asyncio.run(test_analysis_and_report())
    print("Batch analysis and report test script finished.")
