# Fichier : src/report_generator.py

import json
import logging
from typing import List, Dict, Any, Optional
import asyncio # Nécessaire pour les appels async

# Assurez-vous que l'import LitellmAPIClient fonctionne

from llm_client import LitellmAPIClient
from xai_client import XAIAPIClient


logger =  logging.getLogger(__name__)

class ReportGenerationError(Exception):
    """Exception levée lors de la génération du rapport."""
    pass

class ReportGenerator:
    """
    Génère un rapport professionnel basé sur les vulnérabilités découvertes et les détails de l'API.
    """
    def __init__(self, llm_client: Optional[LitellmAPIClient | XAIAPIClient]):
        self.llm_client = llm_client
        # Si LitellmClient n'est pas fourni, la reformulation LLM sera désactivée.

    def _format_severity(self, severity: Optional[str]) -> str:
        """Formate la sévérité pour l'affichage."""
        if not severity: return "Unknown"
        return severity.capitalize()

    def _format_request_details(self, request: Dict[str, Any]) -> str:
        """Formate les détails de la requête pour le rapport."""
        method = request.get('method', 'N/A')
        url = request.get('url', 'N/A')
        headers = request.get('headers', 'N/A')
        params = request.get('params', 'N/A')
        json_body = request.get('json', 'N/A')
        data_body = request.get('data', 'N/A')
        auth = request.get('auth', 'N/A')

        details = f"  Method: {method}\n  URL: {url}\n"
        if headers and headers != 'N/A': details += f"  Headers: {json.dumps(headers, indent=4)}\n"
        if params and params != 'N/A': details += f"  Params: {json.dumps(params, indent=4)}\n"
        if json_body and json_body != 'N/A': details += f"  JSON Body: {json.dumps(json_body, indent=4)}\n"
        if data_body and data_body != 'N/A': details += f"  Data Body: {data_body}\n"
        if auth and auth != 'N/A': details += f"  Auth: {auth}\n"
        return details

    def _format_response_summary(self, response_summary: Dict[str, Any]) -> str:
        """Formate le résumé de la réponse pour le rapport."""
        status_code = response_summary.get('status_code', 'N/A')
        elapsed_time = response_summary.get('elapsed_time', 'N/A')
        body_preview = response_summary.get('body_preview', 'N/A')
        
        summary = f"  Status Code: {status_code}\n"
        if elapsed_time != 'N/A' and isinstance(elapsed_time, (int, float)):
            summary += f"  Response Time: {elapsed_time:.4f}s\n"
        else:
            summary += f"  Response Time: {elapsed_time}\n"
        summary += f"  Body Preview: {body_preview}\n"
        return summary

    def _build_prompt_for_vulnerability_reformulation(self, vulnerability_data: Dict[str, Any]) -> str:
        """Construit le prompt pour demander au LLM de reformuler la description/recommandation."""
        raw_description = vulnerability_data.get('llm_analysis', {}).get('reasoning', 'No detailed reasoning provided.')
        raw_recommendation = vulnerability_data.get('llm_analysis', {}).get('recommendation', 'No specific recommendation provided.')
        vuln_type = vulnerability_data.get('type', 'Unknown Vulnerability')
        
        prompt_parts = [
            f"You are an expert technical writer specializing in cybersecurity reports.",
            f"Your task is to take raw vulnerability details and reformulate them into a clear, professional, and actionable description and recommendation suitable for a penetration test report.",
            f"\n--- Vulnerability Context ---",
            f"Vulnerability Type: {vuln_type}",
            
            f"\n--- Raw Details ---",
            f"Raw Reasoning/Description: {raw_description}",
            f"Raw Recommendation: {raw_recommendation}",
            
            f"\n--- Your Task ---",
            f"1. Reformulate the 'Raw Reasoning/Description' into a concise and professional description of the vulnerability. Explain the potential impact it could have.",
            f"2. Reformulate the 'Raw Recommendation' into clear, actionable steps for remediation. Prioritize security best practices.",
            
            f"\nIMPORTANT: ",
            f"- Output ONLY a valid JSON object with two keys: 'professional_description' and 'professional_recommendation'.",
            f"- Do not include any introductory text, explanations, or markdown formatting around the JSON object.",
            f"- Ensure all string values are properly JSON escaped."
        ]
        return "\n".join(prompt_parts)

    async def reformulate_vulnerability_details(self, vulnerability_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Utilise le LLM pour reformuler la description et la recommandation de la vulnérabilité.
        Retourne un dictionnaire avec les nouvelles clés ou les valeurs originales en cas d'échec.
        """
        if not self.llm_client:
            logger.warning("Litellm client not available, skipping LLM reformulation for vulnerability details.")
            return {
                "professional_description": vulnerability_data.get('llm_analysis', {}).get('reasoning', 'N/A'),
                "professional_recommendation": vulnerability_data.get('llm_analysis', {}).get('recommendation', 'N/A')
            }

        prompt = self._build_prompt_for_vulnerability_reformulation(vulnerability_data)
        
        try:
            completion = await self.llm_client.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=500 
            )

            if "error" in completion:
                logger.error(f"LLM Error during reformulation: {completion['error']['message']}")
                return {
                    "professional_description": vulnerability_data.get('llm_analysis', {}).get('reasoning', 'N/A'),
                    "professional_recommendation": vulnerability_data.get('llm_analysis', {}).get('recommendation', 'N/A')
                }

            response_text = completion.get("choices", [{}])[0].get("message", {}).get("content", "")

            if not response_text:
                logger.warning("LLM returned empty response for reformulation.")
                return {
                    "professional_description": vulnerability_data.get('llm_analysis', {}).get('reasoning', 'N/A'),
                    "professional_recommendation": vulnerability_data.get('llm_analysis', {}).get('recommendation', 'N/A')
                }

            try:
                reformulated_data = json.loads(response_text)
                if not isinstance(reformulated_data, dict):
                    raise ValueError("LLM response was not a JSON object.")
                
                return {
                    "professional_description": reformulated_data.get('professional_description', 'N/A'),
                    "professional_recommendation": reformulated_data.get('professional_recommendation', 'N/A')
                }

            except (json.JSONDecodeError, ValueError) as e:
                logger.error(f"Failed to decode LLM reformulation JSON response: {e}. Response: {response_text[:500]}...")
                return {
                    "professional_description": vulnerability_data.get('llm_analysis', {}).get('reasoning', 'N/A'),
                    "professional_recommendation": vulnerability_data.get('llm_analysis', {}).get('recommendation', 'N/A')
                }

        except Exception as e:
            logger.error(f"Error communicating with LLM for reformulation: {e}")
            return {
                "professional_description": vulnerability_data.get('llm_analysis', {}).get('reasoning', 'N/A'),
                "professional_recommendation": vulnerability_data.get('llm_analysis', {}).get('recommendation', 'N/A')
            }


    # --- MODIFICATION: La méthode generate_report doit être 'async' ---
    async def generate_report(
        self, 
        discovered_vulnerabilities: List[Dict[str, Any]], 
        api_details: Dict[str, Any], 
        audit_log: List[str]
    ) -> str:
        """
        Génère le rapport de pentest au format Markdown.
        Utilise le LLM pour les sections nécessitant une reformulation via 'await'.
        """
        logger.info("Generating pentest report...")

        # --- Section 1 : Résumé Exécutif ---
        executive_summary = "## Executive Summary\n\n"
        critical_high_vulns = [v for v in discovered_vulnerabilities if v.get('llm_analysis', {}).get('severity', '').lower() in ['critical', 'high']]
        
        if not discovered_vulnerabilities:
            executive_summary += "No significant vulnerabilities were detected during the penetration test.\n"
        elif critical_high_vulns:
            vuln_list_str = "\n".join([f"- {v.get('type')} (Severity: {v.get('llm_analysis', {}).get('severity', 'Unknown')})" for v in critical_high_vulns])
            
            summary_prompt = f"You are a cybersecurity analyst. Summarize the following critical or high severity vulnerabilities found during a pentest into a concise executive summary for a professional report.\n\nContext:\nAPI Base URL: {api_details.get('api_base_url', 'N/A')}\nOAS File: {api_details.get('oas_file_path', 'N/A')}\n\nCritical/High Vulnerabilities found:\n{vuln_list_str}\n\nTask: Write a brief executive summary (~3-5 sentences) highlighting the main risks identified."
            
            if self.llm_client:
                try:
                    logger.info("Generating executive summary with LLM...")
                    # -- L'appel ici DOIT être awaité --
                    completion = await self.llm_client.chat_completion(
                        messages=[{"role": "user", "content": summary_prompt}],
                        temperature=0.3,
                        max_tokens=300
                    )
                    if "error" in completion:
                        logger.error(f"LLM error during executive summary generation: {completion['error']['message']}")
                        executive_summary += "An error occurred while generating the executive summary.\n"
                    else:
                        response_text = completion.get("choices", [{}])[0].get("message", {}).get("content", "")
                        if response_text:
                            executive_summary += response_text + "\n"
                        else:
                            executive_summary += "No specific critical findings to report briefly.\n"
                except Exception as e:
                    logger.error(f"Error communicating with LLM for executive summary generation: {e}")
                    executive_summary += "An error occurred while generating the executive summary.\n"
            else:
                executive_summary += "Critical vulnerabilities were found but could not be summarized by LLM (client unavailable). Please refer to detailed findings.\n"
        else:
            executive_summary += "No critical or high severity vulnerabilities were detected. Low and informational findings may exist. Please check detailed findings.\n"
        
        report_content = executive_summary + "\n"

        # --- Section 2 : Méthodologie ---
        report_content += "## Methodology\n\n"
        report_content += "The penetration test was conducted following a structured methodology to identify potential security weaknesses in the target API.\n\n"
        report_content += f"- **Endpoint Discovery & Testing:** All discovered endpoints were used to generate specific test cases for identified vulnerabilities.\n"
        
        tested_vulns_set = set()
        for vuln in discovered_vulnerabilities:
            tested_vulns_set.add(vuln.get('type', 'Unknown'))
        if tested_vulns_set:
            report_content += f"  - Relevant vulnerability types tested: {', '.join(sorted(list(tested_vulns_set)))}\n"
        else:
            report_content += "  - A range of common API vulnerabilities were tested.\n"
            
        report_content += f"- **Automated Test Generation:** An AI-powered agent was used to generate context-aware test requests.\n"
        report_content += f"- **Request Execution:** Generated requests were executed against the target API (`{api_details.get('api_base_url', 'N/A')}`).\n"
        report_content += f"- **Batch Vulnerability Analysis:** The results of executed tests were analyzed in batches using LLMs to confirm potential vulnerabilities, assess confidence and severity.\n"
        report_content += f"- **Reporting:** Findings are compiled into this report, including technical details and remediation recommendations.\n\n"

        # --- Section 3 : Constatations Détaillées ---
        report_content += "## Detailed Findings\n\n"
        if not discovered_vulnerabilities:
            report_content += "No vulnerabilities were detected during the scope of this assessment.\n"
        else:
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
            sorted_vulnerabilities = sorted(
                discovered_vulnerabilities,
                key=lambda v: severity_order.get(v.get('llm_analysis', {}).get('severity', 'unknown').lower(), 5)
            )
            
            for i, vuln in enumerate(sorted_vulnerabilities):
                vuln_type = vuln.get('type', 'Unknown Vulnerability')
                llm_analysis = vuln.get('llm_analysis', {})
                confidence = llm_analysis.get('confidence', 'N/A')
                severity = llm_analysis.get('severity', 'Unknown')
                
                # --- L'appel à reformulate_vulnerability_details DOIT être awaité ---
                professional_details = await self.reformulate_vulnerability_details(vuln)
                description = professional_details.get('professional_description', llm_analysis.get('reasoning', 'No detailed reasoning provided.'))
                recommendation = professional_details.get('professional_recommendation', llm_analysis.get('recommendation', 'No specific recommendation provided.'))

                report_content += f"### Finding {i+1}: {vuln_type} ({self._format_severity(severity)})\n\n"
                
                report_content += f"**Severity:** {self._format_severity(severity)}\n"
                report_content += f"**Confidence:** {confidence}\n"
                report_content += f"**Potential Impact:** {llm_analysis.get('impact', 'Not specified by LLM.')}\n\n" 

                report_content += f"**Description:**\n{description}\n\n"
                
                report_content += f"**Evidence:**\n"
                report_content += f"- **Request Details:**\n{self._format_request_details(vuln.get('request', {}))}\n"
                report_content += f"- **Response Summary:**\n{self._format_response_summary(vuln.get('response_summary', {}))}\n"
                if llm_analysis.get('evidence'):
                    report_content += f"- **LLM Provided Evidence:**\n  {llm_analysis.get('evidence')}\n"

                report_content += f"\n**Recommendation:**\n{recommendation}\n\n"
                
                report_content += "---\n\n" # Séparateur entre les constatations

        # --- Section 4 : API Details (Optionnel) ---
        report_content += "## Target API Details\n\n"
        report_content += f"- **Base URL:** `{api_details.get('api_base_url', 'N/A')}`\n"
        report_content += f"- **OAS File Used:** `{api_details.get('oas_file_path', 'N/A')}`\n\n"
        
        logger.info("Report generation complete.")
        return report_content
