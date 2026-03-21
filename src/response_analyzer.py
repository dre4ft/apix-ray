import httpx
import json
import logging
import re
import asyncio
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urljoin
from datetime import datetime
from llm_client import LitellmAPIClient
from xai_client import XAIAPIClient

logger = logging.getLogger(__name__)

class ResponseAnalyzer:
    def __init__(self, litellm_client: LitellmAPIClient | XAIAPIClient):
        self.litellm_client = litellm_client

    def _build_chain_analysis_prompt(
            self,
            test_chain: List[Dict[str, Any]],
            vulnerability_type: str
    ) -> str:
        prompt_parts = [
            f"You are a Senior Security Analyst making a FINAL JUDGMENT on a potential '{vulnerability_type}' vulnerability.",
            "You have been provided with the COMPLETE sequence of tests performed against a single API endpoint. Analyze the entire chain to determine if a vulnerability exists.",
            "\n--- Full Test and Response History ---"
        ]
        for i, result in enumerate(test_chain):
            request = result.get('request', {})
            response = result.get('response', {})
            error = result.get('error')
            prompt_parts.append(f"\n--- Attempt #{i + 1} ---")
            prompt_parts.append(f"Request: {request.get('method')} {request.get('url')}")
            if request.get('json'): prompt_parts.append(f"  JSON Body: {json.dumps(request.get('json'))}")
            if error:
                prompt_parts.append(f"Response: FAILED - {error}")
            elif response:
                body = str(response.get('body', 'N/A'))
                prompt_parts.append(f"Response Status: {response.get('status_code', 'N/A')}")
                prompt_parts.append(f"Response Body: {body[:1000]}")  # Limit body length in prompt

        prompt_parts.extend([
            "\n--- Final Analysis ---",
            "Based on the ENTIRE history, provide your final verdict in a single JSON object with the following keys:",
            "  - 'is_vulnerable' (boolean): True if the evidence strongly indicates the vulnerability.",
            "  - 'confidence' (string): 'High', 'Medium', or 'Low'.",
            "  - 'reasoning' (string): CRITICAL - Explain your conclusion by referencing the sequence of attempts. For example: 'Attempt #1 returned a 404, but Attempt #3 with a SQL payload returned a 500 with a database error, indicating the payload was processed.'",
            "  - 'evidence' (string): Quote the most compelling snippet from any of the responses that supports your finding.",
            "  - 'severity' (string): 'Critical', 'High', 'Medium', 'Low', 'Informational'.",
            "  - 'recommendation' (string): A brief recommendation for remediation.",
            "\nOutput ONLY the single, valid JSON object. No other text."
        ])
        return "\n".join(prompt_parts)

    async def analyze_test_chain(self, test_chain: List[Dict[str, Any]], vulnerability_type: str) -> Optional[
        Dict[str, Any]]:
        """Analyzes a sequence of test results and returns a single conclusion."""
        if not test_chain: return None
        logger.info(f"Performing final analysis on a chain of {len(test_chain)} results for '{vulnerability_type}'.")
        prompt = self._build_chain_analysis_prompt(test_chain, vulnerability_type)

        try:
            completion = await self.litellm_client.chat_completion(
                messages=[{"role": "user", "content": prompt}], temperature=0.1, max_tokens=2000
            )
            response_text = completion.get("choices", [{}])[0].get("message", {}).get("content", "")

            # Find the JSON object in the response
            match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if not match:
                logger.error(f"Could not find JSON object in final analysis response for '{vulnerability_type}'.")
                return None

            analysis_result = json.loads(match.group(0))

            if isinstance(analysis_result, dict) and analysis_result.get('is_vulnerable'):
                logger.info(
                    f"Final analysis confirms potential '{vulnerability_type}' with confidence '{analysis_result.get('confidence')}'.")
                return {
                    "type": vulnerability_type,
                    "request": test_chain[-1].get('request'),  # Last request as representative
                    "llm_analysis": analysis_result,
                    "full_test_history": test_chain
                }
            else:
                logger.info(f"Final analysis did not confirm '{vulnerability_type}' for this chain.")
                return None
        except (json.JSONDecodeError, IndexError) as e:
            logger.error(
                f"Failed to decode final analysis response for '{vulnerability_type}': {e}. Content: {response_text[:300]}")
            return None
        except Exception as e:
            logger.error(f"Error during final analysis of '{vulnerability_type}': {e}")
            return None