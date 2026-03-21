from llm_client import LitellmAPIClient
from xai_client import XAIAPIClient
import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
# --- Classe RequestDetailsValidator (inchangée) ---
class RequestDetailsValidator:
    @staticmethod
    def is_valid_request(request_dict: Dict[str, Any]) -> bool:
        if not isinstance(request_dict, dict): return False
        if "method" not in request_dict or not isinstance(request_dict["method"], str): return False
        if "url" not in request_dict or not isinstance(request_dict["url"], str): return False
        return True



class TestGenerationError(Exception): pass


class TestRefinementError(Exception): pass


class TestGenerator:
    def __init__(self, litellm_client: LitellmAPIClient | XAIAPIClient, target_url: str):
        self.litellm_client = litellm_client
        self.validator = RequestDetailsValidator()
        self.target_url = target_url

    def _parse_llm_json_response(self, response_text: str, context: str) -> List[Dict[str, Any]]:
        """Helper to parse JSON array from LLM response robustly."""
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            logger.warning(f"Direct JSON parse failed for {context}. Attempting to extract from markers.")
            start = response_text.find('[')
            end = response_text.rfind(']')
            if start != -1 and end != -1 and start < end:
                json_str = response_text[start:end + 1]
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    logger.error(f"Failed to decode extracted JSON for {context}. Snippet: {json_str[:200]}")
                    return []
            else:
                logger.error(f"Could not find JSON array markers for {context}. Response: {response_text[:200]}")
                return []

    def _build_prompt_for_vulnerability(self, endpoint_details: Dict[str, Any], vulnerability_type: str) -> str:
        prompt_parts = [
            f"You are an expert security researcher specializing in API pentesting.",
            f"Your task is to generate HTTP requests to test for '{vulnerability_type}' vulnerability on the following API endpoint.",
            f"\n--- Endpoint Details ---",
            f"Method: {endpoint_details.get('method', 'N/A')}",
            f"Path: {endpoint_details.get('path', 'N/A')}",
            f"Summary: {endpoint_details.get('summary', 'N/A')}",
        ]
        if endpoint_details.get('parameters'):
            prompt_parts.append(f"\nParameters:")
            for param in endpoint_details['parameters']:
                prompt_parts.append(f"  - {param.get('name', 'N/A')} (in: {param.get('in', 'N/A')})")
        if endpoint_details.get('requestBody'):
            prompt_parts.append(f"\nExpected Request Body available.")

        prompt_parts.extend([
            f"\n--- Your Task ---",
            f"Generate a list of 3-5 distinct HTTP requests (as JSON objects in a JSON array) to effectively test for '{vulnerability_type}'.",
            "IMPORTANT: Your primary goal is to inject test payloads any possible input vector but one by request (ie one request with payload in the body and another with a payload in the path"
            ". This includes:",
            "  - URL Path segments (e.g., replacing '{id}').",
            "  - URL Query parameters.",
            "  - ALL relevant fields within a JSON or form data body.",
            "  - HTTP Headers where relevant (e.g., 'User-Agent', custom headers).",
            "Be creative and thorough. Do not just send normal-looking requests.",
            f"For each request, provide 'method', 'url', and optional 'headers', 'params', 'json', 'data'.",
            f"The base URL for all generated 'url' values MUST be '{self.target_url}'.",
            f"Output ONLY a valid JSON array. No introductory text or explanations."
        ])
        return "\n".join(prompt_parts)

    async def generate_tests_for_endpoint(
            self,
            endpoint_details: Dict[str, Any],
            vulnerability_types: List[str]
    ) -> List[Dict[str, Any]]:
        generated_requests = []
        for vul_type in vulnerability_types:
            prompt = self._build_prompt_for_vulnerability(endpoint_details, vul_type)
            try:
                completion = await self.litellm_client.chat_completion(
                    messages=[{"role": "user", "content": prompt}],
                    #temperature=0.5,
                    #max_tokens=3000
                    #TODO how to fix for ollama which doesn't support these params? Should we add them as optional in the client method and ignore if not supported?
                )
                response_text = completion.get("choices", [{}])[0].get("message", {}).get("content", "")
                potential_requests = self._parse_llm_json_response(response_text,
                                                                   f"{vul_type} on {endpoint_details['path']}")

                for req in potential_requests:
                    if self.validator.is_valid_request(req):
                        # Attach metadata for later grouping
                        req['vulnerability_type'] = vul_type
                        req['endpoint_key'] = f"{endpoint_details['method'].upper()}:{endpoint_details['path']}"
                        generated_requests.append(req)
            except Exception as e:
                logger.error(f"Error generating tests for '{vul_type}' on {endpoint_details['path']}: {e}")
                raise TestGenerationError(f"LLM failed to generate initial tests: {e}") from e
        return generated_requests

    def _build_refinement_prompt(
            self,
            endpoint_details: Dict[str, Any],
            vulnerability_type: str,
            test_history: List[Dict[str, Any]]
    ) -> str:
        prompt_parts = [
            f"You are an expert security researcher pentesting for '{vulnerability_type}'.",
            f"You are iteratively attacking the endpoint: {endpoint_details.get('method')} {endpoint_details.get('path')}.",
            "Analyze the following history and devise a NEW, SMARTER set of 2-3 requests to continue the attack.",
            "\n--- Previous Attempts and Results ---"
        ]
        for i, result in enumerate(test_history):
            request = result.get('request', {})
            response = result.get('response', {})
            error = result.get('error')
            prompt_parts.append(f"\n--- Attempt #{i + 1} ---")
            prompt_parts.append(f"Request: {request.get('method')} {request.get('url')}")
            if request.get('json'): prompt_parts.append(f"  JSON Body: {json.dumps(request.get('json'))}")
            if error:
                prompt_parts.append(f"Response: FAILED - {error}")
            elif response:
                status = response.get('status_code', 'N/A')
                body_preview = str(response.get('body', ''))[:300].replace('\n', ' ')
                prompt_parts.append(f"Response Status: {status}, Body (preview): {body_preview}...")

        prompt_parts.extend([
            "\n--- Your Next Move ---",
            "Analyze the responses. Did an error message leak information? Did a simple payload get blocked, suggesting a more complex or encoded one is needed?",
            "Generate a new list of 2-3 refined HTTP requests as a JSON array.",
            "These new requests should be an EVOLUTION of your previous attempts, designed to bypass observed defenses or exploit discovered information.",
            f"The base URL for new requests must be '{self.target_url}'.",
            "Output ONLY the valid JSON array of new requests. Do not include any other text."
        ])
        return "\n".join(prompt_parts)

    async def refine_tests_based_on_results(
            self,
            endpoint_details: Dict[str, Any],
            vulnerability_type: str,
            test_history: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        if not test_history: return []
        logger.info(
            f"Refining tests for '{vulnerability_type}' on {endpoint_details['path']} based on {len(test_history)} results.")
        prompt = self._build_refinement_prompt(endpoint_details, vulnerability_type, test_history)

        try:
            completion = await self.litellm_client.chat_completion(
                messages=[{"role": "user", "content": prompt}],
                temperature=0.6,
                max_tokens=2000
            )
            response_text = completion.get("choices", [{}])[0].get("message", {}).get("content", "")
            potential_requests = self._parse_llm_json_response(response_text, f"refinement for {vulnerability_type}")

            validated_requests = []
            for req in potential_requests:
                if self.validator.is_valid_request(req):
                    req['vulnerability_type'] = vulnerability_type
                    req['endpoint_key'] = f"{endpoint_details['method'].upper()}:{endpoint_details['path']}"
                    validated_requests.append(req)

            logger.info(
                f"Generated {len(validated_requests)} refined requests for {vulnerability_type} on {endpoint_details['path']}.")
            return validated_requests
        except Exception as e:
            logger.error(f"Error during test refinement for '{vulnerability_type}': {e}")
            raise TestRefinementError(f"LLM failed to generate refined tests: {e}") from e

