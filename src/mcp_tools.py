"""
MCP Tools for APIX-Ray Pentest Agent
Provides dynamic tools that the LLM can call during execution
"""

import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class ToolResult:
    """Result of a tool execution"""
    success: bool
    data: Any
    message: str

class APIPentestTools:
    """Collection of MCP tools for API penetration testing"""

    def __init__(self, oas_content: Dict[str, Any], api_base_url: str, request_manager, request_limits: Dict[str, Any] = None):
        self.oas_content = oas_content
        self.api_base_url = api_base_url
        self.request_manager = request_manager
        self.discovered_endpoints = {}
        self.test_history = []

        # Dynamic request configuration
        self.request_limits = request_limits or {
            "global_max_requests": 100,
            "per_vulnerability_max": 25,
            "adaptive_enabled": True,
            "relevance_threshold": 0.7,
            "evolution_factor": 1.2
        }

    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Return the list of available MCP tools"""
        return [
            {
                "name": "discover_endpoints",
                "description": "Discover and analyze API endpoints from OpenAPI specification",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "comprehensive_security_scan",
                "description": "Perform comprehensive security testing across all endpoints for multiple vulnerability types with configurable request limits",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vulnerability_types": {"type": "array", "description": "List of vulnerability types to test"},
                        "depth": {"type": "string", "description": "Scan depth: 'basic', 'intermediate', 'deep'", "enum": ["basic", "intermediate", "deep"]},
                        "max_requests": {"type": "integer", "description": "Maximum number of HTTP requests to perform (overrides depth settings)"}
                    },
                    "required": ["vulnerability_types"]
                }
            },
            {
                "name": "targeted_security_scan",
                "description": "Perform precise security testing with exact request count control and endpoint prioritization",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "vulnerability_types": {"type": "array", "description": "List of vulnerability types to test"},
                        "exact_requests": {"type": "integer", "description": "Exact number of HTTP requests to perform", "minimum": 1},
                        "prioritize_sensitive": {"type": "boolean", "description": "Prioritize sensitive endpoints (login, user data, admin)", "default": True}
                    },
                    "required": ["vulnerability_types", "exact_requests"]
                }
            },
            {
                "name": "generate_advanced_tests",
                "description": "Generate advanced security test cases with multiple payloads and edge cases",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "endpoint_key": {"type": "string", "description": "Endpoint identifier (METHOD:path)"},
                        "vulnerability_type": {"type": "string", "description": "Type of vulnerability to test"},
                        "intensity": {"type": "string", "description": "Test intensity: 'light', 'normal', 'aggressive'", "enum": ["light", "normal", "aggressive"]}
                    },
                    "required": ["endpoint_key", "vulnerability_type"]
                }
            },
            {
                "name": "execute_batch_tests",
                "description": "Execute multiple test requests in batch for efficiency",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "test_requests": {"type": "array", "description": "List of HTTP request details to execute"}
                    },
                    "required": ["test_requests"]
                }
            },
            {
                "name": "intelligent_vulnerability_analysis",
                "description": "Perform intelligent analysis of test results using pattern recognition and ML-like techniques",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "test_results": {"type": "array", "description": "List of test execution results"},
                        "vulnerability_type": {"type": "string", "description": "Type of vulnerability being tested"},
                        "context": {"type": "object", "description": "Additional context about the API and testing"}
                    },
                    "required": ["test_results", "vulnerability_type"]
                }
            },
            {
                "name": "test_authentication_bypass",
                "description": "Test for authentication and authorization bypass vulnerabilities",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "endpoint_key": {"type": "string", "description": "Endpoint identifier to test"},
                        "auth_tokens": {"type": "array", "description": "List of authentication tokens to test"}
                    },
                    "required": ["endpoint_key"]
                }
            },
            {
                "name": "test_rate_limiting",
                "description": "Test for rate limiting and DoS vulnerabilities",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "endpoint_key": {"type": "string", "description": "Endpoint identifier to test"},
                        "requests_per_second": {"type": "integer", "description": "Number of requests per second to send"}
                    },
                    "required": ["endpoint_key"]
                }
            },
            {
                "name": "generate_executive_report",
                "description": "Generate comprehensive executive report with findings, risks, and recommendations",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array", "description": "List of security findings"},
                        "scan_metadata": {"type": "object", "description": "Metadata about the scan"}
                    },
                    "required": ["findings"]
                }
            }
        ]

    async def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> ToolResult:
        """Execute a specific tool"""
        try:
            if tool_name == "discover_endpoints":
                return await self._discover_endpoints()
            elif tool_name == "generate_security_tests":
                return await self._generate_security_tests(
                    parameters["endpoint_key"],
                    parameters["vulnerability_type"]
                )
            elif tool_name == "execute_test_request":
                return await self._execute_test_request(parameters["request"])
            elif tool_name == "analyze_test_results":
                return await self._analyze_test_results(
                    parameters["test_results"],
                    parameters["vulnerability_type"]
                )
            elif tool_name == "refine_test_strategy":
                return await self._refine_test_strategy(
                    parameters["endpoint_key"],
                    parameters["vulnerability_type"],
                    parameters["previous_results"]
                )
            elif tool_name == "comprehensive_security_scan":
                return await self._comprehensive_security_scan(
                    parameters["vulnerability_types"],
                    parameters.get("depth", "intermediate"),
                    parameters.get("max_requests")
                )
            elif tool_name == "targeted_security_scan":
                return await self._targeted_security_scan(
                    parameters["vulnerability_types"],
                    parameters["exact_requests"],
                    parameters.get("prioritize_sensitive", True)
                )
            elif tool_name == "generate_advanced_tests":
                return await self._generate_advanced_tests(
                    parameters["endpoint_key"],
                    parameters["vulnerability_type"],
                    parameters.get("intensity", "normal")
                )
            elif tool_name == "execute_batch_tests":
                return await self._execute_batch_tests(parameters["test_requests"])
            elif tool_name == "intelligent_vulnerability_analysis":
                return await self._intelligent_vulnerability_analysis(
                    parameters["test_results"],
                    parameters["vulnerability_type"],
                    parameters.get("context", {})
                )
            elif tool_name == "test_authentication_bypass":
                return await self._test_authentication_bypass(
                    parameters["endpoint_key"],
                    parameters.get("auth_tokens", [])
                )
            elif tool_name == "test_rate_limiting":
                return await self._test_rate_limiting(
                    parameters["endpoint_key"],
                    parameters.get("requests_per_second", 10)
                )
            elif tool_name == "generate_executive_report":
                return await self._generate_executive_report(
                    parameters["findings"],
                    parameters.get("scan_metadata", {})
                )
            else:
                return ToolResult(False, None, f"Unknown tool: {tool_name}")
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return ToolResult(False, None, f"Tool execution failed: {str(e)}")

    async def _discover_endpoints(self) -> ToolResult:
        """Discover endpoints from OAS"""
        from endpoint_discovery import discover_endpoints_from_oas, inspect_endpoint_details

        try:
            endpoints = discover_endpoints_from_oas(self.oas_content)
            detailed_endpoints = {}

            for endpoint in endpoints:
                key = f"{endpoint['method'].upper()}:{endpoint['path']}"
                try:
                    details = inspect_endpoint_details(self.oas_content, endpoint['path'], endpoint['method'])
                    detailed_endpoints[key] = details
                except Exception as e:
                    logger.warning(f"Could not inspect endpoint {key}: {e}")

            self.discovered_endpoints = detailed_endpoints
            return ToolResult(True, detailed_endpoints, f"Discovered {len(detailed_endpoints)} endpoints")
        except Exception as e:
            return ToolResult(False, None, f"Endpoint discovery failed: {str(e)}")

    async def _generate_security_tests(self, endpoint_key: str, vulnerability_type: str) -> ToolResult:
        """Generate security tests for an endpoint"""
        if endpoint_key not in self.discovered_endpoints:
            return ToolResult(False, None, f"Endpoint {endpoint_key} not found")

        endpoint_details = self.discovered_endpoints[endpoint_key]

        # Use LLM to generate test prompts (simplified version)
        prompt = f"Generate 3-5 HTTP requests to test for {vulnerability_type} on endpoint {endpoint_details.get('method')} {endpoint_details.get('path')}"

        # This would normally call the LLM, but for now return a placeholder
        test_requests = [
            {
                "method": endpoint_details.get("method", "GET"),
                "url": f"{self.api_base_url}{endpoint_details.get('path', '')}",
                "vulnerability_type": vulnerability_type,
                "endpoint_key": endpoint_key
            }
        ]

        return ToolResult(True, test_requests, f"Generated {len(test_requests)} test requests")

    async def _comprehensive_security_scan(self, vulnerability_types: List[str], depth: str = "intermediate", max_requests: int = None) -> ToolResult:
        """Perform comprehensive security testing across all endpoints with adaptive request management"""
        if not self.discovered_endpoints:
            return ToolResult(False, None, "No endpoints discovered. Run discover_endpoints first.")

        all_findings = []
        total_tests = 0

        # Define test depth parameters
        depth_config = {
            "basic": {"max_payloads_per_type": 3, "max_endpoints_per_type": 5},
            "intermediate": {"max_payloads_per_type": 10, "max_endpoints_per_type": 15},
            "deep": {"max_payloads_per_type": 25, "max_endpoints_per_type": 50}
        }

        config = depth_config.get(depth, depth_config["intermediate"])

        # Use adaptive request calculation if no explicit max_requests
        if max_requests is None and self.request_limits.get("adaptive_enabled", True):
            # Calculate adaptive requests per type
            base_requests_per_type = self.request_limits.get("per_vulnerability_max", 25)
            total_adaptive_requests = 0

            for vuln_type in vulnerability_types:
                # This would be called from the agent, so we need to calculate adaptively
                # For now, use base calculation - agent will override with adaptive counts
                adaptive_count = base_requests_per_type
                total_adaptive_requests += adaptive_count

            max_requests = min(total_adaptive_requests, self.request_limits.get("global_max_requests", 100))

        # Override with max_requests if specified
        if max_requests:
            # Distribute requests across vulnerability types and endpoints
            requests_per_type = max(1, max_requests // len(vulnerability_types))
            config["max_payloads_per_type"] = max(1, requests_per_type // len(self.discovered_endpoints))
            config["max_endpoints_per_type"] = len(self.discovered_endpoints)  # Test all endpoints but limit payloads

        for vuln_type in vulnerability_types:
            vuln_findings = []
            tested_endpoints = 0

            # Select endpoints to test using relevance scoring
            if hasattr(self, '_agent_relevance_func') and self._agent_relevance_func:
                # Use agent's relevance function if available
                endpoints_with_scores = []
                for endpoint_key in self.discovered_endpoints.keys():
                    relevance_score = self._agent_relevance_func(endpoint_key, vuln_type)
                    if relevance_score >= self.request_limits.get("relevance_threshold", 0.7):
                        endpoints_with_scores.append((endpoint_key, relevance_score))

                # Sort by relevance score descending
                endpoints_with_scores.sort(key=lambda x: x[1], reverse=True)
                endpoints_to_test = [ep[0] for ep in endpoints_with_scores[:config["max_endpoints_per_type"]]]
            else:
                # Fallback to traditional selection
                endpoints_to_test = self._select_endpoints_for_vulnerability(vuln_type, config["max_endpoints_per_type"])

            for endpoint_key in endpoints_to_test:
                if tested_endpoints >= config["max_endpoints_per_type"]:
                    break

                # Generate advanced tests for this endpoint and vulnerability
                test_result = await self._generate_advanced_tests(endpoint_key, vuln_type, "normal")
                if not test_result.success:
                    continue

                test_requests = test_result.data[:config["max_payloads_per_type"]]

                # Execute tests in batch
                if test_requests:
                    batch_result = await self._execute_batch_tests(test_requests)
                    total_tests += len(test_requests)

                    # Analyze results
                    analysis_result = await self._intelligent_vulnerability_analysis(
                        batch_result.data if batch_result.success else [],
                        vuln_type,
                        {"endpoint": endpoint_key, "depth": depth}
                    )

                    if analysis_result.success and analysis_result.data:
                        vuln_findings.extend(analysis_result.data)

                tested_endpoints += 1

            all_findings.extend(vuln_findings)

        # Generate comprehensive report
        report_result = await self._generate_executive_report(all_findings, {
            "total_endpoints": len(self.discovered_endpoints),
            "vulnerability_types_tested": vulnerability_types,
            "total_tests_executed": total_tests,
            "scan_depth": depth,
            "scan_timestamp": "2026-03-21T19:35:00Z"
        })

        return ToolResult(True, {
            "findings": all_findings,
            "report": report_result.data if report_result.success else None,
            "statistics": {
                "total_endpoints_tested": len(self.discovered_endpoints),
                "vulnerability_types_covered": len(vulnerability_types),
                "total_tests_executed": total_tests,
                "findings_count": len(all_findings)
            }
        }, f"Comprehensive security scan completed. Tested {len(vulnerability_types)} vulnerability types across {len(self.discovered_endpoints)} endpoints. Found {len(all_findings)} potential issues.")

    async def _targeted_security_scan(self, vulnerability_types: List[str], exact_requests: int, prioritize_sensitive: bool = True) -> ToolResult:
        """Perform precise security testing with exact request count control"""
        if not self.discovered_endpoints:
            return ToolResult(False, None, "No endpoints discovered. Run discover_endpoints first.")

        if exact_requests < 1:
            return ToolResult(False, None, "exact_requests must be at least 1.")

        all_findings = []
        total_tests = 0
        requests_made = 0

        # Calculate requests per vulnerability type
        requests_per_type = max(1, exact_requests // len(vulnerability_types))

        for vuln_type in vulnerability_types:
            vuln_findings = []
            remaining_requests = requests_per_type

            # Select most relevant endpoints for this vulnerability type
            if prioritize_sensitive:
                endpoints_to_test = self._select_endpoints_for_vulnerability(vuln_type, len(self.discovered_endpoints))
                # Prioritize the most sensitive endpoints
                sensitive_endpoints = [ep for ep in endpoints_to_test if any(keyword in ep.lower()
                    for keyword in ['login', 'user', 'admin', 'auth', 'token', 'password', 'search', 'data'])]
                other_endpoints = [ep for ep in endpoints_to_test if ep not in sensitive_endpoints]
                endpoints_to_test = sensitive_endpoints + other_endpoints
            else:
                endpoints_to_test = list(self.discovered_endpoints.keys())

            for endpoint_key in endpoints_to_test:
                if remaining_requests <= 0 or requests_made >= exact_requests:
                    break

                # Calculate how many requests to allocate to this endpoint
                requests_for_endpoint = min(remaining_requests, 3)  # Max 3 requests per endpoint for targeted testing

                # Generate targeted tests for this endpoint and vulnerability
                test_result = await self._generate_advanced_tests(endpoint_key, vuln_type, "normal")
                if not test_result.success:
                    continue

                # Limit the number of test requests based on our allocation
                test_requests = test_result.data[:requests_for_endpoint]

                if test_requests:
                    batch_result = await self._execute_batch_tests(test_requests)
                    total_tests += len(test_requests)
                    requests_made += len(test_requests)
                    remaining_requests -= len(test_requests)

                    # Analyze results
                    analysis_result = await self._intelligent_vulnerability_analysis(
                        batch_result.data if batch_result.success else [],
                        vuln_type,
                        {"endpoint": endpoint_key, "targeted": True}
                    )

                    if analysis_result.success and analysis_result.data:
                        vuln_findings.extend(analysis_result.data)

            all_findings.extend(vuln_findings)

        # Generate targeted report
        report_result = await self._generate_executive_report(all_findings, {
            "total_endpoints": len(self.discovered_endpoints),
            "vulnerability_types_tested": vulnerability_types,
            "total_tests_executed": total_tests,
            "exact_requests_target": exact_requests,
            "actual_requests_made": requests_made,
            "scan_timestamp": "2026-03-21T19:35:00Z"
        })

        return ToolResult(True, {
            "findings": all_findings,
            "report": report_result.data if report_result.success else None,
            "statistics": {
                "total_endpoints_tested": len([ep for vuln in vulnerability_types
                    for ep in self._select_endpoints_for_vulnerability(vuln, len(self.discovered_endpoints))]),
                "vulnerability_types_covered": len(vulnerability_types),
                "total_tests_executed": total_tests,
                "exact_requests_target": exact_requests,
                "actual_requests_made": requests_made,
                "findings_count": len(all_findings)
            }
        }, f"Targeted security scan completed. Made exactly {requests_made} HTTP requests across {len(vulnerability_types)} vulnerability types. Found {len(all_findings)} potential issues.")

    def _select_endpoints_for_vulnerability(self, vulnerability_type: str, max_endpoints: int) -> List[str]:
        """Select most relevant endpoints for a specific vulnerability type"""
        endpoint_keys = list(self.discovered_endpoints.keys())

        # Prioritize endpoints based on vulnerability type
        priority_patterns = {
            "SQL Injection": ["GET", "POST", "PUT", "query", "search", "filter"],
            "XSS": ["GET", "POST", "text", "name", "comment", "message"],
            "IDOR": ["GET", "user", "profile", "account", "{user_id}", "{id}"],
            "Broken Access Control": ["GET", "POST", "PUT", "DELETE", "admin", "user"],
            "CSRF": ["POST", "PUT", "DELETE", "form", "update"],
            "Command Injection": ["GET", "POST", "exec", "run", "cmd", "shell"],
            "Rate Limiting": ["GET", "POST", "login", "auth", "api"],
            "Authentication Bypass": ["GET", "POST", "login", "auth", "token"]
        }

        patterns = priority_patterns.get(vulnerability_type, [])
        prioritized_endpoints = []

        # First, add endpoints that match vulnerability-specific patterns
        for key in endpoint_keys:
            method, path = key.split(":", 1)
            if any(pattern.lower() in path.lower() or pattern.lower() in method.lower() for pattern in patterns):
                prioritized_endpoints.append(key)

        # Then add remaining endpoints
        for key in endpoint_keys:
            if key not in prioritized_endpoints:
                prioritized_endpoints.append(key)

        return prioritized_endpoints[:max_endpoints]

    async def _generate_advanced_tests(self, endpoint_key: str, vulnerability_type: str, intensity: str = "normal") -> ToolResult:
        """Generate advanced security tests with multiple payloads and edge cases"""
        if endpoint_key not in self.discovered_endpoints:
            return ToolResult(False, None, f"Endpoint {endpoint_key} not found")

        endpoint_details = self.discovered_endpoints[endpoint_key]
        base_url = f"{self.api_base_url}{endpoint_details.get('path', '')}"

        # Define payloads based on vulnerability type and intensity
        payload_configs = {
            "SQL Injection": {
                "light": ["'", "''", "' OR '1'='1"],
                "normal": ["'", "''", "' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT * FROM users--"],
                "aggressive": ["'", "''", "' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT * FROM users--", "' AND 1=0 UNION SELECT username, password FROM users--"]
            },
            "XSS": {
                "light": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "normal": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)"],
                "aggressive": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "javascript:alert(1)", "<iframe src=javascript:alert(1)></iframe>"]
            },
            "IDOR": {
                "light": ["../", "..", "."],
                "normal": ["../", "..", ".", "../../../etc/passwd", "../../admin"],
                "aggressive": ["../", "..", ".", "../../../etc/passwd", "../../admin", "../../../../root", "0", "-1", "999999"]
            }
        }

        payloads = payload_configs.get(vulnerability_type, {"normal": ["test payload"]}).get(intensity, ["test payload"])

        test_requests = []
        parameters = endpoint_details.get("parameters", [])

        for payload in payloads:
            # Generate test requests for each parameter
            for param in parameters:
                if param.get("in") in ["query", "path"]:
                    test_request = {
                        "method": endpoint_details.get("method", "GET"),
                        "url": base_url,
                        "vulnerability_type": vulnerability_type,
                        "endpoint_key": endpoint_key,
                        "test_payload": payload,
                        "target_parameter": param.get("name")
                    }

                    # Add payload to appropriate parameter
                    if param.get("in") == "query":
                        test_request["params"] = {param.get("name"): payload}
                    elif param.get("in") == "path":
                        # Replace path parameter with payload
                        test_request["url"] = base_url.replace(f"{{{param.get('name')}}}", payload)

                    test_requests.append(test_request)

        return ToolResult(True, test_requests, f"Generated {len(test_requests)} advanced test requests for {vulnerability_type}")

    async def _execute_batch_tests(self, test_requests: List[Dict[str, Any]]) -> ToolResult:
        """Execute multiple test requests in batch"""
        results = []

        for request in test_requests:
            try:
                result = await self.request_manager.send_request(request)
                results.append(result)
                self.test_history.append(result)

                # Small delay to avoid overwhelming the API
                await asyncio.sleep(0.1)
            except Exception as e:
                results.append({
                    "request": request,
                    "response": {"error_message": str(e)},
                    "success": False
                })

        return ToolResult(True, results, f"Executed {len(results)} batch test requests")

    async def _intelligent_vulnerability_analysis(self, test_results: List[Dict[str, Any]], vulnerability_type: str, context: Dict[str, Any]) -> ToolResult:
        """Perform intelligent analysis of test results"""
        findings = []

        for result in test_results:
            if not result.get("success", False):
                continue

            response = result.get("response", {})
            status_code = response.get("status_code", 0)
            response_body = str(response.get("body", ""))

            # Analyze based on vulnerability type
            if vulnerability_type == "SQL Injection":
                if self._detect_sql_injection(response_body, status_code):
                    findings.append(self._create_finding(vulnerability_type, result, "High", "SQL injection vulnerability detected"))

            elif vulnerability_type == "XSS":
                if self._detect_xss(response_body):
                    findings.append(self._create_finding(vulnerability_type, result, "Medium", "Potential XSS vulnerability detected"))

            elif vulnerability_type == "IDOR":
                if self._detect_idor(response, status_code):
                    findings.append(self._create_finding(vulnerability_type, result, "High", "IDOR vulnerability detected"))

            # Add more vulnerability-specific analysis here

        return ToolResult(True, findings, f"Analysis completed. Found {len(findings)} potential vulnerabilities")

    def _detect_sql_injection(self, response_body: str, status_code: int) -> bool:
        """Detect SQL injection indicators"""
        sql_indicators = [
            "sql syntax", "mysql", "postgresql", "sqlite", "oracle",
            "you have an error in your sql", "unclosed quotation mark",
            "syntax error", "invalid sql"
        ]
        return any(indicator.lower() in response_body.lower() for indicator in sql_indicators) or status_code in [500, 502, 503]

    def _detect_xss(self, response_body: str) -> bool:
        """Detect XSS indicators"""
        # Check if payloads are reflected without encoding
        dangerous_patterns = ["<script>", "javascript:", "onerror=", "onload="]
        return any(pattern in response_body for pattern in dangerous_patterns)

    def _detect_idor(self, response: Dict[str, Any], status_code: int) -> bool:
        """Detect IDOR indicators"""
        # IDOR might be indicated by accessing unauthorized resources
        # This is a simplified check - real IDOR detection requires more context
        return status_code in [200, 201] and "unauthorized" not in str(response.get("body", "")).lower()

    def _create_finding(self, vuln_type: str, test_result: Dict[str, Any], severity: str, description: str) -> Dict[str, Any]:
        """Create a standardized finding object"""
        return {
            "vulnerability_type": vuln_type,
            "severity": severity,
            "description": description,
            "endpoint": test_result.get("request", {}).get("endpoint_key"),
            "url": test_result.get("request", {}).get("url"),
            "request": test_result.get("request"),
            "response": test_result.get("response"),
            "evidence": str(test_result.get("response", {}).get("body", ""))[:500],  # First 500 chars
            "timestamp": "2026-03-21T19:35:00Z",
            "cvss_score": self._calculate_cvss_score(severity),
            "recommendations": self._generate_recommendations(vuln_type)
        }

    def _calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        scores = {"Critical": 9.5, "High": 8.0, "Medium": 6.0, "Low": 4.0, "Info": 2.0}
        return scores.get(severity, 5.0)

    def _generate_recommendations(self, vuln_type: str) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = {
            "SQL Injection": [
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Use ORM libraries with built-in SQL injection protection",
                "Apply principle of least privilege to database accounts"
            ],
            "XSS": [
                "Implement output encoding for user input",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user inputs",
                "Use secure templating engines"
            ],
            "IDOR": [
                "Implement proper access control checks",
                "Use session-based authorization",
                "Validate user permissions for each resource access",
                "Implement resource ownership verification"
            ]
        }
        return recommendations.get(vuln_type, ["Implement proper security controls", "Conduct regular security testing"])

    async def _test_authentication_bypass(self, endpoint_key: str, auth_tokens: List[str]) -> ToolResult:
        """Test for authentication bypass vulnerabilities"""
        if endpoint_key not in self.discovered_endpoints:
            return ToolResult(False, None, f"Endpoint {endpoint_key} not found")

        endpoint_details = self.discovered_endpoints[endpoint_key]
        base_url = f"{self.api_base_url}{endpoint_details.get('path', '')}"

        test_requests = []

        # Test with different auth tokens
        for token in auth_tokens + ["", "invalid_token", "admin", "Bearer invalid"]:
            test_requests.append({
                "method": endpoint_details.get("method", "GET"),
                "url": base_url,
                "headers": {"Authorization": token} if token else {},
                "vulnerability_type": "Authentication Bypass",
                "endpoint_key": endpoint_key
            })

        # Execute tests
        batch_result = await self._execute_batch_tests(test_requests)

        # Analyze for auth bypass indicators
        findings = []
        for result in batch_result.data:
            status_code = result.get("response", {}).get("status_code", 0)
            if status_code in [200, 201] and not result.get("request", {}).get("headers", {}).get("Authorization"):
                findings.append(self._create_finding("Authentication Bypass", result, "High", "Potential authentication bypass detected"))

        return ToolResult(True, findings, f"Authentication bypass testing completed. Found {len(findings)} potential issues")

    async def _test_rate_limiting(self, endpoint_key: str, requests_per_second: int = 10) -> ToolResult:
        """Test for rate limiting vulnerabilities"""
        if endpoint_key not in self.discovered_endpoints:
            return ToolResult(False, None, f"Endpoint {endpoint_key} not found")

        endpoint_details = self.discovered_endpoints[endpoint_key]
        base_url = f"{self.api_base_url}{endpoint_details.get('path', '')}"

        # Send multiple requests rapidly
        test_requests = []
        for i in range(min(requests_per_second * 5, 50)):  # Max 50 requests
            test_requests.append({
                "method": endpoint_details.get("method", "GET"),
                "url": base_url,
                "vulnerability_type": "Rate Limiting",
                "endpoint_key": endpoint_key
            })

        # Execute with timing
        start_time = asyncio.get_event_loop().time()
        batch_result = await self._execute_batch_tests(test_requests)
        end_time = asyncio.get_event_loop().time()

        # Analyze rate limiting
        success_count = sum(1 for r in batch_result.data if r.get("response", {}).get("status_code") in [200, 201])
        error_count = sum(1 for r in batch_result.data if r.get("response", {}).get("status_code") in [429, 503])

        findings = []
        if error_count == 0 and success_count > requests_per_second * 3:
            findings.append({
                "vulnerability_type": "Rate Limiting",
                "severity": "Medium",
                "description": "No rate limiting detected - API may be vulnerable to DoS attacks",
                "endpoint": endpoint_key,
                "evidence": f"All {success_count} requests succeeded without rate limiting"
            })

        return ToolResult(True, findings, f"Rate limiting test completed. {success_count} successful, {error_count} rate limited")

    async def _generate_executive_report(self, findings: List[Dict[str, Any]], scan_metadata: Dict[str, Any]) -> ToolResult:
        """Generate comprehensive executive report"""
        # Group findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        vuln_type_counts = {}

        for finding in findings:
            severity = finding.get("severity", "Info")
            vuln_type = finding.get("vulnerability_type", "Unknown")

            severity_counts[severity] += 1
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1

        # Calculate risk score
        risk_score = sum(self._calculate_cvss_score(sev) * count for sev, count in severity_counts.items()) / max(len(findings), 1)

        # Generate Markdown report
        report = f"""# API Security Assessment Report

## Executive Summary

**Assessment Date:** {scan_metadata.get('scan_timestamp', '2026-03-21')}
**Target API:** {self.api_base_url}
**Assessment Type:** Comprehensive Security Testing
**Risk Score:** {risk_score:.1f}/10

### Key Findings
- **Total Endpoints Tested:** {scan_metadata.get('total_endpoints', 0)}
- **Vulnerability Types Tested:** {', '.join(scan_metadata.get('vulnerability_types_tested', []))}
- **Total Tests Executed:** {scan_metadata.get('total_tests_executed', 0)}
- **Security Issues Found:** {len(findings)}

### Severity Breakdown
- **Critical:** {severity_counts['Critical']}
- **High:** {severity_counts['High']}
- **Medium:** {severity_counts['Medium']}
- **Low:** {severity_counts['Low']}
- **Info:** {severity_counts['Info']}

## Methodology

This assessment followed a comprehensive testing methodology including:

1. **Endpoint Discovery:** Automated discovery and analysis of all API endpoints
2. **Vulnerability Testing:** Systematic testing for {len(scan_metadata.get('vulnerability_types_tested', []))} vulnerability types
3. **Payload Injection:** Advanced payload testing with multiple attack vectors
4. **Response Analysis:** Intelligent analysis of API responses for vulnerability indicators
5. **Risk Assessment:** CVSS-based scoring and impact analysis

## Detailed Findings

"""

        # Add detailed findings
        for i, finding in enumerate(findings, 1):
            report += f"""### Finding {i}: {finding.get('vulnerability_type', 'Unknown')}

**Severity:** {finding.get('severity', 'Unknown')} (CVSS: {finding.get('cvss_score', 0):.1f})
**Endpoint:** {finding.get('endpoint', 'Unknown')}
**URL:** {finding.get('url', 'Unknown')}

**Description:**
{finding.get('description', 'No description available')}

**Evidence:**
```
{finding.get('evidence', 'No evidence available')}
```

**Recommendations:**
"""

            for rec in finding.get('recommendations', []):
                report += f"- {rec}\n"

            report += "\n---\n\n"

        # Add conclusion
        report += f"""## Conclusion

The API security assessment has identified {len(findings)} security issues across {len(vuln_type_counts)} vulnerability categories.

**Overall Risk Assessment:** {'High' if risk_score >= 7.0 else 'Medium' if risk_score >= 4.0 else 'Low'}

### Next Steps
1. **Immediate Actions:** Address all Critical and High severity findings
2. **Short-term:** Implement recommended security controls
3. **Long-term:** Establish continuous security testing and monitoring
4. **Compliance:** Ensure alignment with security standards and regulations

### Recommendations Summary
- Implement input validation and sanitization across all endpoints
- Deploy Web Application Firewall (WAF) for additional protection
- Conduct regular security assessments and penetration testing
- Implement proper authentication and authorization mechanisms
- Enable comprehensive logging and monitoring

---
*Report generated by APIX-Ray Security Assessment Tool*
*Contact: security@apix-ray.com*
"""

        return ToolResult(True, report, f"Executive report generated with {len(findings)} findings")

    async def _execute_test_request(self, request: Dict[str, Any]) -> ToolResult:
        """Execute a test request"""
        try:
            result = await self.request_manager.send_request(request)
            self.test_history.append(result)
            return ToolResult(True, result, "Test request executed successfully")
        except Exception as e:
            return ToolResult(False, None, f"Request execution failed: {str(e)}")

    async def _analyze_test_results(self, test_results: List[Dict[str, Any]], vulnerability_type: str) -> ToolResult:
        """Analyze test results for vulnerabilities"""
        # Simplified analysis - would normally use LLM
        vulnerabilities_found = []

        for result in test_results:
            if result.get("response", {}).get("status_code") in [200, 201, 403, 401]:
                # Placeholder logic - in reality would use LLM analysis
                if "potential vulnerability" in str(result).lower():
                    vulnerabilities_found.append({
                        "type": vulnerability_type,
                        "endpoint": result.get("request", {}).get("endpoint_key"),
                        "severity": "medium",
                        "description": f"Potential {vulnerability_type} vulnerability detected"
                    })

        return ToolResult(True, vulnerabilities_found, f"Analysis of {vulnerability_type} tests completed, found {len(vulnerabilities_found)} potential vulnerabilities. Continue testing other vulnerability types.")

    async def _refine_test_strategy(self, endpoint_key: str, vulnerability_type: str, previous_results: List[Dict[str, Any]]) -> ToolResult:
        """Refine testing strategy based on previous results"""
        # Analyze previous results and suggest new tests
        new_tests = []

        # Placeholder logic - would use LLM to refine
        if previous_results:
            new_tests.append({
                "method": "POST",
                "url": f"{self.api_base_url}/refined-test",
                "vulnerability_type": vulnerability_type,
                "endpoint_key": endpoint_key
            })

        return ToolResult(True, new_tests, f"Refined strategy with {len(new_tests)} additional tests")