"""
MCP-based Pentest Agent
Uses Model Context Protocol to dynamically call tools during execution
"""

import json
import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import uuid

from mcp_tools import APIPentestTools, ToolResult
from request_manager import HttpRequestManager

logger = logging.getLogger(__name__)

class MCPPentestAgent:
    """
    Agent that uses MCP (Model Context Protocol) to dynamically execute pentesting tasks.
    The LLM can call tools to perform actions like endpoint discovery, test generation, etc.
    """

    def __init__(
        self,
        scan_id: uuid.UUID,
        llm_client,  # Any LLM client (Ollama, xAI, etc.)
        oas_content: Dict[str, Any],
        api_base_url: str,
        max_concurrent_requests: int = 10,
        results_callback: Optional[Callable] = None,
        auth: Optional[str] = None,
        request_limits: Optional[Dict[str, Any]] = None
    ):
        self.scan_id = scan_id
        self.llm_client = llm_client
        self.oas_content = oas_content
        self.api_base_url = api_base_url
        self.max_concurrent_requests = max_concurrent_requests
        self.results_callback = results_callback
        self.auth = auth

        # Dynamic request limit configuration
        self.request_limits = request_limits or {
            "global_max_requests": 100,  # Default global limit
            "per_vulnerability_max": 25,  # Max requests per vulnerability type
            "adaptive_enabled": True,  # Enable adaptive request generation
            "relevance_threshold": 0.7,  # Minimum relevance score for endpoints
            "evolution_factor": 1.2  # How much to increase requests based on findings
        }

        # Initialize components
        self.request_manager = HttpRequestManager(
            base_url=api_base_url,
            max_retries=2,
            retry_delay=0.5,
            default_timeout=30.0,
            auth=auth
        )

        # Initialize MCP tools with request limits
        self.tools = APIPentestTools(oas_content, api_base_url, self.request_manager, self.request_limits)

        # Set relevance function for adaptive endpoint selection
        self.tools._agent_relevance_func = self._calculate_endpoint_relevance

        # State tracking
        self.conversation_history = []
        self.vulnerabilities_found = []
        self.audit_log = []
        self.is_initialized = False

        # KPI tracking for dashboard
        self.scan_start_time = None
        self.requests_executed = 0
        self.requests_successful = 0
        self.response_times = []  # List of response times in ms
        self.tests_generated = 0
        self.low_severity_count = 0
        self.medium_severity_count = 0
        self.high_severity_count = 0
        self.critical_severity_count = 0
        self.info_severity_count = 0

        # Adaptive testing state
        self.endpoint_relevance_scores = {}  # Track relevance of endpoints
        self.vulnerability_context = {}  # Context for each vulnerability type
        self.adaptive_request_counts = {}  # Dynamic request counts per vulnerability

    async def initialize(self):
        """Initialize the agent and discover endpoints"""
        logger.info("Initializing MCP Pentest Agent...")

        # Start scan timer
        self.scan_start_time = datetime.now()

        # Use the discover_endpoints tool
        result = await self.tools.execute_tool("discover_endpoints", {})
        if not result.success:
            raise Exception(f"Failed to discover endpoints: {result.message}")

        self.audit_log.append(f"Agent initialized with {len(result.data)} discovered endpoints")
        self.is_initialized = True
        logger.info("MCP Agent initialized successfully")

    def _get_current_kpis(self) -> Dict[str, Any]:
        """Calculate and return current KPIs for dashboard"""
        # Calculate scan time
        scan_time_seconds = 0
        if self.scan_start_time:
            scan_time_seconds = (datetime.now() - self.scan_start_time).total_seconds()

        # Calculate average response time
        avg_response_time = 0
        if self.response_times:
            avg_response_time = sum(self.response_times) / len(self.response_times)

        # Calculate success rate
        success_rate = 0
        if self.requests_executed > 0:
            success_rate = (self.requests_successful / self.requests_executed) * 100

        # Estimate progress based on workflow completion
        progress = 0
        if len(self.tools.discovered_endpoints) > 0:
            progress = 25  # Endpoints discovered
        if self.tests_generated > 0:
            progress = 50  # Tests generated
        if self.requests_executed > 0:
            progress = 75  # Tests executed
        if len(self.vulnerabilities_found) > 0:
            progress = 90  # Analysis completed

        return {
            "endpoints_discovered": len(self.tools.discovered_endpoints),
            "tests_generated": self.tests_generated,
            "requests_executed": self.requests_executed,
            "vulnerabilities_found": len(self.vulnerabilities_found),
            "high_severity": self.high_severity_count,
            "medium_severity": self.medium_severity_count,
            "low_severity": self.low_severity_count,
            "critical_severity": self.critical_severity_count,
            "info_severity": self.info_severity_count,
            "scan_time_seconds": scan_time_seconds,
            "avg_response_time_ms": round(avg_response_time, 2),
            "success_rate_percent": round(success_rate, 1),
            "progress": progress
        }
    def _calculate_endpoint_relevance(self, endpoint_key: str, vulnerability_type: str) -> float:
        """Calculate relevance score for an endpoint given a vulnerability type"""
        if endpoint_key in self.endpoint_relevance_scores:
            return self.endpoint_relevance_scores[endpoint_key].get(vulnerability_type, 0.5)

        # Parse endpoint
        try:
            method, path = endpoint_key.split(":", 1)
        except ValueError:
            return 0.5

        # Relevance patterns for different vulnerability types
        relevance_patterns = {
            "SQL Injection": [
                ("path", ["query", "search", "filter", "select", "where", "{id}", "{user_id}"]),
                ("method", ["GET", "POST"]),
                ("high_value", 0.9)
            ],
            "XSS": [
                ("path", ["comment", "message", "text", "name", "description", "content"]),
                ("method", ["POST", "PUT"]),
                ("high_value", 0.85)
            ],
            "IDOR": [
                ("path", ["user", "profile", "account", "data", "{user_id}", "{id}"]),
                ("method", ["GET", "PUT", "DELETE"]),
                ("high_value", 0.95)
            ],
            "Broken Access Control": [
                ("path", ["admin", "user", "private", "internal", "config"]),
                ("method", ["GET", "POST", "PUT", "DELETE"]),
                ("high_value", 0.9)
            ],
            "Command Injection": [
                ("path", ["exec", "run", "cmd", "shell", "system", "command"]),
                ("method", ["POST", "GET"]),
                ("high_value", 0.8)
            ]
        }

        patterns = relevance_patterns.get(vulnerability_type, [])
        if not patterns:
            return 0.5

        path_patterns, method_patterns, high_value = patterns

        score = 0.3  # Base score

        # Check path patterns
        path_lower = path.lower()
        for pattern in path_patterns:
            if pattern.lower() in path_lower:
                score = max(score, 0.7)

        # Check method patterns
        if method in method_patterns:
            score += 0.2

        # Boost for high-value endpoints
        if any(keyword in path_lower for keyword in ["login", "auth", "token", "password", "admin"]):
            score = min(score + 0.3, high_value)

        # Store and return
        if endpoint_key not in self.endpoint_relevance_scores:
            self.endpoint_relevance_scores[endpoint_key] = {}
        self.endpoint_relevance_scores[endpoint_key][vulnerability_type] = score

        return score

    def _calculate_adaptive_request_count(self, vulnerability_type: str, base_count: int) -> int:
        """Calculate adaptive request count based on context and previous findings"""
        if not self.request_limits.get("adaptive_enabled", True):
            return base_count

        # Get context for this vulnerability type
        context = self.vulnerability_context.get(vulnerability_type, {
            "findings_count": 0,
            "requests_made": 0,
            "success_rate": 0
        })

        evolution_factor = self.request_limits.get("evolution_factor", 1.2)

        # Increase requests if we found vulnerabilities (indicates this area needs more testing)
        if context["findings_count"] > 0:
            adaptive_count = int(base_count * evolution_factor)
        else:
            adaptive_count = base_count

        # Cap at global max
        global_max = self.request_limits.get("global_max_requests", 100)
        max_per_vuln = self.request_limits.get("per_vulnerability_max", 25)

        return min(adaptive_count, max_per_vuln, global_max // 2)  # Leave room for other vuln types

    def _update_vulnerability_context(self, vulnerability_type: str, findings_count: int, requests_made: int):
        """Update context for a vulnerability type based on results"""
        if vulnerability_type not in self.vulnerability_context:
            self.vulnerability_context[vulnerability_type] = {
                "findings_count": 0,
                "requests_made": 0,
                "success_rate": 0
            }

        context = self.vulnerability_context[vulnerability_type]
        context["findings_count"] += findings_count
        context["requests_made"] += requests_made

        # Calculate success rate (findings per request)
        if context["requests_made"] > 0:
            context["success_rate"] = context["findings_count"] / context["requests_made"]
    async def _call_llm_with_tools(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """Call LLM with tool calling capability"""
        available_tools = self.tools.get_available_tools()

        # Add system message about available tools
        tools_json = json.dumps(available_tools, indent=2)
        system_content = f"""You are an expert API penetration testing agent. You have access to the following tools:

{tools_json}

When you need to perform an action, respond with a tool call in this format:
{{"tool_call": {{"name": "tool_name", "parameters": {{...}}}}}}

Available tools:
- discover_endpoints: Discover API endpoints from OpenAPI spec
- generate_security_tests: Generate test cases for specific vulnerabilities
- execute_test_request: Execute HTTP requests for testing
- analyze_test_results: Analyze results to find vulnerabilities
- refine_test_strategy: Improve testing based on previous results

Always use tools to perform actions rather than describing what you would do."""

        system_message = {
            "role": "system",
            "content": system_content
        }

        full_messages = [system_message] + messages

        # Call LLM
        response = await self.llm_client.chat_completion(
            messages=full_messages,
            temperature=0.1,  # Low temperature for tool calling
            max_tokens=2000
        )

        # Handle different response formats from different LLM clients
        if isinstance(response, dict):
            # OpenAI-style response with choices
            if "choices" in response and response["choices"]:
                content = response["choices"][0]["message"]["content"]
            elif "error" in response:
                return {"error": response["error"]["message"]}
            else:
                content = str(response)
        else:
            # Direct string response (like Ollama)
            content = str(response)

        # Check if content contains a tool call
        if content and "tool_call" in content:
            try:
                tool_call = json.loads(content)["tool_call"]
                return {"tool_call": tool_call}
            except:
                pass

        return {"response": content}

    async def _execute_tool_call(self, tool_call: Dict[str, Any]) -> ToolResult:
        """Execute a tool call from the LLM"""
        tool_name = tool_call.get("name")
        parameters = tool_call.get("parameters", {})

        logger.info(f"Executing tool: {tool_name} with params: {parameters}")
        result = await self.tools.execute_tool(tool_name, parameters)

        if result.success:
            logger.info(f"Tool {tool_name} executed successfully")
            # Update KPIs based on tool execution
            await self._update_kpis_from_tool_result(tool_name, result)
        else:
            logger.error(f"Tool {tool_name} failed: {result.message}")

        return result

    async def _update_kpis_from_tool_result(self, tool_name: str, result: ToolResult):
        """Update KPIs based on tool execution result and notify dashboard"""
        try:
            # Update KPIs based on tool type
            if tool_name == "discover_endpoints" and result.success:
                # Endpoints discovered - already tracked in self.tools.discovered_endpoints
                pass

            elif tool_name == "generate_security_tests" and result.success:
                # Tests generated - count the test requests
                if result.data and isinstance(result.data, list):
                    self.tests_generated += len(result.data)

            elif tool_name == "execute_test_request":
                # Request executed - update counters and response time
                self.requests_executed += 1
                if result.success:
                    self.requests_successful += 1
                if result.data and isinstance(result.data, dict):
                    response_time = result.data.get("response_time_ms")
                    if response_time:
                        self.response_times.append(response_time)

            elif tool_name == "analyze_test_results" and result.success:
                # Vulnerabilities found - update vulnerability counts
                if result.data and isinstance(result.data, list):
                    for vuln in result.data:
                        self.vulnerabilities_found.append(vuln)
                        severity = vuln.get("severity", "low")
                        if severity == "high":
                            self.high_severity_count += 1
                        elif severity == "medium":
                            self.medium_severity_count += 1
                        elif severity == "low":
                            self.low_severity_count += 1
                        elif severity == "critical":
                            self.critical_severity_count += 1
                        else:
                            self.info_severity_count += 1

            # Update adaptive context for scan tools
            if tool_name in ["comprehensive_security_scan", "targeted_security_scan"] and result.success:
                if result.data and "statistics" in result.data:
                    stats = result.data["statistics"]
                    findings_count = stats.get("findings_count", 0)
                    requests_made = stats.get("total_tests_executed", 0)

                    # Extract vulnerability types from parameters
                    tool_params = tool_call.get("parameters", {})
                    vuln_types = tool_params.get("vulnerability_types", [])

                    # Update context for each vulnerability type
                    for vuln_type in vuln_types:
                        self._update_vulnerability_context(vuln_type, findings_count // len(vuln_types), requests_made // len(vuln_types))

            # Notify dashboard with current KPIs
            if self.results_callback:
                current_kpis = self._get_current_kpis()
                await self.results_callback([], current_kpis)  # Empty list for test results, just KPIs

        except Exception as e:
            logger.error(f"Error updating KPIs from tool result: {e}")

    async def run_pentest_workflow(self, vulnerability_types: List[str] = None) -> Dict[str, Any]:
        """
        Run the complete pentesting workflow using MCP tools with LLM-driven decisions
        """
        if not self.is_initialized:
            await self.initialize()

        if vulnerability_types is None:
            vulnerability_types = ["IDOR", "Broken Access Control", "SQL Injection", "XSS"]

        logger.info(f"Starting MCP-based pentest workflow for vulnerabilities: {vulnerability_types}")

        # Track scan completion and results
        scan_completed = False
        comprehensive_scan_results = None

        # Calculate adaptive request limits for this scan
        adaptive_limits = {}
        total_adaptive_requests = 0

        for vuln_type in vulnerability_types:
            base_count = self.request_limits.get("per_vulnerability_max", 25)
            adaptive_count = self._calculate_adaptive_request_count(vuln_type, base_count)
            adaptive_limits[vuln_type] = adaptive_count
            total_adaptive_requests += adaptive_count

        # Cap at global max
        global_max = self.request_limits.get("global_max_requests", 100)
        if total_adaptive_requests > global_max:
            # Scale down proportionally
            scale_factor = global_max / total_adaptive_requests
            for vuln_type in adaptive_limits:
                adaptive_limits[vuln_type] = int(adaptive_limits[vuln_type] * scale_factor)

        # Initialize conversation with the LLM
        conversation = [
            {
                "role": "user",
                "content": f"""You are an expert API penetration testing agent. Your task is to perform a comprehensive, methodical security assessment of an API with ADAPTIVE REQUEST MANAGEMENT.

CRITICAL REQUIREMENTS:
You MUST perform a thorough security assessment following this exact methodology:

1. **Endpoint Discovery**: First discover all API endpoints from the OpenAPI specification
2. **Adaptive Security Scan**: Use intelligent request allocation based on context and previous findings:
   - Global request limit: {global_max} HTTP requests maximum
   - Adaptive allocation per vulnerability: {', '.join([f'{k}={v}' for k,v in adaptive_limits.items()])}
   - Focus on HIGHLY RELEVANT endpoints for each vulnerability type
   - Requests evolve based on findings (more testing where vulnerabilities are found)
3. **Deep Analysis**: Use intelligent_vulnerability_analysis for pattern recognition and false positive reduction
4. **Executive Report**: Generate a detailed Markdown report with all findings, CVSS scores, and remediation recommendations

AVAILABLE TOOLS FOR ADAPTIVE TESTING:
- comprehensive_security_scan: Adaptive testing with configurable request limits
  * max_requests: Automatically calculated based on vulnerability context
  * depth: 'basic', 'intermediate', 'deep' (adapted based on findings)
- targeted_security_scan: Precise control with adaptive request count
  * exact_requests: Dynamically calculated per vulnerability type
  * prioritize_sensitive: AI-powered endpoint prioritization using relevance scoring
- intelligent_vulnerability_analysis: Advanced analysis with ML-like pattern recognition
- generate_executive_report: Creates professional security reports

ADAPTIVE REQUEST MANAGEMENT:
- Initial allocation: {adaptive_limits}
- Evolution factor: {self.request_limits.get('evolution_factor', 1.2)}x more requests where vulnerabilities found
- Relevance threshold: {self.request_limits.get('relevance_threshold', 0.7)} minimum score for endpoint testing
- Quality over quantity: Each request tests a specific, relevant vulnerability scenario

WORKFLOW:
1. Start with endpoint discovery
2. Run adaptive scans with calculated request limits
3. Analyze results and evolve request strategy
4. Generate executive report with findings

Be methodical, thorough, and professional. Use adaptive intelligence to focus testing where it matters most."""
            }
        ]

        max_iterations = 20  # Allow more time for comprehensive testing
        iteration = 0

        while iteration < max_iterations and not scan_completed:
            iteration += 1

            # Get LLM response with tool access
            llm_response = await self._call_llm_with_tools(conversation)

            # Check for errors in LLM response
            if "error" in llm_response:
                logger.error(f"LLM returned error: {llm_response['error']}")
                # Continue with next iteration or break if too many errors
                if iteration >= max_iterations // 2:  # If we're past halfway, stop on error
                    logger.error("Too many LLM errors, stopping workflow")
                    break
                continue

            if "tool_call" in llm_response:
                # Execute the tool call
                tool_call = llm_response["tool_call"]
                tool_result = await self._execute_tool_call(tool_call)

                # Check if comprehensive scan was completed
                if tool_call["name"] == "comprehensive_security_scan" and tool_result.success:
                    scan_completed = True
                    comprehensive_scan_results = tool_result.data
                    logger.info("Comprehensive security scan completed successfully")

                # Add tool result to conversation
                conversation.append({
                    "role": "assistant",
                    "content": f"I called tool: {tool_call['name']} with parameters: {tool_call['parameters']}"
                })

                conversation.append({
                    "role": "user",
                    "content": f"Tool result: {tool_result.message}\nData: {json.dumps(tool_result.data) if tool_result.data else 'None'}"
                })

                # Force continuation after discover_endpoints
                if tool_call["name"] == "discover_endpoints" and tool_result.success:
                    conversation.append({
                        "role": "user",
                        "content": f"Great! Endpoints discovered. Now run comprehensive_security_scan with all vulnerability types: {', '.join(vulnerability_types)} and depth 'deep'."
                    })

                # Check if we should stop (LLM indicates completion)
                if self._should_stop_workflow(conversation):
                    break

            else:
                # LLM provided final answer or summary
                logger.info(f"LLM completed analysis: {llm_response}")
                break

        # Generate final report
        if comprehensive_scan_results and "report" in comprehensive_scan_results:
            report = comprehensive_scan_results["report"]
            logger.info("Using comprehensive scan executive report")
        else:
            report = await self._generate_final_report()

        # Send final KPI update
        if self.results_callback:
            final_kpis = self._get_current_kpis()
            final_kpis["progress"] = 100  # Mark as completed
            final_kpis["status"] = "completed"  # Mark status as completed
            await self.results_callback([], final_kpis)

        return {
            "status": "completed",
            "vulnerabilities_found": len(self.vulnerabilities_found),
            "iterations": iteration,
            "report": report
        }

    async def _run_vulnerability_testing_round(self, vulnerability_type: str, round_num: int):
        """Run initial testing for a specific vulnerability type"""
        logger.info(f"Round {round_num}: Testing {vulnerability_type}")

        # Get all discovered endpoints
        endpoints = list(self.tools.discovered_endpoints.keys())

        for endpoint_key in endpoints:
            # Generate tests for this endpoint and vulnerability
            test_result = await self.tools.execute_tool("generate_security_tests", {
                "endpoint_key": endpoint_key,
                "vulnerability_type": vulnerability_type
            })

            if test_result.success and test_result.data:
                # Execute the generated tests
                for test_request in test_result.data:
                    exec_result = await self.tools.execute_tool("execute_test_request", {
                        "request": test_request
                    })

                    if exec_result.success:
                        # Update results callback if provided
                        if self.results_callback:
                            await self.results_callback([exec_result.data], {
                                "endpoints_discovered": len(endpoints),
                                "tests_generated": len(self.tools.test_history),
                                "high_severity": len([v for v in self.vulnerabilities_found if v.get("severity") == "high"]),
                                "medium_severity": len([v for v in self.vulnerabilities_found if v.get("severity") == "medium"])
                            })

    async def _run_refinement_round(self, vulnerability_type: str, round_num: int):
        """Run refinement testing based on previous results"""
        logger.info(f"Refinement Round {round_num}: Refining {vulnerability_type} tests")

        # Get previous results for this vulnerability type
        previous_results = [r for r in self.tools.test_history
                          if r.get("request", {}).get("vulnerability_type") == vulnerability_type]

        if not previous_results:
            return

        # Group by endpoint
        endpoint_groups = {}
        for result in previous_results:
            endpoint = result.get("request", {}).get("endpoint_key")
            if endpoint:
                if endpoint not in endpoint_groups:
                    endpoint_groups[endpoint] = []
                endpoint_groups[endpoint].append(result)

        # Refine strategy for each endpoint
        for endpoint_key, results in endpoint_groups.items():
            refine_result = await self.tools.execute_tool("refine_test_strategy", {
                "endpoint_key": endpoint_key,
                "vulnerability_type": vulnerability_type,
                "previous_results": results
            })

            if refine_result.success and refine_result.data:
                # Execute refined tests
                for test_request in refine_result.data:
                    exec_result = await self.tools.execute_tool("execute_test_request", {
                        "request": test_request
                    })

                    if exec_result.success and self.results_callback:
                        await self.results_callback([exec_result.data], {
                            "endpoints_discovered": len(self.tools.discovered_endpoints),
                            "tests_generated": len(self.tools.test_history),
                            "high_severity": len([v for v in self.vulnerabilities_found if v.get("severity") == "high"]),
                            "medium_severity": len([v for v in self.vulnerabilities_found if v.get("severity") == "medium"])
                        })

    async def _run_final_analysis(self):
        """Run final analysis on all collected results"""
        logger.info("Running final analysis on all test results")

        # Group results by vulnerability type
        vuln_groups = {}
        for result in self.tools.test_history:
            vuln_type = result.get("request", {}).get("vulnerability_type")
            if vuln_type:
                if vuln_type not in vuln_groups:
                    vuln_groups[vuln_type] = []
                vuln_groups[vuln_type].append(result)

        # Analyze each group
        for vuln_type, results in vuln_groups.items():
            analysis_result = await self.tools.execute_tool("analyze_test_results", {
                "test_results": results,
                "vulnerability_type": vuln_type
            })

            if analysis_result.success and analysis_result.data:
                self.vulnerabilities_found.extend(analysis_result.data)

        logger.info(f"Final analysis complete. Found {len(self.vulnerabilities_found)} vulnerabilities")

    async def _generate_final_report(self) -> str:
        """Generate a final report"""
        report = f"""# APIX-Ray Security Assessment Report
**Scan ID:** {self.scan_id}
**Date:** {datetime.now().isoformat()}
**Target API:** {self.api_base_url}

## Executive Summary
- **Endpoints Discovered:** {len(self.tools.discovered_endpoints)}
- **Tests Executed:** {len(self.tools.test_history)}
- **Vulnerabilities Found:** {len(self.vulnerabilities_found)}

## Vulnerabilities Details
"""

        for vuln in self.vulnerabilities_found:
            report += f"""
### {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'unknown').upper()}
- **Endpoint:** {vuln.get('endpoint', 'N/A')}
- **Description:** {vuln.get('description', 'N/A')}
"""

        report += "\n## Audit Log\n"
        for log_entry in self.audit_log:
            report += f"- {log_entry}\n"

        return report

    async def _call_llm_with_tools(self, conversation: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Call LLM with access to MCP tools
        """
        # Build system message with available tools
        system_message = f"""You are an expert API penetration testing agent with access to specialized tools.

Available tools:
{self._get_tools_description()}

Your task is to systematically test APIs for security vulnerabilities using these tools.
Always use tools when you need to perform actions - don't just describe what you would do.

CRITICAL SCAN CONTROL:
- Use targeted_security_scan for precise control: exact_requests=50, prioritize_sensitive=true
- Use comprehensive_security_scan for broader coverage with max_requests limit
- Each HTTP request should test a specific, relevant vulnerability scenario
- Prioritize sensitive endpoints: login, user data, admin functions, search endpoints
- Quality over quantity: ensure every request contributes to security assessment

IMPORTANT: Continue testing until you have covered all major vulnerability types and endpoints.
Do not stop after testing just one vulnerability. Keep using tools to test additional vulnerabilities.

When you want to use a tool, respond with a JSON object containing:
{{
    "tool_call": {{
        "name": "tool_name",
        "parameters": {{
            "param1": "value1",
            "param2": "value2"
        }}
    }}
}}

Only provide a final summary without tool calls when you have completed comprehensive testing of all vulnerability types."""

        messages = [{"role": "system", "content": system_message}] + conversation

        try:
            # Add timeout for LLM calls to prevent hanging
            response = await asyncio.wait_for(
                self.llm_client.chat_completion(
                    messages=messages,
                    temperature=0.1,  # Low temperature for more deterministic tool selection
                    max_tokens=1000
                ),
                timeout=60.0  # 60 second timeout for LLM calls
            )

            # Handle different response formats from different LLM clients
            if isinstance(response, dict):
                # OpenAI-style response with choices
                if "choices" in response and response["choices"]:
                    content = response["choices"][0]["message"]["content"]
                elif "error" in response:
                    return {"error": response["error"]["message"]}
                else:
                    content = str(response)
            else:
                # Direct string response (like Ollama)
                content = str(response)

            # Try to parse tool call from content
            try:
                parsed = json.loads(content.strip())
                if "tool_call" in parsed:
                    return parsed
            except json.JSONDecodeError:
                # Try to parse natural language tool calls
                tool_call = self._parse_tool_call_from_text(content)
                if tool_call:
                    return {"tool_call": tool_call}

            # If no tool call found, return as regular response
            return {"response": content}

        except asyncio.TimeoutError:
            logger.error("LLM call timed out after 60 seconds")
            return {"error": "LLM call timed out - the API may be overloaded or there may be network issues"}
        except Exception as e:
            logger.error(f"Error calling LLM with tools: {e}")
            return {"error": str(e)}

    def _parse_tool_call_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Parse natural language tool calls from LLM response text.
        Looks for patterns like "I called tool: tool_name with parameters: {...}"
        """
        import re

        # Find the tool name
        tool_match = re.search(r"I called tool:\s*(\w+)", text, re.IGNORECASE)
        if not tool_match:
            return None

        tool_name = tool_match.group(1)

        # Find the parameters JSON - look for the JSON object after "parameters:"
        params_match = re.search(r"with parameters:\s*(\{.+\})", text, re.IGNORECASE | re.DOTALL)
        if not params_match:
            return None

        params_str = params_match.group(1)

        # Convert single quotes to double quotes for valid JSON
        params_str = params_str.replace("'", '"')

        try:
            parameters = json.loads(params_str)
            return {
                "name": tool_name,
                "parameters": parameters
            }
        except json.JSONDecodeError as e:
            logger.warning(f"Could not parse parameters JSON: {params_str} - Error: {e}")
            # Try with ast.literal_eval as fallback for Python-like dict syntax
            try:
                import ast
                parameters = ast.literal_eval(params_str.replace('"', "'"))
                return {
                    "name": tool_name,
                    "parameters": parameters
                }
            except:
                pass
            return None

    def _get_tools_description(self) -> str:
        """Get description of available tools for the LLM"""
        tools = []
        logger.info(f"Getting available tools from {type(self.tools)}")
        available_tools = self.tools.get_available_tools()
        logger.info(f"Available tools: {available_tools}")
        for tool_info in available_tools:
            tool_name = tool_info['name']
            tools.append(f"- {tool_name}: {tool_info['description']}")
            if tool_info.get('parameters') and tool_info['parameters'].get('properties'):
                params = []
                properties = tool_info['parameters']['properties']
                required_params = tool_info['parameters'].get('required', [])
                for param_name, param_info in properties.items():
                    required = "(required)" if param_name in required_params else "(optional)"
                    description = param_info.get('description', '') if isinstance(param_info, dict) else str(param_info)
                    params.append(f"  - {param_name}: {description} {required}")
                tools.append("  Parameters:")
                tools.extend(params)

        return "\n".join(tools)

    async def _execute_tool_call(self, tool_call: Dict[str, Any]) -> ToolResult:
        """Execute a tool call from the LLM"""
        tool_name = tool_call.get("name")
        parameters = tool_call.get("parameters", {})

        logger.info(f"Executing tool: {tool_name} with params: {parameters}")

        try:
            return await self.tools.execute_tool(tool_name, parameters)
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return ToolResult(
                success=False,
                message=f"Error executing tool {tool_name}: {str(e)}",
                data=None
            )

    def _should_stop_workflow(self, conversation: List[Dict[str, Any]]) -> bool:
        """Determine if the workflow should stop based on conversation"""
        # Check the last few messages for completion indicators
        recent_messages = conversation[-3:]  # Last 3 messages

        for msg in recent_messages:
            content = msg.get("content", "").lower()
            if any(phrase in content for phrase in [
                "analysis complete", "testing finished", "no more tests needed",
                "comprehensive assessment done", "final summary"
            ]):
                return True

        return False

    async def close(self):
        """Clean up resources"""
        await self.request_manager.close()
        if hasattr(self.llm_client, 'close'):
            await self.llm_client.close()