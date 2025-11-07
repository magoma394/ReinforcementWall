"""
Baseline attack detector for ReinforceWall.

This module provides rule-based attack detection heuristics that can be
used as ground truth labels for training and comparing RL agent performance.
"""

import re
from typing import Dict, Any, Tuple
from dataclasses import dataclass

from reinforcewall.state import NetworkRequest
from reinforcewall.simulator import AttackSimulator


@dataclass
class DetectionResult:
    """Result of attack detection."""
    
    is_attack: bool
    attack_type: str
    confidence: float
    reason: str


class AttackDetector:
    """Rule-based attack detector using signature-based patterns."""
    
    # SQL Injection patterns
    SQL_PATTERNS = [
        r"'.*OR.*'1'='1",
        r"'.*OR.*1=1",
        r"'.*--",
        r"'.*;.*DROP",
        r"UNION.*SELECT",
        r"'.*/\*",
        r"'.*OR.*'1'='1'",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script.*>",
        r"<img.*onerror",
        r"<svg.*onload",
        r"javascript:",
        r"<iframe.*src",
        r"<body.*onload",
        r"onclick=.*alert",
    ]
    
    # Brute force indicators
    BRUTE_FORCE_THRESHOLD = 5  # Requests per minute from same IP
    BRUTE_FORCE_ENDPOINTS = ["/login", "/auth", "/api/login"]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r";\s*(cat|ls|rm|wget|curl|nc|bash|sh)",
        r"\|\s*(whoami|id|uname|nc)",
        r"&&\s*(rm|wget|curl|nc)",
        r"`[^`]+`",
        r"\$\([^)]+\)",
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.[\\/]",
        r"\.\.%2[Ff]",
        r"%2[eE]%2[eE]",
        r"\.\.[\\/]\.\.[\\/]",
    ]
    
    # DDoS indicators
    DDOS_THRESHOLD = 30  # Requests per minute across all IPs
    DDOS_IP_COUNT_THRESHOLD = 5  # Number of unique IPs in short time
    
    # Port scanning indicators
    PORT_SCAN_THRESHOLD = 10  # Different endpoints/ports per minute from same IP
    
    def __init__(self):
        """Initialize attack detector."""
        self.request_counts: Dict[str, int] = {}
        self.request_timestamps: Dict[str, list] = {}
        self.ip_endpoints: Dict[str, set] = {}  # Track unique endpoints per IP
        self.global_request_timestamps: list = []  # For DDoS detection
    
    def detect(self, request: NetworkRequest) -> DetectionResult:
        """
        Detect if a request is an attack using rule-based heuristics.
        
        Args:
            request: Network request to analyze
        
        Returns:
            DetectionResult with detection information
        """
        # Check for SQL injection
        sql_result = self._detect_sql_injection(request)
        if sql_result.is_attack:
            return sql_result
        
        # Check for XSS
        xss_result = self._detect_xss(request)
        if xss_result.is_attack:
            return xss_result
        
        # Check for brute force
        brute_result = self._detect_brute_force(request)
        if brute_result.is_attack:
            return brute_result
        
        # Check for DDoS
        ddos_result = self._detect_ddos(request)
        if ddos_result.is_attack:
            return ddos_result
        
        # Check for command injection
        cmd_result = self._detect_command_injection(request)
        if cmd_result.is_attack:
            return cmd_result
        
        # Check for path traversal
        path_result = self._detect_path_traversal(request)
        if path_result.is_attack:
            return path_result
        
        # Check for port scanning
        port_result = self._detect_port_scanning(request)
        if port_result.is_attack:
            return port_result
        
        # Check for CSRF
        csrf_result = self._detect_csrf(request)
        if csrf_result.is_attack:
            return csrf_result
        
        # Check for MITM
        mitm_result = self._detect_mitm(request)
        if mitm_result.is_attack:
            return mitm_result
        
        # Check for phishing
        phishing_result = self._detect_phishing(request)
        if phishing_result.is_attack:
            return phishing_result
        
        # Normal request
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=1.0,
            reason="No attack patterns detected"
        )
    
    def _detect_sql_injection(self, request: NetworkRequest) -> DetectionResult:
        """Detect SQL injection patterns."""
        # In a real implementation, we'd check the payload
        # For now, we use the payload_type field
        if request.payload_type == "sql_injection":
            return DetectionResult(
                is_attack=True,
                attack_type="sql_injection",
                confidence=0.9,
                reason="SQL injection pattern detected"
            )
        
        # Pattern matching (if we had actual payload strings)
        # This is a simplified check
        if request.endpoint in ["/login", "/search"] and request.http_method == "POST":
            # High suspicion for POST requests to login/search
            if request.payload_size > 1000:  # Large payload might indicate injection
                return DetectionResult(
                    is_attack=True,
                    attack_type="sql_injection",
                    confidence=0.6,
                    reason="Suspicious POST request to sensitive endpoint"
                )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_xss(self, request: NetworkRequest) -> DetectionResult:
        """Detect XSS patterns."""
        if request.payload_type == "xss":
            return DetectionResult(
                is_attack=True,
                attack_type="xss",
                confidence=0.9,
                reason="XSS pattern detected"
            )
        
        # Pattern matching for XSS
        if request.http_method == "POST" and request.payload_size > 500:
            # XSS attacks often have larger payloads
            return DetectionResult(
                is_attack=True,
                attack_type="xss",
                confidence=0.5,
                reason="Suspicious payload size for POST request"
            )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_brute_force(self, request: NetworkRequest) -> DetectionResult:
        """Detect brute force attack patterns."""
        if request.payload_type == "brute_force":
            return DetectionResult(
                is_attack=True,
                attack_type="brute_force",
                confidence=0.95,
                reason="Brute force pattern detected"
            )
        
        # Track requests from same IP
        ip = request.ip_address
        endpoint = request.endpoint
        
        # Check if targeting login endpoint
        if endpoint in self.BRUTE_FORCE_ENDPOINTS:
            # Update request count
            if ip not in self.request_counts:
                self.request_counts[ip] = 0
                self.request_timestamps[ip] = []
            
            self.request_counts[ip] += 1
            self.request_timestamps[ip].append(request.timestamp)
            
            # Check frequency (requests per minute)
            recent_requests = [
                ts for ts in self.request_timestamps[ip]
                if request.timestamp - ts < 60  # Last minute
            ]
            
            if len(recent_requests) >= self.BRUTE_FORCE_THRESHOLD:
                return DetectionResult(
                    is_attack=True,
                    attack_type="brute_force",
                    confidence=0.8,
                    reason=f"High frequency requests to {endpoint} ({len(recent_requests)}/min)"
                )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_ddos(self, request: NetworkRequest) -> DetectionResult:
        """Detect DDoS attack patterns (high volume from multiple IPs)."""
        if request.payload_type == "ddos":
            return DetectionResult(
                is_attack=True,
                attack_type="ddos",
                confidence=0.95,
                reason="DDoS pattern detected"
            )
        
        # Track global request timestamps
        self.global_request_timestamps.append(request.timestamp)
        
        # Clean old timestamps (older than 1 minute)
        cutoff_time = request.timestamp - 60
        self.global_request_timestamps = [
            ts for ts in self.global_request_timestamps if ts >= cutoff_time
        ]
        
        # Check for high global request frequency
        if len(self.global_request_timestamps) >= self.DDOS_THRESHOLD:
            # Check number of unique IPs in recent requests
            # This is simplified - in real implementation, we'd track IPs
            return DetectionResult(
                is_attack=True,
                attack_type="ddos",
                confidence=0.7,
                reason=f"High global request frequency ({len(self.global_request_timestamps)}/min)"
            )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_command_injection(self, request: NetworkRequest) -> DetectionResult:
        """Detect command injection patterns."""
        if request.payload_type == "command_injection":
            return DetectionResult(
                is_attack=True,
                attack_type="command_injection",
                confidence=0.9,
                reason="Command injection pattern detected"
            )
        
        # Pattern matching (if we had actual payload strings)
        # Check endpoint for command execution indicators
        if any(keyword in request.endpoint.lower() for keyword in ["execute", "system", "command", "run"]):
            if request.http_method == "POST" and request.payload_size > 50:
                return DetectionResult(
                    is_attack=True,
                    attack_type="command_injection",
                    confidence=0.6,
                    reason="Suspicious POST request to command execution endpoint"
                )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_path_traversal(self, request: NetworkRequest) -> DetectionResult:
        """Detect path traversal patterns."""
        if request.payload_type == "path_traversal":
            return DetectionResult(
                is_attack=True,
                attack_type="path_traversal",
                confidence=0.9,
                reason="Path traversal pattern detected"
            )
        
        # Check endpoint for path traversal patterns
        endpoint_lower = request.endpoint.lower()
        if any(keyword in endpoint_lower for keyword in ["file", "download", "read", "document"]):
            # Check for directory traversal sequences
            if ".." in endpoint_lower or "%2e%2e" in endpoint_lower.lower():
                return DetectionResult(
                    is_attack=True,
                    attack_type="path_traversal",
                    confidence=0.8,
                    reason="Path traversal sequence detected in endpoint"
                )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_port_scanning(self, request: NetworkRequest) -> DetectionResult:
        """Detect port scanning patterns."""
        if request.payload_type == "port_scanning":
            return DetectionResult(
                is_attack=True,
                attack_type="port_scanning",
                confidence=0.95,
                reason="Port scanning pattern detected"
            )
        
        # Track unique endpoints accessed by IP
        ip = request.ip_address
        if ip not in self.ip_endpoints:
            self.ip_endpoints[ip] = set()
        
        self.ip_endpoints[ip].add(request.endpoint)
        
        # Clean old data
        if ip not in self.request_timestamps:
            self.request_timestamps[ip] = []
        
        self.request_timestamps[ip].append(request.timestamp)
        
        # Check for sequential access to many different endpoints (port scanning)
        recent_timestamps = [
            ts for ts in self.request_timestamps[ip]
            if request.timestamp - ts < 60  # Last minute
        ]
        
        unique_endpoints = len(self.ip_endpoints[ip])
        
        if len(recent_timestamps) >= self.PORT_SCAN_THRESHOLD and unique_endpoints >= 5:
            return DetectionResult(
                is_attack=True,
                attack_type="port_scanning",
                confidence=0.75,
                reason=f"High endpoint diversity from single IP ({unique_endpoints} unique endpoints)"
            )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_csrf(self, request: NetworkRequest) -> DetectionResult:
        """Detect CSRF attack patterns."""
        if request.payload_type == "csrf":
            return DetectionResult(
                is_attack=True,
                attack_type="csrf",
                confidence=0.9,
                reason="CSRF pattern detected"
            )
        
        # Check for suspicious referer and state-changing operations
        endpoint_lower = request.endpoint.lower()
        if request.http_method == "POST" and any(keyword in endpoint_lower for keyword in ["transfer", "update", "change", "modify"]):
            # Check for suspicious referer patterns
            if "referer" in request.headers:
                referer = request.headers.get("referer", "").lower()
                if any(suspicious in referer for suspicious in ["evil", "malicious", "fake", "phishing"]):
                    return DetectionResult(
                        is_attack=True,
                        attack_type="csrf",
                        confidence=0.7,
                        reason="Suspicious referer with state-changing operation"
                    )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_mitm(self, request: NetworkRequest) -> DetectionResult:
        """Detect MITM attack patterns."""
        if request.payload_type == "mitm":
            return DetectionResult(
                is_attack=True,
                attack_type="mitm",
                confidence=0.9,
                reason="MITM pattern detected"
            )
        
        # Check for suspicious proxy headers
        headers_lower = {k.lower(): v.lower() for k, v in request.headers.items()}
        
        # Check for suspicious X-Forwarded-For or Via headers
        if "x-forwarded-for" in headers_lower:
            # Multiple IPs or suspicious pattern
            xff = headers_lower["x-forwarded-for"]
            if "," in xff or xff.startswith("192.168") or xff.startswith("10."):
                return DetectionResult(
                    is_attack=True,
                    attack_type="mitm",
                    confidence=0.6,
                    reason="Suspicious proxy headers detected"
                )
        
        if "via" in headers_lower and "proxy" in headers_lower["via"]:
            return DetectionResult(
                is_attack=True,
                attack_type="mitm",
                confidence=0.65,
                reason="Suspicious Via header with proxy"
            )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def _detect_phishing(self, request: NetworkRequest) -> DetectionResult:
        """Detect phishing attack patterns."""
        if request.payload_type == "phishing":
            return DetectionResult(
                is_attack=True,
                attack_type="phishing",
                confidence=0.9,
                reason="Phishing pattern detected"
            )
        
        # Check for suspicious redirect patterns
        endpoint_lower = request.endpoint.lower()
        query_params = endpoint_lower.split("?")[1] if "?" in endpoint_lower else ""
        
        if any(keyword in endpoint_lower for keyword in ["login", "verify", "reset", "update"]):
            # Check for redirect parameters
            if any(suspicious in query_params for suspicious in ["redirect", "url", "return", "next"]):
                if any(evil in query_params for evil in ["evil", "fake", "phishing", "malicious"]):
                    return DetectionResult(
                        is_attack=True,
                        attack_type="phishing",
                        confidence=0.8,
                        reason="Suspicious redirect pattern detected"
                    )
        
        # Check referer for phishing sites
        if "referer" in request.headers:
            referer = request.headers.get("referer", "").lower()
            if any(suspicious in referer for suspicious in ["fake", "phishing", "evil", "malicious"]):
                return DetectionResult(
                    is_attack=True,
                    attack_type="phishing",
                    confidence=0.7,
                    reason="Suspicious referer detected"
                )
        
        return DetectionResult(
            is_attack=False,
            attack_type="normal",
            confidence=0.0,
            reason=""
        )
    
    def reset(self):
        """Reset detector state."""
        self.request_counts.clear()
        self.request_timestamps.clear()
        self.ip_endpoints.clear()
        self.global_request_timestamps.clear()
    
    def get_ground_truth(self, request: NetworkRequest) -> Tuple[bool, str]:
        """
        Get ground truth label for a request (for training/evaluation).
        
        Args:
            request: Network request
        
        Returns:
            Tuple of (is_attack, attack_type)
        """
        return (request.is_attack, request.payload_type)

