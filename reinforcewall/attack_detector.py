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
    
    def __init__(self):
        """Initialize attack detector."""
        self.request_counts: Dict[str, int] = {}
        self.request_timestamps: Dict[str, list] = {}
    
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
    
    def reset(self):
        """Reset detector state."""
        self.request_counts.clear()
        self.request_timestamps.clear()
    
    def get_ground_truth(self, request: NetworkRequest) -> Tuple[bool, str]:
        """
        Get ground truth label for a request (for training/evaluation).
        
        Args:
            request: Network request
        
        Returns:
            Tuple of (is_attack, attack_type)
        """
        return (request.is_attack, request.payload_type)

