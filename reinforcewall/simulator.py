"""
Attack traffic simulator for ReinforceWall.

This module generates synthetic network traffic including normal requests
and various attack patterns (SQL Injection, XSS, Brute Force).
"""

import random
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from reinforcewall.state import NetworkRequest
from reinforcewall.config import ATTACK_CONFIG


@dataclass
class TrafficPattern:
    """Represents a traffic generation pattern."""
    
    attack_type: str
    probability: float
    requests_per_attack: int
    ip_pool: List[str]
    
    def __init__(self, attack_type: str, probability: float, requests_per_attack: int):
        self.attack_type = attack_type
        self.probability = probability
        self.requests_per_attack = requests_per_attack
        self.ip_pool = []


class AttackSimulator:
    """Simulates network traffic including attacks."""
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "1' UNION SELECT NULL--",
        "admin'--",
        "' OR 1=1--",
        "1' OR '1'='1",
        "admin'/*",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'>",
        "<body onload=alert('XSS')>",
    ]
    
    # Common endpoints
    ENDPOINTS = [
        "/",
        "/login",
        "/api/users",
        "/api/data",
        "/search",
        "/profile",
        "/admin",
        "/dashboard",
    ]
    
    # HTTP methods
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD"]
    
    def __init__(self, num_ips: int = 50):
        """
        Initialize attack simulator.
        
        Args:
            num_ips: Number of unique IP addresses to simulate
        """
        self.num_ips = num_ips
        self.ip_pool = self._generate_ip_pool(num_ips)
        self.attack_patterns = self._initialize_attack_patterns()
        
        # Traffic generation state
        self.current_attack: Optional[Dict[str, Any]] = None
        self.attack_remaining_requests = 0
        
    def _generate_ip_pool(self, num_ips: int) -> List[str]:
        """Generate pool of IP addresses."""
        ips = []
        base_ip = "192.168.1."
        
        for i in range(1, min(num_ips + 1, 255)):
            ips.append(f"{base_ip}{i}")
        
        # Add some external IPs
        external_base = "10.0.0."
        for i in range(1, min(num_ips // 2 + 1, 255)):
            ips.append(f"{external_base}{i}")
        
        return ips[:num_ips]
    
    def _initialize_attack_patterns(self) -> Dict[str, TrafficPattern]:
        """Initialize attack patterns."""
        return {
            "sql_injection": TrafficPattern(
                "sql_injection",
                ATTACK_CONFIG.PROB_SQL_INJECTION,
                ATTACK_CONFIG.SQL_INJECTION_REQUESTS
            ),
            "xss": TrafficPattern(
                "xss",
                ATTACK_CONFIG.PROB_XSS,
                ATTACK_CONFIG.XSS_REQUESTS
            ),
            "brute_force": TrafficPattern(
                "brute_force",
                ATTACK_CONFIG.PROB_BRUTE_FORCE,
                ATTACK_CONFIG.BRUTE_FORCE_REQUESTS
            ),
            "normal": TrafficPattern(
                "normal",
                ATTACK_CONFIG.PROB_NORMAL,
                1
            ),
        }
    
    def generate_traffic(self) -> NetworkRequest:
        """
        Generate a single network request (normal or attack).
        
        Returns:
            NetworkRequest object
        """
        # Check if we're in the middle of an attack
        if self.current_attack and self.attack_remaining_requests > 0:
            return self._generate_attack_request()
        
        # Decide whether to start a new attack
        attack_type = self._select_attack_type()
        
        if attack_type == "normal":
            return self._generate_normal_request()
        else:
            # Start new attack
            self.current_attack = {
                "type": attack_type,
                "ip": random.choice(self.ip_pool),
                "start_time": time.time(),
            }
            pattern = self.attack_patterns[attack_type]
            self.attack_remaining_requests = pattern.requests_per_attack
            return self._generate_attack_request()
    
    def _select_attack_type(self) -> str:
        """Select attack type based on probabilities."""
        rand = random.random()
        cumulative = 0.0
        
        for attack_type, pattern in self.attack_patterns.items():
            cumulative += pattern.probability
            if rand <= cumulative:
                return attack_type
        
        return "normal"  # Fallback
    
    def _generate_normal_request(self) -> NetworkRequest:
        """Generate a normal network request."""
        ip_address = random.choice(self.ip_pool)
        timestamp = time.time()
        http_method = random.choice(self.HTTP_METHODS)
        endpoint = random.choice(self.ENDPOINTS)
        
        # Normal payload size (50-2000 bytes)
        payload_size = random.randint(50, 2000)
        
        # Generate normal headers
        headers = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)",
            ]),
            "Accept": "text/html,application/json",
        }
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="normal",
            http_method=http_method,
            payload_size=payload_size,
            endpoint=endpoint,
            headers=headers,
            is_attack=False,
        )
    
    def _generate_attack_request(self) -> NetworkRequest:
        """Generate an attack request."""
        if not self.current_attack:
            return self._generate_normal_request()
        
        attack_type = self.current_attack["type"]
        ip_address = self.current_attack["ip"]
        timestamp = time.time()
        
        self.attack_remaining_requests -= 1
        
        # Generate attack-specific request
        if attack_type == "sql_injection":
            return self._generate_sql_injection(ip_address, timestamp)
        elif attack_type == "xss":
            return self._generate_xss(ip_address, timestamp)
        elif attack_type == "brute_force":
            return self._generate_brute_force(ip_address, timestamp)
        else:
            return self._generate_normal_request()
    
    def _generate_sql_injection(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate SQL injection attack request."""
        payload = random.choice(self.SQL_INJECTION_PATTERNS)
        payload_size = len(payload.encode('utf-8'))
        
        # SQL injection typically targets login or search endpoints
        endpoint = random.choice(["/login", "/search", "/api/users"])
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="sql_injection",
            http_method="POST",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "sqlmap/1.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            is_attack=True,
        )
    
    def _generate_xss(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate XSS attack request."""
        payload = random.choice(self.XSS_PATTERNS)
        payload_size = len(payload.encode('utf-8'))
        
        # XSS can target various endpoints
        endpoint = random.choice(self.ENDPOINTS)
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="xss",
            http_method="POST",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; XSSBot/1.0)",
                "Content-Type": "text/html",
            },
            is_attack=True,
        )
    
    def _generate_brute_force(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate brute force attack request."""
        # Brute force typically targets login endpoint
        endpoint = "/login"
        
        # Generate random username/password attempt
        username = random.choice(["admin", "user", "root", "test"])
        password = random.choice(["123456", "password", "admin", "qwerty"])
        payload_size = len(f"{username}:{password}".encode('utf-8'))
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="brute_force",
            http_method="POST",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "python-requests/2.28.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            is_attack=True,
        )
    
    def reset(self):
        """Reset simulator state."""
        self.current_attack = None
        self.attack_remaining_requests = 0

