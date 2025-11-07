"""
State representation and feature extraction for ReinforceWall.

This module handles state representation, feature extraction from network
requests, and state normalization for the RL environment.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import numpy as np
from datetime import datetime

from reinforcewall.config import ENV_CONFIG, ATTACK_CONFIG
from reinforcewall.utils import (
    normalize_value,
    ip_to_numeric,
    encode_payload_type,
    encode_http_method,
    calculate_request_frequency,
    get_max_attack_types,
)


@dataclass
class NetworkRequest:
    """Represents a network request with metadata."""
    
    ip_address: str
    timestamp: float
    payload_type: str  # "normal", "sql_injection", "xss", "brute_force", "ddos", 
                       # "command_injection", "path_traversal", "port_scanning",
                       # "csrf", "mitm", "phishing"
    http_method: str
    payload_size: int
    endpoint: str
    headers: Dict[str, str]
    is_attack: bool
    
    def __post_init__(self):
        """Validate request data."""
        if not self.ip_address:
            raise ValueError("IP address is required")
        if self.timestamp <= 0:
            raise ValueError("Timestamp must be positive")


class StateExtractor:
    """Extracts features from network requests to create state vectors."""
    
    def __init__(self):
        """Initialize state extractor."""
        self.state_dimension = ENV_CONFIG.STATE_DIMENSION
        self.time_window = ATTACK_CONFIG.TIME_WINDOW_SECONDS
        
        # Request history for frequency calculation
        self.request_history: List[NetworkRequest] = []
        self.max_history_size = 1000
    
    def add_request(self, request: NetworkRequest):
        """Add a request to the history for frequency calculation."""
        self.request_history.append(request)
        
        # Limit history size
        if len(self.request_history) > self.max_history_size:
            self.request_history = self.request_history[-self.max_history_size:]
    
    def extract_features(self, current_request: NetworkRequest) -> np.ndarray:
        """
        Extract features from current request and history.
        
        Args:
            current_request: Current network request to process
        
        Returns:
            Normalized state vector as numpy array
        """
        # Add current request to history
        self.add_request(current_request)
        
        # Extract features
        features = []
        
        # 1. Request frequency (requests per time window)
        recent_requests = self._get_recent_requests(current_request.timestamp)
        request_freq = calculate_request_frequency(
            [r.timestamp for r in recent_requests],
            self.time_window
        )
        features.append(request_freq)
        
        # 2. Payload type (encoded)
        payload_type_encoded = encode_payload_type(current_request.payload_type)
        max_attack_types = get_max_attack_types()
        features.append(payload_type_encoded / max_attack_types)  # Normalize to [0, 1]
        
        # 3. IP address (normalized hash)
        ip_numeric = ip_to_numeric(current_request.ip_address)
        features.append(ip_numeric)
        
        # 4. IP behavior - request count from this IP
        ip_request_count = self._count_ip_requests(
            current_request.ip_address,
            current_request.timestamp
        )
        features.append(normalize_value(
            ip_request_count,
            0,
            ENV_CONFIG.MAX_REQUESTS_PER_WINDOW
        ))
        
        # 5. IP behavior - unique endpoints accessed
        unique_endpoints = self._count_unique_endpoints(
            current_request.ip_address,
            current_request.timestamp
        )
        features.append(normalize_value(
            unique_endpoints,
            0,
            ENV_CONFIG.MAX_UNIQUE_ENDPOINTS
        ))
        
        # 6. Request size
        features.append(normalize_value(
            current_request.payload_size,
            0,
            ENV_CONFIG.MAX_PAYLOAD_SIZE
        ))
        
        # 7. HTTP method (encoded)
        method_encoded = encode_http_method(current_request.http_method)
        features.append(method_encoded / 5.0)  # Normalize to [0, 1]
        
        # 8. Attack probability (based on payload patterns)
        attack_prob = 1.0 if current_request.is_attack else 0.0
        features.append(attack_prob)
        
        # 9. Time-based features (hour of day, normalized)
        hour_of_day = datetime.fromtimestamp(current_request.timestamp).hour
        features.append(hour_of_day / 23.0)  # Normalize to [0, 1]
        
        # 10. Request rate acceleration (change in request rate)
        rate_acceleration = self._calculate_rate_acceleration(
            current_request.ip_address,
            current_request.timestamp
        )
        features.append(min(rate_acceleration, 1.0))
        
        # 11. Average payload size from this IP
        avg_payload_size = self._average_payload_size(
            current_request.ip_address,
            current_request.timestamp
        )
        features.append(normalize_value(
            avg_payload_size,
            0,
            ENV_CONFIG.MAX_PAYLOAD_SIZE
        ))
        
        # 12. Suspicious pattern indicator
        suspicious_score = self._calculate_suspicious_score(
            current_request,
            recent_requests
        )
        features.append(suspicious_score)
        
        # 13. Time since last request from this IP
        time_since_last = self._time_since_last_request(
            current_request.ip_address,
            current_request.timestamp
        )
        features.append(min(time_since_last / 3600.0, 1.0))  # Normalize to 1 hour
        
        # 14. Request diversity (ratio of unique endpoints to total requests)
        diversity = self._calculate_diversity(
            current_request.ip_address,
            current_request.timestamp
        )
        features.append(diversity)
        
        # 15. Attack type distribution (if attack)
        if current_request.is_attack:
            attack_type_dist = self._attack_type_distribution(
                current_request.ip_address,
                current_request.timestamp
            )
        else:
            attack_type_dist = 0.0
        features.append(attack_type_dist)
        
        # Pad or truncate to match state dimension
        while len(features) < self.state_dimension:
            features.append(0.0)
        
        features = features[:self.state_dimension]
        
        # Convert to numpy array and ensure it's in [0, 1] range
        state_vector = np.array(features, dtype=np.float32)
        state_vector = np.clip(state_vector, 0.0, 1.0)
        
        return state_vector
    
    def _get_recent_requests(self, current_timestamp: float) -> List[NetworkRequest]:
        """Get requests within the time window."""
        cutoff_time = current_timestamp - self.time_window
        return [
            req for req in self.request_history
            if req.timestamp >= cutoff_time
        ]
    
    def _count_ip_requests(self, ip_address: str, current_timestamp: float) -> int:
        """Count requests from IP within time window."""
        recent_requests = self._get_recent_requests(current_timestamp)
        return sum(1 for req in recent_requests if req.ip_address == ip_address)
    
    def _count_unique_endpoints(self, ip_address: str, current_timestamp: float) -> int:
        """Count unique endpoints accessed by IP."""
        recent_requests = self._get_recent_requests(current_timestamp)
        ip_requests = [req for req in recent_requests if req.ip_address == ip_address]
        unique_endpoints = set(req.endpoint for req in ip_requests)
        return len(unique_endpoints)
    
    def _calculate_rate_acceleration(
        self,
        ip_address: str,
        current_timestamp: float
    ) -> float:
        """Calculate change in request rate (acceleration)."""
        recent_requests = self._get_recent_requests(current_timestamp)
        ip_requests = [req for req in recent_requests if req.ip_address == ip_address]
        
        if len(ip_requests) < 2:
            return 0.0
        
        # Split into two time windows
        mid_time = current_timestamp - (self.time_window / 2)
        first_half = [r for r in ip_requests if r.timestamp < mid_time]
        second_half = [r for r in ip_requests if r.timestamp >= mid_time]
        
        rate1 = len(first_half) / (self.time_window / 2) if first_half else 0.0
        rate2 = len(second_half) / (self.time_window / 2) if second_half else 0.0
        
        acceleration = (rate2 - rate1) / max(rate1, 0.1)  # Normalized change
        return min(abs(acceleration), 1.0)
    
    def _average_payload_size(
        self,
        ip_address: str,
        current_timestamp: float
    ) -> float:
        """Calculate average payload size from IP."""
        recent_requests = self._get_recent_requests(current_timestamp)
        ip_requests = [req for req in recent_requests if req.ip_address == ip_address]
        
        if not ip_requests:
            return 0.0
        
        avg_size = sum(req.payload_size for req in ip_requests) / len(ip_requests)
        return avg_size
    
    def _calculate_suspicious_score(
        self,
        current_request: NetworkRequest,
        recent_requests: List[NetworkRequest]
    ) -> float:
        """Calculate suspicious behavior score."""
        score = 0.0
        
        # High request frequency
        if len(recent_requests) > 50:
            score += 0.3
        
        # Large payload size
        if current_request.payload_size > 5000:
            score += 0.2
        
        # Multiple endpoints from same IP
        ip_endpoints = set(
            req.endpoint for req in recent_requests
            if req.ip_address == current_request.ip_address
        )
        if len(ip_endpoints) > 10:
            score += 0.2
        
        # POST requests (potentially more suspicious)
        if current_request.http_method == "POST":
            score += 0.1
        
        # Known attack type
        if current_request.is_attack:
            score += 0.2
        
        return min(score, 1.0)
    
    def _time_since_last_request(
        self,
        ip_address: str,
        current_timestamp: float
    ) -> float:
        """Calculate time since last request from this IP."""
        ip_requests = [
            req for req in self.request_history
            if req.ip_address == ip_address and req.timestamp < current_timestamp
        ]
        
        if not ip_requests:
            return 3600.0  # Default to 1 hour
        
        last_request = max(ip_requests, key=lambda r: r.timestamp)
        return current_timestamp - last_request.timestamp
    
    def _calculate_diversity(
        self,
        ip_address: str,
        current_timestamp: float
    ) -> float:
        """Calculate request diversity (unique endpoints / total requests)."""
        recent_requests = self._get_recent_requests(current_timestamp)
        ip_requests = [req for req in recent_requests if req.ip_address == ip_address]
        
        if not ip_requests:
            return 0.0
        
        unique_endpoints = set(req.endpoint for req in ip_requests)
        diversity = len(unique_endpoints) / len(ip_requests)
        return diversity
    
    def _attack_type_distribution(
        self,
        ip_address: str,
        current_timestamp: float
    ) -> float:
        """Calculate distribution of attack types from this IP."""
        recent_requests = self._get_recent_requests(current_timestamp)
        ip_attacks = [
            req for req in recent_requests
            if req.ip_address == ip_address and req.is_attack
        ]
        
        if not ip_attacks:
            return 0.0
        
        # Count different attack types
        attack_types = {}
        for req in ip_attacks:
            attack_types[req.payload_type] = attack_types.get(req.payload_type, 0) + 1
        
        # Calculate entropy-like metric (higher if mixed attack types)
        total = len(ip_attacks)
        if total == 0:
            return 0.0
        
        max_attack_types = get_max_attack_types()
        diversity = len(attack_types) / max_attack_types  # Normalize by max attack types
        return min(diversity, 1.0)
    
    def reset(self):
        """Reset request history."""
        self.request_history = []

