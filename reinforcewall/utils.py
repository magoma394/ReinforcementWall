"""
Utility functions for ReinforceWall.

This module provides helper functions for state normalization, IP encoding,
and other common operations.
"""

import hashlib
import ipaddress
from typing import List, Union
import numpy as np


def normalize_value(value: float, min_val: float, max_val: float) -> float:
    """
    Normalize a value to [0, 1] range.
    
    Args:
        value: Value to normalize
        min_val: Minimum possible value
        max_val: Maximum possible value
    
    Returns:
        Normalized value in [0, 1] range
    """
    if max_val == min_val:
        return 0.0
    normalized = (value - min_val) / (max_val - min_val)
    return max(0.0, min(1.0, normalized))  # Clamp to [0, 1]


def ip_to_hash(ip_address: str) -> int:
    """
    Convert IP address to a hash integer for use in state representation.
    
    Args:
        ip_address: IP address string (e.g., "192.168.1.1")
    
    Returns:
        Hash integer (0-255 range for simple encoding)
    """
    try:
        # Validate IP address
        ip = ipaddress.ip_address(ip_address)
        
        # Convert to integer hash (0-255 range)
        ip_int = int(ip)
        if isinstance(ip, ipaddress.IPv4Address):
            # Use last octet for IPv4
            return ip_int % 256
        else:
            # Use last 8 bits for IPv6
            return ip_int % 256
    except ValueError:
        # Invalid IP, return 0
        return 0


def ip_to_numeric(ip_address: str) -> float:
    """
    Convert IP address to normalized numeric value.
    
    Args:
        ip_address: IP address string
    
    Returns:
        Normalized value between 0 and 1
    """
    hash_val = ip_to_hash(ip_address)
    return hash_val / 255.0


def encode_payload_type(payload_type: str) -> int:
    """
    Encode payload type to integer.
    
    Args:
        payload_type: Type of payload ("normal", "sql_injection", "xss", "brute_force")
    
    Returns:
        Encoded integer (0=normal, 1=SQL, 2=XSS, 3=brute_force)
    """
    encoding = {
        "normal": 0,
        "sql_injection": 1,
        "xss": 2,
        "brute_force": 3,
    }
    return encoding.get(payload_type.lower(), 0)


def encode_http_method(method: str) -> int:
    """
    Encode HTTP method to integer.
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
    
    Returns:
        Encoded integer
    """
    encoding = {
        "GET": 0,
        "POST": 1,
        "PUT": 2,
        "DELETE": 3,
        "HEAD": 4,
        "OPTIONS": 5,
    }
    return encoding.get(method.upper(), 0)


def normalize_state_vector(state: List[float], max_values: List[float]) -> np.ndarray:
    """
    Normalize a state vector using maximum values.
    
    Args:
        state: List of state values
        max_values: List of maximum values for each feature
    
    Returns:
        Normalized numpy array
    """
    state_array = np.array(state, dtype=np.float32)
    max_array = np.array(max_values, dtype=np.float32)
    
    # Avoid division by zero
    max_array = np.where(max_array == 0, 1.0, max_array)
    
    normalized = state_array / max_array
    return np.clip(normalized, 0.0, 1.0)


def calculate_request_frequency(timestamps: List[float], window_seconds: int) -> float:
    """
    Calculate request frequency in a time window.
    
    Args:
        timestamps: List of request timestamps
        window_seconds: Time window size in seconds
    
    Returns:
        Requests per second (normalized)
    """
    if not timestamps:
        return 0.0
    
    if len(timestamps) == 1:
        return 1.0 / window_seconds
    
    # Calculate requests per second
    time_span = max(timestamps) - min(timestamps)
    if time_span == 0:
        time_span = 1.0
    
    requests_per_second = len(timestamps) / max(time_span, 1.0)
    
    # Normalize (assuming max 100 requests per second)
    return min(requests_per_second / 100.0, 1.0)


def validate_ip_address(ip_address: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    Args:
        ip_address: IP address string to validate
    
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def get_action_name(action: int) -> str:
    """
    Get human-readable action name.
    
    Args:
        action: Action integer (0-3)
    
    Returns:
        Action name string
    """
    action_names = {
        0: "BLOCK",
        1: "ALERT",
        2: "LOG",
        3: "IGNORE",
    }
    return action_names.get(action, "UNKNOWN")

