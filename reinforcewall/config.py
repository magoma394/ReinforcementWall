"""
Configuration constants for ReinforceWall.

This module contains all configuration parameters including state space
dimensions, reward values, episode settings, and attack probabilities.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional


@dataclass
class RewardConfig:
    """Reward configuration for RL environment."""
    
    # Positive rewards
    BLOCK_ATTACK: float = 10.0  # Successfully block an attack
    LOG_ATTACK: float = 1.0      # Log/alert on an attack
    
    # Negative rewards (penalties)
    BLOCK_LEGITIMATE: float = -5.0    # False positive: block legitimate traffic
    IGNORE_ATTACK: float = -2.0       # False negative: ignore an attack
    IGNORE_LEGITIMATE: float = -1.0    # Minor penalty for ignoring legitimate traffic


@dataclass
class EnvironmentConfig:
    """Environment configuration."""
    
    # Episode settings
    MAX_EPISODE_STEPS: int = 100  # Maximum steps per episode
    STATE_DIMENSION: int = 15     # Number of features in state vector
    
    # Action space
    ACTION_BLOCK: int = 0
    ACTION_ALERT: int = 1
    ACTION_LOG: int = 2
    ACTION_IGNORE: int = 3
    NUM_ACTIONS: int = 4
    
    # State space bounds for normalization
    MAX_REQUESTS_PER_WINDOW: int = 100
    MAX_PAYLOAD_SIZE: int = 10000
    MAX_UNIQUE_ENDPOINTS: int = 50


@dataclass
class AttackConfig:
    """Attack simulation configuration."""
    
    # Attack probabilities (per timestep)
    PROB_SQL_INJECTION: float = 0.08
    PROB_XSS: float = 0.08
    PROB_BRUTE_FORCE: float = 0.10
    PROB_DDOS: float = 0.07
    PROB_COMMAND_INJECTION: float = 0.05
    PROB_PATH_TRAVERSAL: float = 0.04
    PROB_PORT_SCANNING: float = 0.04
    PROB_CSRF: float = 0.03
    PROB_MITM: float = 0.02
    PROB_PHISHING: float = 0.03
    
    # Normal traffic probability
    PROB_NORMAL: float = 0.50
    
    # Attack intensity (requests per attack)
    SQL_INJECTION_REQUESTS: int = 5
    XSS_REQUESTS: int = 3
    BRUTE_FORCE_REQUESTS: int = 10
    DDOS_REQUESTS: int = 50
    DDOS_NUM_IPS: int = 10
    COMMAND_INJECTION_REQUESTS: int = 4
    PATH_TRAVERSAL_REQUESTS: int = 6
    PORT_SCANNING_REQUESTS: int = 20
    PORT_SCANNING_PORTS: Optional[List[int]] = None
    CSRF_REQUESTS: int = 3
    MITM_REQUESTS: int = 5
    PHISHING_REQUESTS: int = 4
    
    # Time window for request frequency calculation
    TIME_WINDOW_SECONDS: int = 60
    
    def __post_init__(self):
        """Initialize default port scanning ports if not provided."""
        if self.PORT_SCANNING_PORTS is None:
            self.PORT_SCANNING_PORTS = [80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 6379]
        
        # Normalize probabilities if they don't sum to 1.0
        total_prob = (
            self.PROB_SQL_INJECTION +
            self.PROB_XSS +
            self.PROB_BRUTE_FORCE +
            self.PROB_DDOS +
            self.PROB_COMMAND_INJECTION +
            self.PROB_PATH_TRAVERSAL +
            self.PROB_PORT_SCANNING +
            self.PROB_CSRF +
            self.PROB_MITM +
            self.PROB_PHISHING +
            self.PROB_NORMAL
        )
        
        if abs(total_prob - 1.0) > 0.01:  # Allow small floating point errors
            # Normalize all probabilities
            scale = 1.0 / total_prob if total_prob > 0 else 1.0
            self.PROB_SQL_INJECTION *= scale
            self.PROB_XSS *= scale
            self.PROB_BRUTE_FORCE *= scale
            self.PROB_DDOS *= scale
            self.PROB_COMMAND_INJECTION *= scale
            self.PROB_PATH_TRAVERSAL *= scale
            self.PROB_PORT_SCANNING *= scale
            self.PROB_CSRF *= scale
            self.PROB_MITM *= scale
            self.PROB_PHISHING *= scale
            self.PROB_NORMAL *= scale


@dataclass
class FirewallConfig:
    """Firewall configuration."""
    
    # Simulation mode (safe for demos, no sudo required)
    SIMULATION_MODE: bool = True
    
    # Logging
    LOG_DIR: str = "data/logs"
    ALERT_LOG_FILE: str = "data/logs/alerts.log"
    TRAFFIC_LOG_FILE: str = "data/logs/traffic.log"
    
    # iptables settings (if not in simulation mode)
    IPTABLES_CHAIN: str = "INPUT"
    IPTABLES_TABLE: str = "filter"


@dataclass
class TrainingConfig:
    """Training configuration for RL agent."""
    
    # Training parameters
    LEARNING_RATE: float = 0.001
    BATCH_SIZE: int = 32
    MEMORY_SIZE: int = 10000
    GAMMA: float = 0.95  # Discount factor
    EPSILON_START: float = 1.0
    EPSILON_END: float = 0.01
    EPSILON_DECAY: float = 0.995


# Global configuration instances
REWARD_CONFIG = RewardConfig()
ENV_CONFIG = EnvironmentConfig()
ATTACK_CONFIG = AttackConfig()
FIREWALL_CONFIG = FirewallConfig()
TRAINING_CONFIG = TrainingConfig()


def get_config_dict() -> Dict[str, Any]:
    """Return all configuration as a dictionary."""
    return {
        "rewards": {
            "block_attack": REWARD_CONFIG.BLOCK_ATTACK,
            "log_attack": REWARD_CONFIG.LOG_ATTACK,
            "block_legitimate": REWARD_CONFIG.BLOCK_LEGITIMATE,
            "ignore_attack": REWARD_CONFIG.IGNORE_ATTACK,
            "ignore_legitimate": REWARD_CONFIG.IGNORE_LEGITIMATE,
        },
        "environment": {
            "max_episode_steps": ENV_CONFIG.MAX_EPISODE_STEPS,
            "state_dimension": ENV_CONFIG.STATE_DIMENSION,
            "num_actions": ENV_CONFIG.NUM_ACTIONS,
        },
        "attacks": {
            "prob_sql_injection": ATTACK_CONFIG.PROB_SQL_INJECTION,
            "prob_xss": ATTACK_CONFIG.PROB_XSS,
            "prob_brute_force": ATTACK_CONFIG.PROB_BRUTE_FORCE,
            "prob_ddos": ATTACK_CONFIG.PROB_DDOS,
            "prob_command_injection": ATTACK_CONFIG.PROB_COMMAND_INJECTION,
            "prob_path_traversal": ATTACK_CONFIG.PROB_PATH_TRAVERSAL,
            "prob_port_scanning": ATTACK_CONFIG.PROB_PORT_SCANNING,
            "prob_csrf": ATTACK_CONFIG.PROB_CSRF,
            "prob_mitm": ATTACK_CONFIG.PROB_MITM,
            "prob_phishing": ATTACK_CONFIG.PROB_PHISHING,
            "prob_normal": ATTACK_CONFIG.PROB_NORMAL,
        },
        "firewall": {
            "simulation_mode": FIREWALL_CONFIG.SIMULATION_MODE,
            "log_dir": FIREWALL_CONFIG.LOG_DIR,
        },
    }

