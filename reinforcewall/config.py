"""
Configuration constants for ReinforceWall.

This module contains all configuration parameters including state space
dimensions, reward values, episode settings, and attack probabilities.
"""

from dataclasses import dataclass
from typing import Dict, Any


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
    PROB_SQL_INJECTION: float = 0.1
    PROB_XSS: float = 0.1
    PROB_BRUTE_FORCE: float = 0.15
    
    # Normal traffic probability
    PROB_NORMAL: float = 0.65
    
    # Attack intensity (requests per attack)
    SQL_INJECTION_REQUESTS: int = 5
    XSS_REQUESTS: int = 3
    BRUTE_FORCE_REQUESTS: int = 10
    
    # Time window for request frequency calculation
    TIME_WINDOW_SECONDS: int = 60


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
            "prob_normal": ATTACK_CONFIG.PROB_NORMAL,
        },
        "firewall": {
            "simulation_mode": FIREWALL_CONFIG.SIMULATION_MODE,
            "log_dir": FIREWALL_CONFIG.LOG_DIR,
        },
    }

