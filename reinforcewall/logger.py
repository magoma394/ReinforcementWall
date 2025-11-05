"""
Centralized logging system for ReinforceWall.

This module provides structured logging for all components including
attack events, agent actions, and system events.
"""

import logging
import os
from pathlib import Path
from typing import Optional
from datetime import datetime


class ReinforceWallLogger:
    """Centralized logger for ReinforceWall components."""
    
    _instance: Optional['ReinforceWallLogger'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self.log_dir = Path("data/logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_loggers()
    
    def _setup_loggers(self):
        """Setup all logger instances."""
        # Main logger
        self.main_logger = self._create_logger(
            "reinforcewall",
            self.log_dir / "reinforcewall.log",
            level=logging.INFO
        )
        
        # Attack logger
        self.attack_logger = self._create_logger(
            "attacks",
            self.log_dir / "attacks.log",
            level=logging.WARNING
        )
        
        # Agent logger
        self.agent_logger = self._create_logger(
            "agent",
            self.log_dir / "agent.log",
            level=logging.INFO
        )
        
        # Firewall logger
        self.firewall_logger = self._create_logger(
            "firewall",
            self.log_dir / "firewall.log",
            level=logging.INFO
        )
    
    def _create_logger(
        self,
        name: str,
        log_file: Path,
        level: int = logging.INFO
    ) -> logging.Logger:
        """Create and configure a logger instance."""
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Prevent duplicate handlers
        if logger.handlers:
            return logger
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_format = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_attack(self, attack_type: str, ip_address: str, details: dict):
        """Log an attack event."""
        self.attack_logger.warning(
            f"Attack detected - Type: {attack_type}, IP: {ip_address}, "
            f"Details: {details}"
        )
    
    def log_agent_action(
        self,
        action: int,
        state: dict,
        reward: float,
        episode: int,
        step: int
    ):
        """Log an agent action."""
        action_names = ["BLOCK", "ALERT", "LOG", "IGNORE"]
        self.agent_logger.info(
            f"Episode {episode}, Step {step} - Action: {action_names[action]}, "
            f"Reward: {reward:.2f}"
        )
    
    def log_firewall_action(
        self,
        action: str,
        ip_address: str,
        success: bool,
        details: Optional[str] = None
    ):
        """Log a firewall action."""
        status = "SUCCESS" if success else "FAILED"
        message = f"Firewall {action} - IP: {ip_address}, Status: {status}"
        if details:
            message += f", Details: {details}"
        self.firewall_logger.info(message)
    
    def log_training_metrics(
        self,
        episode: int,
        total_reward: float,
        steps: int,
        attacks_detected: int,
        false_positives: int,
        false_negatives: int
    ):
        """Log training metrics for an episode."""
        accuracy = (attacks_detected / (attacks_detected + false_negatives)) * 100 if (attacks_detected + false_negatives) > 0 else 0
        self.main_logger.info(
            f"Episode {episode} - Reward: {total_reward:.2f}, Steps: {steps}, "
            f"Attacks Detected: {attacks_detected}, FP: {false_positives}, "
            f"FN: {false_negatives}, Accuracy: {accuracy:.2f}%"
        )


# Global logger instance
logger = ReinforceWallLogger()

