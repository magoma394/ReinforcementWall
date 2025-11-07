"""
Metrics tracking for ReinforceWall training.

This module tracks and exports training metrics including episode rewards,
attack detection rates, false positives/negatives, and action distributions.
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime

from reinforcewall.logger import logger


@dataclass
class EpisodeMetrics:
    """Metrics for a single episode."""
    
    episode: int
    total_reward: float
    steps: int
    attacks_detected: int
    false_positives: int
    false_negatives: int
    true_positives: int
    true_negatives: int
    action_distribution: Dict[int, int]  # Action -> count
    avg_reward_per_step: float = field(init=False)  # Will be calculated in __post_init__
    
    def __post_init__(self):
        """Calculate derived metrics."""
        if self.steps > 0:
            self.avg_reward_per_step = self.total_reward / self.steps
        else:
            self.avg_reward_per_step = 0.0
        
        # Calculate accuracy metrics
        total_attacks = self.attacks_detected + self.false_negatives
        total_legitimate = self.true_negatives + self.false_positives
        
        if total_attacks > 0:
            self.attack_detection_rate = self.true_positives / total_attacks
        else:
            self.attack_detection_rate = 0.0
        
        if total_legitimate > 0:
            self.legitimate_accuracy = self.true_negatives / total_legitimate
        else:
            self.legitimate_accuracy = 0.0


class MetricsTracker:
    """Tracks and exports training metrics."""
    
    def __init__(self, output_dir: str = "data/metrics"):
        """
        Initialize metrics tracker.
        
        Args:
            output_dir: Directory to save metrics files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.episodes: List[EpisodeMetrics] = []
        self.current_episode: Optional[Dict[str, Any]] = None
    
    def start_episode(self, episode: int):
        """Start tracking a new episode."""
        self.current_episode = {
            "episode": episode,
            "total_reward": 0.0,
            "steps": 0,
            "attacks_detected": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "true_positives": 0,
            "true_negatives": 0,
            "action_distribution": {0: 0, 1: 0, 2: 0, 3: 0},  # block, alert, log, ignore
        }
    
    def record_step(
        self,
        action: int,
        reward: float,
        is_attack: bool,
        action_taken: str  # "block", "alert", "log", "ignore"
    ):
        """
        Record a step in the current episode.
        
        Args:
            action: Action taken (0-3)
            reward: Reward received
            is_attack: Whether the request was an attack
            action_taken: Human-readable action name
        """
        if self.current_episode is None:
            return
        
        self.current_episode["steps"] += 1
        self.current_episode["total_reward"] += reward
        self.current_episode["action_distribution"][action] += 1
        
        # Update detection metrics based on reward
        # Positive reward for blocking/logging attack = true positive
        # Negative reward for blocking legitimate = false positive
        # Negative reward for ignoring attack = false negative
        # Neutral/positive for ignoring legitimate = true negative
        
        if action == 0:  # BLOCK
            if is_attack:
                self.current_episode["true_positives"] += 1
                self.current_episode["attacks_detected"] += 1
            else:
                self.current_episode["false_positives"] += 1
        elif action in [1, 2]:  # ALERT or LOG
            if is_attack:
                self.current_episode["true_positives"] += 1
                self.current_episode["attacks_detected"] += 1
            else:
                # Alerting/logging legitimate traffic is not ideal but not as bad as blocking
                pass
        else:  # IGNORE
            if is_attack:
                self.current_episode["false_negatives"] += 1
            else:
                self.current_episode["true_negatives"] += 1
    
    def end_episode(self) -> EpisodeMetrics:
        """
        End the current episode and save metrics.
        
        Returns:
            EpisodeMetrics object
        """
        if self.current_episode is None:
            raise ValueError("No episode started")
        
        metrics = EpisodeMetrics(**self.current_episode)
        self.episodes.append(metrics)
        
        # Log metrics
        logger.log_training_metrics(
            metrics.episode,
            metrics.total_reward,
            metrics.steps,
            metrics.attacks_detected,
            metrics.false_positives,
            metrics.false_negatives
        )
        
        self.current_episode = None
        return metrics
    
    def export_json(self, filename: Optional[str] = None) -> Path:
        """
        Export metrics to JSON file.
        
        Args:
            filename: Output filename (default: metrics_YYYYMMDD_HHMMSS.json)
        
        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"metrics_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        data = {
            "episodes": [asdict(ep) for ep in self.episodes],
            "summary": self.get_summary(),
        }
        
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.main_logger.info(f"Exported metrics to {filepath}")
        return filepath
    
    def export_csv(self, filename: Optional[str] = None) -> Path:
        """
        Export metrics to CSV file.
        
        Args:
            filename: Output filename (default: metrics_YYYYMMDD_HHMMSS.csv)
        
        Returns:
            Path to exported file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"metrics_{timestamp}.csv"
        
        filepath = self.output_dir / filename
        
        if not self.episodes:
            logger.main_logger.warning("No episodes to export")
            return filepath
        
        fieldnames = [
            "episode",
            "total_reward",
            "steps",
            "attacks_detected",
            "false_positives",
            "false_negatives",
            "true_positives",
            "true_negatives",
            "avg_reward_per_step",
            "attack_detection_rate",
            "legitimate_accuracy",
            "action_block",
            "action_alert",
            "action_log",
            "action_ignore",
        ]
        
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for ep in self.episodes:
                row = {
                    "episode": ep.episode,
                    "total_reward": ep.total_reward,
                    "steps": ep.steps,
                    "attacks_detected": ep.attacks_detected,
                    "false_positives": ep.false_positives,
                    "false_negatives": ep.false_negatives,
                    "true_positives": ep.true_positives,
                    "true_negatives": ep.true_negatives,
                    "avg_reward_per_step": ep.avg_reward_per_step,
                    "attack_detection_rate": ep.attack_detection_rate,
                    "legitimate_accuracy": ep.legitimate_accuracy,
                    "action_block": ep.action_distribution.get(0, 0),
                    "action_alert": ep.action_distribution.get(1, 0),
                    "action_log": ep.action_distribution.get(2, 0),
                    "action_ignore": ep.action_distribution.get(3, 0),
                }
                writer.writerow(row)
        
        logger.main_logger.info(f"Exported metrics to {filepath}")
        return filepath
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics across all episodes.
        
        Returns:
            Dictionary with summary metrics
        """
        if not self.episodes:
            return {}
        
        total_episodes = len(self.episodes)
        avg_reward = sum(ep.total_reward for ep in self.episodes) / total_episodes
        avg_steps = sum(ep.steps for ep in self.episodes) / total_episodes
        total_attacks = sum(ep.attacks_detected for ep in self.episodes)
        total_fp = sum(ep.false_positives for ep in self.episodes)
        total_fn = sum(ep.false_negatives for ep in self.episodes)
        
        avg_detection_rate = (
            sum(ep.attack_detection_rate for ep in self.episodes) / total_episodes
        )
        avg_accuracy = (
            sum(ep.legitimate_accuracy for ep in self.episodes) / total_episodes
        )
        
        # Action distribution totals
        total_actions = {
            "block": sum(ep.action_distribution.get(0, 0) for ep in self.episodes),
            "alert": sum(ep.action_distribution.get(1, 0) for ep in self.episodes),
            "log": sum(ep.action_distribution.get(2, 0) for ep in self.episodes),
            "ignore": sum(ep.action_distribution.get(3, 0) for ep in self.episodes),
        }
        
        return {
            "total_episodes": total_episodes,
            "avg_reward": avg_reward,
            "avg_steps": avg_steps,
            "total_attacks_detected": total_attacks,
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "avg_detection_rate": avg_detection_rate,
            "avg_legitimate_accuracy": avg_accuracy,
            "total_actions": total_actions,
        }
    
    def reset(self):
        """Reset all metrics."""
        self.episodes.clear()
        self.current_episode = None

