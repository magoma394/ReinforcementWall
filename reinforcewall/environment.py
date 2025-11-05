"""
Reinforcement Learning environment for network defense.

This module implements a Gymnasium-compatible environment for training
RL agents to detect and respond to network attacks.
"""

import numpy as np
from typing import Tuple, Dict, Any, Optional
import gymnasium as gym
from gymnasium import spaces

from reinforcewall.config import (
    ENV_CONFIG,
    REWARD_CONFIG,
    ATTACK_CONFIG,
)
from reinforcewall.simulator import AttackSimulator
from reinforcewall.firewall import Firewall
from reinforcewall.state import StateExtractor, NetworkRequest
from reinforcewall.attack_detector import AttackDetector
from reinforcewall.logger import logger


class NetworkDefenseEnv(gym.Env):
    """
    Network Defense Reinforcement Learning Environment.
    
    This environment simulates network traffic and allows an RL agent to
    learn defensive actions (block, alert, log, ignore) based on observed
    network requests.
    """
    
    metadata = {"render_modes": ["human", "rgb_array"], "render_fps": 4}
    
    def __init__(
        self,
        max_steps: Optional[int] = None,
        simulation_mode: bool = True,
        render_mode: Optional[str] = None
    ):
        """
        Initialize the network defense environment.
        
        Args:
            max_steps: Maximum steps per episode (default: ENV_CONFIG.MAX_EPISODE_STEPS)
            simulation_mode: If True, firewall uses simulation mode
            render_mode: Rendering mode (currently not implemented)
        """
        super().__init__()
        
        self.max_steps = max_steps or ENV_CONFIG.MAX_EPISODE_STEPS
        self.simulation_mode = simulation_mode
        
        # Initialize components
        self.simulator = AttackSimulator()
        self.firewall = Firewall(simulation_mode=simulation_mode)
        self.state_extractor = StateExtractor()
        self.detector = AttackDetector()
        
        # Environment state
        self.current_step = 0
        self.current_request: Optional[NetworkRequest] = None
        self.episode_reward = 0.0
        self.episode_attacks = 0
        self.episode_false_positives = 0
        self.episode_false_negatives = 0
        
        # Define action and observation spaces
        self.action_space = spaces.Discrete(ENV_CONFIG.NUM_ACTIONS)
        self.observation_space = spaces.Box(
            low=0.0,
            high=1.0,
            shape=(ENV_CONFIG.STATE_DIMENSION,),
            dtype=np.float32
        )
        
        # Render mode
        self.render_mode = render_mode
    
    def reset(
        self,
        seed: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Reset the environment to initial state.
        
        Args:
            seed: Random seed for reproducibility
            options: Additional options for reset
        
        Returns:
            Tuple of (observation, info)
        """
        super().reset(seed=seed)
        
        # Reset components
        self.simulator.reset()
        self.firewall.reset()
        self.state_extractor.reset()
        self.detector.reset()
        
        # Reset episode state
        self.current_step = 0
        self.episode_reward = 0.0
        self.episode_attacks = 0
        self.episode_false_positives = 0
        self.episode_false_negatives = 0
        self.current_request = None
        
        # Generate initial request
        self.current_request = self.simulator.generate_traffic()
        
        # Extract initial state
        observation = self.state_extractor.extract_features(self.current_request)
        
        info = {
            "step": self.current_step,
            "request": {
                "ip": self.current_request.ip_address,
                "type": self.current_request.payload_type,
                "is_attack": self.current_request.is_attack,
            }
        }
        
        return observation, info
    
    def step(
        self,
        action: int
    ) -> Tuple[np.ndarray, float, bool, bool, Dict[str, Any]]:
        """
        Execute one step in the environment.
        
        Args:
            action: Action to take (0=block, 1=alert, 2=log, 3=ignore)
        
        Returns:
            Tuple of (observation, reward, terminated, truncated, info)
        """
        if self.current_request is None:
            raise ValueError("Environment not reset. Call reset() first.")
        
        # Validate action
        if not self.action_space.contains(action):
            raise ValueError(f"Invalid action: {action}")
        
        # Execute action
        reward = self._execute_action(action, self.current_request)
        
        # Update episode statistics
        self.episode_reward += reward
        if self.current_request.is_attack:
            self.episode_attacks += 1
        
        # Check if episode is done
        self.current_step += 1
        terminated = False
        truncated = self.current_step >= self.max_steps
        
        # Episode ends early if attack is successfully blocked
        if action == 0 and self.current_request.is_attack:  # BLOCK on attack
            terminated = True
        
        # Generate next request
        if not terminated and not truncated:
            self.current_request = self.simulator.generate_traffic()
            observation = self.state_extractor.extract_features(self.current_request)
        else:
            # Use zero state for terminal state
            observation = np.zeros(self.observation_space.shape, dtype=np.float32)
        
        # Prepare info dictionary
        info = {
            "step": self.current_step,
            "reward": reward,
            "episode_reward": self.episode_reward,
            "request": {
                "ip": self.current_request.ip_address if self.current_request else None,
                "type": self.current_request.payload_type if self.current_request else None,
                "is_attack": self.current_request.is_attack if self.current_request else False,
            },
            "action": self._get_action_name(action),
            "attacks_detected": self.episode_attacks,
            "false_positives": self.episode_false_positives,
            "false_negatives": self.episode_false_negatives,
        }
        
        return observation, reward, terminated, truncated, info
    
    def _execute_action(
        self,
        action: int,
        request: NetworkRequest
    ) -> float:
        """
        Execute an action and return the reward.
        
        Args:
            action: Action to execute
            request: Current network request
        
        Returns:
            Reward value
        """
        is_attack = request.is_attack
        ip_address = request.ip_address
        
        if action == 0:  # BLOCK
            success = self.firewall.block_ip(
                ip_address,
                reason=f"Agent blocked {request.payload_type}"
            )
            if success:
                if is_attack:
                    # True positive: blocking an attack
                    reward = REWARD_CONFIG.BLOCK_ATTACK
                    logger.agent_logger.info(
                        f"Correctly blocked attack from {ip_address}"
                    )
                else:
                    # False positive: blocking legitimate traffic
                    reward = REWARD_CONFIG.BLOCK_LEGITIMATE
                    self.episode_false_positives += 1
                    logger.agent_logger.warning(
                        f"False positive: blocked legitimate traffic from {ip_address}"
                    )
            else:
                # Failed to block (shouldn't happen often)
                reward = -1.0
        
        elif action == 1:  # ALERT
            success = self.firewall.alert(
                ip_address,
                request.payload_type if is_attack else "suspicious",
                {
                    "endpoint": request.endpoint,
                    "method": request.http_method,
                    "payload_size": request.payload_size,
                }
            )
            if success:
                if is_attack:
                    reward = REWARD_CONFIG.LOG_ATTACK
                else:
                    reward = 0.0  # Neutral for alerting on legitimate traffic
            else:
                reward = -0.5
        
        elif action == 2:  # LOG
            success = self.firewall.log(
                ip_address,
                {
                    "endpoint": request.endpoint,
                    "method": request.http_method,
                    "payload_type": request.payload_type,
                    "payload_size": request.payload_size,
                    "is_attack": is_attack,
                }
            )
            if success:
                if is_attack:
                    reward = REWARD_CONFIG.LOG_ATTACK
                else:
                    reward = 0.0  # Neutral for logging legitimate traffic
            else:
                reward = -0.5
        
        else:  # IGNORE (action == 3)
            self.firewall.ignore()
            if is_attack:
                # False negative: ignoring an attack
                reward = REWARD_CONFIG.IGNORE_ATTACK
                self.episode_false_negatives += 1
                logger.agent_logger.warning(
                    f"False negative: ignored attack from {ip_address}"
                )
            else:
                # True negative: correctly ignoring legitimate traffic
                reward = REWARD_CONFIG.IGNORE_LEGITIMATE
        
        return reward
    
    def _get_action_name(self, action: int) -> str:
        """Get human-readable action name."""
        action_names = {
            0: "BLOCK",
            1: "ALERT",
            2: "LOG",
            3: "IGNORE",
        }
        return action_names.get(action, "UNKNOWN")
    
    def render(self):
        """Render the environment (placeholder for future implementation)."""
        if self.render_mode == "human":
            print(f"Step: {self.current_step}, Reward: {self.episode_reward:.2f}")
            if self.current_request:
                print(
                    f"Request: {self.current_request.ip_address} - "
                    f"{self.current_request.payload_type} "
                    f"(Attack: {self.current_request.is_attack})"
                )
    
    def close(self):
        """Clean up environment resources."""
        self.firewall.reset()
        self.simulator.reset()
        self.state_extractor.reset()
        self.detector.reset()

