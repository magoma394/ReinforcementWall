"""
Test suite for ReinforceWall environment.

Tests the core RL environment functionality including reset, step, and
reward calculation.
"""

import pytest
import numpy as np
from reinforcewall import NetworkDefenseEnv


class TestNetworkDefenseEnv:
    """Test cases for NetworkDefenseEnv."""
    
    def test_environment_initialization(self):
        """Test environment can be initialized."""
        env = NetworkDefenseEnv(simulation_mode=True)
        assert env is not None
        assert env.action_space.n == 4
        assert env.observation_space.shape == (15,)
        env.close()
    
    def test_reset(self):
        """Test environment reset."""
        env = NetworkDefenseEnv(simulation_mode=True)
        obs, info = env.reset()
        
        assert obs is not None
        assert isinstance(obs, np.ndarray)
        assert obs.shape == (15,)
        assert obs.dtype == np.float32
        assert all(0.0 <= val <= 1.0 for val in obs)  # Normalized
        
        assert "step" in info
        assert "request" in info
        assert info["step"] == 0
        
        env.close()
    
    def test_step(self):
        """Test environment step function."""
        env = NetworkDefenseEnv(simulation_mode=True, max_steps=10)
        obs, info = env.reset()
        
        # Take a step
        action = 0  # BLOCK
        obs, reward, terminated, truncated, info = env.step(action)
        
        assert obs is not None
        assert isinstance(reward, (int, float))
        assert isinstance(terminated, bool)
        assert isinstance(truncated, bool)
        assert "step" in info
        assert "reward" in info
        assert "action" in info
        
        env.close()
    
    def test_episode_termination(self):
        """Test episode terminates correctly."""
        env = NetworkDefenseEnv(simulation_mode=True, max_steps=5)
        obs, info = env.reset()
        
        done = False
        steps = 0
        while not done:
            action = env.action_space.sample()
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            steps += 1
        
        assert steps <= 5  # Should terminate at max_steps
        env.close()
    
    def test_action_space(self):
        """Test action space is valid."""
        env = NetworkDefenseEnv(simulation_mode=True)
        assert env.action_space.contains(0)
        assert env.action_space.contains(1)
        assert env.action_space.contains(2)
        assert env.action_space.contains(3)
        assert not env.action_space.contains(4)
        assert not env.action_space.contains(-1)
        env.close()
    
    def test_observation_space(self):
        """Test observation space is valid."""
        env = NetworkDefenseEnv(simulation_mode=True)
        obs, info = env.reset()
        
        assert env.observation_space.contains(obs)
        assert all(0.0 <= val <= 1.0 for val in obs)
        env.close()
    
    def test_reward_range(self):
        """Test rewards are within expected range."""
        env = NetworkDefenseEnv(simulation_mode=True, max_steps=20)
        obs, info = env.reset()
        
        rewards = []
        for _ in range(20):
            action = env.action_space.sample()
            obs, reward, terminated, truncated, info = env.step(action)
            rewards.append(reward)
            if terminated or truncated:
                break
        
        # Reward should be in reasonable range (based on config)
        assert min(rewards) >= -5.0  # Worst penalty
        assert max(rewards) <= 10.0  # Best reward
        env.close()
    
    def test_simulation_mode(self):
        """Test simulation mode doesn't require sudo."""
        env = NetworkDefenseEnv(simulation_mode=True)
        obs, info = env.reset()
        
        # Should work without sudo
        action = 0  # BLOCK
        obs, reward, terminated, truncated, info = env.step(action)
        
        assert "action" in info
        env.close()

