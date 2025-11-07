"""
Deep Q-Network (DQN) Agent for ReinforceWall.

This module implements a DQN agent for learning optimal network defense strategies
through reinforcement learning.
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
import random
from typing import Tuple, List, Optional
from pathlib import Path

from reinforcewall.config import TRAINING_CONFIG


class DQN(nn.Module):
    """Deep Q-Network neural network."""
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dims: List[int] = None):
        """
        Initialize DQN network.
        
        Args:
            state_dim: Dimension of state space
            action_dim: Dimension of action space
            hidden_dims: List of hidden layer dimensions (default: [128, 128])
        """
        super(DQN, self).__init__()
        
        if hidden_dims is None:
            hidden_dims = [128, 128]
        
        layers = []
        input_dim = state_dim
        
        for hidden_dim in hidden_dims:
            layers.append(nn.Linear(input_dim, hidden_dim))
            layers.append(nn.ReLU())
            input_dim = hidden_dim
        
        layers.append(nn.Linear(input_dim, action_dim))
        
        self.network = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through the network.
        
        Args:
            x: Input state tensor
        
        Returns:
            Q-values for each action
        """
        return self.network(x)


class ReplayBuffer:
    """Experience replay buffer for DQN training."""
    
    def __init__(self, capacity: int = 10000):
        """
        Initialize replay buffer.
        
        Args:
            capacity: Maximum number of experiences to store
        """
        self.buffer = deque(maxlen=capacity)
    
    def push(self, state: np.ndarray, action: int, reward: float, 
             next_state: np.ndarray, done: bool):
        """
        Add experience to buffer.
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode ended
        """
        self.buffer.append((state, action, reward, next_state, done))
    
    def sample(self, batch_size: int) -> Tuple:
        """
        Sample a batch of experiences.
        
        Args:
            batch_size: Number of experiences to sample
        
        Returns:
            Tuple of (states, actions, rewards, next_states, dones)
        """
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))
        states, actions, rewards, next_states, dones = zip(*batch)
        
        return (
            np.array(states),
            np.array(actions),
            np.array(rewards, dtype=np.float32),
            np.array(next_states),
            np.array(dones, dtype=np.bool_)
        )
    
    def __len__(self) -> int:
        """Return current size of buffer."""
        return len(self.buffer)


class DQNAgent:
    """Deep Q-Network agent for network defense."""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        learning_rate: float = None,
        gamma: float = None,
        epsilon_start: float = None,
        epsilon_end: float = None,
        epsilon_decay: float = None,
        batch_size: int = None,
        memory_size: int = None,
        target_update_freq: int = 10,
        device: Optional[str] = None
    ):
        """
        Initialize DQN agent.
        
        Args:
            state_dim: Dimension of state space
            action_dim: Dimension of action space
            learning_rate: Learning rate for optimizer
            gamma: Discount factor
            epsilon_start: Initial epsilon for epsilon-greedy
            epsilon_end: Final epsilon for epsilon-greedy
            epsilon_decay: Epsilon decay rate
            batch_size: Batch size for training
            memory_size: Size of replay buffer
            target_update_freq: Frequency of target network updates
            device: Device to run on ('cuda' or 'cpu')
        """
        # Use config defaults if not provided
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.learning_rate = learning_rate or TRAINING_CONFIG.LEARNING_RATE
        self.gamma = gamma or TRAINING_CONFIG.GAMMA
        self.epsilon = epsilon_start or TRAINING_CONFIG.EPSILON_START
        self.epsilon_start = epsilon_start or TRAINING_CONFIG.EPSILON_START
        self.epsilon_end = epsilon_end or TRAINING_CONFIG.EPSILON_END
        self.epsilon_decay = epsilon_decay or TRAINING_CONFIG.EPSILON_DECAY
        self.batch_size = batch_size or TRAINING_CONFIG.BATCH_SIZE
        self.memory_size = memory_size or TRAINING_CONFIG.MEMORY_SIZE
        self.target_update_freq = target_update_freq
        
        # Device setup
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)
        
        # Networks
        self.q_network = DQN(state_dim, action_dim).to(self.device)
        self.target_network = DQN(state_dim, action_dim).to(self.device)
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=self.learning_rate)
        self.criterion = nn.MSELoss()
        
        # Replay buffer
        self.memory = ReplayBuffer(capacity=self.memory_size)
        
        # Training stats
        self.step_count = 0
        self.update_target_network()
    
    def act(self, state: np.ndarray, training: bool = True) -> int:
        """
        Select action using epsilon-greedy policy.
        
        Args:
            state: Current state
            training: Whether in training mode (uses epsilon-greedy)
        
        Returns:
            Selected action
        """
        if training and random.random() < self.epsilon:
            return random.randrange(self.action_dim)
        
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_values = self.q_network(state_tensor)
        return q_values.argmax().item()
    
    def remember(self, state: np.ndarray, action: int, reward: float,
                 next_state: np.ndarray, done: bool):
        """
        Store experience in replay buffer.
        
        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode ended
        """
        self.memory.push(state, action, reward, next_state, done)
    
    def replay(self) -> Optional[float]:
        """
        Train the network on a batch of experiences.
        
        Returns:
            Loss value if training occurred, None otherwise
        """
        if len(self.memory) < self.batch_size:
            return None
        
        states, actions, rewards, next_states, dones = self.memory.sample(self.batch_size)
        
        # Convert to tensors
        states = torch.FloatTensor(states).to(self.device)
        actions = torch.LongTensor(actions).to(self.device)
        rewards = torch.FloatTensor(rewards).to(self.device)
        next_states = torch.FloatTensor(next_states).to(self.device)
        dones = torch.BoolTensor(dones).to(self.device)
        
        # Current Q values
        current_q = self.q_network(states).gather(1, actions.unsqueeze(1))
        
        # Next Q values from target network
        with torch.no_grad():
            next_q = self.target_network(next_states).max(1)[0]
            target_q = rewards + (self.gamma * next_q * ~dones)
        
        # Compute loss
        loss = self.criterion(current_q.squeeze(), target_q)
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping for stability
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
        self.optimizer.step()
        
        # Update epsilon
        if self.epsilon > self.epsilon_end:
            self.epsilon = max(self.epsilon_end, self.epsilon * self.epsilon_decay)
        
        self.step_count += 1
        
        # Update target network
        if self.step_count % self.target_update_freq == 0:
            self.update_target_network()
        
        return loss.item()
    
    def update_target_network(self):
        """Update target network with current Q-network weights."""
        self.target_network.load_state_dict(self.q_network.state_dict())
    
    def save(self, filepath: str):
        """
        Save agent to file.
        
        Args:
            filepath: Path to save file
        """
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            'q_network_state_dict': self.q_network.state_dict(),
            'target_network_state_dict': self.target_network.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'step_count': self.step_count,
        }, filepath)
    
    def load(self, filepath: str):
        """
        Load agent from file.
        
        Args:
            filepath: Path to load file
        """
        checkpoint = torch.load(filepath, map_location=self.device)
        self.q_network.load_state_dict(checkpoint['q_network_state_dict'])
        self.target_network.load_state_dict(checkpoint['target_network_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.epsilon = checkpoint.get('epsilon', self.epsilon_start)
        self.step_count = checkpoint.get('step_count', 0)
    
    def get_q_values(self, state: np.ndarray) -> np.ndarray:
        """
        Get Q-values for a given state.
        
        Args:
            state: Input state
        
        Returns:
            Q-values for each action
        """
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_values = self.q_network(state_tensor)
        return q_values.cpu().numpy()[0]

