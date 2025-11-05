# ReinforceWall

A Reinforcement Learning-based Network Defense System for detecting and responding to cybersecurity attacks in real-time.

## Overview

ReinforceWall is an educational project that demonstrates how Reinforcement Learning (specifically Deep Q-Learning) can be used to train an intelligent agent to detect and respond to network attacks. The system simulates network traffic patterns and various attack scenarios (SQL Injection, XSS, Brute Force) while training an RL agent to make optimal defensive decisions.

## Features

- **Custom RL Environment**: Gymnasium-compatible environment for network defense scenarios
- **Attack Simulation**: Realistic simulation of SQL Injection, XSS, and Brute Force attacks
- **Firewall Integration**: Supports both simulation mode (safe for demos) and real iptables integration
- **State Representation**: 15-dimensional feature vector capturing network behavior patterns
- **Action Space**: 4 defensive actions (Block, Alert, Log, Ignore)
- **Reward System**: Balanced reward structure encouraging accurate attack detection
- **Metrics Tracking**: Comprehensive metrics for training analysis and evaluation
- **Baseline Detection**: Rule-based attack detector for comparison

## Project Structure

```
ReinforcementWall/
├── reinforcewall/          # Core package
│   ├── environment.py      # RL environment (Gymnasium-compatible)
│   ├── simulator.py        # Attack traffic generator
│   ├── firewall.py         # Firewall actions (block, alert, log, ignore)
│   ├── state.py            # State representation and feature extraction
│   ├── config.py           # Configuration constants
│   ├── logger.py           # Centralized logging system
│   ├── utils.py            # Utility functions
│   ├── attack_detector.py  # Baseline rule-based detector
│   └── metrics.py           # Training metrics tracking
├── models/                 # RL models (placeholder for DQN)
├── dashboard/              # Flask dashboard (future)
├── examples/               # Jupyter notebooks for demos
├── tests/                  # Test suite
├── data/                   # Logs, metrics, and saved models
├── docs/                   # Documentation
├── requirements.txt        # Python dependencies
├── config.yaml            # Configuration file
└── README.md              # This file
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ReinforcementWall
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

### Basic Environment Usage

```python
from reinforcewall import NetworkDefenseEnv

# Create environment
env = NetworkDefenseEnv(simulation_mode=True)

# Reset environment
obs, info = env.reset()

# Run a simple episode
done = False
total_reward = 0
while not done:
    action = env.action_space.sample()  # Random action
    obs, reward, terminated, truncated, info = env.step(action)
    done = terminated or truncated
    total_reward += reward
    print(f"Step: {info['step']}, Reward: {reward:.2f}, Action: {info['action']}")

print(f"Episode completed. Total reward: {total_reward:.2f}")
env.close()
```

### Using Metrics Tracker

```python
from reinforcewall import NetworkDefenseEnv, MetricsTracker

env = NetworkDefenseEnv()
metrics = MetricsTracker()

# Training loop
for episode in range(10):
    metrics.start_episode(episode)
    obs, info = env.reset()
    done = False
    
    while not done:
        action = env.action_space.sample()
        obs, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated
        
        metrics.record_step(
            action=action,
            reward=reward,
            is_attack=info['request']['is_attack'],
            action_taken=info['action']
        )
    
    episode_metrics = metrics.end_episode()
    print(f"Episode {episode}: Reward={episode_metrics.total_reward:.2f}, "
          f"Attacks Detected={episode_metrics.attacks_detected}")

# Export metrics
metrics.export_csv()
metrics.export_json()
```

## Configuration

The system can be configured via `config.yaml` or by modifying constants in `reinforcewall/config.py`. Key configuration options:

- **Reward values**: Adjust rewards for different action-outcome combinations
- **Attack probabilities**: Control frequency of different attack types
- **Episode length**: Maximum steps per training episode
- **Firewall mode**: Switch between simulation and real iptables

## Environment Details

### State Space

15-dimensional normalized feature vector:
1. Request frequency (requests per time window)
2. Payload type (encoded: 0=normal, 1=SQL, 2=XSS, 3=brute_force)
3. IP address (normalized hash)
4. IP request count
5. Unique endpoints accessed
6. Request payload size
7. HTTP method
8. Attack probability indicator
9. Hour of day
10. Request rate acceleration
11. Average payload size from IP
12. Suspicious pattern score
13. Time since last request
14. Request diversity
15. Attack type distribution

### Action Space

Discrete actions:
- **0: BLOCK** - Block the source IP address
- **1: ALERT** - Log an alert for suspicious activity
- **2: LOG** - Log the request for audit purposes
- **3: IGNORE** - Take no action

### Reward Structure

- **+10.0**: Successfully blocking an attack (true positive)
- **-5.0**: Blocking legitimate traffic (false positive)
- **-2.0**: Ignoring an attack (false negative)
- **+1.0**: Logging/alerting an attack
- **-1.0**: Ignoring legitimate traffic (minor penalty)

## Attack Types

The simulator generates three types of attacks:

1. **SQL Injection**: Attempts to inject malicious SQL queries
2. **XSS (Cross-Site Scripting)**: Attempts to inject malicious scripts
3. **Brute Force**: Repeated login attempts to gain unauthorized access

## Safety Features

- **Simulation Mode**: Default mode prevents accidental blocking of real network traffic
- **Sudo Check**: Automatically switches to simulation mode if sudo access is unavailable
- **Comprehensive Logging**: All actions are logged for audit and debugging

## Future Enhancements

- [ ] Deep Q-Network (DQN) agent implementation
- [ ] Flask dashboard for real-time visualization
- [ ] Support for additional attack types
- [ ] Multi-agent reinforcement learning
- [ ] Transfer learning from baseline detector
- [ ] Advanced state representations (LSTM, attention mechanisms)

## Testing

Run the test suite:
```bash
pytest tests/
```

## Documentation

See the `docs/` directory for detailed documentation including:
- Architecture overview
- RL concepts explanation
- Algorithm flowcharts

## License

This project is for educational purposes. Please use responsibly and only in authorized environments.

## Contributing

This is an academic project. For questions or suggestions, please open an issue.

## Acknowledgments

Built for educational purposes to demonstrate Reinforcement Learning applications in cybersecurity.

