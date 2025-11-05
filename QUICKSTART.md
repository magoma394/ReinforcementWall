# Quick Start Guide

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Verify installation:**
   ```bash
   python3 -c "from reinforcewall import NetworkDefenseEnv; print('Success!')"
   ```

## Running Examples

### Basic Usage Example

Run the basic usage script:
```bash
python3 examples/basic_usage.py
```

This will:
- Create an environment
- Run 5 episodes with random actions
- Track metrics
- Export results to CSV and JSON

### Jupyter Notebook

Open the demo notebook:
```bash
jupyter notebook examples/demo_environment.ipynb
```

## Quick Test

```python
from reinforcewall import NetworkDefenseEnv

# Create environment
env = NetworkDefenseEnv(simulation_mode=True)

# Reset and run one step
obs, info = env.reset()
print(f"Initial state: {obs.shape}")
print(f"Request: {info['request']}")

# Take an action
action = 0  # BLOCK
obs, reward, terminated, truncated, info = env.step(action)
print(f"Reward: {reward}, Action: {info['action']}")

env.close()
```

## Project Structure

- `reinforcewall/` - Core package
- `examples/` - Example scripts and notebooks
- `tests/` - Test suite
- `data/` - Logs and metrics (created automatically)

## Next Steps

1. Review `README.md` for detailed documentation
2. Explore `config.yaml` to customize behavior
3. Check `examples/` for more usage examples
4. Run tests with `pytest tests/`

