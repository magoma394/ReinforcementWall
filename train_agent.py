#!/usr/bin/env python3
"""
Training script for ReinforceWall DQN agent.

This script trains a DQN agent to learn optimal network defense strategies.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
import numpy as np

from reinforcewall import NetworkDefenseEnv, MetricsTracker
from reinforcewall.config import ENV_CONFIG, TRAINING_CONFIG
from models.dqn_agent import DQNAgent


def train_agent(
    episodes: int = 1000,
    max_steps: int = None,
    save_freq: int = 100,
    eval_freq: int = 50,
    model_dir: str = "models/checkpoints",
    metrics_dir: str = "data/metrics",
    verbose: bool = True
):
    """
    Train DQN agent.
    
    Args:
        episodes: Number of training episodes
        max_steps: Maximum steps per episode
        save_freq: Frequency of model saving
        eval_freq: Frequency of evaluation
        model_dir: Directory to save models
        metrics_dir: Directory to save metrics
        verbose: Whether to print progress
    """
    # Setup directories
    model_path = Path(model_dir)
    model_path.mkdir(parents=True, exist_ok=True)
    metrics_path = Path(metrics_dir)
    metrics_path.mkdir(parents=True, exist_ok=True)
    
    # Create environment
    max_steps = max_steps or ENV_CONFIG.MAX_EPISODE_STEPS
    env = NetworkDefenseEnv(simulation_mode=True, max_steps=max_steps)
    
    # Create agent
    state_dim = ENV_CONFIG.STATE_DIMENSION
    action_dim = ENV_CONFIG.NUM_ACTIONS
    agent = DQNAgent(state_dim=state_dim, action_dim=action_dim)
    
    # Metrics tracking
    metrics = MetricsTracker(output_dir=str(metrics_path))
    
    # Training statistics
    training_stats = {
        'episode_rewards': [],
        'episode_lengths': [],
        'episode_losses': [],
        'episode_attacks_detected': [],
        'episode_false_positives': [],
        'episode_false_negatives': [],
        'epsilon_values': []
    }
    
    print("=" * 70)
    print("ReinforceWall DQN Agent Training")
    print("=" * 70)
    print(f"Episodes: {episodes}")
    print(f"Max steps per episode: {max_steps}")
    print(f"State dimension: {state_dim}")
    print(f"Action dimension: {action_dim}")
    print(f"Device: {agent.device}")
    print(f"Initial epsilon: {agent.epsilon_start}")
    print("=" * 70)
    print()
    
    best_reward = float('-inf')
    
    for episode in range(episodes):
        # Reset environment
        state, info = env.reset()
        metrics.start_episode(episode)
        
        episode_reward = 0.0
        episode_loss = 0.0
        episode_loss_count = 0
        done = False
        step = 0
        
        while not done:
            # Select action
            action = agent.act(state, training=True)
            
            # Take step
            next_state, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            
            # Store experience
            agent.remember(state, action, reward, next_state, done)
            
            # Train agent
            loss = agent.replay()
            if loss is not None:
                episode_loss += loss
                episode_loss_count += 1
            
            # Update state
            state = next_state
            episode_reward += reward
            step += 1
            
            # Record metrics
            metrics.record_step(
                action=action,
                reward=reward,
                is_attack=info['request']['is_attack'],
                action_taken=info['action']
            )
        
        # End episode
        episode_metrics = metrics.end_episode()
        avg_loss = episode_loss / episode_loss_count if episode_loss_count > 0 else 0.0
        
        # Update statistics
        training_stats['episode_rewards'].append(episode_reward)
        training_stats['episode_lengths'].append(step)
        training_stats['episode_losses'].append(avg_loss)
        training_stats['episode_attacks_detected'].append(episode_metrics.attacks_detected)
        training_stats['episode_false_positives'].append(episode_metrics.false_positives)
        training_stats['episode_false_negatives'].append(episode_metrics.false_negatives)
        training_stats['epsilon_values'].append(agent.epsilon)
        
        # Print progress
        if verbose and (episode + 1) % 10 == 0:
            avg_reward = np.mean(training_stats['episode_rewards'][-10:])
            avg_attacks = np.mean(training_stats['episode_attacks_detected'][-10:])
            print(f"Episode {episode + 1}/{episodes} | "
                  f"Reward: {episode_reward:7.2f} (avg: {avg_reward:6.2f}) | "
                  f"Steps: {step:3d} | "
                  f"Attacks: {episode_metrics.attacks_detected:2d} (avg: {avg_attacks:4.1f}) | "
                  f"Loss: {avg_loss:6.4f} | "
                  f"Epsilon: {agent.epsilon:.3f}")
        
        # Save model
        if (episode + 1) % save_freq == 0:
            checkpoint_path = model_path / f"checkpoint_ep{episode + 1}.pth"
            agent.save(str(checkpoint_path))
            if verbose:
                print(f"  Saved checkpoint: {checkpoint_path}")
        
        # Save best model
        if episode_reward > best_reward:
            best_reward = episode_reward
            best_model_path = model_path / "best_model.pth"
            agent.save(str(best_model_path))
    
    # Save final model
    final_model_path = model_path / "final_model.pth"
    agent.save(str(final_model_path))
    print(f"\nSaved final model: {final_model_path}")
    
    # Save training statistics
    stats_path = metrics_path / f"training_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(stats_path, 'w') as f:
        json.dump(training_stats, f, indent=2)
    print(f"Saved training statistics: {stats_path}")
    
    # Export metrics
    csv_path = metrics.export_csv()
    json_path = metrics.export_json()
    print(f"Exported metrics: {csv_path}, {json_path}")
    
    # Print summary
    print("\n" + "=" * 70)
    print("Training Summary")
    print("=" * 70)
    print(f"Total episodes: {episodes}")
    print(f"Average reward: {np.mean(training_stats['episode_rewards']):.2f}")
    print(f"Best reward: {best_reward:.2f}")
    print(f"Average episode length: {np.mean(training_stats['episode_lengths']):.1f}")
    print(f"Average attacks detected: {np.mean(training_stats['episode_attacks_detected']):.1f}")
    print(f"Final epsilon: {agent.epsilon:.4f}")
    print("=" * 70)
    
    env.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Train ReinforceWall DQN agent")
    parser.add_argument("--episodes", type=int, default=1000, help="Number of training episodes")
    parser.add_argument("--max-steps", type=int, default=None, help="Max steps per episode")
    parser.add_argument("--save-freq", type=int, default=100, help="Model save frequency")
    parser.add_argument("--eval-freq", type=int, default=50, help="Evaluation frequency")
    parser.add_argument("--model-dir", type=str, default="models/checkpoints", help="Model directory")
    parser.add_argument("--metrics-dir", type=str, default="data/metrics", help="Metrics directory")
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    
    args = parser.parse_args()
    
    train_agent(
        episodes=args.episodes,
        max_steps=args.max_steps,
        save_freq=args.save_freq,
        eval_freq=args.eval_freq,
        model_dir=args.model_dir,
        metrics_dir=args.metrics_dir,
        verbose=not args.quiet
    )


if __name__ == "__main__":
    main()

