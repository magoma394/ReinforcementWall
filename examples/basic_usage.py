#!/usr/bin/env python3
"""
Basic usage example for ReinforceWall.

This script demonstrates how to use the ReinforceWall environment
for training and evaluation.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from reinforcewall import NetworkDefenseEnv, MetricsTracker


def main():
    """Run a simple training demonstration."""
    print("=" * 60)
    print("ReinforceWall - Basic Usage Example")
    print("=" * 60)
    
    # Create environment
    print("\n1. Creating environment...")
    env = NetworkDefenseEnv(simulation_mode=True, max_steps=50)
    print(f"   Action space: {env.action_space}")
    print(f"   Observation space: {env.observation_space}")
    
    # Create metrics tracker
    print("\n2. Initializing metrics tracker...")
    metrics = MetricsTracker()
    
    # Run a few episodes
    print("\n3. Running episodes...")
    num_episodes = 5
    
    for episode in range(num_episodes):
        metrics.start_episode(episode)
        obs, info = env.reset()
        
        print(f"\n   Episode {episode + 1}/{num_episodes}")
        print(f"   Initial request: {info['request']}")
        
        done = False
        step_count = 0
        
        while not done:
            # Random action for demonstration
            action = env.action_space.sample()
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            
            metrics.record_step(
                action=action,
                reward=reward,
                is_attack=info['request']['is_attack'],
                action_taken=info['action']
            )
            
            step_count += 1
            
            if step_count % 10 == 0:
                print(f"      Step {step_count}: {info['action']} -> "
                      f"Reward: {reward:.2f}")
        
        # End episode
        episode_metrics = metrics.end_episode()
        print(f"   Episode completed:")
        print(f"      Steps: {step_count}")
        print(f"      Total reward: {episode_metrics.total_reward:.2f}")
        print(f"      Attacks detected: {episode_metrics.attacks_detected}")
        print(f"      False positives: {episode_metrics.false_positives}")
        print(f"      False negatives: {episode_metrics.false_negatives}")
    
    # Export metrics
    print("\n4. Exporting metrics...")
    csv_path = metrics.export_csv()
    json_path = metrics.export_json()
    print(f"   CSV exported to: {csv_path}")
    print(f"   JSON exported to: {json_path}")
    
    # Print summary
    print("\n5. Training Summary:")
    summary = metrics.get_summary()
    print(f"   Total episodes: {summary['total_episodes']}")
    print(f"   Average reward: {summary['avg_reward']:.2f}")
    print(f"   Average steps: {summary['avg_steps']:.1f}")
    print(f"   Total attacks detected: {summary['total_attacks_detected']}")
    print(f"   Average detection rate: {summary['avg_detection_rate']:.2%}")
    print(f"   Average legitimate accuracy: {summary['avg_legitimate_accuracy']:.2%}")
    
    # Cleanup
    env.close()
    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()

