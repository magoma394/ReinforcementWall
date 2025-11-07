#!/usr/bin/env python3
"""
Evaluation script for ReinforceWall DQN agent.

This script evaluates a trained agent and compares it with the baseline detector.
"""

import argparse
import json
from pathlib import Path
from datetime import datetime
import numpy as np
from collections import defaultdict

from reinforcewall import NetworkDefenseEnv, MetricsTracker, AttackDetector
from reinforcewall.config import ENV_CONFIG
from models.dqn_agent import DQNAgent


def evaluate_agent(
    model_path: str,
    episodes: int = 100,
    max_steps: int = None,
    compare_baseline: bool = True,
    output_dir: str = "data/evaluation"
):
    """
    Evaluate trained agent.
    
    Args:
        model_path: Path to trained model
        episodes: Number of evaluation episodes
        max_steps: Maximum steps per episode
        compare_baseline: Whether to compare with baseline detector
        output_dir: Directory to save evaluation results
    """
    # Setup
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    max_steps = max_steps or ENV_CONFIG.MAX_EPISODE_STEPS
    
    # Create environment
    env = NetworkDefenseEnv(simulation_mode=True, max_steps=max_steps)
    
    # Load agent
    state_dim = ENV_CONFIG.STATE_DIMENSION
    action_dim = ENV_CONFIG.NUM_ACTIONS
    agent = DQNAgent(state_dim=state_dim, action_dim=action_dim)
    agent.load(model_path)
    agent.epsilon = 0.0  # No exploration during evaluation
    
    print("=" * 70)
    print("ReinforceWall Agent Evaluation")
    print("=" * 70)
    print(f"Model: {model_path}")
    print(f"Episodes: {episodes}")
    print(f"Max steps per episode: {max_steps}")
    print("=" * 70)
    print()
    
    # Agent metrics
    agent_metrics = MetricsTracker(output_dir=str(output_path / "agent"))
    
    # Baseline metrics (if comparing)
    baseline_metrics = None
    baseline_detector = None
    if compare_baseline:
        baseline_metrics = MetricsTracker(output_dir=str(output_path / "baseline"))
        baseline_detector = AttackDetector()
    
    # Statistics
    agent_stats = {
        'episode_rewards': [],
        'episode_lengths': [],
        'episode_attacks_detected': [],
        'episode_false_positives': [],
        'episode_false_negatives': [],
        'attack_type_performance': defaultdict(lambda: {'detected': 0, 'total': 0, 'blocked': 0})
    }
    
    baseline_stats = None
    if compare_baseline:
        baseline_stats = {
            'episode_rewards': [],
            'episode_lengths': [],
            'episode_attacks_detected': [],
            'episode_false_positives': [],
            'episode_false_negatives': [],
            'attack_type_performance': defaultdict(lambda: {'detected': 0, 'total': 0, 'blocked': 0})
        }
    
    # Evaluate agent
    print("Evaluating trained agent...")
    for episode in range(episodes):
        state, info = env.reset()
        agent_metrics.start_episode(episode)
        
        episode_reward = 0.0
        done = False
        step = 0
        
        while not done:
            # Agent action
            action = agent.act(state, training=False)
            next_state, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            
            # Track attack type performance
            if info['request']['is_attack']:
                attack_type = info['request']['type']
                agent_stats['attack_type_performance'][attack_type]['total'] += 1
                if action == 0:  # BLOCK
                    agent_stats['attack_type_performance'][attack_type]['blocked'] += 1
                    agent_stats['attack_type_performance'][attack_type]['detected'] += 1
                elif action in [1, 2]:  # ALERT or LOG
                    agent_stats['attack_type_performance'][attack_type]['detected'] += 1
            
            state = next_state
            episode_reward += reward
            step += 1
            
            agent_metrics.record_step(
                action=action,
                reward=reward,
                is_attack=info['request']['is_attack'],
                action_taken=info['action']
            )
        
        episode_metrics = agent_metrics.end_episode()
        agent_stats['episode_rewards'].append(episode_reward)
        agent_stats['episode_lengths'].append(step)
        agent_stats['episode_attacks_detected'].append(episode_metrics.attacks_detected)
        agent_stats['episode_false_positives'].append(episode_metrics.false_positives)
        agent_stats['episode_false_negatives'].append(episode_metrics.false_negatives)
        
        if (episode + 1) % 10 == 0:
            print(f"  Episode {episode + 1}/{episodes} | "
                  f"Reward: {episode_reward:7.2f} | "
                  f"Attacks: {episode_metrics.attacks_detected:2d} | "
                  f"FP: {episode_metrics.false_positives:2d} | "
                  f"FN: {episode_metrics.false_negatives:2d}")
    
    # Evaluate baseline (if comparing)
    if compare_baseline:
        print("\nEvaluating baseline detector...")
        baseline_detector.reset()
        
        for episode in range(episodes):
            state, info = env.reset()
            baseline_metrics.start_episode(episode)
            
            episode_reward = 0.0
            done = False
            step = 0
            
            while not done:
                # Use baseline detector to determine action
                request_data = info['request']
                # Simplified: Use detector confidence to decide action
                # In practice, baseline would use rule-based logic
                if request_data['is_attack']:
                    # Baseline: Always block attacks
                    action = 0  # BLOCK
                else:
                    # Baseline: Ignore legitimate traffic
                    action = 3  # IGNORE
                
                next_state, reward, terminated, truncated, info = env.step(action)
                done = terminated or truncated
                
                # Track attack type performance
                if info['request']['is_attack']:
                    attack_type = info['request']['type']
                    baseline_stats['attack_type_performance'][attack_type]['total'] += 1
                    if action == 0:  # BLOCK
                        baseline_stats['attack_type_performance'][attack_type]['blocked'] += 1
                        baseline_stats['attack_type_performance'][attack_type]['detected'] += 1
                    elif action in [1, 2]:  # ALERT or LOG
                        baseline_stats['attack_type_performance'][attack_type]['detected'] += 1
                
                state = next_state
                episode_reward += reward
                step += 1
                
                baseline_metrics.record_step(
                    action=action,
                    reward=reward,
                    is_attack=info['request']['is_attack'],
                    action_taken=info['action']
                )
            
            episode_metrics = baseline_metrics.end_episode()
            baseline_stats['episode_rewards'].append(episode_reward)
            baseline_stats['episode_lengths'].append(step)
            baseline_stats['episode_attacks_detected'].append(episode_metrics.attacks_detected)
            baseline_stats['episode_false_positives'].append(episode_metrics.false_positives)
            baseline_stats['episode_false_negatives'].append(episode_metrics.false_negatives)
    
    env.close()
    
    # Calculate metrics
    def calculate_metrics(stats):
        """Calculate performance metrics."""
        metrics = {}
        metrics['avg_reward'] = np.mean(stats['episode_rewards'])
        metrics['std_reward'] = np.std(stats['episode_rewards'])
        metrics['avg_length'] = np.mean(stats['episode_lengths'])
        metrics['avg_attacks_detected'] = np.mean(stats['episode_attacks_detected'])
        metrics['avg_false_positives'] = np.mean(stats['episode_false_positives'])
        metrics['avg_false_negatives'] = np.mean(stats['episode_false_negatives'])
        
        total_attacks = sum(stats['episode_attacks_detected'])
        total_fp = sum(stats['episode_false_positives'])
        total_fn = sum(stats['episode_false_negatives'])
        
        if total_attacks + total_fn > 0:
            metrics['precision'] = total_attacks / (total_attacks + total_fp) if (total_attacks + total_fp) > 0 else 0
            metrics['recall'] = total_attacks / (total_attacks + total_fn) if (total_attacks + total_fn) > 0 else 0
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall']) if (metrics['precision'] + metrics['recall']) > 0 else 0
        else:
            metrics['precision'] = 0
            metrics['recall'] = 0
            metrics['f1_score'] = 0
        
        return metrics
    
    agent_performance = calculate_metrics(agent_stats)
    
    # Print results
    print("\n" + "=" * 70)
    print("Evaluation Results")
    print("=" * 70)
    print("\nAgent Performance:")
    print(f"  Average Reward: {agent_performance['avg_reward']:.2f} ± {agent_performance['std_reward']:.2f}")
    print(f"  Average Episode Length: {agent_performance['avg_length']:.1f}")
    print(f"  Attacks Detected: {agent_performance['avg_attacks_detected']:.1f}")
    print(f"  False Positives: {agent_performance['avg_false_positives']:.2f}")
    print(f"  False Negatives: {agent_performance['avg_false_negatives']:.2f}")
    print(f"  Precision: {agent_performance['precision']:.3f}")
    print(f"  Recall: {agent_performance['recall']:.3f}")
    print(f"  F1 Score: {agent_performance['f1_score']:.3f}")
    
    if compare_baseline:
        baseline_performance = calculate_metrics(baseline_stats)
        print("\nBaseline Performance:")
        print(f"  Average Reward: {baseline_performance['avg_reward']:.2f} ± {baseline_performance['std_reward']:.2f}")
        print(f"  Average Episode Length: {baseline_performance['avg_length']:.1f}")
        print(f"  Attacks Detected: {baseline_performance['avg_attacks_detected']:.1f}")
        print(f"  False Positives: {baseline_performance['avg_false_positives']:.2f}")
        print(f"  False Negatives: {baseline_performance['avg_false_negatives']:.2f}")
        print(f"  Precision: {baseline_performance['precision']:.3f}")
        print(f"  Recall: {baseline_performance['recall']:.3f}")
        print(f"  F1 Score: {baseline_performance['f1_score']:.3f}")
        
        print("\nImprovement:")
        reward_improvement = ((agent_performance['avg_reward'] - baseline_performance['avg_reward']) / abs(baseline_performance['avg_reward'])) * 100
        f1_improvement = ((agent_performance['f1_score'] - baseline_performance['f1_score']) / max(baseline_performance['f1_score'], 0.001)) * 100
        print(f"  Reward: {reward_improvement:+.1f}%")
        print(f"  F1 Score: {f1_improvement:+.1f}%")
    
    # Attack type performance
    print("\nAttack Type Performance (Agent):")
    for attack_type in sorted(agent_stats['attack_type_performance'].keys()):
        perf = agent_stats['attack_type_performance'][attack_type]
        if perf['total'] > 0:
            detection_rate = perf['detected'] / perf['total']
            block_rate = perf['blocked'] / perf['total']
            print(f"  {attack_type:20s}: {detection_rate:.2%} detected, {block_rate:.2%} blocked ({perf['total']} total)")
    
    # Save results
    results = {
        'agent_performance': agent_performance,
        'agent_stats': {k: v for k, v in agent_stats.items() if k != 'attack_type_performance'},
        'agent_attack_performance': dict(agent_stats['attack_type_performance']),
        'model_path': model_path,
        'episodes': episodes,
        'timestamp': datetime.now().isoformat()
    }
    
    if compare_baseline:
        results['baseline_performance'] = baseline_performance
        results['baseline_stats'] = {k: v for k, v in baseline_stats.items() if k != 'attack_type_performance'}
        results['baseline_attack_performance'] = dict(baseline_stats['attack_type_performance'])
    
    results_path = output_path / f"evaluation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSaved evaluation results: {results_path}")
    
    # Export metrics
    agent_csv = agent_metrics.export_csv()
    agent_json = agent_metrics.export_json()
    print(f"Exported agent metrics: {agent_csv}, {agent_json}")
    
    if compare_baseline:
        baseline_csv = baseline_metrics.export_csv()
        baseline_json = baseline_metrics.export_json()
        print(f"Exported baseline metrics: {baseline_csv}, {baseline_json}")
    
    print("=" * 70)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Evaluate ReinforceWall DQN agent")
    parser.add_argument("model", type=str, help="Path to trained model")
    parser.add_argument("--episodes", type=int, default=100, help="Number of evaluation episodes")
    parser.add_argument("--max-steps", type=int, default=None, help="Max steps per episode")
    parser.add_argument("--no-baseline", action="store_true", help="Don't compare with baseline")
    parser.add_argument("--output-dir", type=str, default="data/evaluation", help="Output directory")
    
    args = parser.parse_args()
    
    evaluate_agent(
        model_path=args.model,
        episodes=args.episodes,
        max_steps=args.max_steps,
        compare_baseline=not args.no_baseline,
        output_dir=args.output_dir
    )


if __name__ == "__main__":
    main()

