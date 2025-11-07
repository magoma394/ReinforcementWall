#!/usr/bin/env python3
"""
Test script to verify all new attack types are working correctly.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from reinforcewall import NetworkDefenseEnv
from collections import Counter

def main():
    env = NetworkDefenseEnv(simulation_mode=True, max_steps=1000)
    
    print("Testing all attack types...")
    print("=" * 60)
    
    attack_types_found = Counter()
    total_requests = 0
    attacks_seen = 0
    episodes_completed = 0
    max_episodes = 10
    
    while episodes_completed < max_episodes and total_requests < 500:
        obs, info = env.reset()
        episodes_completed += 1
        done = False
        
        while not done and total_requests < 500:
            action = env.action_space.sample()  # Random action
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            total_requests += 1
            
            request = info['request']
            if request['is_attack']:
                attacks_seen += 1
                attack_type = request['type']
                attack_types_found[attack_type] += 1
                if attacks_seen <= 20:  # Show first 20 attacks
                    print(f"Attack #{attacks_seen}: {attack_type:20s} | IP: {request['ip']:15s} | Reward: {reward:6.2f}")
            
            if total_requests % 50 == 0:
                print(f"\nProgress: {total_requests} requests, {attacks_seen} attacks found so far...")
                print(f"Attack types seen: {dict(attack_types_found)}\n")
    
    env.close()
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Episodes completed: {episodes_completed}")
    print(f"Total requests: {total_requests}")
    print(f"Total attacks: {attacks_seen}")
    if total_requests > 0:
        print(f"Attack rate: {attacks_seen/total_requests*100:.1f}%")
    print(f"\nAttack types detected:")
    for attack_type, count in attack_types_found.most_common():
        percentage = count/attacks_seen*100 if attacks_seen > 0 else 0
        print(f"  - {attack_type:20s}: {count:3d} times ({percentage:5.1f}%)")
    
    print("\nExpected attack types:")
    expected = ["sql_injection", "xss", "brute_force", "ddos", 
                "command_injection", "path_traversal", "port_scanning"]
    for exp_type in expected:
        status = "✓" if exp_type in attack_types_found else "✗"
        print(f"  {status} {exp_type}")
    
    # Check if we found all expected types
    found_all = all(exp_type in attack_types_found for exp_type in expected)
    if found_all:
        print("\n✓ SUCCESS: All attack types are being generated!")
    else:
        missing = [exp_type for exp_type in expected if exp_type not in attack_types_found]
        print(f"\n⚠ WARNING: Missing attack types: {missing}")
        print("   (This might be due to random probability - try running again)")

if __name__ == "__main__":
    main()

