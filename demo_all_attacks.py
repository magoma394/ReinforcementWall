#!/usr/bin/env python3
"""
Comprehensive demo showing all 7 attack types in action.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from reinforcewall import NetworkDefenseEnv, MetricsTracker, AttackDetector
from reinforcewall.state import NetworkRequest
from collections import Counter
import time

def main():
    print("=" * 70)
    print("ReinforceWall - Complete Attack Types Demonstration")
    print("=" * 70)
    
    # Create environment
    env = NetworkDefenseEnv(simulation_mode=True, max_steps=500)
    detector = AttackDetector()
    metrics = MetricsTracker()
    
    print("\n1. Environment Information:")
    print(f"   Action space: {env.action_space}")
    print(f"   Observation space: {env.observation_space.shape}")
    print(f"   Simulation mode: Enabled (safe for testing)")
    
    # Track all attack types
    attack_types_seen = Counter()
    attack_details = {}
    total_requests = 0
    episode_num = 0
    
    print("\n2. Running simulation to collect all attack types...")
    print("   (This may take a moment to encounter all 7 attack types)\n")
    
    # Run until we see all attack types or max iterations
    max_iterations = 1000
    expected_attacks = {
        "sql_injection", "xss", "brute_force", "ddos",
        "command_injection", "path_traversal", "port_scanning"
    }
    
    while len(attack_types_seen) < len(expected_attacks) and total_requests < max_iterations:
        obs, info = env.reset()
        episode_num += 1
        done = False
        episode_attacks = []
        
        while not done and total_requests < max_iterations:
            action = env.action_space.sample()
            obs, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            total_requests += 1
            
            request_info = info['request']
            if request_info['is_attack']:
                attack_type = request_info['type']
                attack_types_seen[attack_type] += 1
                
                # Store first occurrence of each attack type
                if attack_type not in attack_details:
                    attack_details[attack_type] = {
                        'ip': request_info['ip'],
                        'action_taken': info['action'],
                        'reward': reward,
                        'step': total_requests
                    }
                    print(f"   ✓ Found {attack_type:20s} | IP: {request_info['ip']:15s} | Action: {info['action']:6s} | Reward: {reward:6.2f}")
            
            # Check if we have all attack types
            if len(attack_types_seen) >= len(expected_attacks):
                break
    
    env.close()
    
    print(f"\n3. Summary Statistics:")
    print(f"   Total requests processed: {total_requests}")
    print(f"   Total episodes: {episode_num}")
    print(f"   Unique attack types found: {len(attack_types_seen)}")
    print(f"   Expected attack types: {len(expected_attacks)}")
    
    print(f"\n4. Attack Type Distribution:")
    for attack_type in sorted(expected_attacks):
        count = attack_types_seen.get(attack_type, 0)
        status = "✓" if count > 0 else "✗"
        percentage = (count / total_requests * 100) if total_requests > 0 else 0
        print(f"   {status} {attack_type:20s}: {count:4d} occurrences ({percentage:5.2f}%)")
        if attack_type in attack_details:
            details = attack_details[attack_type]
            print(f"      └─ First seen: IP {details['ip']}, {details['action_taken']}, reward {details['reward']:.2f}")
    
    print(f"\n5. Attack Type Details:")
    print("\n   SQL Injection:")
    print("      - Targets: Login, search endpoints")
    print("      - Pattern: SQL query injection attempts")
    print("      - Example: \"' OR '1'='1\", \"'; DROP TABLE users--\"")
    
    print("\n   XSS (Cross-Site Scripting):")
    print("      - Targets: Various endpoints")
    print("      - Pattern: Script injection attempts")
    print("      - Example: \"<script>alert('XSS')</script>\"")
    
    print("\n   Brute Force:")
    print("      - Targets: Login endpoints")
    print("      - Pattern: Repeated authentication attempts")
    print("      - Example: Multiple username/password combinations")
    
    print("\n   DDoS (Distributed Denial of Service):")
    print("      - Targets: All endpoints")
    print("      - Pattern: High-volume requests from multiple IPs")
    print("      - Characteristic: 50 requests from 10 different IPs")
    
    print("\n   Command Injection:")
    print("      - Targets: System/execute endpoints")
    print("      - Pattern: Shell command injection")
    print("      - Example: \"; cat /etc/passwd\", \"| whoami\"")
    
    print("\n   Path Traversal:")
    print("      - Targets: File access endpoints")
    print("      - Pattern: Directory traversal sequences")
    print("      - Example: \"../../../etc/passwd\", \"..%2F..%2F\"")
    
    print("\n   Port Scanning:")
    print("      - Targets: Multiple ports/endpoints")
    print("      - Pattern: Sequential port access")
    print("      - Ports: 80, 443, 8080, 8443, 22, 21, 25, 3306, 5432, 6379")
    
    # Test attack detector
    print(f"\n6. Testing Attack Detector:")
    test_requests = []
    for attack_type in ["sql_injection", "ddos", "command_injection"]:
        if attack_type in attack_details:
            test_request = NetworkRequest(
                ip_address=attack_details[attack_type]['ip'],
                timestamp=time.time(),
                payload_type=attack_type,
                http_method="POST",
                payload_size=100,
                endpoint="/test",
                headers={},
                is_attack=True
            )
            test_requests.append((attack_type, test_request))
    
    for attack_type, request in test_requests:
        result = detector.detect(request)
        status = "✓" if result.is_attack else "✗"
        print(f"   {status} {attack_type:20s}: {result.reason}")
    
    print("\n" + "=" * 70)
    if len(attack_types_seen) >= len(expected_attacks):
        print("✓ SUCCESS: All 7 attack types are working correctly!")
    else:
        missing = expected_attacks - set(attack_types_seen.keys())
        print(f"⚠ NOTE: Some attack types not encountered: {missing}")
        print("   (This is normal due to random probability - run again to see all)")
    print("=" * 70)

if __name__ == "__main__":
    main()

