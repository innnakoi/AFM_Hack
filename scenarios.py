"""
Generate synthetic threat scenarios for testing
This helps demonstrate the detection capabilities
"""

import json
import time
from datetime import datetime

def generate_normal_behavior():
    """Generate normal system behavior"""
    return {
        'processes': [
            {'cpu_percent': 5, 'memory_percent': 2, 'num_threads': 20},
            {'cpu_percent': 3, 'memory_percent': 1.5, 'num_threads': 15},
            {'cpu_percent': 8, 'memory_percent': 3, 'num_threads': 30},
        ],
        'connections': [{} for _ in range(5)],
        'metrics': {'cpu_percent': 10, 'memory': {'percent': 40}}
    }

def generate_cryptolocker_attack():
    """Simulate ransomware behavior"""
    return {
        'timestamp': datetime.now().isoformat(),
        'threat_name': 'Cryptolocker-like Ransomware',
        'threat_level': 'CRITICAL',
        'threat_score': 0.95,
        'reason': '''
        Process detected attempting to encrypt files:
        • Created 450+ files in 60 seconds (extreme file activity)
        • Network connections to command & control servers (suspicious IPs)
        • Process running from %APPDATA%/Temp (suspicious location)
        • File extensions: .encrypted, .locked, .ransom
        • CPU usage: 88% sustained
        • Attempting access to shadow copies and system files
        ''',
        'recommended_action': 'QUARANTINE IMMEDIATELY'
    }

def generate_botnet_scenario():
    """Simulate botnet activity"""
    return {
        'timestamp': datetime.now().isoformat(),
        'threat_name': 'Botnet Activity Detected',
        'threat_level': 'HIGH',
        'threat_score': 0.82,
        'reason': '''
        Suspicious process detected:
        • 350+ simultaneous network connections to unknown IPs
        • Process spawning multiple child processes
        • Unusual DNS queries to suspicious domains
        • Large outbound data transfer detected
        • Process name suspicious (svchost.exe variant)
        • Registry modifications for persistence
        ''',
        'recommended_action': 'ISOLATE FROM NETWORK'
    }

def generate_privilege_escalation():
    """Simulate privilege escalation attempt"""
    return {
        'timestamp': datetime.now().isoformat(),
        'threat_name': 'Privilege Escalation Attempt',
        'threat_level': 'HIGH',
        'threat_score': 0.78,
        'reason': '''
        Suspicious system behavior:
        • Unauthorized attempt to access %WINDIR%/System32
        • Multiple failed authentication attempts
        • Process attempting to modify system files
        • Access to Security Accounts Manager (SAM)
        • SYSTEM privilege requested from user-level process
        • Unusual kernel access patterns
        ''',
        'recommended_action': 'ALERT ADMINISTRATOR'
    }

def generate_data_exfiltration():
    """Simulate data exfiltration"""
    return {
        'timestamp': datetime.now().isoformat(),
        'threat_name': 'Data Exfiltration Detected',
        'threat_level': 'CRITICAL',
        'threat_score': 0.91,
        'reason': '''
        Unauthorized data transfer detected:
        • Process accessing sensitive files (documents, databases, credentials)
        • Large outbound data transfer (2.5 GB in 5 minutes)
        • Connection to non-business IP address
        • Accessing files outside user's normal workflow
        • Encryption detected on local data before transfer
        • Process attempting to cover tracks (clearing logs)
        ''',
        'recommended_action': 'BLOCK ALL OUTBOUND CONNECTIONS'
    }

def generate_persistent_threat():
    """Simulate persistence mechanism"""
    return {
        'timestamp': datetime.now().isoformat(),
        'threat_name': 'Persistence Mechanism Detected',
        'threat_level': 'MEDIUM',
        'threat_score': 0.65,
        'reason': '''
        Malware persistence setup detected:
        • Process modifying Windows Registry for autostart
        • Creating scheduled tasks for re-infection
        • Installing browser extensions without permission
        • DLL injection attempts into system processes
        • Disabling Windows Defender
        • Creating backup executables in hidden folders
        ''',
        'recommended_action': 'REMOVE PERSISTENCE + FULL SCAN'
    }

def main():
    """Generate and display threat scenarios"""
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║     AI Shield Guardian - Threat Scenario Generator         ║
    ║                                                            ║
    ║    These scenarios demonstrate detection capabilities     ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    scenarios = [
        ("Normal Behavior", generate_normal_behavior),
        ("Ransomware (Cryptolocker)", generate_cryptolocker_attack),
        ("Botnet Activity", generate_botnet_scenario),
        ("Privilege Escalation", generate_privilege_escalation),
        ("Data Exfiltration", generate_data_exfiltration),
        ("Persistence Mechanism", generate_persistent_threat),
    ]
    
    for name, generator in scenarios:
        print(f"\n{'='*60}")
        print(f"  {name}")
        print(f"{'='*60}")
        
        scenario = generator()
        
        if isinstance(scenario, dict):
            # Threat scenario
            print(f"Threat Level: {scenario.get('threat_level', 'N/A')}")
            print(f"Threat Score: {scenario.get('threat_score', 0):.2%}")
            print(f"Threat Name: {scenario.get('threat_name', 'Unknown')}")
            print(f"\nDetailed Reason:")
            print(scenario.get('reason', 'N/A'))
            print(f"\nRecommended Action: {scenario.get('recommended_action', 'Investigate')}")
        
        time.sleep(2)
    
    print(f"\n{'='*60}")
    print("✓ Scenario generation complete")
    print("\nThese scenarios can be used to:")
    print("• Demonstrate threat detection capabilities")
    print("• Test API response to various threat levels")
    print("• Showcase explainable AI features")
    print("• Validate frontend threat visualization")
    print("• Benchmark detection accuracy")

if __name__ == "__main__":
    main()
