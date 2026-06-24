"""
AI Shield Guardian - API Testing Script
Test all endpoints and functionality
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"

def print_section(title):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def test_health():
    """Test health endpoint"""
    print_section("Health Check")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Status: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_status():
    """Test system status endpoint"""
    print_section("System Status")
    try:
        response = requests.get(f"{BASE_URL}/api/status")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"CPU: {data['cpu_percent']:.1f}%")
        print(f"Memory: {data['memory_percent']:.1f}%")
        print(f"Active Processes: {data['active_processes']}")
        print(f"Network Connections: {data['network_connections']}")
        print(f"Last Threat Level: {data['last_threat_level']}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_processes():
    """Test processes endpoint"""
    print_section("Running Processes")
    try:
        response = requests.get(f"{BASE_URL}/api/processes")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Total processes returned: {len(data)}")
        print("\nTop 5 processes:")
        for i, proc in enumerate(data[:5], 1):
            print(f"{i}. {proc['name']} (PID: {proc['pid']}, CPU: {proc['cpu_percent']:.1f}%)")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_connections():
    """Test network connections endpoint"""
    print_section("Network Connections")
    try:
        response = requests.get(f"{BASE_URL}/api/connections")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Total connections: {data['total_connections']}")
        if data['connections']:
            print("\nSample connections:")
            for i, conn in enumerate(data['connections'][:3], 1):
                print(f"{i}. {conn['process']} - {conn['local_addr']} → {conn['remote_addr']}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_metrics():
    """Test system metrics endpoint"""
    print_section("System Metrics")
    try:
        response = requests.get(f"{BASE_URL}/api/metrics")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"CPU: {data['cpu_percent']:.1f}%")
        print(f"Memory: {data['memory']['percent']:.1f}%")
        print(f"Disk: {data['disk']['percent']:.1f}%")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_analyze():
    """Test threat analysis endpoint"""
    print_section("Threat Analysis")
    try:
        response = requests.post(f"{BASE_URL}/api/analyze")
        print(f"Status: {response.status_code}")
        data = response.json()
        
        threat = data['threat_analysis']
        print(f"Threat Level: {threat['threat_level']}")
        print(f"Threat Score: {threat['threat_score']:.2%}")
        print(f"Anomaly Score: {data['anomaly_score']:.4f}")
        print(f"Processes Analyzed: {data['processes_analyzed']}")
        print(f"High Risk Processes: {len(data['high_risk_processes'])}")
        
        if data['network_anomalies']:
            print(f"Network Anomalies: {', '.join(data['network_anomalies'])}")
        
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_threats():
    """Test threat history endpoint"""
    print_section("Threat History")
    try:
        response = requests.get(f"{BASE_URL}/api/threats")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Total threats: {data['total_threats']}")
        if data['threats']:
            print("\nRecent threats:")
            for i, threat in enumerate(data['threats'][-3:], 1):
                print(f"{i}. {threat['threat_level']} - {threat['timestamp']}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_dashboard():
    """Test dashboard data endpoint"""
    print_section("Dashboard Data")
    try:
        response = requests.get(f"{BASE_URL}/api/dashboard")
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Last Update: {data['last_update']}")
        print(f"Threat History Count: {data['threat_history_count']}")
        print(f"Top Connections: {len(data['top_connections'])}")
        print(f"Top Processes: {len(data['top_processes'])}")
        print(f"System Status: {data['status']['status']}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Run all tests"""
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║           API Testing - AI Shield Guardian                 ║
    ║                                                            ║
    ║  Make sure backend is running: python backend/app.py      ║
    ╚════════════════════════════════════════════════════════════╝
    """)
    
    # Wait for server
    print("Waiting for server to be ready...")
    for i in range(10):
        try:
            requests.get(f"{BASE_URL}/health")
            print("✓ Server is ready!\n")
            break
        except:
            print(f"  Attempt {i+1}/10...", end='\r')
            time.sleep(1)
    
    # Run tests
    tests = [
        test_health,
        test_status,
        test_metrics,
        test_processes,
        test_connections,
        test_analyze,
        test_threats,
        test_dashboard,
    ]
    
    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"❌ Test failed: {e}")
            results.append(False)
    
    # Summary
    print_section("Test Summary")
    passed = sum(results)
    total = len(results)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {passed/total*100:.1f}%")
    
    if passed == total:
        print("\n✅ All tests passed!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")

if __name__ == "__main__":
    main()
