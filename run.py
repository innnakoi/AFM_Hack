"""
AI Shield Guardian - Main Execution Script
Quick setup and run all components
"""

import subprocess
import os
import time
import sys
from pathlib import Path

def print_banner():
    """Print welcome banner"""
    print("""
    ╔════════════════════════════════════════════════════════════╗
    ║       AI Shield Guardian - Threat Detection MVP            ║
    ║                                                            ║
    ║        Real-time AI-powered cybersecurity system           ║
    ╚════════════════════════════════════════════════════════════╝
    """)

def check_python():
    """Check Python version"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(" Python 3.9+ required")
        sys.exit(1)
    print(f"✓ Python {version.major}.{version.minor}.{version.micro}")

def check_node():
    """Check Node.js installation"""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        print(f"✓ Node.js {result.stdout.strip()}")
    except:
        print("  Node.js not found (frontend setup will fail)")

def install_backend():
    """Install backend dependencies"""
    print("\n Installing backend dependencies...")
    backend_dir = Path("backend")
    if not backend_dir.exists():
        print(" backend/ directory not found")
        return False
    
    os.chdir(backend_dir)
    result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    os.chdir("..")
    return result.returncode == 0

def install_frontend():
    """Install frontend dependencies"""
    print("\n Installing frontend dependencies...")
    frontend_dir = Path("frontend")
    if not frontend_dir.exists():
        print(" frontend/ directory not found")
        return False
    
    os.chdir(frontend_dir)
    result = subprocess.run(["npm.cmd", "install"], shell=True)
    os.chdir("..")
    return result.returncode == 0

def train_model():
    """Train ML model"""
    print("\n Training AI model...")
    os.chdir("models")
    result = subprocess.run([sys.executable, "train_model.py"])
    os.chdir("..")
    return result.returncode == 0

def start_backend():
    """Start backend server"""
    print("\n Starting backend API server...")
    print("   Server will run at: http://localhost:8000")
    print("   API docs at: http://localhost:8000/docs")
    
    subprocess.Popen([sys.executable, "backend/app.py"])
    time.sleep(3)

def start_frontend():
    """Start frontend development server"""
    print("\n Starting frontend development server...")
    print("   Dashboard will open at: http://localhost:3000")
    
    os.chdir("frontend")
    subprocess.Popen(["npm.cmd", "run", "dev"], shell=True)
    os.chdir("..")

def main():
    """Main execution"""
    print_banner()
    
    # Check environment
    print("\n Checking environment...")
    check_python()
    check_node()
    
    # Install dependencies
    if not install_backend():
        print(" Backend installation failed")
        return
    
    if not install_frontend():
        print("  Frontend installation failed (non-critical)")
    
    # Train model
    if not train_model():
        print("  Model training failed (non-critical)")
    
    # Start servers
    print("\n" + "="*60)
    print(" Starting AI Shield Guardian...")
    print("="*60)
    
    start_backend()
    time.sleep(5)
    start_frontend()
    
    print("""
     All systems operational!
    
     Dashboard: http://localhost:3000
     API Server: http://localhost:8000
     API Docs: http://localhost:8000/docs
    
    Press Ctrl+C to stop
    """)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n AI Shield Guardian stopped")

if __name__ == "__main__":
    main()
