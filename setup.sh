#!/bin/bash
# AI Shield Guardian - Quick Setup Script for Linux/Mac

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     🛡️  AI Shield Guardian Setup Script  🛡️                ║"
echo "║                                                            ║"
echo "║        Installing dependencies and starting system       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check Python
echo "📋 Checking Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Install Python 3.9+ first."
    exit 1
fi
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION"

# Check Node
echo "📋 Checking Node.js..."
if ! command -v node &> /dev/null; then
    echo "⚠️  Node.js not found. Frontend setup will be skipped."
    SKIP_FRONTEND=true
fi

# Setup Backend
echo ""
echo "📦 Installing backend dependencies..."
cd backend || exit 1
pip install -r requirements.txt
cd ..

if [ "$SKIP_FRONTEND" != "true" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend || exit 1
    npm install
    cd ..
fi

# Train model
echo ""
echo "🤖 Training AI model..."
cd models || exit 1
python3 train_model.py
cd ..

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Starting AI Shield Guardian..."
echo ""
echo "To start the system:"
echo "  Terminal 1: python backend/app.py"
echo "  Terminal 2: cd frontend && npm start"
echo ""
echo "Dashboard: http://localhost:3000"
echo "API Server: http://localhost:8000"
echo "API Docs: http://localhost:8000/docs"
