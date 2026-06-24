# Quick Start Guide for AI Shield Guardian

## 🚀 Fastest Way to Get Started (5 minutes)

### 1. Backend Setup

```bash
# Navigate to backend
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Start the API server
python app.py
```

**Output should show:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 2. Frontend Setup (in a new terminal)

```bash
# Navigate to frontend
cd frontend

# Install npm dependencies
npm install

# Start development server
npm start
```

**Browser will open at:** `http://localhost:3000`

### 3. Start Monitoring

Once both servers are running, the dashboard will:
- ✅ Automatically connect to the API
- ✅ Start collecting system data
- ✅ Run threat analysis every 5 seconds
- ✅ Display real-time metrics and alerts

## 📊 Dashboard Overview

1. **Status Cards** (Top)
   - CPU Usage
   - Memory Usage
   - Active Processes
   - Network Connections

2. **Charts** (Middle)
   - System Metrics (CPU & Memory over time)
   - Threat Timeline

3. **Panels** (Bottom)
   - Recent Threats
   - Top Processes

## 🔴 Threat Levels

- 🟢 **LOW** - Normal behavior
- 🟡 **MEDIUM** - Suspicious activity
- 🟠 **HIGH** - Potential threat
- 🔴 **CRITICAL** - Immediate action required

## 💻 API Usage

### Check System Status
```bash
curl http://localhost:8000/api/status
```

### Get Running Processes
```bash
curl http://localhost:8000/api/processes
```

### Analyze System for Threats
```bash
curl -X POST http://localhost:8000/api/analyze
```

### View Threat History
```bash
curl http://localhost:8000/api/threats
```

### Terminate a Process
```bash
curl -X POST http://localhost:8000/api/block_process/1234
```

## ⚙️ Configuration

### Backend Configuration (.env)

Create `backend/.env` file:

```
DATABASE_URL=sqlite:///./ai_shield.db
DEBUG=True
API_PORT=8000
```

### For PostgreSQL (Production)

```
DATABASE_URL=postgresql://user:password@localhost:5432/ai_shield
```

## 🧠 Train AI Model

```bash
cd models
python train_model.py
```

This will:
- Generate synthetic training data
- Train the Isolation Forest model
- Test the model
- Save trained models to `models/` directory

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check if port 8000 is in use
netstat -an | grep 8000

# Or specify different port
# Edit app.py and change port=8000
```

### Frontend can't connect to API
```bash
# Check if backend is running
curl http://localhost:8000/health

# Check browser console for errors (F12)
```

### Permission denied for process monitoring
- Windows: Run terminal as Administrator
- Linux: Run with `sudo`
- macOS: Might need sudo for full monitoring

### High CPU usage
- Reduce monitoring frequency
- Disable file system monitoring (edit `monitor.py`)
- Use sampling instead of continuous monitoring

## 📈 Performance Tips

1. **Reduce API call frequency**
   - Edit `Dashboard.jsx` line with `setInterval(fetchDashboardData, 5000)`
   - Increase 5000 to 10000 for less frequent updates

2. **Limit process monitoring**
   - In `api/processes` change `[:50]` to `[:20]`

3. **Use SQLite for MVP**
   - Default SQLite is perfect for demos
   - Switch to PostgreSQL for production

## 🎯 Key Files to Understand

| File | Purpose |
|------|---------|
| `backend/app.py` | Main API server |
| `backend/monitor.py` | System monitoring |
| `backend/detector.py` | AI threat detection |
| `frontend/Dashboard.jsx` | Main UI component |
| `models/train_model.py` | Model training script |
| `database/models.py` | Database schemas |

## 🔍 Testing the System

### Test 1: Check API
```bash
curl http://localhost:8000
```

### Test 2: Get System Status
```bash
curl http://localhost:8000/api/status
```

### Test 3: Run Analysis
```bash
curl -X POST http://localhost:8000/api/analyze
```

### Test 4: Open Dashboard
```
Open browser: http://localhost:3000
```

## 📚 API Documentation

Full Swagger documentation available at:
```
http://localhost:8000/docs
```

## 🎓 Learning Resources

- **Isolation Forest**: scikit-learn documentation
- **FastAPI**: https://fastapi.tiangolo.com/
- **React**: https://react.dev/
- **Tailwind CSS**: https://tailwindcss.com/

## 🚀 Next Steps

1. ✅ Get backend and frontend running
2. ✅ Verify dashboard displays data
3. ✅ Test threat detection API
4. ✅ Generate synthetic threats for testing
5. ✅ Customize threat thresholds
6. ✅ Add more monitoring features
7. ✅ Deploy to production

## ❓ FAQ

**Q: Why isn't the dashboard showing threats?**
A: Threats are only generated when suspicious behavior is detected. Use synthetic data or modify threshold settings in `detector.py`.

**Q: Can I run this on Linux/Mac?**
A: Yes! All components are cross-platform. Some process monitoring might require `sudo`.

**Q: How do I add custom threat rules?**
A: Edit the `ThreatAnalyzer.analyze_process()` method in `backend/detector.py`.

**Q: Can I use my own ML model?**
A: Yes! Replace the model in `models/anomaly_model.pkl` or modify `detector.py`.

---

**Happy Coding! 🚀** For issues or questions, check the main README.md or create an issue.
