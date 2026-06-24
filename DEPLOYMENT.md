# Deployment Guide for AI Shield Guardian

## 🚀 Production Deployment

### Prerequisites
- Ubuntu 20.04+ or Windows Server 2019+
- Python 3.9+
- Node.js 16+
- PostgreSQL 12+ (recommended)
- At least 2GB RAM

## 📦 Backend Deployment

### 1. Install Dependencies
```bash
sudo apt update
sudo apt install python3.9 python3-pip postgresql
```

### 2. Clone and Setup
```bash
git clone <repo-url> ai-shield
cd ai-shield/backend

# Create virtual environment
python3.9 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with production settings
```

### 4. Setup Database
```bash
sudo -u postgres psql
CREATE DATABASE ai_shield;
CREATE USER ai_shield WITH PASSWORD 'your_secure_password';
ALTER ROLE ai_shield SET client_encoding TO 'utf8';
ALTER ROLE ai_shield SET default_transaction_isolation TO 'read committed';
ALTER ROLE ai_shield SET default_transaction_deferrable TO on;
ALTER ROLE ai_shield SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE ai_shield TO ai_shield;
```

Update `.env`:
```
DATABASE_URL=postgresql://ai_shield:your_secure_password@localhost:5432/ai_shield
```

### 5. Setup Systemd Service
Create `/etc/systemd/system/ai-shield-api.service`:
```ini
[Unit]
Description=AI Shield Guardian API
After=network.target

[Service]
Type=notify
User=ai-shield
WorkingDirectory=/opt/ai-shield/backend
ExecStart=/opt/ai-shield/backend/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 6. Start Service
```bash
sudo systemctl enable ai-shield-api.service
sudo systemctl start ai-shield-api.service
sudo systemctl status ai-shield-api.service
```

## 🎨 Frontend Deployment

### 1. Build
```bash
cd frontend
npm install
npm run build
```

### 2. Setup Web Server (Nginx)
Create `/etc/nginx/sites-available/ai-shield`:
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    root /opt/ai-shield/frontend/build;
    index index.html;
    
    location / {
        try_files $uri /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/ai-shield /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## 🔒 Security Hardening

### 1. HTTPS/SSL
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot certonly --nginx -d your-domain.com
```

### 2. API Authentication
Update `backend/app.py` to add authentication:
```python
from fastapi.security import HTTPBearer, HTTPAuthCredentials

security = HTTPBearer()

@app.get("/api/status")
async def get_status(credentials: HTTPAuthCredentials = Depends(security)):
    # Verify token
    return {}
```

### 3. Firewall Rules
```bash
sudo ufw allow 22
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

### 4. Process Privileges
```bash
# Run with limited privileges
sudo useradd -r -s /bin/false ai-shield
sudo chown -R ai-shield:ai-shield /opt/ai-shield
```

## 📊 Monitoring & Logging

### 1. Application Logging
Update `backend/app.py`:
```python
import logging
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler(
    'ai-shield.log',
    maxBytes=10485760,  # 10MB
    backupCount=10
)
logging.getLogger().addHandler(handler)
```

### 2. System Monitoring
```bash
# Install monitoring tools
sudo apt install prometheus grafana-server

# Monitor systemd service
sudo systemctl status ai-shield-api
sudo journalctl -u ai-shield-api -f
```

## 🐳 Docker Deployment

### Backend Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/ .
CMD ["python", "app.py"]
```

### Docker Compose
```yaml
version: '3'
services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/ai_shield
    depends_on:
      - db
  
  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=ai_shield
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
    ports:
      - "3000:3000"

volumes:
  postgres_data:
```

## 🔄 Update Procedure

### 1. Backup Database
```bash
sudo -u postgres pg_dump ai_shield > backup.sql
```

### 2. Stop Service
```bash
sudo systemctl stop ai-shield-api
```

### 3. Update Code
```bash
cd /opt/ai-shield
git pull origin main
```

### 4. Update Dependencies
```bash
source backend/venv/bin/activate
pip install -r backend/requirements.txt
```

### 5. Run Migrations
```bash
python backend/app.py
```

### 6. Restart
```bash
sudo systemctl start ai-shield-api
```

## 📈 Performance Tuning

### 1. API Server
Edit `backend/app.py`:
```python
uvicorn.run(
    app,
    host="0.0.0.0",
    port=8000,
    workers=4,  # Adjust based on CPU cores
    loop="uvloop"  # Faster event loop
)
```

### 2. Database
```sql
-- Create indexes for faster queries
CREATE INDEX idx_threats_timestamp ON threat_alerts(timestamp);
CREATE INDEX idx_metrics_timestamp ON system_metrics(timestamp);
```

### 3. Frontend Caching
Update Nginx config:
```nginx
location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

## ⚠️ Troubleshooting

### API won't start
```bash
sudo journalctl -u ai-shield-api -n 50 -f
```

### Database connection error
```bash
sudo -u postgres psql -c "SELECT version();"
```

### High CPU usage
- Check process monitoring interval
- Reduce database query frequency
- Enable caching

### Memory leak
- Monitor with `htop`
- Check for unbounded lists in detector.py
- Implement memory limits in Systemd

## 🎯 Next Steps

1. ✅ Deploy to production server
2. ✅ Setup monitoring and alerts
3. ✅ Configure backup procedures
4. ✅ Create runbooks for common issues
5. ✅ Setup security scanning
6. ✅ Configure log aggregation

---

For more help, see QUICKSTART.md or README.md
