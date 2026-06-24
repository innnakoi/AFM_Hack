# AI Shield Guardian - Database

SQLAlchemy models and initialization for threat detection system.

## Models

- **ThreatAlert**: Stores detected threats with severity levels
- **ProcessMetric**: Per-process resource metrics
- **SystemMetric**: System-wide metrics
- **AnomalyEvent**: AI-detected anomalies with scores
- **BlockedProcess**: Log of blocked/terminated processes

## Setup

```bash
python database.py
```

## Usage

```python
from database import SessionLocal, init_db
from models import ThreatAlert

# Initialize database
init_db()

# Get session
db = SessionLocal()

# Query threats
threats = db.query(ThreatAlert).all()
```
