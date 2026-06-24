

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import logging
from datetime import datetime
from random import randint, random

from monitor import MonitoringService, ProcessMonitor, NetworkMonitor, SystemMetrics
from detector import AnomalyDetector, ThreatAnalyzer, ModelTrainer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


app = FastAPI(
    title="AI Shield Guardian",
    description="Real-time threat detection and anomaly analysis system",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


monitoring_service = MonitoringService()
anomaly_detector = AnomalyDetector(contamination=0.1)
threat_analyzer = ThreatAnalyzer()

training_data = ModelTrainer.create_training_data(100)
anomaly_detector.train(training_data)

class ProcessInfo(BaseModel):
    pid: int
    name: str
    exe: Optional[str]
    cpu_percent: float
    memory_percent: float

class ThreatAlert(BaseModel):
    timestamp: str
    threat_level: str
    threat_score: float
    description: str
    affected_processes: List[str]

class SystemStatus(BaseModel):
    status: str
    cpu_percent: float
    memory_percent: float
    active_processes: int
    network_connections: int
    last_threat_level: str

class SecuritySignal(BaseModel):
    id: str
    category: str
    title: str
    severity: str
    confidence: int
    risk_score: int
    source: str
    summary: str
    evidence: List[str]
    factors: List[Dict[str, int]]
    recommended_actions: List[str]
    status: str
    detected_at: str

threat_history: List[ThreatAlert] = []
last_threat_level = "NORMAL"

SOC_SCENARIOS = [
    {
        "id": "INC-2406-017",
        "category": "Unauthorized access",
        "title": "Possible account takeover",
        "severity": "CRITICAL",
        "confidence": 94,
        "risk_score": 92,
        "source": "vpn-gw-02 / iam",
        "summary": "User session combines impossible travel, new device fingerprint, and admin-scope access request.",
        "evidence": [
            "Login from a new country occurred minutes after a local session.",
            "The session requested finance workspace and OAuth application permissions.",
            "Behavior differs from the user's 30-day baseline by time, geo, and device."
        ],
        "factors": [
            {"name": "Geo anomaly", "weight": 96},
            {"name": "Privilege request", "weight": 88},
            {"name": "Device mismatch", "weight": 81}
        ],
        "recommended_actions": [
            "Require step-up MFA",
            "Revoke active tokens",
            "Open SOC incident"
        ],
        "status": "Containment ready"
    },
    {
        "id": "INC-2406-018",
        "category": "Data leak prevention",
        "title": "Sensitive archive export blocked",
        "severity": "HIGH",
        "confidence": 91,
        "risk_score": 87,
        "source": "cloud-storage / dlp",
        "summary": "DLP detected customer PII inside an archive sent to a low-reputation external domain.",
        "evidence": [
            "Archive contains passport-like IDs, phone numbers, and email addresses.",
            "Recipient domain has no trusted exchange history with the organization.",
            "Upload volume is 11x higher than the department baseline."
        ],
        "factors": [
            {"name": "PII density", "weight": 93},
            {"name": "External domain", "weight": 86},
            {"name": "Upload burst", "weight": 82}
        ],
        "recommended_actions": [
            "Block file transfer",
            "Notify data owner",
            "Preserve audit trail"
        ],
        "status": "Blocked"
    },
    {
        "id": "INC-2406-019",
        "category": "Phishing",
        "title": "Credential phishing campaign",
        "severity": "HIGH",
        "confidence": 86,
        "risk_score": 79,
        "source": "mail-sec / gateway",
        "summary": "Email cluster imitates corporate SSO and asks users to approve a suspicious OAuth token.",
        "evidence": [
            "Lookalike domain differs from the trusted domain by one character.",
            "Landing page requests OAuth consent outside the corporate SSO flow.",
            "The same template was delivered to 42 inboxes."
        ],
        "factors": [
            {"name": "Lookalike domain", "weight": 90},
            {"name": "Token request", "weight": 84},
            {"name": "Sender reputation", "weight": 75}
        ],
        "recommended_actions": [
            "Quarantine messages",
            "Block sender domain",
            "Reset exposed passwords"
        ],
        "status": "Quarantined"
    },
    {
        "id": "INC-2406-020",
        "category": "Endpoint behavior",
        "title": "Suspicious reconnaissance script",
        "severity": "MEDIUM",
        "confidence": 68,
        "risk_score": 61,
        "source": "endpoint-117 / edr",
        "summary": "Endpoint telemetry shows short PowerShell bursts that enumerate processes and connections.",
        "evidence": [
            "Script inspected running processes and network sessions.",
            "Command line entropy is higher than regular admin automation.",
            "No confirmed malware hash yet, so the host remains under observation."
        ],
        "factors": [
            {"name": "Script entropy", "weight": 69},
            {"name": "Process scan", "weight": 64},
            {"name": "Network probe", "weight": 56}
        ],
        "recommended_actions": [
            "Collect triage package",
            "Limit outbound traffic",
            "Watch for persistence"
        ],
        "status": "Watching"
    }
]


@app.on_event("startup")
async def startup_event():
    """Initialize monitoring on startup"""
    logger.info("AI Shield Guardian started")
    logger.info("Starting system monitoring...")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    monitoring_service.stop_file_monitoring()
    logger.info("AI Shield Guardian stopped")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AI Shield Guardian - Real-time Threat Detection",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/status", response_model=SystemStatus)
async def get_system_status():
    """Get current system status"""
    try:
        metrics = SystemMetrics.get_metrics()
        processes = ProcessMonitor.get_processes()
        connections = NetworkMonitor.get_connections()
        
        return SystemStatus(
            status="monitoring",
            cpu_percent=metrics['cpu_percent'],
            memory_percent=metrics['memory']['percent'],
            active_processes=len(processes),
            network_connections=len(connections),
            last_threat_level=last_threat_level
        )
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/processes", response_model=List[ProcessInfo])
async def get_processes():
    """Get list of running processes"""
    try:
        processes = ProcessMonitor.get_processes()
        return [
            ProcessInfo(
                pid=p['pid'],
                name=p['name'],
                exe=p.get('exe'),
                cpu_percent=p.get('cpu_percent', 0),
                memory_percent=p.get('memory_percent', 0)
            )
            for p in processes[:50]  # Return top 50
        ]
    except Exception as e:
        logger.error(f"Error getting processes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/processes/{pid}")
async def get_process_details(pid: int):
    """Get detailed information about a specific process"""
    try:
        details = ProcessMonitor.get_process_details(pid)
        if not details:
            raise HTTPException(status_code=404, detail="Process not found")
        return details
    except Exception as e:
        logger.error(f"Error getting process details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/connections")
async def get_network_connections():
    """Get active network connections"""
    try:
        connections = NetworkMonitor.get_connections()
        return {
            "total_connections": len(connections),
            "connections": connections[:50]  # Return top 50
        }
    except Exception as e:
        logger.error(f"Error getting connections: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threats")
async def get_threat_history():
    """Get threat history"""
    return {
        "total_threats": len(threat_history),
        "threats": threat_history[-50:]  # Return last 50
    }


@app.get("/api/security-feed")
async def get_security_feed():
    """Get AI security scenarios for the SOC dashboard"""
    metrics = SystemMetrics.get_metrics()
    processes = ProcessMonitor.get_processes()
    connections = NetworkMonitor.get_connections()

    dynamic_risk = min(
        99,
        max(
            35,
            int(
                SOC_SCENARIOS[0]["risk_score"]
                + (metrics["memory"]["percent"] - 70) * 0.18
                + len(connections) * 0.015
                + randint(-3, 3)
            )
        )
    )

    signals = []
    for index, scenario in enumerate(SOC_SCENARIOS):
        item = dict(scenario)
        item["detected_at"] = datetime.now().isoformat()
        if index == 0:
            item["risk_score"] = dynamic_risk
            item["confidence"] = min(98, max(86, item["confidence"] + randint(-2, 2)))
        signals.append(item)

    return {
        "mode": "defend",
        "overall_risk": dynamic_risk,
        "risk_level": "CRITICAL" if dynamic_risk >= 90 else "HIGH" if dynamic_risk >= 75 else "MEDIUM",
        "mean_detect_time_seconds": round(0.7 + random() * 0.4, 2),
        "blocked_data_gb": round(1.4 + random() * 0.5, 2),
        "protected_assets": 1248 + len(processes),
        "active_incidents": len([s for s in signals if s["severity"] in ["HIGH", "CRITICAL"]]),
        "signals": signals,
        "timeline": [
            {"time": "13:21:43", "event": "AI correlated IAM, DLP, email, and endpoint signals."},
            {"time": "13:22:08", "event": "DLP blocked finance-q2.zip export to an external domain."},
            {"time": "13:22:35", "event": "Mail gateway quarantined 42 phishing messages."},
            {"time": "13:23:01", "event": "Step-up MFA was required for a risky user session."},
            {"time": "13:23:21", "event": "Endpoint-117 switched to evidence collection mode."}
        ],
        "coverage": [
            {"name": "Unauthorized access", "value": 96},
            {"name": "User behavior anomalies", "value": 91},
            {"name": "Data leaks", "value": 88},
            {"name": "Phishing", "value": 86},
            {"name": "Endpoint compromise", "value": 74}
        ],
        "last_update": datetime.now().isoformat()
    }


@app.post("/api/analyze")
async def analyze_system():
    """Analyze current system state for threats"""
    global last_threat_level
    
    try:
        # Collect monitoring data
        data = monitoring_service.collect_all_data()
        
        # Run anomaly detection
        anomaly_score, is_anomalous = anomaly_detector.predict(data)
        
        # Analyze individual processes
        processes = data.get('processes', [])
        high_risk_processes = []
        
        for proc in processes[:20]:  # Analyze top processes
            proc_analysis = threat_analyzer.analyze_process(proc)
            if proc_analysis['threat_score'] > 0.3:
                high_risk_processes.append(proc_analysis)
        
        # Analyze network
        suspicious_ips = NetworkMonitor.get_suspicious_ips()
        
        # Calculate overall threat
        threat_data = {
            'anomaly_score': anomaly_score,
            'process_threats': high_risk_processes,
            'file_threats': {'threat_score': 0},
            'network_anomalies': suspicious_ips
        }
        
        threat_assessment = threat_analyzer.calculate_overall_threat(
            anomaly_score,
            high_risk_processes,
            threat_data['file_threats'],
            suspicious_ips
        )
        
        last_threat_level = threat_assessment['threat_level']
        
        # Create threat alert
        alert = ThreatAlert(
            timestamp=datetime.now().isoformat(),
            threat_level=threat_assessment['threat_level'],
            threat_score=threat_assessment['threat_score'],
            description=threat_analyzer.explain_threat(threat_assessment),
            affected_processes=[p['process_name'] for p in high_risk_processes]
        )
        
        # Store in history if threat detected
        if threat_assessment['threat_level'] in ['MEDIUM', 'HIGH', 'CRITICAL']:
            threat_history.append(alert)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "threat_analysis": threat_assessment,
            "anomaly_score": anomaly_score,
            "processes_analyzed": len(processes),
            "high_risk_processes": high_risk_processes,
            "network_anomalies": suspicious_ips,
            "alert": alert
        }
    except Exception as e:
        logger.error(f"Error analyzing system: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/block_process/{pid}")
async def block_process(pid: int):
    """Block a suspicious process"""
    try:
        import psutil
        proc = psutil.Process(pid)
        proc.terminate()
        
        return {
            "status": "success",
            "message": f"Process {pid} has been terminated",
            "process_name": proc.name()
        }
    except Exception as e:
        logger.error(f"Error blocking process: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/metrics")
async def get_system_metrics():
    """Get detailed system metrics"""
    try:
        metrics = SystemMetrics.get_metrics()
        return metrics
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/dashboard")
async def get_dashboard_data():
    """Get all data for dashboard"""
    try:
        # Collect all data
        status = await get_system_status()
        metrics = SystemMetrics.get_metrics()
        connections = NetworkMonitor.get_connections()
        processes = ProcessMonitor.get_processes()
        
        return {
            "status": status,
            "metrics": metrics,
            "top_connections": connections[:10],
            "top_processes": processes[:10],
            "threat_history_count": len(threat_history),
            "last_threats": threat_history[-5:],
            "last_update": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
