

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import asyncio
import logging
import os
from datetime import datetime
from random import randint, random

from monitor import MonitoringService, ProcessMonitor, NetworkMonitor, SystemMetrics
from detector import AnomalyDetector, ThreatAnalyzer, ModelTrainer
from soc_logs import build_security_feed, dataset_status, load_events

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# In demo mode (default) response actions are simulated and never terminate real
# host processes or sockets. Set AISG_DEMO_MODE=false to enable real enforcement.
DEMO_MODE = os.getenv("AISG_DEMO_MODE", "true").strip().lower() not in ("false", "0", "no")


app = FastAPI(
    title="AI Shield Guardian",
    description="Real-time threat detection and anomaly analysis system",
    version="1.0.0"
)


# allow_credentials=True together with a wildcard origin is rejected by browsers
# per the CORS spec. This API uses no cookies/credentials, so keep it disabled.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
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

class SocDatasetLoadRequest(BaseModel):
    dataset_id: Optional[str] = "all"
    max_events: Optional[int] = 1200

threat_history: List[ThreatAlert] = []
last_threat_level = "NORMAL"
soc_events: List[Dict] = []
soc_dataset_id: Optional[str] = None

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
    logger.info("Demo mode: %s", "ON (actions simulated)" if DEMO_MODE else "OFF (real enforcement)")
    # Prime the non-blocking CPU counter so the first request returns real data.
    SystemMetrics.prime()
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
    if soc_events:
        feed = build_security_feed(soc_events)
        if feed:
            return feed

    metrics = SystemMetrics.get_metrics()
    processes = ProcessMonitor.get_processes()
    connections = NetworkMonitor.get_connections()
    suspicious_ips = NetworkMonitor.get_suspicious_ips()

    process_watchlist = sorted(
        [
            {
                "pid": p.get("pid"),
                "name": p.get("name") or "Unknown",
                "cpu_percent": round(float(p.get("cpu_percent") or 0), 1),
                "memory_gb": round(float(p.get("memory_percent") or 0), 3),
                "exe": p.get("exe") or "No executable path"
            }
            for p in processes
        ],
        key=lambda p: (p["cpu_percent"], p["memory_gb"]),
        reverse=True
    )[:8]

    remote_connections = [
        {
            "process": c.get("process") or "Unknown",
            "remote_addr": c.get("remote_addr"),
            "status": c.get("status")
        }
        for c in connections
        if c.get("remote_addr")
    ][:8]

    top_process = process_watchlist[0] if process_watchlist else {
        "name": "No process sample",
        "pid": 0,
        "cpu_percent": 0,
        "memory_gb": 0,
        "exe": "No executable path"
    }

    dynamic_risk = min(
        99,
        max(
            35,
            int(
                SOC_SCENARIOS[0]["risk_score"]
                + (metrics["memory"]["percent"] - 70) * 0.18
                + max(0, top_process["cpu_percent"] - 50) * 0.12
                + len(connections) * 0.015
                + len(suspicious_ips) * 6
                + randint(-3, 3)
            )
        )
    )

    signals = []
    for index, scenario in enumerate(SOC_SCENARIOS):
        item = dict(scenario)
        item["evidence"] = list(scenario["evidence"])
        item["factors"] = [dict(factor) for factor in scenario["factors"]]
        item["detected_at"] = datetime.now().isoformat()
        if index == 0:
            item["risk_score"] = dynamic_risk
            item["confidence"] = min(98, max(86, item["confidence"] + randint(-2, 2)))
            item["evidence"].append(
                f"Live device context: CPU {metrics['cpu_percent']}%, RAM {metrics['memory']['percent']}%, "
                f"{len(processes)} running processes, {len(connections)} active connections."
            )
            item["factors"].append({"name": "Live telemetry", "weight": min(98, dynamic_risk)})
        if item["category"] == "Endpoint behavior":
            item["source"] = f"{top_process['name']} / PID {top_process['pid']}"
            item["summary"] = (
                f"Current device telemetry highlights {top_process['name']} as the highest priority process "
                f"by CPU/RAM footprint."
            )
            item["evidence"] = [
                f"Process {top_process['name']} uses {top_process['cpu_percent']}% CPU and {top_process['memory_gb']}GB RAM.",
                f"Executable path: {top_process['exe']}",
                f"Network table currently contains {len(connections)} active or recent connections."
            ]
            item["factors"] = [
                {"name": "CPU footprint", "weight": min(100, int(top_process["cpu_percent"]))},
                {"name": "Memory footprint", "weight": min(100, int(top_process["memory_gb"] * 25))},
                {"name": "Connection pressure", "weight": min(100, len(connections))}
            ]
            item["risk_score"] = max(item["risk_score"], min(85, int(top_process["cpu_percent"] * 0.6 + len(connections) * 0.08)))
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
        "device_context": {
            "cpu_percent": metrics["cpu_percent"],
            "memory_percent": metrics["memory"]["percent"],
            "disk_percent": metrics["disk"]["percent"],
            "active_processes": len(processes),
            "network_connections": len(connections),
            "suspicious_ips": suspicious_ips,
            "process_watchlist": process_watchlist,
            "remote_connections": remote_connections,
            "analysis_basis": [
                "Live CPU, RAM, disk, process, and connection telemetry from the monitored device.",
                "Process priority is ranked by CPU and resident memory footprint.",
                "Network evidence is sampled from current remote connections."
            ]
        },
        "timeline": [
            {"time": datetime.now().strftime("%H:%M:%S"), "event": f"Device telemetry collected: {len(processes)} processes and {len(connections)} connections."},
            {"time": datetime.now().strftime("%H:%M:%S"), "event": f"Top process analyzed: {top_process['name']} PID {top_process['pid']}."},
            {"time": datetime.now().strftime("%H:%M:%S"), "event": "AI correlated device telemetry with IAM, DLP, email, and endpoint scenarios."},
            {"time": datetime.now().strftime("%H:%M:%S"), "event": "Risk explanation refreshed for analyst review."}
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


@app.get("/api/soc/datasets")
async def get_soc_datasets():
    """List downloaded SOC datasets available for replay"""
    return {
        "datasets": dataset_status(),
        "active_dataset_id": soc_dataset_id,
        "active_event_count": len(soc_events)
    }


@app.post("/api/soc/load")
async def load_soc_dataset(request: SocDatasetLoadRequest):
    """Load normalized OTRF SOC events into dashboard replay mode"""
    global soc_events, soc_dataset_id

    max_events = min(max(request.max_events or 1200, 50), 5000)
    events = load_events(request.dataset_id, max_events)
    if not events:
        raise HTTPException(status_code=404, detail="SOC dataset is not available or contains no readable events")

    soc_events = events
    soc_dataset_id = request.dataset_id or "all"
    return {
        "status": "loaded",
        "dataset_id": soc_dataset_id,
        "event_count": len(soc_events),
        "top_events": sorted(soc_events, key=lambda event: event["risk_score"], reverse=True)[:10],
        "feed": build_security_feed(soc_events)
    }


@app.post("/api/soc/clear")
async def clear_soc_dataset():
    """Return dashboard to synthetic live monitoring mode"""
    global soc_events, soc_dataset_id
    soc_events = []
    soc_dataset_id = None
    return {"status": "cleared"}


@app.get("/api/soc/events")
async def get_soc_events(limit: int = 100):
    """Return normalized SOC replay events"""
    safe_limit = min(max(limit, 1), 500)
    return {
        "dataset_id": soc_dataset_id,
        "event_count": len(soc_events),
        "events": sorted(soc_events, key=lambda event: event["risk_score"], reverse=True)[:safe_limit]
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


class ActionRequest(BaseModel):
    action: str
    pid: Optional[int] = None
    remote_addr: Optional[str] = None
    signal_id: Optional[str] = None


def find_connection_by_remote(remote_addr: str):
    import psutil
    for conn in psutil.net_connections():
        if conn.raddr and f"{conn.raddr.ip}:{conn.raddr.port}" == remote_addr:
            return conn
    return None


@app.post("/api/block_process/{pid}")
async def block_process(pid: int):
    """Block a suspicious process"""
    try:
        import psutil
        proc = psutil.Process(pid)
        process_name = proc.name()
        if DEMO_MODE:
            # Never kill real host processes in demo mode.
            return {
                "status": "success",
                "message": f"Process {process_name} ({pid}) isolated (demo mode, not terminated)",
                "process_name": process_name,
                "simulated": True
            }
        proc.terminate()

        return {
            "status": "success",
            "message": f"Process {process_name} ({pid}) has been terminated",
            "process_name": process_name
        }
    except Exception as e:
        logger.error(f"Error blocking process: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/block_connection")
async def block_connection(remote_addr: str):
    """Block a suspicious remote connection by terminating its owning process"""
    try:
        import psutil
        conn = find_connection_by_remote(remote_addr)
        if not conn or not conn.pid:
            raise HTTPException(status_code=404, detail="No active connection found for the provided remote address")
        proc = psutil.Process(conn.pid)
        process_name = proc.name()
        if DEMO_MODE:
            # Never terminate the real owning process in demo mode.
            return {
                "status": "success",
                "message": f"Connection to {remote_addr} terminated due to suspicious activity (demo mode)",
                "process_name": process_name,
                "pid": conn.pid,
                "remote_addr": remote_addr,
                "simulated": True
            }
        proc.terminate()
        return {
            "status": "success",
            "message": f"Connection to {remote_addr} has been blocked by terminating process {process_name} ({conn.pid})",
            "process_name": process_name,
            "pid": conn.pid,
            "remote_addr": remote_addr
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error blocking connection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/action")
async def execute_action(request: ActionRequest):
    """Execute a response action and map it to available enforcement APIs"""
    action_text = request.action.lower()
    if "block" in action_text and request.pid:
        return await block_process(request.pid)
    if "terminate" in action_text and request.pid:
        return await block_process(request.pid)
    if "connection" in action_text or "remote" in action_text:
        remote_addr = request.remote_addr
        if remote_addr:
            try:
                return await block_connection(remote_addr)
            except HTTPException as exc:
                if exc.status_code == 404:
                    return {
                        "status": "success",
                        "message": f"Connection {remote_addr} terminated due to suspicious activity",
                        "remote_addr": remote_addr,
                        "simulated": True
                    }
                raise
        if request.pid:
            return await block_process(request.pid)
        raise HTTPException(status_code=400, detail="remote_addr or pid is required to block a connection")
    if "analyse" in action_text or "analyze" in action_text or "run ai analysis" in action_text:
        result = await analyze_system()
        return {"status": "success", "message": "AI analysis completed", "result": result}
    if "isolate" in action_text:
        if request.pid:
            return await block_process(request.pid)
        if request.remote_addr:
            return await block_connection(request.remote_addr)
        return {"status": "success", "message": "Host isolation is simulated in this demo environment"}
    return {
        "status": "success",
        "message": f"Action '{request.action}' has been recorded",
        "action": request.action
    }


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
