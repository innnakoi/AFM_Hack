"""
Database models for AI Shield Guardian
"""

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class ThreatAlert(Base):
    """Store threat alerts"""
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    threat_level = Column(String(20), index=True)
    threat_score = Column(Float)
    description = Column(Text)
    affected_processes = Column(String)
    
    def __repr__(self):
        return f"<ThreatAlert {self.id} - {self.threat_level}>"


class ProcessMetric(Base):
    """Store process metrics"""
    __tablename__ = "process_metrics"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    pid = Column(Integer, index=True)
    process_name = Column(String(255))
    cpu_percent = Column(Float)
    memory_mb = Column(Float)
    thread_count = Column(Integer)
    
    def __repr__(self):
        return f"<ProcessMetric {self.process_name} - {self.pid}>"


class SystemMetric(Base):
    """Store system-wide metrics"""
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    cpu_percent = Column(Float)
    memory_percent = Column(Float)
    disk_percent = Column(Float)
    network_connections = Column(Integer)
    active_processes = Column(Integer)
    
    def __repr__(self):
        return f"<SystemMetric {self.timestamp}>"


class AnomalyEvent(Base):
    """Store detected anomalies"""
    __tablename__ = "anomaly_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    anomaly_score = Column(Float)
    is_anomalous = Column(Boolean, default=False)
    features = Column(Text)  # JSON string
    explanation = Column(Text)
    
    def __repr__(self):
        return f"<AnomalyEvent {self.id} - score: {self.anomaly_score}>"


class BlockedProcess(Base):
    """Store blocked processes"""
    __tablename__ = "blocked_processes"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    pid = Column(Integer)
    process_name = Column(String(255))
    reason = Column(String(255))
    
    def __repr__(self):
        return f"<BlockedProcess {self.process_name} - {self.pid}>"
