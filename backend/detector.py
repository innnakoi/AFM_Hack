import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple
import joblib
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect anomalies in system behavior using Isolation Forest"""
    
    def __init__(self, contamination: float = 0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'cpu_percent',
            'memory_mb',
            'network_connections',
            'file_operations',
            'process_count',
            'thread_count'
        ]
    
    def extract_features(self, data: Dict) -> np.ndarray:
        """Extract features from monitoring data"""
        try:
            processes = data.get('processes', [])
            connections = data.get('connections', [])
            metrics = data.get('metrics', {})
            
            # Calculate aggregated features
            total_cpu = sum(p.get('cpu_percent', 0) for p in processes)
            total_memory = sum(p.get('memory_percent', 0) for p in processes)
            num_connections = len(connections)
            num_processes = len(processes)
            total_threads = sum(p.get('num_threads', 0) for p in processes)
            
            features = np.array([[
                total_cpu,
                total_memory,
                num_connections,
                0,  # file_operations (will be filled from file monitor)
                num_processes,
                total_threads
            ]])
            
            return features
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return np.array([[0, 0, 0, 0, 0, 0]])
    
    def train(self, training_data: List[Dict]):
        """Train the anomaly detection model"""
        try:
            features_list = []
            for data in training_data:
                features = self.extract_features(data)
                features_list.append(features[0])
            
            X = np.array(features_list)
            X_scaled = self.scaler.fit_transform(X)
            self.model.fit(X_scaled)
            self.is_trained = True
            logger.info("Anomaly detection model trained successfully")
        except Exception as e:
            logger.error(f"Error training model: {e}")
    
    def predict(self, data: Dict) -> Tuple[float, bool]:
        """
        Predict if current data is anomalous
        Returns: (anomaly_score, is_anomaly)
        """
        if not self.is_trained:
            logger.warning("Model not trained yet")
            return 0.0, False
        
        try:
            features = self.extract_features(data)
            features_scaled = self.scaler.transform(features)
            
            # Get anomaly score (negative is normal, positive is anomalous)
            score = self.model.score_samples(features_scaled)[0]
            # Normalize to 0-1 range
            anomaly_score = 1 / (1 + np.exp(-score))
            
            is_anomaly = self.model.predict(features_scaled)[0] == -1
            
            return anomaly_score, is_anomaly
        except Exception as e:
            logger.error(f"Error predicting anomaly: {e}")
            return 0.0, False
    
    def save_model(self, path: str):
        """Save trained model"""
        try:
            joblib.dump(self.model, f"{path}/anomaly_model.pkl")
            joblib.dump(self.scaler, f"{path}/scaler.pkl")
            logger.info(f"Model saved to {path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def load_model(self, path: str):
        """Load pre-trained model"""
        try:
            self.model = joblib.load(f"{path}/anomaly_model.pkl")
            self.scaler = joblib.load(f"{path}/scaler.pkl")
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")


class ThreatAnalyzer:
    """Analyze and rate threats based on multiple factors"""
    
    # Threat levels
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    
    @staticmethod
    def analyze_process(process_data: Dict) -> Dict:
        """Analyze a specific process for threats"""
        threat_factors = []
        threat_score = 0.0
        
        # Check CPU usage
        cpu = process_data.get('cpu_percent', 0)
        if cpu > 80:
            threat_factors.append("High CPU usage")
            threat_score += 0.2
        
        # Check memory usage
        memory = process_data.get('memory_percent', 0)
        if memory > 1000:  # 1GB
            threat_factors.append("High memory usage")
            threat_score += 0.15
        
        # Check number of connections
        connections = process_data.get('connections', 0)
        if connections > 50:
            threat_factors.append("Unusual number of network connections")
            threat_score += 0.25
        
        # Check for suspicious executable paths
        exe = (process_data.get('exe') or '').lower()
        suspicious_paths = ['temp', 'appdata', 'users', 'downloads']
        if any(path in exe for path in suspicious_paths):
            threat_factors.append("Suspicious executable location")
            threat_score += 0.2
        
        return {
            'process_name': process_data.get('name'),
            'threat_score': threat_score,
            'threat_factors': threat_factors
        }
    
    @staticmethod
    def analyze_file_activity(file_events: List[Dict]) -> Dict:
        """Analyze file system activity for threats"""
        threat_factors = []
        threat_score = 0.0
        
        # Count file operations
        if len(file_events) > 100:
            threat_factors.append("Excessive file operations detected")
            threat_score += 0.3
        
        # Check for suspicious file extensions
        suspicious_ext = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs', '.js']
        suspicious_files = [
            f for f in file_events
            if any(f['path'].lower().endswith(ext) for ext in suspicious_ext)
        ]
        
        if len(suspicious_files) > 10:
            threat_factors.append("Multiple suspicious executable files created")
            threat_score += 0.35
        
        return {
            'file_operation_count': len(file_events),
            'suspicious_file_count': len(suspicious_files),
            'threat_score': threat_score,
            'threat_factors': threat_factors
        }
    
    @staticmethod
    def calculate_overall_threat(
        anomaly_score: float,
        process_threats: List[Dict],
        file_threats: Dict,
        network_anomalies: List[str]
    ) -> Dict:
        """Calculate overall threat level"""
        
        total_score = anomaly_score * 0.4  # 40% weight to anomaly score
        
        # Add process threat scores (30% weight)
        if process_threats:
            avg_process_threat = sum(p.get('threat_score', 0) for p in process_threats) / len(process_threats)
            total_score += avg_process_threat * 0.3
        
        # Add file threat score (20% weight)
        total_score += file_threats.get('threat_score', 0) * 0.2
        
        # Add network threat (10% weight)
        if network_anomalies:
            total_score += 0.2 * 0.1
        
        # Determine threat level
        if total_score > 0.8:
            level = ThreatAnalyzer.CRITICAL
        elif total_score > 0.6:
            level = ThreatAnalyzer.HIGH
        elif total_score > 0.3:
            level = ThreatAnalyzer.MEDIUM
        else:
            level = ThreatAnalyzer.LOW
        
        return {
            'threat_level': level,
            'threat_score': min(total_score, 1.0),
            'factors': []
        }
    
    @staticmethod
    def explain_threat(threat_analysis: Dict) -> str:
        """Generate human-readable explanation of threat"""
        
        explanation = f"Threat Level: {threat_analysis['threat_level']}\n"
        explanation += f"Threat Score: {threat_analysis['threat_score']:.2%}\n\n"
        explanation += "Reasons:\n"
        
        for factor in threat_analysis.get('factors', []):
            explanation += f"• {factor}\n"
        
        return explanation


class ModelTrainer:
    """Train machine learning models on historical data"""
    
    @staticmethod
    def create_training_data(normal_samples: int = 100) -> List[Dict]:
        """Generate synthetic training data"""
        training_data = []
        
        for i in range(normal_samples):
            data = {
                'processes': [
                    {
                        'cpu_percent': np.random.normal(10, 5),
                        'memory_percent': np.random.normal(2, 1),
                        'num_threads': np.random.randint(1, 50)
                    }
                    for _ in range(np.random.randint(5, 30))
                ],
                'connections': [
                    {} for _ in range(np.random.randint(0, 20))
                ],
                'metrics': {
                    'cpu_percent': np.random.normal(30, 10),
                    'memory': {'percent': np.random.normal(50, 15)}
                }
            }
            training_data.append(data)
        
        return training_data
