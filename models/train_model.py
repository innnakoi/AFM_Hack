"""
Model training script for AI Shield Guardian
Trains the anomaly detection model on historical data
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import sys
sys.path.append('../backend')

from detector import AnomalyDetector, ModelTrainer


def train_models():
    """Train anomaly detection models"""
    
    print("🤖 AI Shield Guardian - Model Training")
    print("=" * 50)
    
    # Create detector
    detector = AnomalyDetector(contamination=0.1)
    
    print("\n1. Generating synthetic training data...")
    # Generate normal behavior data
    training_data = ModelTrainer.create_training_data(normal_samples=200)
    print(f"   Generated {len(training_data)} training samples")
    
    print("\n2. Training anomaly detection model...")
    detector.train(training_data)
    print("   ✓ Model trained successfully")
    
    print("\n3. Testing model...")
    # Test with normal data
    test_normal = training_data[0]
    score, is_anomaly = detector.predict(test_normal)
    print(f"   Normal data - Score: {score:.4f}, Anomalous: {is_anomaly}")
    
    # Test with simulated anomalous data
    test_anomalous = {
        'processes': [
            {
                'cpu_percent': 95,
                'memory_percent': 2000,
                'num_threads': 500
            }
            for _ in range(50)
        ],
        'connections': [{} for _ in range(100)],
        'metrics': {}
    }
    score, is_anomaly = detector.predict(test_anomalous)
    print(f"   Anomalous data - Score: {score:.4f}, Anomalous: {is_anomaly}")
    
    print("\n4. Saving model...")
    detector.save_model('../models')
    print("   ✓ Model saved to models/")
    
    print("\n" + "=" * 50)
    print("✓ Training completed successfully!")


if __name__ == "__main__":
    train_models()
