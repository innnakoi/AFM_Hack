# AI Shield Guardian - Models

Machine learning models for threat detection and anomaly analysis.

## Files

- `train_model.py` - Training script for anomaly detection model
- `anomaly_model.pkl` - Trained Isolation Forest model
- `scaler.pkl` - Feature scaler for data normalization

## Training

```bash
python train_model.py
```

## Model Architecture

### Isolation Forest
- **Purpose**: Detect anomalies in system behavior
- **Features**:
  - CPU usage percentage
  - Memory usage (MB)
  - Network connections count
  - File operations count
  - Process count
  - Thread count

- **Contamination**: 0.1 (assumes 10% of data is anomalous)
- **Performance**: O(n log n) time complexity

## Usage

```python
from detector import AnomalyDetector

detector = AnomalyDetector()
detector.load_model('../models')

# Predict anomaly
score, is_anomalous = detector.predict(monitoring_data)
```
