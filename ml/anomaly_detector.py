import numpy as np
import joblib
import os
import time
from sklearn.ensemble import IsolationForest
from collections import deque

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.feature_buffer = deque(maxlen=1000)
        self.is_trained = False
        self.last_train_time = None
        self.train_count = 0
        self.min_samples = 200
        self.contamination = 0.02
        self.last_scores = deque(maxlen=100)
        self.total_predictions = 0
        self.anomaly_count = 0

    def extract_features(self, packet_info):
        size = packet_info.get("size", 64)
        ttl = packet_info.get("ttl", 64)
        is_syn = 1.0 if packet_info.get("flags") == "S" else 0.0
        has_payload = 1.0 if packet_info.get("payload_size", 0) > 0 else 0.0
        dst_port = packet_info.get("dst_port", 0) or 0
        port_category = 0
        if dst_port in [80, 443, 8080]:
            port_category = 0.1
        elif dst_port in [22, 23, 3389, 21, 25, 110, 143]:
            port_category = 0.5
        elif dst_port > 1024:
            port_category = 0.8
        else:
            port_category = 0.3
        proto = packet_info.get("type", "OTHER")
        proto_code = {"TCP": 0.1, "UDP": 0.3, "ICMP": 0.5, "OTHER": 0.9}.get(proto, 0.9)
        normalized_size = min(size / 1500, 1.0)
        normalized_ttl = ttl / 255
        return [normalized_size, normalized_ttl, is_syn, has_payload, port_category, proto_code, dst_port / 65535]

    def add_sample(self, features):
        self.feature_buffer.append(features)

    def predict(self, features):
        if not self.is_trained or self.model is None:
            return 0.0
        try:
            score = self.model.decision_function([features])[0]
            anomaly_score = max(0, min(1, -score * 2 + 0.5))
        except Exception:
            anomaly_score = 0.0
        self.total_predictions += 1
        self.last_scores.append({"score": anomaly_score, "time": time.time()})
        if anomaly_score > 0.5:
            self.anomaly_count += 1
        return round(anomaly_score, 3)

    def train(self):
        if len(self.feature_buffer) < self.min_samples:
            return False
        try:
            X = np.array(list(self.feature_buffer))
            self.model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X)
            self.is_trained = True
            self.last_train_time = time.time()
            self.train_count += 1
            return True
        except Exception as e:
            print(f"[ML] Training failed: {e}")
            return False

    def save_model(self, path="ml/model.pkl"):
        if self.model and self.is_trained:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "model": self.model,
                "is_trained": self.is_trained,
                "last_train_time": self.last_train_time,
                "train_count": self.train_count,
                "contamination": self.contamination
            }
            joblib.dump(data, path)
            return True
        return False

    def load_model(self, path="ml/model.pkl"):
        if os.path.exists(path):
            try:
                data = joblib.load(path)
                self.model = data["model"]
                self.is_trained = data.get("is_trained", False)
                self.last_train_time = data.get("last_train_time")
                self.train_count = data.get("train_count", 0)
                self.contamination = data.get("contamination", 0.05)
                return True
            except Exception as e:
                print(f"[ML] Model load failed: {e}")
                return False
        return False

    def get_status(self):
        return {
            "is_trained": self.is_trained,
            "buffer_size": len(self.feature_buffer),
            "min_samples": self.min_samples,
            "last_train_time": self.last_train_time,
            "train_count": self.train_count,
            "total_predictions": self.total_predictions,
            "anomaly_count": self.anomaly_count,
            "anomaly_rate": round(self.anomaly_count / max(self.total_predictions, 1), 4)
        }

    def get_recent_scores(self, limit=30):
        recent = list(self.last_scores)[-limit:]
        return [{"score": s["score"], "timestamp": s["time"]} for s in recent]
