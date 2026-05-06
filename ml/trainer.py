import os
import time

class Trainer:
    def __init__(self, anomaly_detector):
        self.anomaly_detector = anomaly_detector
        self.is_training = False
        self.last_training_result = None

    def train(self):
        if self.is_training:
            return {"success": False, "message": "Already training"}
        self.is_training = True
        try:
            success = self.anomaly_detector.train()
            if success:
                self.anomaly_detector.save_model()
                self.last_training_result = {"success": True, "time": time.time(), "samples": len(self.anomaly_detector.feature_buffer)}
                return {"success": True, "message": f"Trained on {len(self.anomaly_detector.feature_buffer)} samples"}
            else:
                self.last_training_result = {"success": False, "message": f"Need at least {self.anomaly_detector.min_samples} samples (have {len(self.anomaly_detector.feature_buffer)})"}
                return self.last_training_result
        except Exception as e:
            self.last_training_result = {"success": False, "message": str(e)}
            return self.last_training_result
        finally:
            self.is_training = False

    def load_model(self):
        success = self.anomaly_detector.load_model()
        return {"success": success, "message": "Model loaded" if success else "No saved model found"}

    def reset(self):
        self.anomaly_detector.model = None
        self.anomaly_detector.is_trained = False
        self.anomaly_detector.last_train_time = None
        self.anomaly_detector.train_count = 0
        self.anomaly_detector.total_predictions = 0
        self.anomaly_detector.anomaly_count = 0
        return {"success": True, "message": "Model reset"}
