from ml.anomaly_detector import AnomalyDetector
from ml.ip_scorer import IPScorer
from ml.dns_resolver import DNSResolver
from ml.trainer import Trainer

anomaly_detector = AnomalyDetector()
ip_scorer = IPScorer()
dns_resolver = DNSResolver()
trainer = Trainer(anomaly_detector)
