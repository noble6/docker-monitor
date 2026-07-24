"""Rule-based scoring models for security and anomaly detection.

These are deterministic weighted rule scorers. Not a trained ML model.
Weights are empirically tuned heuristics.
"""

from __future__ import annotations

import math
import logging
from typing import Dict


class RuleBasedRiskScorer:
    """Deterministic weighted rule scorer for static scan risk scoring. Not a trained ML model. Weights are empirically tuned heuristics."""

    # Tuned offline; stored as constants (pre-trained model artifact)
    _WEIGHTS = {
        "critical": 0.08,
        "high": 0.03,
        "medium": 0.01,
        "low": 0.002,
        "fatal": 0.08,
        "warn": 0.02,
        "engine_coverage": -0.5,
    }
    _BIAS = -2.0

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1 / (1 + math.exp(-x))

    def score(self, features: Dict[str, float]) -> float:
        z = self._BIAS
        for key, w in self._WEIGHTS.items():
            z += w * float(features.get(key, 0.0))
        return round(self._sigmoid(z) * 100, 2)


class RuleBasedAnomalyScorer:
    """Deterministic weighted rule scorer for runtime anomaly detection returning anomaly probability [0,100]. Not a trained ML model. Weights are empirically tuned heuristics."""

    _WEIGHTS = {
        "cpu": 0.04,
        "memory": 0.03,
        "network_total": 0.015,
        "pids": 0.01,
        "restart_count": 0.35,
        "cpu_z": 0.85,
        "memory_z": 0.7,
        "network_z": 1.1,
        "pid_z": 0.95,
    }
    _BIAS = -2.4

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1 / (1 + math.exp(-x))

    def score(self, features: Dict[str, float]) -> float:
        z = self._BIAS
        for key, w in self._WEIGHTS.items():
            z += w * float(features.get(key, 0.0))
        return round(self._sigmoid(z) * 100, 2)


try:
    from sklearn.ensemble import IsolationForest
    import joblib
    import numpy as np
except ImportError:
    IsolationForest = None
    joblib = None
    np = None

import os


class MLAnomalyDetector:
    """Trained ML anomaly detector using Isolation Forest for runtime telemetry features.
    Combined with RuleBasedAnomalyScorer for an ensemble score (rule-based + ML).
    """

    MODEL_PATH = "ml_anomaly_model.joblib"

    def __init__(self):
        self.model = None
        if joblib and os.path.exists(self.MODEL_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
                logging.info(f"ML model successfully loaded from {self.MODEL_PATH}")
            except Exception as e:
                logging.warning(f"Failed to load ML model from {self.MODEL_PATH}: {e}")
        else:
            logging.warning(f"ML model not loaded. joblib present: {bool(joblib)}, file exists: {os.path.exists(self.MODEL_PATH)}")

    @classmethod
    def train_and_save(cls):
        if not IsolationForest or not np:
            return False

        # Generate synthetic normal baseline data
        # features: cpu, memory, network_total, pids, restart_count, cpu_z, memory_z, network_z, pid_z
        np.random.seed(42)
        n_samples = 1000
        cpu = np.random.uniform(0, 20, n_samples)
        mem = np.random.uniform(0, 30, n_samples)
        net = np.random.uniform(0, 50, n_samples)
        pids = np.random.uniform(10, 50, n_samples)
        restart = np.zeros(n_samples)
        cpu_z = np.random.normal(0, 0.5, n_samples)
        mem_z = np.random.normal(0, 0.5, n_samples)
        net_z = np.random.normal(0, 0.5, n_samples)
        pid_z = np.random.normal(0, 0.5, n_samples)

        X = np.column_stack((cpu, mem, net, pids, restart, cpu_z, mem_z, net_z, pid_z))

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        joblib.dump(model, cls.MODEL_PATH)
        return True

    def score(self, features: Dict[str, float]) -> float:
        if not self.model or not np:
            return 0.0

        x = np.array([[
            float(features.get("cpu", 0.0)),
            float(features.get("memory", 0.0)),
            float(features.get("network_total", 0.0)),
            float(features.get("pids", 0.0)),
            float(features.get("restart_count", 0.0)),
            float(features.get("cpu_z", 0.0)),
            float(features.get("memory_z", 0.0)),
            float(features.get("network_z", 0.0)),
            float(features.get("pid_z", 0.0)),
        ]])

        score_val = self.model.decision_function(x)[0]
        # Invert so higher means more anomalous
        anomaly_score = -score_val
        prob = 1 / (1 + math.exp(- (anomaly_score * 10)))
        return round(prob * 100, 2)
