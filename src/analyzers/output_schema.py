"""Standardized JSON schema for analyzer outputs.

Each analyzer returns a dictionary with at least the following top-level keys:

    module: str           # "network" or "memory"
    anomaly_detected: bool
    confidence: float     # highest confidence among reported anomalies
    anomalies: list       # list of anomaly objects

An anomaly object has this form:

    {
        "anomaly_type": "protocol_anomaly" | "ghost_connection" | "beaconing" | "high_entropy" | ...,
        "confidence": 0.5,
        "evidence": {...}  # structured evidence specific to the type
    }

The correlation layer produces:

    {"correlation_tags": ["possible_c2", "injection_suspected", ...]}

This module is purely for documentation and may be imported by downstream
components to validate or construct output payloads.
"""

# placeholders; real code could use pydantic/cerberus if needed


class AnomalySchema:
    def __init__(self, anomaly_type: str, evidence: dict, confidence: float):
        self.anomaly_type = anomaly_type
        self.evidence = evidence
        self.confidence = confidence


class AnalyzerOutputSchema:
    def __init__(self, module: str, anomaly_detected: bool, anomalies: list, confidence: float):
        self.module = module
        self.anomaly_detected = anomaly_detected
        self.anomalies = anomalies
        self.confidence = confidence
