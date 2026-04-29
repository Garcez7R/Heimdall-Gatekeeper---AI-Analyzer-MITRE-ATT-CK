from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

@dataclass
class Event:
    raw_log: str
    source: str
    timestamp: datetime
    ip: Optional[str] = None
    user: Optional[str] = None
    status: Optional[str] = None  # success | failed

@dataclass
class AnalysisResult:
    classification: str
    confidence: float
    mitre_techniques: List[str]
    explanation: str
    reasoning: Optional[str] = None
