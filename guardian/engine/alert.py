"""Unified alert data model used across all Guardian modules."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }[self.value]


@dataclass
class Alert:
    module: str
    title: str
    description: str
    severity: Severity
    evidence: str = ""
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "module": self.module,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_slm_json(cls, module: str, raw: str, fallback_evidence: str = "") -> "Alert | None":
        """Parse an Alert from SLM JSON output. Returns None if parsing fails."""
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == 0:
                return None
            data = json.loads(raw[start:end])
            severity_str = data.get("severity", "MEDIUM").upper()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.MEDIUM
            return cls(
                module=module,
                title=data.get("title", "Unnamed threat"),
                description=data.get("description", ""),
                severity=severity,
                evidence=data.get("evidence", fallback_evidence),
                recommendation=data.get("recommendation", ""),
                metadata=data.get("metadata", {}),
            )
        except (json.JSONDecodeError, TypeError):
            return None
