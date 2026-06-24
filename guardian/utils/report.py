"""Report generation utilities — JSON and plain text."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Sequence

from guardian.engine.alert import Alert


def save_json_report(alerts: Sequence[Alert], output: str | Path) -> None:
    output = Path(output)
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_alerts": len(alerts),
        "severity_summary": _severity_summary(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    output.write_text(json.dumps(data, indent=2))


def _severity_summary(alerts: Sequence[Alert]) -> dict[str, int]:
    summary: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for a in alerts:
        summary[a.severity.value] = summary.get(a.severity.value, 0) + 1
    return summary
