"""
Threat correlation engine.

Ingests Alerts from all modules and groups them into Campaigns —
coordinated attack sequences detected across time, source IPs, ATT&CK
kill-chain ordering, and shared entities (IPs, files, PIDs, users).

Design principles:
  - No SLM on the hot path: grouping is pure logic.
  - SLM is called once per campaign, lazily, only when a campaign is
    'mature' (≥ MIN_ALERTS alerts or a kill-chain gap is detected).
  - Thread-safe: all public methods can be called from multiple module
    threads simultaneously.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from guardian.engine.alert import Alert, Severity
from guardian.engine.attck import Technique, map_techniques, top_technique


# ─── Configuration ────────────────────────────────────────────────────────────

CAMPAIGN_WINDOW_SECS = 300.0   # 5 minutes: max time between alerts in same campaign
CAMPAIGN_MIN_ALERTS = 2        # minimum alerts to constitute a campaign
CAMPAIGN_SLM_THRESHOLD = 3     # trigger SLM synthesis after this many alerts
CAMPAIGN_PRUNE_INTERVAL = 60.0 # how often to expire old campaigns
MAX_CAMPAIGNS = 500            # hard cap on in-memory campaigns


# ─── Data model ──────────────────────────────────────────────────────────────

class CampaignStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SYNTHESIZED = "SYNTHESIZED"  # SLM has summarized it
    EXPIRED = "EXPIRED"


@dataclass
class Campaign:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    alerts: list[Alert] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)  # IPs, PIDs, file paths, users
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    status: CampaignStatus = CampaignStatus.ACTIVE
    synthesis: str = ""   # SLM-generated campaign summary
    severity: Severity = Severity.MEDIUM
    title: str = ""
    # Recommended responses for this campaign (from SLM synthesis or the
    # rule-based fallback). Surfaced to the dashboard via to_dict().
    immediate_actions: list[str] = field(default_factory=list)
    # Alert count at the time SLM synthesis last ran — used to decide when a
    # campaign has grown enough to warrant re-synthesis.
    synthesized_alert_count: int = 0

    @property
    def duration_secs(self) -> float:
        return self.last_seen - self.first_seen

    @property
    def kill_chain_range(self) -> tuple[int, int]:
        if not self.techniques:
            return (5, 5)
        positions = [t.kill_chain_pos for t in self.techniques]
        return (min(positions), max(positions))

    @property
    def tactics(self) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for t in sorted(self.techniques, key=lambda x: x.kill_chain_pos):
            if t.tactic not in seen:
                seen.add(t.tactic)
                result.append(t.tactic)
        return result

    def _recompute_severity(self) -> None:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        worst = min(self.alerts, key=lambda a: order.index(a.severity.value))
        self.severity = worst.severity

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title or f"Campaign {self.id}",
            "status": self.status.value,
            "severity": self.severity.value,
            "alert_count": len(self.alerts),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_secs": self.duration_secs,
            "tactics": self.tactics,
            "techniques": [{"id": t.id, "name": t.name, "tactic": t.tactic} for t in self.techniques],
            "entities": sorted(self.entities),
            "synthesis": self.synthesis,
            "immediate_actions": list(self.immediate_actions),
            "alerts": [a.to_dict() for a in self.alerts],
        }


# ─── Entity extraction ────────────────────────────────────────────────────────

import re as _re

_IP_RE = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PID_RE = _re.compile(r"\bpid[:\s=]+(\d+)\b", _re.IGNORECASE)
_USER_RE = _re.compile(r"\buser[:\s=]+(\w+)\b", _re.IGNORECASE)
_FILE_RE = _re.compile(r"(/[a-zA-Z0-9_./\-]{6,})")


def _extract_entities(alert: Alert) -> set[str]:
    """Pull IPs, PIDs, users, and file paths out of an alert."""
    text = f"{alert.title} {alert.description} {alert.evidence}"
    entities: set[str] = set()
    entities.update(_IP_RE.findall(text))
    entities.update(m.group(1) for m in _PID_RE.finditer(text))
    entities.update(f"user:{m.group(1)}" for m in _USER_RE.finditer(text))
    entities.update(m.group(1) for m in _FILE_RE.finditer(text) if len(m.group(1)) > 6)

    # Pull from structured metadata
    for key in ("src_ip", "dst_ip"):
        if key in alert.metadata:
            entities.add(str(alert.metadata[key]))
    if "pid" in alert.metadata:
        entities.add(str(alert.metadata["pid"]))
    if "user" in alert.metadata:
        entities.add(f"user:{alert.metadata['user']}")
    if "path" in alert.metadata:
        entities.add(str(alert.metadata["path"]))

    return entities


# ─── Correlation logic ───────────────────────────────────────────────────────

def _alerts_are_related(a: Alert, b: Alert, a_entities: set[str], b_entities: set[str]) -> bool:
    """Return True if two alerts should be grouped into the same campaign."""
    # Same module + overlapping entities
    if a_entities & b_entities:
        return True

    # Different modules that share an IP
    a_ips = {e for e in a_entities if _IP_RE.match(e)}
    b_ips = {e for e in b_entities if _IP_RE.match(e)}
    if a_ips & b_ips:
        return True

    # Kill-chain progression from same rough source: detect step-up in kill chain
    a_tech = top_technique(f"{a.title} {a.description}")
    b_tech = top_technique(f"{b.title} {b.description}")
    if a_tech and b_tech and a_tech.kill_chain_pos != b_tech.kill_chain_pos:
        # Alerts at different stages with any shared entity → strong signal
        if a_entities & b_entities:
            return True

    return False


def _rule_based_synthesis(campaign: "Campaign") -> dict[str, object]:
    """Fallback narrative when SLM is unavailable or fails."""
    tactics = " → ".join(campaign.tactics) if campaign.tactics else "unknown pattern"
    modules = sorted({a.module for a in campaign.alerts})
    entities = sorted(campaign.entities)[:6]
    entity_str = ", ".join(entities) if entities else "none extracted"
    narrative = (
        f"Detected {len(campaign.alerts)} related alerts over "
        f"{campaign.duration_secs:.0f} seconds from {', '.join(modules) or 'local monitors'}. "
        f"Kill-chain progression: {tactics}. Shared indicators: {entity_str}."
    )
    sev = campaign.severity.value
    return {
        "title": f"Coordinated activity — {sev}",
        "attack_narrative": narrative,
        "severity": sev,
        "immediate_actions": [
            "Review all alerts in this campaign in the Threat Feed panel",
            "Block or monitor shared source IPs if confirmed malicious",
            "Check affected accounts or systems referenced in alert details",
        ],
    }


def _apply_synthesis_data(campaign: "Campaign", data: dict[str, object]) -> None:
    campaign.synthesis = str(data.get("attack_narrative", ""))
    campaign.title = str(data.get("title", campaign.title or f"Campaign {campaign.id}"))
    try:
        campaign.severity = Severity(str(data.get("severity", campaign.severity.value)).upper())
    except ValueError:
        pass
    campaign.status = CampaignStatus.SYNTHESIZED
    raw_actions = data.get("immediate_actions", [])
    if isinstance(raw_actions, list):
        campaign.immediate_actions = [str(a) for a in raw_actions if a]
    else:
        campaign.immediate_actions = []


def _ensure_baseline_narrative(campaign: "Campaign") -> None:
    if campaign.synthesis:
        return
    _apply_synthesis_data(campaign, _rule_based_synthesis(campaign))


# ─── SLM synthesis prompt ────────────────────────────────────────────────────

def _build_synthesis_prompt(campaign: "Campaign") -> str:
    alert_summaries = "\n".join(
        f"- [{a.severity.value}] [{a.module}] {a.title}: {a.description[:120]}"
        for a in campaign.alerts
    )
    tactics = " → ".join(campaign.tactics) if campaign.tactics else "Unknown"
    return (
        f"A multi-stage attack campaign has been detected spanning {len(campaign.alerts)} "
        f"security alerts over {campaign.duration_secs:.0f} seconds.\n\n"
        f"Kill-chain progression: {tactics}\n\n"
        f"Individual alerts:\n{alert_summaries}\n\n"
        "Synthesize these into a single campaign threat assessment. "
        "Return JSON:\n"
        "{\n"
        '  "title": "campaign name (attack type or threat actor pattern)",\n'
        '  "description": "what the attacker is doing step by step",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '  "attack_narrative": "concise paragraph describing the full attack chain",\n'
        '  "immediate_actions": ["action 1", "action 2", "action 3"]\n'
        "}"
    )


# ─── Correlator ──────────────────────────────────────────────────────────────

class Correlator:
    """
    Thread-safe correlation engine.

    Usage:
        correlator = Correlator(on_campaign=my_handler)
        correlator.start()
        correlator.ingest(alert)   # call from any thread
    """

    def __init__(
        self,
        on_campaign: Callable[["Campaign"], None] | None = None,
        use_slm: bool = True,
    ):
        self._on_campaign = on_campaign
        self._use_slm = use_slm
        self._lock = threading.Lock()
        self._campaigns: dict[str, Campaign] = {}
        # alert_id → campaign_id
        self._alert_to_campaign: dict[str, str] = {}
        # campaign_id → set of entity strings seen in that campaign
        self._campaign_entities: dict[str, set[str]] = defaultdict(set)
        self._stop = threading.Event()
        self._prune_thread: threading.Thread | None = None

    def start(self) -> None:
        self._prune_thread = threading.Thread(target=self._prune_loop, daemon=True)
        self._prune_thread.start()

    def stop(self) -> None:
        self._stop.set()

    def ingest(self, alert: Alert) -> Campaign | None:
        """
        Ingest one alert. Returns the Campaign it was added to (or None if
        it stands alone and hasn't reached the min-alerts threshold yet).
        """
        entities = _extract_entities(alert)
        techniques = map_techniques(f"{alert.title} {alert.description} {alert.evidence}")

        with self._lock:
            now = time.time()
            matched_campaign: Campaign | None = None

            # Try to find an existing open campaign to join
            for cid, campaign in self._campaigns.items():
                if campaign.status == CampaignStatus.EXPIRED:
                    continue
                # Must be within the time window
                if now - campaign.last_seen > CAMPAIGN_WINDOW_SECS:
                    continue
                camp_entities = self._campaign_entities[cid]
                if _alerts_are_related(
                    alert, campaign.alerts[-1],
                    entities, camp_entities,
                ):
                    matched_campaign = campaign
                    break

            if matched_campaign:
                matched_campaign.alerts.append(alert)
                matched_campaign.last_seen = now
                matched_campaign.techniques = _merge_techniques(
                    matched_campaign.techniques, techniques
                )
                matched_campaign._recompute_severity()
                self._campaign_entities[matched_campaign.id] |= entities
                self._alert_to_campaign[alert.id] = matched_campaign.id
                campaign_to_return = matched_campaign
            else:
                # Start a new campaign
                new_campaign = Campaign(
                    alerts=[alert],
                    techniques=techniques,
                    entities=entities,
                    first_seen=now,
                    last_seen=now,
                    severity=alert.severity,
                )
                self._campaigns[new_campaign.id] = new_campaign
                self._campaign_entities[new_campaign.id] = set(entities)
                self._alert_to_campaign[alert.id] = new_campaign.id
                campaign_to_return = new_campaign

        # Outside the lock: notify listeners and optionally trigger SLM synthesis
        mature = len(campaign_to_return.alerts) >= CAMPAIGN_MIN_ALERTS
        if mature and self._on_campaign:
            _ensure_baseline_narrative(campaign_to_return)
            self._on_campaign(campaign_to_return)

        if (
            self._use_slm
            and mature
            and len(campaign_to_return.alerts) >= CAMPAIGN_SLM_THRESHOLD
            and campaign_to_return.status == CampaignStatus.ACTIVE
        ):
            # Route through the shared bounded worker instead of spawning a
            # thread per mature campaign, so campaign synthesis can't outrun the
            # CPU cap (it shares the single SLM worker with the monitors).
            from guardian.engine.analysis_queue import submit_analysis
            submit_analysis(lambda: self._synthesize(campaign_to_return))

        if mature:
            return campaign_to_return
        return None

    def _synthesize(self, campaign: Campaign) -> None:
        """Call SLM to produce a campaign narrative. Runs on the analysis worker."""
        # Re-synthesize an already-summarized campaign only once it has grown
        # ~50% beyond the alert count present at the last synthesis. (Previously
        # this compared len(alerts) against itself, so it always returned early
        # and re-synthesis never happened.)
        if campaign.status == CampaignStatus.SYNTHESIZED:
            if len(campaign.alerts) < campaign.synthesized_alert_count * 1.5:
                return

        count_at_synthesis = len(campaign.alerts)

        try:
            from guardian.engine.slm import get_engine
            import json

            engine = get_engine()
            raw = engine.analyze(_build_synthesis_prompt(campaign), max_tokens=400)

            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == 0:
                raise ValueError("no JSON in SLM response")
            data = json.loads(raw[start:end])

            with self._lock:
                _apply_synthesis_data(campaign, data)
                campaign.synthesized_alert_count = count_at_synthesis

            if self._on_campaign:
                self._on_campaign(campaign)

        except Exception:
            with self._lock:
                _apply_synthesis_data(campaign, _rule_based_synthesis(campaign))
                campaign.synthesized_alert_count = count_at_synthesis
            if self._on_campaign:
                self._on_campaign(campaign)

    def get_campaigns(self, active_only: bool = True) -> list[Campaign]:
        with self._lock:
            campaigns = list(self._campaigns.values())
        if active_only:
            campaigns = [c for c in campaigns if c.status != CampaignStatus.EXPIRED]
        return sorted(campaigns, key=lambda c: c.last_seen, reverse=True)

    def get_campaign_for_alert(self, alert_id: str) -> Campaign | None:
        with self._lock:
            cid = self._alert_to_campaign.get(alert_id)
            if cid:
                return self._campaigns.get(cid)
        return None

    def _prune_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(CAMPAIGN_PRUNE_INTERVAL)
            self._prune()

    def _prune(self) -> None:
        now = time.time()
        with self._lock:
            for cid, campaign in list(self._campaigns.items()):
                if now - campaign.last_seen > CAMPAIGN_WINDOW_SECS * 2:
                    campaign.status = CampaignStatus.EXPIRED
            # Hard cap
            if len(self._campaigns) > MAX_CAMPAIGNS:
                sorted_cids = sorted(
                    self._campaigns, key=lambda c: self._campaigns[c].last_seen
                )
                for cid in sorted_cids[: len(self._campaigns) - MAX_CAMPAIGNS]:
                    self._campaigns[cid].status = CampaignStatus.EXPIRED


def _merge_techniques(existing: list[Technique], new: list[Technique]) -> list[Technique]:
    seen = {t.id for t in existing}
    result = list(existing)
    for t in new:
        if t.id not in seen:
            seen.add(t.id)
            result.append(t)
    return sorted(result, key=lambda t: t.kill_chain_pos)


# ─── Global singleton ────────────────────────────────────────────────────────

_correlator: Correlator | None = None
_correlator_lock = threading.Lock()


def get_correlator(
    on_campaign: Callable[[Campaign], None] | None = None,
    use_slm: bool = True,
) -> Correlator:
    global _correlator
    with _correlator_lock:
        if _correlator is None:
            _correlator = Correlator(on_campaign=on_campaign, use_slm=use_slm)
            _correlator.start()
        elif on_campaign and _correlator._on_campaign is None:
            _correlator._on_campaign = on_campaign
    return _correlator
