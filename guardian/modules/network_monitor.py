"""Network traffic analysis module — C2 detection, port scans, exfiltration."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from guardian.engine.alert import Alert, Severity
from guardian.engine.slm import get_engine

MODULE = "network_monitor"

# Ports commonly associated with malicious activity
_SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 6667, 6668, 6669,  # common C2 / IRC / RAT
    1337, 31337, 65535,                           # "leet" ports
    8080, 8443, 9090, 9443,                       # alt-web (common exfil)
}

_HIGH_VOLUME_THRESHOLD = 100   # connections/s to same dest = possible exfil
_SCAN_THRESHOLD = 20           # unique ports hit from same src in short window
_WINDOW_SECS = 10.0


@dataclass
class ConnEvent:
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    size: int = 0
    timestamp: float = field(default_factory=time.time)


def _build_prompt(events: list[ConnEvent], context: str) -> str:
    lines = [
        f"{e.src_ip} -> {e.dst_ip}:{e.dst_port}/{e.proto} bytes={e.size}"
        for e in events[:50]
    ]
    block = "\n".join(lines)
    return (
        f"Context: {context}\n"
        "Analyze the following network connection events for threats (C2 beaconing, "
        "port scanning, data exfiltration, lateral movement, etc.).\n"
        "Return a JSON object:\n"
        "{\n"
        '  "title": "short threat title",\n'
        '  "description": "what is happening",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '  "evidence": "key connections that indicate this threat",\n'
        '  "recommendation": "defensive action to take"\n'
        "}\n"
        "Return null if no threat found.\n\n"
        f"Connection events:\n```\n{block}\n```"
    )


class HeuristicTracker:
    """Fast pre-filter using statistical heuristics before SLM invocation."""

    def __init__(self, callback: Callable[[list[ConnEvent], str], None]):
        self._callback = callback
        self._lock = threading.Lock()
        # src_ip -> list of (timestamp, dst_port)
        self._scan_tracker: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # dst_ip -> list of timestamps
        self._volume_tracker: dict[str, list[float]] = defaultdict(list)
        self._flagged_events: list[ConnEvent] = []

    def ingest(self, event: ConnEvent) -> None:
        now = event.timestamp
        context_parts: list[str] = []

        # Port scan detection
        with self._lock:
            entries = self._scan_tracker[event.src_ip]
            entries.append((now, event.dst_port))
            self._scan_tracker[event.src_ip] = [
                (t, p) for t, p in entries if now - t < _WINDOW_SECS
            ]
            unique_ports = len({p for _, p in self._scan_tracker[event.src_ip]})
            if unique_ports >= _SCAN_THRESHOLD:
                context_parts.append(
                    f"POSSIBLE PORT SCAN: {event.src_ip} hit {unique_ports} unique ports in {_WINDOW_SECS}s"
                )

        # High-volume / exfil detection
        with self._lock:
            times = self._volume_tracker[event.dst_ip]
            times.append(now)
            self._volume_tracker[event.dst_ip] = [t for t in times if now - t < _WINDOW_SECS]
            rate = len(self._volume_tracker[event.dst_ip])
            if rate >= _HIGH_VOLUME_THRESHOLD:
                context_parts.append(
                    f"HIGH VOLUME: {rate} connections to {event.dst_ip} in {_WINDOW_SECS}s"
                )

        # Known bad port
        if event.dst_port in _SUSPICIOUS_PORTS:
            context_parts.append(
                f"SUSPICIOUS PORT: connection to known C2/RAT port {event.dst_port}"
            )

        if context_parts:
            self._flagged_events.append(event)
            if len(self._flagged_events) >= 5:
                batch = self._flagged_events[:20]
                self._flagged_events = self._flagged_events[20:]
                context = "; ".join(context_parts)
                threading.Thread(
                    target=self._callback, args=(batch, context), daemon=True
                ).start()


class NetworkMonitor:
    """Live network monitor using scapy (requires root/cap_net_raw)."""

    def __init__(self, callback: Callable[[Alert], None], iface: str | None = None):
        self.callback = callback
        self.iface = iface
        self._stop = threading.Event()
        self._tracker = HeuristicTracker(self._on_flagged)

    def start(self) -> None:
        t = threading.Thread(target=self._capture_loop, daemon=True)
        t.start()

    def stop(self) -> None:
        self._stop.set()

    def _on_flagged(self, events: list[ConnEvent], context: str) -> None:
        try:
            engine = get_engine()
            raw = engine.analyze(_build_prompt(events, context), max_tokens=300)
            if raw.strip().lower() == "null":
                return
            alert = Alert.from_slm_json(
                MODULE, raw,
                fallback_evidence=f"{context}\n" + "\n".join(
                    f"{e.src_ip}->{e.dst_ip}:{e.dst_port}" for e in events[:5]
                )
            )
            if alert:
                alert.metadata["event_count"] = len(events)
                self.callback(alert)
        except Exception:
            pass

    def _capture_loop(self) -> None:
        try:
            from scapy.all import sniff, IP, TCP, UDP

            def _pkt_handler(pkt):
                if self._stop.is_set():
                    return
                if IP not in pkt:
                    return
                proto = "tcp" if TCP in pkt else ("udp" if UDP in pkt else "ip")
                layer = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
                dst_port = layer.dport if layer else 0
                size = len(pkt)
                event = ConnEvent(
                    src_ip=pkt[IP].src,
                    dst_ip=pkt[IP].dst,
                    dst_port=dst_port,
                    proto=proto,
                    size=size,
                )
                self._tracker.ingest(event)

            sniff(
                iface=self.iface,
                prn=_pkt_handler,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except ImportError:
            pass  # scapy not installed — monitor silently disabled
        except PermissionError:
            pass  # no cap_net_raw — disabled gracefully


def analyze_pcap(path: str) -> list[Alert]:
    """Analyze a PCAP file and return all detected threats."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        raise ImportError("scapy is required for PCAP analysis: pip install scapy")

    alerts: list[Alert] = []
    lock = threading.Lock()

    def _cb(evts: list[ConnEvent], ctx: str) -> None:
        engine = get_engine()
        raw = engine.analyze(_build_prompt(evts, ctx), max_tokens=300)
        if raw.strip().lower() == "null":
            return
        alert = Alert.from_slm_json(MODULE, raw)
        if alert:
            with lock:
                alerts.append(alert)

    tracker = HeuristicTracker(_cb)
    packets = rdpcap(str(path))
    for pkt in packets:
        if IP not in pkt:
            continue
        proto = "tcp" if TCP in pkt else ("udp" if UDP in pkt else "ip")
        layer = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
        dst_port = layer.dport if layer else 0
        tracker.ingest(
            ConnEvent(
                src_ip=pkt[IP].src,
                dst_ip=pkt[IP].dst,
                dst_port=dst_port,
                proto=proto,
                size=len(pkt),
                timestamp=float(pkt.time),
            )
        )
    return alerts
