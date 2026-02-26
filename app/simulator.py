from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import random
from typing import Dict, List

try:
    from scapy.all import IP, TCP
except Exception:  # scapy may not be installed in minimal environments
    IP = TCP = None


@dataclass
class IncidentEvent:
    timestamp: str
    event_type: str
    source_ip: str
    target: str
    severity: str
    confidence: float
    detected: bool
    response_actions: List[str]
    packet_preview: str


EVENT_PROFILES: Dict[str, Dict[str, object]] = {
    "port_scan": {
        "target": "internal-subnet",
        "severity": "medium",
        "response_actions": ["Enable temporary rate limiting", "Start packet capture", "Notify SOC analyst"],
        "dport": 22,
    },
    "dos_attempt": {
        "target": "public-web-app",
        "severity": "high",
        "response_actions": ["Scale edge firewall rules", "Block offending IP", "Activate traffic scrubbing"],
        "dport": 443,
    },
    "credential_stuffing": {
        "target": "auth-service",
        "severity": "high",
        "response_actions": ["Force MFA challenge", "Lock suspicious accounts", "Create threat intel ticket"],
        "dport": 8443,
    },
}


class IncidentSimulator:
    """In-memory simulation engine for response workflow drills."""

    def __init__(self) -> None:
        self.events: List[IncidentEvent] = []

    def generate_event(self, event_type: str, source_ip: str | None = None) -> IncidentEvent:
        if event_type not in EVENT_PROFILES:
            raise ValueError(f"Unsupported event type: {event_type}")

        profile = EVENT_PROFILES[event_type]
        confidence = round(random.uniform(0.63, 0.99), 2)
        detected = confidence >= 0.7
        src_ip = source_ip or self._random_ip()

        event = IncidentEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            source_ip=src_ip,
            target=str(profile["target"]),
            severity=str(profile["severity"]),
            confidence=confidence,
            detected=detected,
            response_actions=list(profile["response_actions"] if detected else ["Flag for manual triage"]),
            packet_preview=self._build_packet_preview(src_ip=src_ip, dport=int(profile["dport"])),
        )
        self.events.insert(0, event)
        return event

    def summary(self) -> Dict[str, object]:
        totals = {"low": 0, "medium": 0, "high": 0}
        detected_count = 0
        for event in self.events:
            totals[event.severity] += 1
            detected_count += int(event.detected)

        coverage = round((detected_count / len(self.events) * 100), 1) if self.events else 0.0
        return {
            "total_events": len(self.events),
            "detected_events": detected_count,
            "detection_coverage": coverage,
            "severity_breakdown": totals,
        }

    @staticmethod
    def _build_packet_preview(src_ip: str, dport: int) -> str:
        if IP is None or TCP is None:
            return f"IP(src={src_ip})/TCP(dport={dport}, flags='S')"
        packet = IP(src=src_ip, dst="192.0.2.10") / TCP(dport=dport, flags="S")
        return packet.summary()

    @staticmethod
    def _random_ip() -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))
