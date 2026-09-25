"""Structured, tamper-evident audit logging for autonomous AI agents.

Regulators expect a complete, reconstructable decision trail for high-risk AI
systems. The EU AI Act (Article 12, record-keeping) and DORA both assume you can
answer "what did the agent do, why, on whose authority, and with what data" long
after the fact. Chapter 12 (Incident Response) depends on these records existing
before an incident, not being reconstructed after it.

This module emits newline-delimited JSON (JSONL) audit events with:

* a stable schema (event type, agent id, actor, action, decision, data class);
* a monotonic sequence number per logger instance;
* a hash chain so that any deletion or edit of a prior record is detectable
  (each record embeds the SHA-256 of the previous record);
* optional redaction of sensitive fields before they are written.

It is dependency-free and safe for concurrent use from multiple threads.

Example
-------
>>> import io
>>> from audit_logger import AuditLogger, EventType, DataClass
>>> buffer = io.StringIO()
>>> log = AuditLogger(agent_id="trade_agent_v3", stream=buffer)
>>> _ = log.record_tool_call(
...     tool="execute_trade",
...     arguments={"symbol": "AAPL", "quantity": 10},
...     decision="allowed",
...     data_class=DataClass.CONFIDENTIAL,
... )
>>> log.verify_chain()
True

Author: Mervin Pearce, Pearce.Academy.
License: CC-BY-4.0.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Optional, TextIO

# Genesis hash for the first link in the chain.
_GENESIS_HASH = "0" * 64

# Fields that are redacted by default wherever they appear in event payloads.
_DEFAULT_REDACT_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "access_token",
        "refresh_token",
        "private_key",
        "account_number",
        "card_number",
        "ssn",
    }
)

_REDACTED = "[REDACTED]"


class EventType(str, Enum):
    """Categories of audit event."""

    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    DECISION = "decision"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    MEMORY_WRITE = "memory_write"
    EGRESS = "egress"
    APPROVAL = "approval"
    GUARDRAIL = "guardrail"
    CIRCUIT_BREAKER = "circuit_breaker"
    INCIDENT = "incident"


class DataClass(str, Enum):
    """Data classification tiers referenced across the handbook."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def redact(value: Any, redact_keys: frozenset[str] = _DEFAULT_REDACT_KEYS) -> Any:
    """Recursively redact sensitive keys in a nested structure.

    Parameters
    ----------
    value:
        Any JSON-serialisable value.
    redact_keys:
        Lower-cased key names whose values are replaced with ``[REDACTED]``.

    Returns
    -------
    Any
        A new structure with sensitive values redacted.
    """
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, val in value.items():
            if isinstance(key, str) and key.lower() in redact_keys:
                result[key] = _REDACTED
            else:
                result[key] = redact(val, redact_keys)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item, redact_keys) for item in value]
    return value


@dataclass
class AuditEvent:
    """A single audit record."""

    sequence: int
    timestamp: str
    event_type: EventType
    agent_id: str
    actor: str
    payload: dict[str, Any]
    data_class: DataClass
    prev_hash: str
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the ordered dictionary representation used for hashing."""
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "agent_id": self.agent_id,
            "actor": self.actor,
            "payload": self.payload,
            "data_class": self.data_class.value,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }


def _hash_record(record: Mapping[str, Any]) -> str:
    """Compute the SHA-256 of a record with ``record_hash`` excluded."""
    material = {k: v for k, v in record.items() if k != "record_hash"}
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class AuditLogger:
    """Append-only, hash-chained JSONL audit logger.

    Parameters
    ----------
    agent_id:
        Identifier of the agent these events belong to.
    stream:
        Writable text stream (for example an open file). If omitted, events are
        retained in memory only and can be read via :meth:`events`.
    default_actor:
        Actor recorded when a call does not specify one (for example
        ``"agent"`` versus a specific human operator).
    redact_keys:
        Set of key names to redact in payloads.
    """

    agent_id: str
    stream: Optional[TextIO] = None
    default_actor: str = "agent"
    redact_keys: frozenset[str] = _DEFAULT_REDACT_KEYS

    _sequence: int = field(default=0, init=False)
    _last_hash: str = field(default=_GENESIS_HASH, init=False)
    _events: list[AuditEvent] = field(default_factory=list, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def record(
        self,
        event_type: EventType,
        payload: Mapping[str, Any],
        *,
        actor: Optional[str] = None,
        data_class: DataClass = DataClass.INTERNAL,
    ) -> AuditEvent:
        """Append a generic audit event and return it."""
        with self._lock:
            safe_payload = redact(dict(payload), self.redact_keys)
            event = AuditEvent(
                sequence=self._sequence,
                timestamp=_utc_now_iso(),
                event_type=event_type,
                agent_id=self.agent_id,
                actor=actor or self.default_actor,
                payload=safe_payload,
                data_class=data_class,
                prev_hash=self._last_hash,
            )
            event.record_hash = _hash_record(event.to_dict())
            self._last_hash = event.record_hash
            self._sequence += 1
            self._events.append(event)
            if self.stream is not None:
                self.stream.write(json.dumps(event.to_dict(), separators=(",", ":")))
                self.stream.write("\n")
                self.stream.flush()
            return event

    # -- Convenience wrappers for the common event types -----------------

    def record_tool_call(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        decision: str,
        *,
        data_class: DataClass = DataClass.INTERNAL,
        actor: Optional[str] = None,
        justification: str = "",
    ) -> AuditEvent:
        """Record an attempted or executed tool call."""
        return self.record(
            EventType.TOOL_CALL,
            {
                "tool": tool,
                "arguments": arguments,
                "decision": decision,
                "justification": justification,
            },
            actor=actor,
            data_class=data_class,
        )

    def record_decision(
        self,
        step: int,
        thought: str,
        chosen_action: str,
        *,
        gate: str = "Gate 0",
        data_class: DataClass = DataClass.INTERNAL,
    ) -> AuditEvent:
        """Record a reasoning step and the action the agent selected."""
        return self.record(
            EventType.DECISION,
            {
                "step": step,
                "thought": thought,
                "chosen_action": chosen_action,
                "gate": gate,
            },
            data_class=data_class,
        )

    def record_egress(
        self,
        destination: str,
        data_class: DataClass,
        byte_count: int,
        *,
        allowed: bool,
    ) -> AuditEvent:
        """Record data leaving the agent boundary."""
        return self.record(
            EventType.EGRESS,
            {
                "destination": destination,
                "byte_count": byte_count,
                "allowed": allowed,
            },
            data_class=data_class,
        )

    def record_incident(
        self, summary: str, severity: str, *, actor: Optional[str] = None
    ) -> AuditEvent:
        """Record an incident marker for later correlation."""
        return self.record(
            EventType.INCIDENT,
            {"summary": summary, "severity": severity},
            actor=actor or "on_call",
            data_class=DataClass.CONFIDENTIAL,
        )

    # -- Integrity and retrieval ----------------------------------------

    def events(self) -> list[AuditEvent]:
        """Return a copy of the in-memory event list."""
        with self._lock:
            return list(self._events)

    def verify_chain(self) -> bool:
        """Verify the in-memory hash chain is intact and correctly ordered."""
        with self._lock:
            prev = _GENESIS_HASH
            for index, event in enumerate(self._events):
                if event.sequence != index:
                    return False
                if event.prev_hash != prev:
                    return False
                if _hash_record(event.to_dict()) != event.record_hash:
                    return False
                prev = event.record_hash
            return True

    @staticmethod
    def verify_stream(lines: Iterable[str]) -> bool:
        """Verify a persisted JSONL audit log.

        Parameters
        ----------
        lines:
            Iterable of JSONL strings, one audit record per line.

        Returns
        -------
        bool
            ``True`` if sequence numbers are contiguous from zero and the hash
            chain is intact; ``False`` otherwise.
        """
        prev = _GENESIS_HASH
        expected_seq = 0
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            record = json.loads(raw)
            if record.get("sequence") != expected_seq:
                return False
            if record.get("prev_hash") != prev:
                return False
            if _hash_record(record) != record.get("record_hash"):
                return False
            prev = record["record_hash"]
            expected_seq += 1
        return True


if __name__ == "__main__":
    import io

    buffer = io.StringIO()
    log = AuditLogger(agent_id="trade_execution_agent_v3", stream=buffer)

    log.record_decision(
        step=1,
        thought="Customer mandate requires rebalance; tech overweight by 15%.",
        chosen_action="execute_trade AAPL -500",
        gate="Gate 2",
    )
    log.record_tool_call(
        tool="execute_trade",
        arguments={"symbol": "AAPL", "quantity": -500, "api_key": "sk-should-be-hidden"},
        decision="allowed",
        data_class=DataClass.CONFIDENTIAL,
        justification="Rebalance per mandate section 4.2",
    )
    log.record_egress(
        destination="reports.internal.example",
        data_class=DataClass.CONFIDENTIAL,
        byte_count=2048,
        allowed=True,
    )

    print(buffer.getvalue())
    print("chain intact (memory):", log.verify_chain())
    print("chain intact (stream):", AuditLogger.verify_stream(buffer.getvalue().splitlines()))
