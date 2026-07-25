"""§18 Audit Ledger — append-only, hash-chained.

Every event stores ``prev_event_hash``, so any retroactive edit breaks the chain and
:meth:`AuditLedger.verify` reports the first broken link. SQLite triggers block
UPDATE and DELETE on the table outright, so tampering requires dropping the trigger,
which itself is visible in the schema.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from ..db import _json_default, dumps, loads
from ..models import AuditEvent
from ..taxonomy import Decision

GENESIS = "0" * 64


def canonical_dumps(value: Any) -> str:
    """Order-independent JSON, so the same logical payload always hashes alike.

    This serialization is **frozen**. Changing it silently invalidates every event
    already on the chain: :meth:`AuditLedger.verify` will report the oldest events
    as tampered even though nothing touched them. If it ever has to change, add a
    per-row format column and dispatch on it — do not edit this function in place.
    """
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=_json_default
    )


def _canonical(event: AuditEvent, prev_hash: str) -> str:
    """Deterministic serialization of the fields the chain commits to."""
    parts = [
        prev_hash,
        event.event_id,
        event.timestamp.isoformat(),
        event.actor,
        event.initiated_by or "",
        event.tenant or "",
        event.action,
        ",".join(sorted(event.targets)),
        str(event.policy_decision or ""),
        ",".join(sorted(event.approved_by)),
        event.credential_type or "",
        event.credential_scope or "",
        event.before_hash or "",
        event.after_hash or "",
        event.result,
        canonical_dumps(event.detail),
    ]
    return "\x1f".join(parts)


def hash_event(event: AuditEvent, prev_hash: str) -> str:
    return hashlib.sha256(_canonical(event, prev_hash).encode("utf-8")).hexdigest()


def content_hash(payload: Any) -> str:
    """``sha256:…`` digest used for before/after comparison of governed content."""
    return "sha256:" + hashlib.sha256(canonical_dumps(payload).encode("utf-8")).hexdigest()


class AuditLedger:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # -- writing ----------------------------------------------------------

    def record(
        self,
        action: str,
        *,
        actor: str = "system",
        initiated_by: str | None = None,
        tenant: str | None = None,
        targets: list[str] | None = None,
        request_id: str | None = None,
        plan_id: str | None = None,
        policy_decision: Decision | None = None,
        approved_by: list[str] | None = None,
        credential_type: str | None = None,
        credential_scope: str | None = None,
        before_hash: str | None = None,
        after_hash: str | None = None,
        result: str = "COMPLETED",
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        now = datetime.now(timezone.utc)
        event = AuditEvent(
            event_id=f"evt_{now.strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:8]}",
            request_id=request_id,
            plan_id=plan_id,
            actor=actor,
            initiated_by=initiated_by,
            tenant=tenant,
            action=action,
            targets=targets or [],
            policy_decision=policy_decision,
            approved_by=approved_by or [],
            credential_type=credential_type,
            credential_scope=credential_scope,
            before_hash=before_hash,
            after_hash=after_hash,
            result=result,
            detail=detail or {},
            timestamp=now,
        )
        prev = self.head_hash()
        event.prev_event_hash = prev
        event.event_hash = hash_event(event, prev)

        self.conn.execute(
            """
            INSERT INTO audit_events (
                event_id, request_id, plan_id, actor, initiated_by, tenant, action,
                targets, policy_decision, approved_by, credential_type, credential_scope,
                before_hash, after_hash, result, detail, timestamp, prev_event_hash, event_hash
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event.event_id,
                event.request_id,
                event.plan_id,
                event.actor,
                event.initiated_by,
                event.tenant,
                event.action,
                dumps(event.targets),
                str(event.policy_decision) if event.policy_decision else None,
                dumps(event.approved_by),
                event.credential_type,
                event.credential_scope,
                event.before_hash,
                event.after_hash,
                event.result,
                dumps(event.detail),
                event.timestamp.isoformat(),
                event.prev_event_hash,
                event.event_hash,
            ),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT sequence FROM audit_events WHERE event_id = ?", (event.event_id,)
        ).fetchone()
        event.sequence = row["sequence"] if row else 0
        return event

    # -- reading ----------------------------------------------------------

    def head_hash(self) -> str:
        row = self.conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row["event_hash"] if row else GENESIS

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]

    def iter_events(self, limit: int | None = None) -> Iterator[AuditEvent]:
        sql = "SELECT * FROM audit_events ORDER BY sequence ASC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in self.conn.execute(sql):
            yield self._row_to_event(row)

    def recent(self, limit: int = 20) -> list[AuditEvent]:
        rows = self.conn.execute(
            "SELECT * FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> AuditEvent:
        return AuditEvent(
            event_id=row["event_id"],
            sequence=row["sequence"],
            request_id=row["request_id"],
            plan_id=row["plan_id"],
            actor=row["actor"],
            initiated_by=row["initiated_by"],
            tenant=row["tenant"],
            action=row["action"],
            targets=loads(row["targets"], []),
            policy_decision=Decision(row["policy_decision"]) if row["policy_decision"] else None,
            approved_by=loads(row["approved_by"], []),
            credential_type=row["credential_type"],
            credential_scope=row["credential_scope"],
            before_hash=row["before_hash"],
            after_hash=row["after_hash"],
            result=row["result"],
            detail=loads(row["detail"], {}),
            timestamp=datetime.fromisoformat(row["timestamp"]),
            prev_event_hash=row["prev_event_hash"],
            event_hash=row["event_hash"],
        )

    # -- integrity --------------------------------------------------------

    def verify(self) -> tuple[bool, str]:
        """Walk the chain. Returns ``(ok, message)`` naming the first broken link."""
        prev = GENESIS
        checked = 0
        for event in self.iter_events():
            if event.prev_event_hash != prev:
                return False, f"chain break at sequence {event.sequence}: prev hash mismatch"
            expected = hash_event(event, prev)
            if expected != event.event_hash:
                return False, f"tampered event at sequence {event.sequence}: digest mismatch"
            prev = event.event_hash
            checked += 1
        return True, f"{checked} events verified"
