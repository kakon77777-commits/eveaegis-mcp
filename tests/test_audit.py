"""§18 — the ledger is append-only and tamper-evident."""

from __future__ import annotations

import sqlite3

import pytest

from eveaegis.audit import AuditLedger, content_hash
from eveaegis.taxonomy import Decision


def test_chain_links_every_event(conn: sqlite3.Connection) -> None:
    ledger = AuditLedger(conn)
    first = ledger.record("inventory_sync_started", actor="agent:local")
    second = ledger.record("inventory_sync_completed", actor="agent:local")

    assert first.prev_event_hash == "0" * 64
    assert second.prev_event_hash == first.event_hash
    assert ledger.verify() == (True, "2 events verified")


def test_sequence_is_monotonic(conn: sqlite3.Connection) -> None:
    ledger = AuditLedger(conn)
    events = [ledger.record(f"action_{i}") for i in range(5)]
    assert [e.sequence for e in events] == sorted(e.sequence for e in events)


def test_update_is_blocked_by_trigger(conn: sqlite3.Connection) -> None:
    ledger = AuditLedger(conn)
    ledger.record("something")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_events SET action = 'tampered'")


def test_delete_is_blocked_by_trigger(conn: sqlite3.Connection) -> None:
    ledger = AuditLedger(conn)
    ledger.record("something")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_events")


def test_verify_detects_tampering(conn: sqlite3.Connection) -> None:
    """Drop the guard trigger the way an attacker would, then edit a row."""
    ledger = AuditLedger(conn)
    ledger.record("first")
    ledger.record("second")

    conn.execute("DROP TRIGGER audit_events_no_update")
    conn.execute("UPDATE audit_events SET action = 'tampered' WHERE sequence = 1")
    conn.commit()

    ok, message = ledger.verify()
    assert not ok
    assert "sequence 1" in message


def test_decision_and_credential_facts_round_trip(conn: sqlite3.Connection) -> None:
    ledger = AuditLedger(conn)
    ledger.record(
        "policy_decision",
        actor="agent:local",
        initiated_by="human:owner",
        tenant="test-tenant",
        targets=["owner/repo"],
        policy_decision=Decision.REQUIRE_APPROVAL,
        credential_type="gh_cli_delegated_oauth_token",
        credential_scope="read_metadata",
    )
    event = ledger.recent(1)[0]
    assert event.policy_decision == Decision.REQUIRE_APPROVAL
    assert event.targets == ["owner/repo"]
    assert event.credential_scope == "read_metadata"


def test_content_hash_is_stable_and_order_independent() -> None:
    a = content_hash({"topics": ["x", "y"], "description": "d"})
    b = content_hash({"description": "d", "topics": ["x", "y"]})
    assert a == b == content_hash({"topics": ["x", "y"], "description": "d"})
    assert a != content_hash({"topics": ["x"], "description": "d"})
