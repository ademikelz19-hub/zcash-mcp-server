"""
ZECSHIELD // CONCURRENCY, FILE LOCKING & RACE CONDITION TESTS
============================================================
Tests vault file locking, multi-threaded double-spend prevention,
and crash-safe atomic single-use consumption under high concurrency.

Verification Category: ADVERSARIAL_CONCURRENCY_TEST
"""

import concurrent.futures
import time
from typing import List, Dict, Any

import pytest
import zecshield_firewall
from server import (
    DEFAULT_TREASURY_UA,
    request_transaction_intent,
    execute_authorized_broadcast,
)


def test_concurrent_broadcast_attempts_double_spend_prevention() -> None:
    """
    CRITICAL SECURITY INVARIANT:
    When 20 concurrent threads attempt to execute the exact same human-approved ticket
    simultaneously, EXACTLY ONE broadcast MUST succeed, and 19 MUST fail closed
    with TICKET_ALREADY_CONSUMED. No double-spending or duplicate broadcast is possible.
    """
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="5.0",
        memo_utf8="High concurrency stress test",
    )
    ticket_id = ticket["ticket_id"]

    # Human operator approves the ticket out-of-band
    approve_res = zecshield_firewall.approve_transaction_intent_ticket(
        ticket_id=ticket_id,
        operator_pin="2026",
        operator_note="Approved for concurrency test",
    )
    assert approve_res["success"] is True
    assert approve_res["status"] == "HUMAN_APPROVED"

    num_threads = 20
    results: List[Dict[str, Any]] = []

    def attempt_broadcast(worker_id: int) -> Dict[str, Any]:
        return execute_authorized_broadcast(
            ticket_id=ticket_id,
            recipient=DEFAULT_TREASURY_UA,
            amount_zec="5.0",
            memo_utf8="High concurrency stress test",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attempt_broadcast, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r.get("status") == "BROADCAST_EXECUTED"]
    failures = [r for r in results if r.get("status") == "BROADCAST_REJECTED"]

    assert len(successes) == 1, f"Expected exactly 1 broadcast success, got {len(successes)}"
    assert len(failures) == num_threads - 1, f"Expected {num_threads - 1} rejections, got {len(failures)}"

    for fail in failures:
        assert fail.get("error") == "TICKET_ALREADY_CONSUMED"

    # Verify final vault state is CONSUMED
    vault_tickets = zecshield_firewall.get_intent_tickets()
    assert vault_tickets[ticket_id]["status"] == "CONSUMED"


def test_concurrent_approval_and_rejection_race() -> None:
    """
    Tests that concurrent approval and rejection requests do not corrupt vault state.
    """
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="1.5",
        memo_utf8="Approval-rejection race test",
    )
    ticket_id = ticket["ticket_id"]

    def do_approve() -> Dict[str, Any]:
        return zecshield_firewall.approve_transaction_intent_ticket(ticket_id, operator_pin="2026")

    def do_reject() -> Dict[str, Any]:
        return zecshield_firewall.reject_transaction_intent_ticket(ticket_id, reason="Operator reject race")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(do_approve)
        f2 = executor.submit(do_reject)
        res1 = f1.result()
        res2 = f2.result()

    # The vault state must be either HUMAN_APPROVED or REJECTED, never inconsistent or corrupted
    vault = zecshield_firewall.get_intent_tickets()
    assert vault[ticket_id]["status"] in ("HUMAN_APPROVED", "REJECTED")


def test_operator_pin_authentication_enforcement() -> None:
    """
    Tests that approve_transaction_intent_ticket rejects invalid PINs and requires valid authentication.
    """
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="2.0",
        memo_utf8="PIN authentication test",
    )
    ticket_id = ticket["ticket_id"]

    # Wrong PIN fails closed
    wrong_res = zecshield_firewall.approve_transaction_intent_ticket(ticket_id, operator_pin="9999")
    assert wrong_res["success"] is False
    assert wrong_res["error"] == "INVALID_OPERATOR_PIN"

    # Correct PIN succeeds
    correct_res = zecshield_firewall.approve_transaction_intent_ticket(ticket_id, operator_pin="2026")
    assert correct_res["success"] is True
    assert correct_res["status"] == "HUMAN_APPROVED"
