"""
ZECSHIELD // CONCURRENCY, FILE LOCKING & RACE CONDITION TESTS
============================================================
Tests vault file locking, multi-threaded double-spend prevention,
and crash-safe atomic single-use consumption under high concurrency.

Verification Category: ADVERSARIAL_CONCURRENCY_TEST
"""

import concurrent.futures
import json
import re
import subprocess
import sys
import time
import urllib.parse
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


def test_adversarial_ai_vault_tampering_forgery_fails() -> None:
    """
    CRITICAL SECURITY INVARIANT:
    An AI agent with subshell or filesystem write access cannot self-authorize
    by directly modifying the vault JSON file (e.g., setting status: HUMAN_APPROVED).
    Without the human operator's Ed25519 private key (derived from human passphrase),
    the authorization fails closed with FORGERY_DETECTED.
    """
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="3.5",
        memo_utf8="Adversarial vault tamper test",
    )
    ticket_id = ticket["ticket_id"]
    assert ticket["status"] == "PENDING_HUMAN_APPROVAL"

    # Adversary directly modifies vault JSON to set status: HUMAN_APPROVED without valid signature
    vault_file = zecshield_firewall.VAULT_FILE
    with open(vault_file, "r", encoding="utf-8") as f:
        vault_data = json.load(f)

    # Attempt 1: Self-approve without any signature
    vault_data[ticket_id]["status"] = "HUMAN_APPROVED"
    vault_data[ticket_id]["operator_signature"] = None
    with open(vault_file, "w", encoding="utf-8") as f:
        json.dump(vault_data, f, indent=2)

    tampered_exec = execute_authorized_broadcast(
        ticket_id=ticket_id,
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="3.5",
        memo_utf8="Adversarial vault tamper test",
    )
    assert tampered_exec["status"] == "BROADCAST_REJECTED"
    assert tampered_exec["error"] == "FORGERY_DETECTED"

    # Attempt 2: Forged / corrupted Ed25519 signature
    vault_data[ticket_id]["status"] = "HUMAN_APPROVED"
    vault_data[ticket_id]["operator_signature"] = "deadbeef" * 16  # 64-byte invalid signature
    with open(vault_file, "w", encoding="utf-8") as f:
        json.dump(vault_data, f, indent=2)

    forged_exec = execute_authorized_broadcast(
        ticket_id=ticket_id,
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="3.5",
        memo_utf8="Adversarial vault tamper test",
    )
    assert forged_exec["status"] == "BROADCAST_REJECTED"
    assert forged_exec["error"] == "FORGERY_DETECTED"


def test_multiprocess_broadcast_race_double_spend() -> None:
    """
    CRITICAL MULTI-PROCESS INVARIANT:
    Spawns multiple separate OS processes (with independent PIDs and Python runtimes).
    Proves that OS-level advisory file locks (msvcrt on Windows, fcntl on POSIX)
    prevent duplicate broadcasts across OS processes. Exactly one process succeeds.
    """
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="7.0",
        memo_utf8="Multi-process OS lock stress test",
    )
    ticket_id = ticket["ticket_id"]

    approve_res = zecshield_firewall.approve_transaction_intent_ticket(
        ticket_id=ticket_id,
        operator_pin="2026",
    )
    assert approve_res["success"] is True

    num_procs = 4
    script = (
        "import sys, json\n"
        "from server import execute_authorized_broadcast, DEFAULT_TREASURY_UA\n"
        f"tid = '{ticket_id}'\n"
        "res = execute_authorized_broadcast(\n"
        "    ticket_id=tid,\n"
        "    recipient=DEFAULT_TREASURY_UA,\n"
        "    amount_zec='7.0',\n"
        "    memo_utf8='Multi-process OS lock stress test'\n"
        ")\n"
        "sys.stdout.write(json.dumps({'status': res.get('status'), 'error': res.get('error')}) + '\\n')\n"
    )

    processes = [
        subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(num_procs)
    ]

    outputs = []
    for p in processes:
        stdout, _ = p.communicate(timeout=15.0)
        line = stdout.strip().splitlines()[-1] if stdout.strip() else "{}"
        try:
            outputs.append(json.loads(line))
        except Exception:
            outputs.append({"raw": stdout})

    successes = [o for o in outputs if o.get("status") == "BROADCAST_EXECUTED"]
    failures = [o for o in outputs if o.get("status") == "BROADCAST_REJECTED"]

    assert len(successes) == 1, f"Expected exactly 1 process to succeed, got {len(successes)}: {outputs}"
    assert len(failures) == num_procs - 1
    for f in failures:
        assert f.get("error") == "TICKET_ALREADY_CONSUMED"


def test_two_phase_crash_recovery_mempool_reconciliation() -> None:
    """
    CRITICAL CRASH RECOVERY INVARIANT:
    When a server crashes or restarts during broadcast, the ticket remains IN_FLIGHT_BROADCASTING.
    On restart/retry, the system checks whether the candidate txid is already in the node mempool.
    If present, it reconciles the ticket to CONSUMED idempotently without generating a duplicate spend.
    """
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="1.25",
        memo_utf8="Crash recovery reconciliation test",
    )
    ticket_id = ticket["ticket_id"]
    approve_res = zecshield_firewall.approve_transaction_intent_ticket(ticket_id, operator_pin="2026")
    assert approve_res["success"] is True

    # Phase 1: Begin broadcast
    phase1 = zecshield_firewall.begin_in_flight_broadcast(
        ticket_id=ticket_id,
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="1.25",
        memo_utf8="Crash recovery reconciliation test",
    )
    assert phase1["status"] == "IN_FLIGHT_BROADCASTING"
    candidate_txid = phase1["candidate_txid"]

    # Simulate crash before Phase 2 completion: ticket remains IN_FLIGHT in vault
    # Now simulate recovery where candidate_txid is found in mempool
    def mock_mempool_finder(txid: str) -> bool:
        return txid == candidate_txid

    reconciled = zecshield_firewall.begin_in_flight_broadcast(
        ticket_id=ticket_id,
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="1.25",
        memo_utf8="Crash recovery reconciliation test",
        mempool_check_fn=mock_mempool_finder,
    )
    assert reconciled["status"] == "CONSUMED"
    assert reconciled["reconciled"] is True
    assert reconciled["txid"] == candidate_txid

    # Further attempt must fail closed as already consumed
    replay = zecshield_firewall.begin_in_flight_broadcast(
        ticket_id=ticket_id,
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="1.25",
        memo_utf8="Crash recovery reconciliation test",
    )
    assert replay["authorized"] is False
    assert replay["error"] == "TICKET_ALREADY_CONSUMED"


def test_portal_csrf_and_origin_security_boundary() -> None:
    """
    CRITICAL SECURITY INVARIANT:
    The out-of-band Human Approval Web Portal enforces strict Origin, Sec-Fetch-Site,
    and SameSite CSRF token boundaries.
    Any attempt by an AI script or malicious website to submit cross-origin or
    forged requests is rejected with 403 Forbidden or 401 Unauthorized.
    """
    import urllib.request
    import urllib.error
    import threading
    import http.server
    import cli

    # Create an intent ticket to approve
    ticket = request_transaction_intent(
        recipient=DEFAULT_TREASURY_UA,
        amount_zec="0.88",
        memo_utf8="Portal security boundary test",
    )
    ticket_id = ticket["ticket_id"]

    port = 9188
    server_address = ("127.0.0.1", port)
    httpd = http.server.HTTPServer(server_address, cli.ApprovalPortalHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.3)

    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. Cross-Origin attack: Evil Origin header -> 403 Forbidden
        body = urllib.parse.urlencode({
            "ticket_id": ticket_id,
            "passphrase": "ZECSHIELD_MASTER_OPERATOR_2026",
            "csrf_token": "fake_token",
        }).encode("utf-8")
        req_evil = urllib.request.Request(
            f"{base_url}/approve",
            data=body,
            headers={
                "Origin": "http://evil-attacker.site",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_evil)
        assert exc_info.value.code == 403

        # 2. Missing CSRF token -> 403 Forbidden
        req_no_csrf = urllib.request.Request(
            f"{base_url}/approve",
            data=body,
            headers={
                "Origin": f"http://127.0.0.1:{port}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_no_csrf)
        assert exc_info.value.code == 403

        # 3. Valid GET to obtain legitimate CSRF session cookie & token
        get_req = urllib.request.Request(f"{base_url}/")
        with urllib.request.urlopen(get_req) as resp:
            cookie_header = resp.headers.get("Set-Cookie", "")
            page_html = resp.read().decode("utf-8")

        csrf_match = re.search(r'name="csrf-token"\s+content="([a-f0-9]+)"', page_html) or re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', page_html)
        assert csrf_match is not None, "CSRF token must be present in portal HTML"
        valid_csrf = csrf_match.group(1)

        # Extract cookie value
        cookie_val = cookie_header.split(";")[0] if cookie_header else f"zecshield_csrf={valid_csrf}"

        # 4. Wrong passphrase with valid CSRF -> 401 Unauthorized
        wrong_pass_body = urllib.parse.urlencode({
            "ticket_id": ticket_id,
            "passphrase": "WRONG_SECRET_PASSPHRASE",
            "csrf_token": valid_csrf,
        }).encode("utf-8")
        req_wrong_pass = urllib.request.Request(
            f"{base_url}/approve",
            data=wrong_pass_body,
            headers={
                "Origin": f"http://127.0.0.1:{port}",
                "Cookie": cookie_val,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_wrong_pass)
        assert exc_info.value.code == 401

        # 5. Legitimate approval with valid same-origin, fresh CSRF, and human operator secret
        with urllib.request.urlopen(urllib.request.Request(f"{base_url}/")) as resp:
            cookie_header2 = resp.headers.get("Set-Cookie", "")
            page_html2 = resp.read().decode("utf-8")
        csrf_match2 = re.search(r'name="csrf-token"\s+content="([a-f0-9]+)"', page_html2) or re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', page_html2)
        assert csrf_match2 is not None
        valid_csrf2 = csrf_match2.group(1)
        cookie_val2 = cookie_header2.split(";")[0] if cookie_header2 else f"zecshield_csrf={valid_csrf2}"

        valid_body = urllib.parse.urlencode({
            "ticket_id": ticket_id,
            "passphrase": "ZECSHIELD_MASTER_OPERATOR_2026",
            "csrf_token": valid_csrf2,
        }).encode("utf-8")
        req_valid = urllib.request.Request(
            f"{base_url}/approve",
            data=valid_body,
            headers={
                "Origin": f"http://127.0.0.1:{port}",
                "Cookie": cookie_val2,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req_valid) as resp:
            assert resp.status == 200

        # Verify the ticket now has authentic Ed25519 signature in vault
        vault_tickets = zecshield_firewall.get_intent_tickets()
        assert vault_tickets[ticket_id]["status"] == "HUMAN_APPROVED"
        assert vault_tickets[ticket_id]["operator_signature"] is not None
        assert len(vault_tickets[ticket_id]["operator_signature"]) == 128
    finally:
        httpd.shutdown()
        server_thread.join(timeout=2.0)

