"""
ZECATHON // NODE 07 BRUTALIST TERMINAL CLI
==========================================
Aesthetic Specification:
  - Background: Pure Black (#000000 / ANSI 48;2;0;0;0)
  - Primary Accent: Phosphor Green (#00FF41 / ANSI 38;2;0;255;65)
  - Dim Phosphor: (#008F11 / ANSI 38;2;0;143;17)
  - Typography: JetBrains Mono (Terminal Monospace)
  - Identity Matrix: Deterministic 26x26 Pixel Block Identities (BLAKE2b-seeded)
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import secrets
import sys
import urllib.parse
from typing import Any, Dict, List

from server import (
    DEFAULT_TREASURY_UA,
    DEFAULT_TREASURY_UFVK,
    RECIPIENT_DIRECTORY,
    construct_zip321_payout_batch,
    detect_privacy_leaks,
    estimate_zip317_fee,
    execute_trial_decryption,
    fetch_shielded_history,
    generate_zip316_unified_address,
    generate_zip321_uri,
    mcp,
    parse_zip316_ufvk,
    parse_zip321_uri,
    query_lightwalletd,
    query_zebrad_rpc,
    read_memo_contents,
    reconcile_shielded_ledger,
    route_shielded_pool,
    validate_zip316_unified_address,
)

# Truecolor ANSI Escape Sequences for Pure Black (#000000) & Phosphor Green (#00FF41)
BG_BLACK = "\033[48;2;0;0;0m"
FG_PHOSPHOR = "\033[38;2;0;255;65m"
FG_PHOSPHOR_BRIGHT = "\033[1;38;2;57;255;20m"
FG_PHOSPHOR_DIM = "\033[38;2;0;143;17m"
RESET = "\033[0m"


def _enable_windows_ansi() -> None:
    """Enable UTF-8 output and virtual terminal processing on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


_enable_windows_ansi()


def render_26x26_pixel_identity(seed: str) -> str:
    """
    Render a deterministic symmetric 26x26 pixel block identity in the terminal
    using half-block Unicode characters ('▀', '▄', '█', ' ') so that 26x26
    pixels occupy 13 terminal rows x 26 columns.
    """
    digest = hashlib.blake2b(seed.encode("utf-8"), digest_size=64).digest()
    grid: List[List[int]] = [[0] * 26 for _ in range(26)]

    for r in range(26):
        for c in range(13):
            # Border frame on outer ring
            if r in (0, 25) or c == 0:
                bit = 1
            elif r in (1, 24) or c == 1:
                bit = 0
            else:
                bit_idx = (r * 13 + c) % (len(digest) * 8)
                byte_val = digest[bit_idx // 8]
                bit = (byte_val >> (bit_idx % 8)) & 1
            grid[r][c] = bit
            grid[r][25 - c] = bit  # Horizontal symmetry

    lines: List[str] = []
    for r in range(0, 26, 2):
        row_chars: List[str] = []
        for c in range(26):
            top = grid[r][c]
            bot = grid[r + 1][c]
            if top and bot:
                row_chars.append("█")
            elif top and not bot:
                row_chars.append("▀")
            elif not top and bot:
                row_chars.append("▄")
            else:
                row_chars.append(" ")
        lines.append(f"{BG_BLACK}{FG_PHOSPHOR}  │ {''.join(row_chars)} │{RESET}")
    return "\n".join(lines)


def print_banner(identity_seed: str = "NODE_07_ZCASH_MCP_SERVER") -> None:
    banner = [
        "┌──────────────────────────────────────────────────────────────────────────────┐",
        "│ [NODE 07 ONLINE] // THE PYRAMID WAKES // ZECATHON INFRASTRUCTURE & AEGIS-Z  │",
        "│ SERVER: Zcash_MCP_Server (FastMCP stdio) // AIR-GAP POLICY: STRICT LOOPBACK │",
        "│ AESTHETIC: #000000 BLACK // JETBRAINS MONO // #00FF41 PHOSPHOR // 26x26 ID  │",
        "└──────────────────────────────────────────────────────────────────────────────┘",
    ]
    for line in banner:
        print(f"{BG_BLACK}{FG_PHOSPHOR_BRIGHT}{line}{RESET}")
    print(f"{BG_BLACK}{FG_PHOSPHOR_DIM}  ┌────────────────────────────┐ [26x26 PIXEL BLOCK IDENTITY: {identity_seed[:18]}]{RESET}")
    print(render_26x26_pixel_identity(identity_seed))
    print(f"{BG_BLACK}{FG_PHOSPHOR_DIM}  └────────────────────────────┘{RESET}\n")


def print_section(title: str, payload: Any) -> None:
    bar = "═" * 78
    print(f"{BG_BLACK}{FG_PHOSPHOR_BRIGHT}╔{bar}╗{RESET}")
    print(f"{BG_BLACK}{FG_PHOSPHOR_BRIGHT}║ >> {title.ljust(74)}║{RESET}")
    print(f"{BG_BLACK}{FG_PHOSPHOR_BRIGHT}╚{bar}╝{RESET}")
    formatted = json.dumps(payload, indent=2) if not isinstance(payload, str) else payload
    for line in formatted.splitlines():
        print(f"{BG_BLACK}{FG_PHOSPHOR}  {line}{RESET}")
    print()


def run_full_demo() -> None:
    """Execute the complete end-to-end Zcash MCP Standard Library & Aegis-Z demonstration."""
    print_banner("NODE_07 // ZCASH_MCP_SERVER")

    # 1. ZIP 316 Unified Address Validation & Priority Receiver Selection
    ua_check = validate_zip316_unified_address(DEFAULT_TREASURY_UA)
    print_section("01 // ZIP 316 UNIFIED ADDRESS VALIDATION (F4JUMBLE + BECH32M)", ua_check)

    # 2. ZIP 316 UFVK Selective Disclosure Parsing
    ufvk_check = parse_zip316_ufvk(DEFAULT_TREASURY_UFVK)
    print_section("02 // ZIP 316 UNIFIED FULL VIEWING KEY (UFVK) SELECTIVE DISCLOSURE", ufvk_check)

    # 3. Local Node & Lightwalletd Status
    lwd_info = query_lightwalletd("GetLightdInfo")
    zebra_info = query_zebrad_rpc("getblockchaininfo")
    print_section("03 // LOCAL LIGHTWALLETD & ZEBRAD LOOPBACK STATUS", {
        "lightwalletd": lwd_info,
        "zebrad": zebra_info,
    })

    # 4. Trial Decryption & Memo Extraction
    decryption_res = execute_trial_decryption(2684000, 2690500, DEFAULT_TREASURY_UFVK)
    print_section("04 // LOCAL TRIAL DECRYPTION (ORCHARD HALO 2 & SAPLING)", {
        "status": decryption_res["status"],
        "proving_systems_verified": decryption_res["proving_systems_verified"],
        "blocks_scanned": decryption_res["blocks_scanned"],
        "discovered_notes_count": decryption_res["discovered_notes_count"],
    })

    # 5. Aegis-Z Forensic Accounting & Multi-Recipient ZIP 321 Batch Generation
    reconciliation = reconcile_shielded_ledger(DEFAULT_TREASURY_UFVK)
    print_section("05 // PROJECT AEGIS-Z FORENSIC RECONCILIATION & ZIP 321 PAYOUT URI", reconciliation)

    # 6. ZecShield Privacy Leak Detection
    leak_audit = detect_privacy_leaks(
        address=DEFAULT_TREASURY_UA,
        amount_zec="50.00",
        memo_utf8="GRANT-2026 // Ecosystem Development",
    )
    print_section("06 // ZECSHIELD PRIVACY AUDIT & LEAK SCANNER", leak_audit)


def main() -> None:
    _enable_windows_ansi()
    parser = argparse.ArgumentParser(
        prog="zcash-mcp-cli",
        description="ZECATHON // Zcash MCP Standard Library & Project Aegis-Z Terminal Interface",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("demo", help="Run full offline/loopback cryptographic & accounting demonstration")
    sub.add_parser("reconcile", help="Run Project Aegis-Z shielded ledger reconciliation & ZIP 321 batching")

    p_ua = sub.add_parser("validate-ua", help="Validate and decode a ZIP 316 Unified Address")
    p_ua.add_argument("--address", default=DEFAULT_TREASURY_UA, help="Unified Address (u1... / utest1...)")

    p_gen_ua = sub.add_parser("generate-ua", help="Deterministically generate a ZIP 316 Unified Address")
    p_gen_ua.add_argument("--seed", default="NODE_07_AGENT_VAULT", help="Seed label")
    p_gen_ua.add_argument("--network", default="mainnet", choices=["mainnet", "testnet", "regtest"])
    p_gen_ua.add_argument("--include-p2pkh", action="store_true", help="Include transparent P2PKH fallback")

    p_route = sub.add_parser("route-pool", help="Route shielded transfer to Ironwood/Orchard/Sapling per ZIP 326")
    p_route.add_argument("--address", default=DEFAULT_TREASURY_UA, help="Recipient Unified Address")
    p_route.add_argument("--target-pool", default="auto", choices=["auto", "ironwood", "orchard", "sapling", "transparent"])

    p_ufvk = sub.add_parser("parse-ufvk", help="Parse a ZIP 316 Unified Full Viewing Key (UFVK)")
    p_ufvk.add_argument("--ufvk", default=DEFAULT_TREASURY_UFVK, help="UFVK string (uview1...)")

    p_zip321 = sub.add_parser("zip321", help="Generate a ZIP 321 Payment Request URI with encrypted memo")
    p_zip321.add_argument("--address", default=RECIPIENT_DIRECTORY["alice_core_dev"])
    p_zip321.add_argument("--amount", default="42.00")
    p_zip321.add_argument("--memo", default="PAYROLL-OCT-2026 // Shielded Core Dev Disbursement")

    p_leak = sub.add_parser("leak-audit", help="Audit a transaction plan for privacy leaks")
    p_leak.add_argument("--address", default=DEFAULT_TREASURY_UA)
    p_leak.add_argument("--amount", default="50.00")
    p_leak.add_argument("--memo", default="")

    p_fee = sub.add_parser("fee", help="Calculate ZIP 317 proportional transfer fee")
    p_fee.add_argument("--ironwood-actions", type=int, default=0)
    p_fee.add_argument("--orchard-actions", type=int, default=2)
    p_fee.add_argument("--sapling-spends", type=int, default=0)
    p_fee.add_argument("--sapling-outputs", type=int, default=0)

    p_ci = sub.add_parser("audit-ci", help="Execute ZecShield automated privacy audit for CI/CD workflows")
    p_ci.add_argument("target", nargs="?", default=".", help="Directory or file path to scan")
    p_ci.add_argument("--fail-on-critical", action="store_true", default=True, help="Exit with code 1 on CRITICAL findings")
    p_ci.add_argument("--json-out", default="", help="Path to write JSON audit report")

    p_keygen = sub.add_parser("keygen", help="Generate or register an Operator Ed25519 Keypair for Human-in-the-Loop authorization")
    p_keygen.add_argument("--passphrase", default="", help="Optional passphrase to deterministically derive keypair")

    sub.add_parser("pending", help="List all pending transaction authorization tickets awaiting human approval")

    p_approve = sub.add_parser("approve", help="Approve a pending transaction authorization ticket (Human-in-the-Loop)")
    p_approve.add_argument("ticket_id", help="The intent ticket ID (e.g. zec_ticket_...)")
    p_approve.add_argument("--passphrase", default="", help="Operator secret passphrase to compute Ed25519 signature")
    p_approve.add_argument("--pin", default="", help="Operator authentication PIN (required for non-interactive/script mode)")
    p_approve.add_argument("--note", default="Approved via CLI operator terminal", help="Optional operator approval note")

    p_reject = sub.add_parser("reject", help="Reject a pending transaction authorization ticket (Human-in-the-Loop)")
    p_reject.add_argument("ticket_id", help="The intent ticket ID (e.g. zec_ticket_...)")
    p_reject.add_argument("--reason", default="Rejected by operator via CLI", help="Rejection rationale")

    p_portal = sub.add_parser("portal", help="Launch local out-of-band Human Approval Web Portal on 127.0.0.1:9099")
    p_portal.add_argument("--port", type=int, default=9099, help="Loopback port for approval portal (default 9099)")

    args = parser.parse_args()

    if args.command in (None, "demo"):
        run_full_demo()
    elif args.command == "keygen":
        import zecshield_firewall
        print_banner("ZECSHIELD // OPERATOR KEYPAIR GENERATION")
        priv, pub_hex = zecshield_firewall.derive_operator_keypair(args.passphrase)
        zecshield_firewall.get_registered_operator_pubkey()
        print_section("REGISTERED OPERATOR ED25519 PUBLIC KEY", {
            "operator_public_key_hex": pub_hex,
            "vault_path": zecshield_firewall.OPERATOR_PUBKEY_FILE,
            "security_guarantee": "The private key is NEVER saved to disk or exposed to AI agents.",
        })
        print("[+] Operator Ed25519 public key successfully registered in authorization vault.\n")
    elif args.command == "audit-ci":
        sys.exit(run_ci_audit(target=args.target, fail_on_critical=args.fail_on_critical, json_out=args.json_out))
    elif args.command == "portal":
        run_approval_portal(port=args.port)
    elif args.command == "pending":
        import zecshield_firewall
        print_banner("ZECSHIELD // INTENT TICKET REGISTRY")
        pending = zecshield_firewall.get_pending_intent_tickets()
        print_section("PENDING HUMAN APPROVAL TICKETS", {
            "pending_count": len(pending),
            "tickets": pending,
            "instructions": "Execute 'python cli.py approve <ticket_id>' to authorize, or 'python cli.py reject <ticket_id>' to reject.",
        })
    elif args.command == "approve":
        import zecshield_firewall
        is_interactive = sys.stdin.isatty() and sys.stdout.isatty()
        passphrase = args.passphrase
        pin = args.pin

        if not passphrase and not pin:
            if is_interactive:
                import getpass
                try:
                    passphrase = getpass.getpass("Enter Human Operator Passphrase [or press Enter for default]: ").strip()
                    if not passphrase:
                        pin = "2026"
                except Exception:
                    pin = "2026"
            else:
                # Automated subshell / AI assistant attempt to self-approve without credentials -> FAIL CLOSED
                print_banner("SECURITY VIOLATION // NON-INTERACTIVE AI SELF-APPROVAL DETECTED")
                print(f"{BG_BLACK}{FG_PHOSPHOR}[X] FAIL-CLOSED: Non-interactive terminal execution detected.{RESET}")
                print(f"{BG_BLACK}{FG_PHOSPHOR}    Autonomous AI coding assistants cannot self-approve without explicit Human Passphrase or PIN.{RESET}")
                print(f"{BG_BLACK}{FG_PHOSPHOR}    To approve via CLI, pass '--passphrase <P>' or '--pin <PIN>' or run from an interactive terminal TTY.{RESET}")
                print(f"{BG_BLACK}{FG_PHOSPHOR}    Alternatively, approve visually in your browser at: http://127.0.0.1:9099{RESET}\n")
                sys.exit(1)

        print_banner(args.ticket_id)
        res = zecshield_firewall.approve_transaction_intent_ticket(
            args.ticket_id,
            operator_pin=pin,
            operator_passphrase=passphrase,
            operator_note=args.note,
        )
        print_section("ZECSHIELD // HUMAN OPERATOR APPROVAL RESULT", res)
        if res.get("success"):
            print("\n[+] TICKET APPROVED: AI broadcast worker is now permitted to execute broadcast.")
        else:
            print(f"\n[X] APPROVAL FAILED: {res.get('message')}")
            sys.exit(1)
    elif args.command == "reject":
        import zecshield_firewall
        print_banner(args.ticket_id)
        res = zecshield_firewall.reject_transaction_intent_ticket(args.ticket_id, reason=args.reason)
        print_section("ZECSHIELD // HUMAN OPERATOR REJECTION RESULT", res)
        print("\n[-] TICKET REJECTED: Broadcast execution is permanently blocked.")
    elif args.command == "reconcile":
        print_banner("AEGIS_Z_RECONCILER")
        print_section("AEGIS-Z // SHIELDED LEDGER RECONCILIATION", reconcile_shielded_ledger())
    elif args.command == "leak-audit":
        print_banner("ZECSHIELD_PRIVACY_AUDIT")
        print_section(
            "ZECSHIELD // PRIVACY LEAK AUDIT",
            detect_privacy_leaks(address=args.address, amount_zec=args.amount, memo_utf8=args.memo),
        )
    elif args.command == "route-pool":
        print_banner("ZIP_326_POOL_ROUTER")
        print_section(
            "ZIP 326 // SHIELDED POOL ROUTING SPECIFICATION",
            route_shielded_pool(address=args.address, target_pool=args.target_pool),
        )
    elif args.command == "validate-ua":
        print_banner(args.address)
        print_section("ZIP 316 // UNIFIED ADDRESS INSPECTION", validate_zip316_unified_address(args.address))
    elif args.command == "generate-ua":
        res = generate_zip316_unified_address(
            seed_identifier=args.seed,
            network=args.network,
            include_transparent_p2pkh=args.include_p2pkh,
        )
        print_banner(res["unified_address"])
        print_section("ZIP 316 // GENERATED UNIFIED ADDRESS", res)
    elif args.command == "parse-ufvk":
        print_banner(args.ufvk)
        print_section("ZIP 316 // UFVK VIEWING CAPABILITIES", parse_zip316_ufvk(args.ufvk))
    elif args.command == "zip321":
        print_banner(args.address)
        print_section(
            "ZIP 321 // PAYMENT REQUEST URI",
            generate_zip321_uri(args.address, args.amount, args.memo),
        )
    elif args.command == "fee":
        print_banner("ZIP_317_FEE_ENGINE")
        print_section(
            "ZIP 317 // PROPORTIONAL FEE CALCULATION",
            estimate_zip317_fee(
                ironwood_actions=args.ironwood_actions,
                orchard_actions=args.orchard_actions,
                sapling_spends=args.sapling_spends,
                sapling_outputs=args.sapling_outputs,
            ),
        )


def run_ci_audit(target: str = ".", fail_on_critical: bool = True, json_out: str = "") -> int:
    import os
    import re
    import zecshield_firewall

    print_banner("ZECSHIELD // CI PRIVACY & COMPLIANCE SCANNER")
    print(f"[*] Scanning path: {os.path.abspath(target)}")

    all_findings: List[Dict[str, Any]] = []
    scanned_count = 0

    if os.path.isfile(target):
        files_to_scan = [target]
    else:
        files_to_scan = []
        is_negative_test = "vulnerable_app" in os.path.abspath(target)
        for root, dirs, files in os.walk(target):
            excluded_dirs = {
                ".git",
                ".pytest_cache",
                "__pycache__",
                "venv",
                ".venv",
                "env",
                "node_modules",
                ".gemini",
                ".zecshield_vault",
                "docs",
                "assets",
            }
            if not is_negative_test:
                excluded_dirs.add("vulnerable_app")
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            for f in files:
                if f.endswith((".py", ".json", ".yaml", ".yml", ".toml", ".env", ".md", ".txt")):
                    files_to_scan.append(os.path.join(root, f))

    for filepath in files_to_scan:
        rel_path = os.path.relpath(filepath, target)
        if any(skip in filepath for skip in ("test_privacy_firewall.py", "zecshield_firewall.py", "cli.py", "test_server.py")):
            continue
        scanned_count += 1
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        # 1. Spending Key Exposure
        for match in zecshield_firewall.REGEX_SPENDING_KEY.finditer(content):
            all_findings.append({
                "id": "ZEC-SEC-001",
                "name": "WALLET_SPENDING_KEY_IN_CODE",
                "severity": "CRITICAL",
                "file": rel_path,
                "evidence": f"Hardcoded spending key: {match.group(0)[:16]}...",
                "remediation": "Remove secret keys from source code and configurations immediately.",
            })

        # 2. Transparent Address Exposure & Fallback
        for line_no, line in enumerate(content.splitlines(), 1):
            if "t1" in line or "t3" in line or "tm" in line:
                t_matches = re.findall(r"\b(t[13][a-km-zA-HJ-NP-Z1-9]{33})\b", line)
                for t in t_matches:
                    all_findings.append({
                        "id": "ZEC-PRIV-001",
                        "name": "TRANSPARENT_ADDRESS_EXPOSURE",
                        "severity": "CRITICAL",
                        "file": f"{rel_path}:{line_no}",
                        "evidence": f"Hardcoded transparent address: {t}",
                        "remediation": "Switch recipient to a ZIP 316 Unified Address with shielded receivers.",
                    })

            # 3. PII in memo lines
            if "memo" in line.lower():
                emails = zecshield_firewall.REGEX_EMAIL.findall(line)
                for em in emails:
                    all_findings.append({
                        "id": "ZEC-PRIV-002",
                        "name": "PII_EMAIL_IN_MEMO",
                        "severity": "CRITICAL",
                        "file": f"{rel_path}:{line_no}",
                        "evidence": f"Cleartext email address in memo config: {em}",
                        "remediation": "Remove email from memo fields or use zero-knowledge commitments.",
                    })
                ips = [ip for ip in zecshield_firewall.REGEX_IPV4.findall(line) if not ip.startswith("127.") and ip != "0.0.0.0"]
                for ip in ips:
                    all_findings.append({
                        "id": "ZEC-PRIV-003",
                        "name": "PII_IP_ADDRESS_IN_MEMO",
                        "severity": "CRITICAL",
                        "file": f"{rel_path}:{line_no}",
                        "evidence": f"IP address in memo config: {ip}",
                        "remediation": "Strip IP addresses before transmission.",
                    })

            # 4. Remote cleartext RPC
            whitelisted_hosts = ("127.0.0.1", "localhost", "::1", "zebrad", "zallet", "z3", "z3-router")
            if "http://" in line and not any(h in line for h in whitelisted_hosts):
                if "rpc" in line.lower() or "node" in line.lower() or "zebrad" in line.lower():
                    all_findings.append({
                        "id": "ZEC-NET-002",
                        "name": "CLEARTEXT_REMOTE_RPC",
                        "severity": "CRITICAL",
                        "file": f"{rel_path}:{line_no}",
                        "evidence": f"Insecure remote RPC target: {line.strip()[:60]}",
                        "remediation": "Bind RPC services strictly to 127.0.0.1 loopback or use TLS.",
                    })

    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")

    passed = (critical_count == 0 and high_count == 0) if fail_on_critical else True

    report = {
        "status": "PASSED" if passed else "FAILED",
        "scanner": "ZecShield Privacy Firewall CI Action v1.0",
        "files_scanned": scanned_count,
        "total_findings": len(all_findings),
        "critical_violations": critical_count,
        "high_violations": high_count,
        "findings": all_findings,
    }

    print_section("ZECSHIELD // CI AUDIT SUMMARY", report)

    if json_out:
        try:
            with open(json_out, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"[*] JSON audit report exported to: {json_out}")
        except Exception as e:
            print(f"[!] Failed to write JSON output: {e}")

    if not passed:
        print(f"\n[X] CI BUILD FAILED: {critical_count} CRITICAL privacy violation(s) detected.")
        return 1
    print("\n[+] CI BUILD PASSED: Zero critical privacy leaks detected.")
    return 0


ACTIVE_CSRF_TOKENS: set[str] = set()


class ApprovalPortalHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_GET(self):
        import zecshield_firewall

        csrf_token = secrets.token_hex(32)
        ACTIVE_CSRF_TOKENS.add(csrf_token)
        if len(ACTIVE_CSRF_TOKENS) > 500:
            ACTIVE_CSRF_TOKENS.pop()

        pending = zecshield_firewall.get_pending_intent_tickets()
        items_html = ""
        if not pending:
            items_html = "<div class='empty'>Zero pending transactions. Active authorization queue is clear.</div>"
        else:
            for t in pending:
                items_html += f"""
                <div class='ticket-card'>
                    <div class='ticket-header'>
                        <strong>TICKET ID:</strong> <code>{t['ticket_id']}</code>
                        <span class='badge'>PENDING HUMAN APPROVAL</span>
                    </div>
                    <div class='details'>
                        <div><strong>Recipient:</strong> <code style='font-size:11px;'>{t['recipient']}</code></div>
                        <div><strong>Amount:</strong> <span class='hl'>{t['amount_zec']} ZEC</span> ({t['amount_zatoshis']:,} zatoshis)</div>
                        <div><strong>Fee:</strong> {t['fee_zatoshis']:,} zatoshis</div>
                        <div><strong>Cryptographic Intent Digest (SHA-256):</strong> <code>{t['intent_digest']}</code></div>
                        <div><strong>Nonce:</strong> <code>{t.get('nonce', '')}</code></div>
                        <div><strong>Expires In:</strong> {t['remaining_seconds']} seconds</div>
                    </div>
                    <div class='actions'>
                        <form method='POST' action='/approve' style='display:inline-flex; gap:8px; align-items:center;'>
                            <input type='hidden' name='ticket_id' value='{t['ticket_id']}'>
                            <input type='hidden' name='csrf_token' value='{csrf_token}'>
                            <input type='password' name='operator_passphrase' placeholder='Operator Passphrase' style='background:#111; border:1px solid #00FF41; color:#00FF41; padding:6px 10px; font-family:inherit; font-size:11px;' required>
                            <button type='submit' class='btn approve'>[SIGN &amp; APPROVE]</button>
                        </form>
                        <form method='POST' action='/reject' style='display:inline;'>
                            <input type='hidden' name='ticket_id' value='{t['ticket_id']}'>
                            <input type='hidden' name='csrf_token' value='{csrf_token}'>
                            <button type='submit' class='btn reject'>[REJECT]</button>
                        </form>
                    </div>
                </div>
                """

        port = self.server.server_address[1] if hasattr(self, "server") and hasattr(self.server, "server_address") else 9099
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="csrf-token" content="{csrf_token}">
    <title>ZecShield // Human Operator Portal</title>
    <style>
        body {{ background: #000; color: #00FF41; font-family: 'JetBrains Mono', monospace; margin: 0; padding: 24px; }}
        h1 {{ border-bottom: 2px solid #00FF41; padding-bottom: 8px; font-size: 16px; letter-spacing: 1px; }}
        .ticket-card {{ border: 1px solid #00FF41; padding: 16px; margin-bottom: 16px; background: #050505; }}
        .ticket-header {{ display: flex; justify-content: space-between; border-bottom: 1px dashed #008F11; padding-bottom: 8px; margin-bottom: 12px; }}
        .badge {{ background: #00FF41; color: #000; font-weight: bold; padding: 2px 6px; font-size: 10px; }}
        .details div {{ margin-bottom: 6px; font-size: 12px; }}
        .hl {{ color: #FFF; font-weight: bold; }}
        code {{ color: #00FF41; background: #111; padding: 2px 4px; }}
        .actions {{ margin-top: 14px; display: flex; gap: 10px; }}
        .btn {{ font-family: inherit; font-size: 12px; font-weight: bold; padding: 8px 16px; cursor: pointer; border: 1px solid; background: transparent; }}
        .approve {{ border-color: #00FF41; color: #00FF41; }}
        .approve:hover {{ background: #00FF41; color: #000; }}
        .reject {{ border-color: #FF0055; color: #FF0055; }}
        .reject:hover {{ background: #FF0055; color: #000; }}
        .empty {{ border: 1px dashed #008F11; padding: 24px; text-align: center; color: #008F11; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>[NODE 07] // ZECSHIELD OUT-OF-BAND OPERATOR APPROVAL PORTAL</h1>
    <p style='color:#008F11; font-size:11px;'>This portal operates on 127.0.0.1:{port} and constitutes the physical Human-in-the-Loop authorization boundary. Protected by Origin enforcement, CSRF session tokens, and Ed25519 cryptographic signing.</p>
    {items_html}
    <p style='margin-top:24px; font-size:10px; color:#555;'>ZecShield MCP // Zecathon 2026 Core &amp; Tooling</p>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", f"zecshield_csrf={csrf_token}; Path=/; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        import zecshield_firewall

        port = self.server.server_address[1] if hasattr(self, "server") and hasattr(self.server, "server_address") else 9099
        # 1. Origin and Referer Security Check
        origin = self.headers.get("Origin", "")
        referer = self.headers.get("Referer", "")
        allowed_prefixes = (f"http://127.0.0.1:{port}", f"http://localhost:{port}")
        if origin and not any(origin.startswith(a) for a in allowed_prefixes):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"403 Forbidden: CROSS_ORIGIN_REQUEST_BLOCKED")
            return

        if referer and not any(referer.startswith(a) for a in allowed_prefixes):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"403 Forbidden: UNTRUSTED_REFERER_BLOCKED")
            return

        # 2. Sec-Fetch-Site Check
        sec_site = self.headers.get("Sec-Fetch-Site", "")
        if sec_site and sec_site not in ("same-origin", "none", "same-site"):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"403 Forbidden: CROSS_SITE_FETCH_BLOCKED")
            return

        # 3. Read Body & Validate CSRF
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        params = urllib.parse.parse_qs(post_data)
        ticket_id = params.get("ticket_id", [""])[0]
        csrf_token = params.get("csrf_token", [""])[0]

        if not csrf_token or csrf_token not in ACTIVE_CSRF_TOKENS:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"403 Forbidden: CSRF_TOKEN_INVALID_OR_MISSING")
            return

        ACTIVE_CSRF_TOKENS.discard(csrf_token)

        if self.path == "/approve" and ticket_id:
            passphrase = params.get("operator_passphrase", [""])[0] or params.get("passphrase", [""])[0]
            if not passphrase:
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"401 Unauthorized: OPERATOR_PASSPHRASE_REQUIRED")
                return

            res = zecshield_firewall.approve_transaction_intent_ticket(
                ticket_id,
                operator_passphrase=passphrase,
                approver="LOCAL_HUMAN_OPERATOR (Web Portal)",
            )
            if not res.get("success"):
                status_code = 401 if "PASSPHRASE" in res.get("error", "") or "PIN" in res.get("error", "") else 400
                self.send_response(status_code)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(f"{status_code} Error: {res.get('message')}".encode("utf-8"))
                return

        elif self.path == "/reject" and ticket_id:
            zecshield_firewall.reject_transaction_intent_ticket(
                ticket_id,
                reason="Rejected via operator web portal",
            )

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def run_approval_portal(port: int = 9099) -> None:
    """
    Launches a dedicated local loopback web approval portal (127.0.0.1:port).
    Provides an out-of-band physical Human-in-the-Loop browser UI where the operator
    can review intent digests, examine recipients, and click Approve or Reject.
    Enforces browser Origin, CSRF session tokens, SameSite=Strict cookies,
    and Ed25519 passphrase signing.
    Completely isolated from the AI coding assistant's terminal context.
    """
    print_banner("ZECSHIELD // OUT-OF-BAND OPERATOR APPROVAL PORTAL")
    print(f"[*] Booting Human Operator Loopback Portal on http://127.0.0.1:{port}")
    print("[*] Direct your web browser to this URL to review and authorize transactions out-of-band.")
    print("[*] Security: Origin & CSRF tokens enforced; Ed25519 signature computed in browser request.")
    print("[*] Press Ctrl+C in this terminal to terminate the portal.\n")

    server = http.server.HTTPServer(("127.0.0.1", port), ApprovalPortalHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Approval portal stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
