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
import json
import sys
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
    p_gen_ua.add_argument("--include-ironwood", action="store_true", help="Include 2026 Ironwood shielded receiver")
    p_gen_ua.add_argument("--include-p2pkh", action="store_true", help="Include transparent P2PKH fallback")

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

    args = parser.parse_args()

    if args.command in (None, "demo"):
        run_full_demo()
    elif args.command == "reconcile":
        print_banner("AEGIS_Z_RECONCILER")
        print_section("AEGIS-Z // SHIELDED LEDGER RECONCILIATION", reconcile_shielded_ledger())
    elif args.command == "leak-audit":
        print_banner("ZECSHIELD_PRIVACY_AUDIT")
        print_section(
            "ZECSHIELD // PRIVACY LEAK AUDIT",
            detect_privacy_leaks(address=args.address, amount_zec=args.amount, memo_utf8=args.memo),
        )
    elif args.command == "validate-ua":
        print_banner(args.address)
        print_section("ZIP 316 // UNIFIED ADDRESS INSPECTION", validate_zip316_unified_address(args.address))
    elif args.command == "generate-ua":
        res = generate_zip316_unified_address(
            seed_identifier=args.seed,
            network=args.network,
            include_ironwood=args.include_ironwood,
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


if __name__ == "__main__":
    main()
