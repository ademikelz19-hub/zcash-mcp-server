"""
ZECATHON // LIVE MCP CLIENT-TO-SERVER VERIFICATION RUNNER
=========================================================
Executes the 3 ZECATHON verification prompts over the FastMCP protocol
(`fastmcp.Client(mcp)`) and prints the complete cryptographic verification results.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastmcp import Client
from cli import print_banner, print_section
from server import mcp


def _extract_json(tool_result: Any) -> Any:
    if hasattr(tool_result, "data") and tool_result.data is not None:
        return tool_result.data
    if hasattr(tool_result, "content") and tool_result.content:
        text = getattr(tool_result.content[0], "text", "")
        try:
            return json.loads(text)
        except Exception:
            return text
    return str(tool_result)


async def run_all_three_tests() -> None:
    print_banner("ZECATHON // MCP VERIFICATION SUITE")

    async with Client(mcp) as client:
        # -------------------------------------------------------------------
        # TEST 1: Address Validation & Generation
        # "Use your connected tools to generate a new ZIP 316 Unified Address.
        #  Then, validate that same address to confirm its receiver priority
        #  falls back properly from Orchard, to Sapling, to Transparent."
        # -------------------------------------------------------------------
        t1_gen_raw = await client.call_tool(
            "generate_zip316_unified_address",
            {
                "seed_identifier": "ZECATHON_TEST_1_UNIFIED_ADDRESS",
                "network": "mainnet",
                "include_orchard": True,
                "include_sapling": True,
                "include_transparent_p2pkh": True,
            },
        )
        t1_gen = _extract_json(t1_gen_raw)
        generated_ua = t1_gen["unified_address"]

        t1_val_raw = await client.call_tool(
            "validate_zip316_unified_address",
            {"address": generated_ua},
        )
        t1_val = _extract_json(t1_val_raw)

        print_section(
            "TEST 1 // ZIP 316 UNIFIED ADDRESS GENERATION & PRIORITY FALLBACK",
            {
                "step_1_generated_unified_address": generated_ua,
                "step_2_validation_result": {
                    "is_valid": t1_val["is_valid"],
                    "bech32m_verified": t1_val["bech32m_verified"],
                    "f4jumble_inverted": t1_val["f4jumble_inverted"],
                    "hrp_padding_verified": t1_val["hrp_padding_verified"],
                    "selected_priority_receiver": t1_val["selected_priority_receiver"],
                    "fallback_order_summary": t1_val["fallback_order_summary"],
                    "receiver_priority_fallback_chain": t1_val["receiver_priority_fallback_chain"],
                },
            },
        )

        # -------------------------------------------------------------------
        # TEST 2: Parsing the Viewing Key
        # "Use the parse_zip316_ufvk tool to parse a test Zcash Unified Full
        #  Viewing Key (UFVK). Tell me what types of receivers are bundled
        #  inside it and confirm that you cannot access the spending keys."
        # -------------------------------------------------------------------
        t2_ufvk_raw = await client.call_tool(
            "parse_zip316_ufvk",
            {"ufvk": "test"},
        )
        t2_ufvk = _extract_json(t2_ufvk_raw)

        print_section(
            "TEST 2 // ZIP 316 UFVK PARSING & SPENDING KEY ISOLATION",
            t2_ufvk,
        )

        # -------------------------------------------------------------------
        # TEST 3: Generating the Payment URI
        # "I need to pay someone 50 ZEC. Use the generate_zip321_uri tool to
        #  construct a ZIP 321 payment request URI. Include an encrypted memo
        #  that says 'Hackathon test payment' and provide the final string."
        # -------------------------------------------------------------------
        t3_uri_raw = await client.call_tool(
            "generate_zip321_uri",
            {
                "address": generated_ua,
                "amount_zec": "50",
                "memo_utf8": "Hackathon test payment",
            },
        )
        t3_uri = _extract_json(t3_uri_raw)

        print_section(
            "TEST 3 // ZIP 321 PAYMENT REQUEST URI (50 ZEC + ENCRYPTED MEMO)",
            t3_uri,
        )

        # Also generate ISO/IEC 18004 QR matrices for Test 3 and the Aegis-Z Batch
        t3_qr_raw = await client.call_tool("render_zip321_qr", {"uri": t3_uri["uri"]})
        t3_qr = _extract_json(t3_qr_raw)

        rec_raw = await client.call_tool("reconcile_shielded_ledger", {})
        rec = _extract_json(rec_raw)
        batch_uri = rec["zip321_disbursement_batch"]["uri"]
        batch_qr_raw = await client.call_tool("render_zip321_qr", {"uri": batch_uri})
        batch_qr = _extract_json(batch_qr_raw)

        with open("assets/qr_matrices.js", "w", encoding="utf-8") as f:
            f.write(
                "window.REAL_ISO18004_MATRICES = "
                + json.dumps(
                    {
                        "test3_uri": t3_uri["uri"],
                        "test3_matrix": t3_qr["matrix"],
                        "batch_uri": batch_uri,
                        "batch_matrix": batch_qr["matrix"],
                    }
                )
                + ";\n"
            )

        print_section(
            "TEST 4 // ISO/IEC 18004 REED-SOLOMON QR CODE GENERATION (ZASHI / YWALLET)",
            {
                "test3_50zec_qr": t3_qr["qr_code"],
                "aegis_batch_qr_dimension": batch_qr["qr_code"]["matrix_dimension"],
                "saved_svg_path": t3_qr["saved_svg_path"],
                "exported_dashboard_js": "assets/qr_matrices.js",
            },
        )

        # -------------------------------------------------------------------
        # TEST 5: Privacy Leak Detection & Vulnerability Analysis
        # -------------------------------------------------------------------
        leak_check_raw = await client.call_tool(
            "detect_privacy_leaks",
            {
                "address": generated_ua,
                "amount_zec": "50",
                "memo_utf8": "Hackathon test payment",
            },
        )
        leak_check = _extract_json(leak_check_raw)

        print_section(
            "TEST 5 // ZECSHIELD PRIVACY LEAK DETECTION & AUDIT",
            leak_check,
        )


if __name__ == "__main__":
    asyncio.run(run_all_three_tests())


