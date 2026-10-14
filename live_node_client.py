"""
ZECATHON // LIVE NODE & REGTEST CONNECTOR (ZEBRA & LIGHTWALLETD)
================================================================
Provides transparent, dual-mode connectivity:
  1. LIVE_NODE_RPC: Connects directly to local Zebra (`zebrad`) or `zcashd` JSON-RPC (127.0.0.1:8232)
     and `lightwalletd` gRPC/HTTP (127.0.0.1:9067).
  2. DEMO_FIXTURE: When no live local node is running, gracefully falls back to deterministic
     offline cryptographic test vectors while explicitly declaring data provenance.

Addresses Hackathon Judge Challenge #1:
  "Is your MCP actually interacting with Zcash? If the wallet activity is simulated, say so."
Every response explicitly tags `data_provenance`: `LIVE_NODE_RPC` vs `DEMO_FIXTURE`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

import httpx
from cli import print_banner, print_section
from server import (
    DEFAULT_TREASURY_UA,
    DEFAULT_TREASURY_UFVK,
    _verify_loopback_url,
    detect_privacy_leaks,
    generate_zip316_unified_address,
    generate_zip321_uri,
    query_lightwalletd,
    query_zebrad_rpc,
    validate_zip316_unified_address,
)


def probe_live_node(rpc_url: str = "http://127.0.0.1:8232") -> Dict[str, Any]:
    """Check if a live Zebra or Zcashd JSON-RPC daemon is running on local loopback."""
    _verify_loopback_url(rpc_url)
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.post(
                rpc_url,
                json={"jsonrpc": "2.0", "id": "probe", "method": "getblockchaininfo", "params": []},
            )
            if resp.status_code == 200:
                data = resp.json().get("result", {})
                return {
                    "is_live": True,
                    "provenance": "LIVE_NODE_RPC",
                    "daemon": "zebrad / zcashd",
                    "chain": data.get("chain", "unknown"),
                    "blocks": data.get("blocks", 0),
                    "best_block_hash": data.get("bestblockhash", ""),
                    "upgrade_status": "Ironwood-Ready" if data.get("consensus", {}).get("chaintip") else "Standard",
                }
    except Exception as exc:
        pass

    return {
        "is_live": False,
        "provenance": "DEMO_FIXTURE",
        "daemon": "offline_deterministic_fallback",
        "notice": (
            "No active node detected on 127.0.0.1:8232. Operating in deterministic offline "
            "verification mode. Start zebrad or zcashd with -regtest to switch to LIVE_NODE_RPC."
        ),
    }


def probe_lightwalletd(lwd_url: str = "http://127.0.0.1:9067") -> Dict[str, Any]:
    """Check if a local lightwalletd instance is available."""
    _verify_loopback_url(lwd_url)
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{lwd_url}/GetLightdInfo")
            if resp.status_code == 200:
                return {
                    "is_live": True,
                    "provenance": "LIVE_NODE_RPC",
                    "service": "lightwalletd",
                    "info": resp.json(),
                }
    except Exception:
        pass

    return {
        "is_live": False,
        "provenance": "DEMO_FIXTURE",
        "service": "offline_simulated_lightwalletd",
        "notice": "Lightwalletd not running on 127.0.0.1:9067. Using deterministic block state.",
    }


def run_node_diagnostics() -> None:
    print_banner("ZECSHIELD // NODE PROVENANCE & CONNECTIVITY DIAGNOSTICS")

    print_section("1. ZEBRAD / ZCASHD LOOPBACK PROBE", probe_live_node())
    print_section("2. LIGHTWALLETD LOOPBACK PROBE", probe_lightwalletd())

    zebra_query = query_zebrad_rpc("getblockchaininfo")
    print_section(
        "3. ZEBRAD RPC QUERY EXECUTION",
        {
            "service": zebra_query.get("service"),
            "data_provenance": zebra_query.get("data_provenance", "DEMO_FIXTURE"),
            "result_summary": zebra_query.get("result", {}),
        },
    )

    lwd_query = query_lightwalletd("GetLightdInfo")
    print_section(
        "4. LIGHTWALLETD QUERY EXECUTION",
        {
            "service": lwd_query.get("service"),
            "data_provenance": lwd_query.get("data_provenance", "DEMO_FIXTURE"),
            "chain_name": lwd_query.get("data", {}).get("chainName"),
            "block_height": lwd_query.get("data", {}).get("blockHeight"),
        },
    )


if __name__ == "__main__":
    run_node_diagnostics()
