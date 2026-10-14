# ZecShield MCP: Zcash Foundation Z3 Integration Guide

This guide describes how to run the official **Zcash Foundation Z3 Development Stack** with ZecShield MCP for authentic, verifiable shielded transactions on a local regtest network.

---

## Architecture Overview

```
 ┌──────────────────────────────────────────────────────────────┐
 │                      AI Client / Host                        │
 │           (Antigravity / Claude Desktop / Cursor)            │
 └──────────────────────────────┬───────────────────────────────┘
                                │ JSON-RPC 2.0 (FastMCP stdio)
                                ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                        ZecShield MCP                         │
 │     [Privacy Firewall] ── [ZIP 316/321/317 Engine]           │
 │                                                              │
 │  Honest Provenance Dispatcher:                               │
 │   - GENUINE_Z3_REGTEST    (Port 8181 / 29232 / 50232)        │
 │   - SIMULATED_MOCK_REGTEST (Port 8232 test mock)             │
 │   - DEMO_FIXTURE           (Deterministic offline vault)     │
 └──────────────────────────────┬───────────────────────────────┘
                                │ HTTP Loopback (127.0.0.1)
                                ▼
 ┌──────────────────────────────────────────────────────────────┐
 │              Official Zcash Foundation Z3 Stack              │
 │                                                              │
 │  ┌───────────────────────┐      ┌─────────────────────────┐  │
 │  │      Z3 RPC Router    │◄────►│      Zallet Wallet      │  │
 │  │   (127.0.0.1:8181)    │      │    (127.0.0.1:50232)    │  │
 │  └───────────┬───────────┘      └────────────┬────────────┘  │
 │              │                               │               │
 │              ▼                               ▼               │
 │  ┌────────────────────────────────────────────────────────┐  │
 │  │                    Zebra Full Node                     │  │
 │  │                   (127.0.0.1:29232)                    │  │
 │  └────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────────┘
```

---

## 1. Prerequisites

### Linux / macOS
- Docker Engine >= 24.0
- Docker Compose v2

### Windows
- Docker Desktop with **WSL 2 Backend** enabled.
- Alternatively, native Linux running inside WSL 2 (Ubuntu 22.04+).

---

## 2. Launching the Official Z3 Stack

From the root of the `zechathon` repository:

```bash
# 1. Start Zebra, Zallet, and the Z3 RPC Router in the background
docker compose up -d

# 2. Check container status
docker compose ps

# 3. Verify Zebra node health on regtest
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8181
```

Expected response contains:
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "chain": "regtest",
    "blocks": 1,
    "consensus": {
      "chaintip": "c2d6d0b4"
    }
  }
}
```

---

## 3. Provenance Modes in ZecShield

ZecShield enforces **strict cryptographic honesty**. Every response returned by ZecShield includes a `provenance` tag:

| Provenance Tag | Meaning | When Used |
|---|---|---|
| `GENUINE_Z3_REGTEST` | Verified connection to authentic Z3 router (8181) or Zallet (50232). Cryptographic proofs and transactions are constructed by official Zcash Foundation software. | Docker Z3 stack is active. |
| `GENUINE_ZEBRA_NODE` | Verified connection to native Zebra full node (29232 or 8232). | Standalone Zebra is running. |
| `SIMULATED_MOCK_REGTEST` | Local Python test mock listening on 127.0.0.1:8232. Used for fast offline test suites when Docker is not installed. | Launched with `python live_node_client.py --regtest-demo` without Docker. |
| `DEMO_FIXTURE` | Fully offline, deterministic cryptographic test vector vault. No sockets or services needed. | Default fallback when no network endpoints are reachable. |

---

## 4. End-to-End Regtest Payment Workflow

When running against the genuine Z3 stack:
1. **Address Generation:** Use `generate_zip316_unified_address` to create a recipient UA with Orchard, Sapling, and Transparent receivers.
2. **ZIP 321 Payment URI:** Construct a standard payment URI with an encrypted memo.
3. **Privacy Pre-Flight Audit:** Pass the transaction through `detect_privacy_leaks` to confirm zero PII, zero transparent fallback, and accurate ZIP 317 fee calculation.
4. **Broadcast via Zallet:** Send the transaction via the Z3 router (`sendrawtransaction`).
5. **Mine Confirmation Block:** Generate 1 regtest block on Zebra to confirm the shielded note.
6. **Reconciliation:** Query confirmed shielded balances via `reconcile_shielded_ledger`.

---

## 5. Offline Fallback & Mock Harness

If Docker or WSL2 is not installed on the host machine:
- ZecShield automatically detects the absence of Docker and falls back safely to `DEMO_FIXTURE` or `SIMULATED_MOCK_REGTEST`.
- It **never** fabricates a transaction ID and claims it was mined by Zebra consensus.
- All test vectors and cryptographic rules (Bech32m, F4Jumble, ZIP 321, ZIP 317) execute with 100% mathematical fidelity offline.
