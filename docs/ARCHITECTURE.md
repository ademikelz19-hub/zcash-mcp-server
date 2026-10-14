# ZecShield MCP: Architecture & Technical Design

## 1. System Architecture

```
 +-------------------------------------------------------------------------+
 |                               AI HOST                                   |
 |              Claude Desktop / Antigravity / Cursor / Custom Agent       |
 +------------------------------------+------------------------------------+
                                      | JSON-RPC 2.0 (FastMCP stdio)
                                      v
 +-------------------------------------------------------------------------+
 |                              ZECSHIELD MCP                              |
 |                                                                         |
 |  +-------------------------------------------------------------------+  |
 |  |                     ZecShield Privacy Firewall                    |  |
 |  |  - CHECK 01: Transparent Exposure       CHECK 06: RPC Air-Gap     |  |
 |  |  - CHECK 02: Privacy Downgrade          CHECK 07: UA Validation   |  |
 |  |  - CHECK 03: Cleartext PII Memo         CHECK 08: Exact Zatoshis  |  |
 |  |  - CHECK 04: Viewing Key Leak           CHECK 09: Human Approval  |  |
 |  |  - CHECK 05: Spending Key Leak          CHECK 10: Correlation ID  |  |
 |  +-------------------------------------------------------------------+  |
 |                                                                         |
 |  +-----------------------------------+ +-----------------------------+  |
 |  |      Zcash Standards Engine       | |   AI Safe Security Boundary |  |
 |  |  - ZIP 316: Bech32m + F4Jumble    | |  - Zero spending key leak   |  |
 |  |  - ZIP 321: Base64URL Memos       | |  - AI Memo Redaction        |  |
 |  |  - ZIP 317: Proportional Fees     | |  - Out-of-band approval     |  |
 |  |  - ZIP 326: Ironwood Pool Routing | |  - Mainnet spend lock       |  |
 |  +-----------------------------------+ +-----------------------------+  |
 |                                                                         |
 |  +-------------------------------------------------------------------+  |
 |  |                     Honest Provenance Dispatcher                  |  |
 |  +-------------------------------------------------------------------+  |
 +-------------------+------------------------+--------------------+-------+
                     |                        |                    |
                     v (Port 8181/29232/50232)| (Port 8232)        v (Offline)
 +-----------------------------+  +-----------+-----------+  +-------------+
 | Official Z3 Regtest Stack   |  | Simulated Regtest     |  | Determin-   |
 |  - Zebra Full Node (Rust)   |  | In-Memory Test Server |  | istic       |
 |  - Zallet Wallet (Rust)     |  | (Mock Consensus)      |  | Test Vector |
 |  - Z3 JSON-RPC Router       |  | [SIMULATED_MOCK_      |  | Vault       |
 |  [GENUINE_Z3_REGTEST]       |  |  REGTEST]             |  | [DEMO_      |
 +-----------------------------+  +-----------------------+  |  FIXTURE]   |
                                                             +-------------+
```

---

## 2. Component Directory

### `server.py`
The foundational FastMCP stdio server exposing 14 cryptographically verified tools:
- **Developer Utilities:** `validate_zip316_unified_address`, `generate_zip316_unified_address`, `parse_zip316_ufvk`, `generate_zip321_uri`, `parse_zip321_uri`, `construct_zip321_payout_batch`, `estimate_zip317_fee`, `route_shielded_pool`, `render_zip321_qr`.
- **Privacy & Security:** `detect_privacy_leaks`, `audit_transaction_privacy`, `explain_privacy_violation`, `sanitize_ai_memo`.
- **Infrastructure:** `check_z3_infrastructure`, `query_zebrad_rpc`, `query_lightwalletd`, `fetch_shielded_history`, `reconcile_shielded_ledger`.

### `zecshield_firewall.py`
The core Privacy Firewall evaluation engine. Contains compiled regular expressions, BIP-39 mnemonic wordlists, satoshi precision validators, and loopback air-gap policy validators. Produces standardized machine-readable audit reports.

### `live_node_client.py`
Dual-mode node client that connects to the official Zcash Foundation Z3 stack when running, probes ports, checks host Docker/WSL2 prerequisites, and provides an offline in-memory test harness explicitly labeled `SIMULATED_MOCK_REGTEST`.

### `cli.py`
Brutalist terminal command-line interface featuring pure black (`#000000`), phosphor green (`#00FF41`), JetBrains Mono typography, and BLAKE2b-derived 26x26 pixel block identities. Includes `audit-ci` for CI/CD pipelines.

### `docker-compose.yml` & `config/zebrad.toml`
Turnkey deployment configuration for the official Zcash Foundation Z3 regtest stack (Zebra node, Zallet wallet, and Z3 RPC router) with Ironwood (ZIP 326) activated from block 1.

---

## 3. Communication Model

All communication between the AI assistant and ZecShield occurs strictly over **local stdio JSON-RPC 2.0**.
No network sockets are opened to the internet, and no analytics or telemetry are transmitted.
All outbound node calls are restricted to loopback (`127.0.0.1`, `localhost`, `::1`), guaranteeing that ZecShield "does not leak".
