# ![NODE 07](./assets/node07_identity_26x26.svg) `ZECSHIELD // ZCASH MCP STANDARD LIBRARY & PROJECT AEGIS-Z`

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│ [NODE 07 ONLINE] // THE PYRAMID WAKES // ZECATHON INFRASTRUCTURE & AEGIS-Z  │
│ SERVER: Zcash_MCP_Server (FastMCP stdio) // POSITIONING: ZECSHIELD MCP       │
│ STANDARDS: ZIP 316 CANONICAL // ZIP 326 (IRONWOOD) // ZIP 321 // ZIP 317    │
│ SECURITY: FAIL-CLOSED // AIR-GAP STRICT LOOPBACK // REGTEST READY            │
│ AESTHETIC: #000000 BLACK // JETBRAINS MONO // #00FF41 PHOSPHOR // 26x26 ID  │
└──────────────────────────────────────────────────────────────────────────────┘
```

> **ZECATHON $15,000 Core & Tooling Track Submission**  
> **Positioning:** AI-Native Zcash Development, Testing, and Privacy Protection ("ZecShield MCP"). Build Zcash applications with AI, test shielded transactions locally, and catch privacy mistakes before deployment.  
> **Execution Guarantee:** 100% Local Stdio / Loopback Execution (`127.0.0.1`). Zero private keys, viewing keys, or decrypted memos ever leak to cloud hosts or external endpoints.

---

## 00 // ARCHITECTURAL BLUEPRINT

The **ZecShield MCP Server** (`Zcash_MCP_Server`) bridges autonomous local AI agents (orchestrated via the **Google Antigravity SDK** `LiteRTAgentConfig` + `McpStdioServer`) with Zcash's core zero-knowledge cryptographic primitives, live local node infrastructure (`zebrad` & `lightwalletd`), and proactive privacy defense tooling.

```mermaid
flowchart LR
    subgraph LocalWorkstation["AIR-GAPPED WORKSTATION (#000000 // NO CLOUD TELEMETRY)"]
        Agent["Google Antigravity SDK\nLiteRTAgentConfig (Gemma 4 26B)"]
        MCP["Zcash_MCP_Server (server.py)\nFastMCP over Local STDIO"]
        Router["ZIP 326 Pool Router\nroute_shielded_pool\n(Ironwood / Orchard / Sapling)"]
        LeakGuard["ZecShield Privacy Guard\ndetect_privacy_leaks\n(Catches PII, Transparent Leaks, Fees)"]
        Crypto["Cryptographic Engine\nZIP 316 (Bech32m + F4Jumble)\nZIP 321 (512B Memo URIs)\nZIP 317 (Proportional Fees)"]
        Node["Live Local Node / Regtest Anchor\nzebrad (127.0.0.1:8232)\nlightwalletd (127.0.0.1:9067)\n+ Built-in Regtest Daemon"]
        Dashboard["Brutalist Terminal UI\ndashboard.html + cli.py\n(ISO 18004 QR Matrix Handoff)"]
    end

    Wallet["Air-Gapped Mobile Signer\n(Zashi / YWallet)"]

    Agent <-->|"JSON-RPC 2.0 (stdio)"| MCP
    MCP --> Router
    MCP --> LeakGuard
    MCP --> Crypto
    MCP <-->|"Loopback RPC / Trial Decryption"| Node
    MCP --> Dashboard
    Dashboard -.->|"Visual ISO 18004 QR Scan (No Spending Keys on Host)"| Wallet
```

---

## 01 // PROTOCOL HARDENING & SPECIFICATION ALIGNMENT

1. **Canonical ZIP 316 Receiver Registry & ZIP 326 Ironwood Pool Routing:**
   - Adheres strictly to the canonical [ZIP 316](https://zips.z.cash/zip-0316) receiver typecode specification:
     - `0x00`: Transparent P2PKH (20 bytes)
     - `0x01`: Transparent P2SH (20 bytes)
     - `0x02`: Sapling (43 bytes)
     - `0x03`: Orchard (43 bytes)
   - Canonical ZIP 316 receiver fallback order:
     $$\textbf{ORCHARD (0x03)} \rightarrow \textbf{SAPLING (0x02)} \rightarrow \textbf{P2SH (0x01)} \rightarrow \textbf{P2PKH (0x00)}$$
   - **ZIP 326 Ironwood Compliance:** Per [ZIP 326](https://zips.z.cash/zip-0326), the 2026 Ironwood shielded pool shares the Orchard-protocol receiver (`0x03`) and incoming viewing key format. Standard Zcash wallets reject non-standard receiver typecodes; therefore, pool selection is implemented in the wallet/transaction builder via `route_shielded_pool(address, target_pool="ironwood")`, directing transaction construction to the Ironwood action bundle while maintaining 100% address compatibility with Zashi, YWallet, and Zebra.
   - ZIP 317 logical action accounting includes `ironwood_actions`.

2. **Proactive Privacy Leak Detection (`detect_privacy_leaks`):**
   - Pre-broadcast audit engine scanning transaction plans and payment URIs:
     - **Transparent Address Fallback:** Flags P2PKH/P2SH exposure destroying zero-knowledge anonymity.
     - **Cleartext PII in Memos:** Flags emails, IPv4 addresses, phone numbers, and corporate IDs.
     - **Amount Precision Fingerprinting:** Flags odd 8-decimal totals correlatable with off-chain merchant logs.
     - **Fee Fingerprinting:** Flags non-standard fees deviating from ZIP 317 marginal rate multiples (5000 zatoshis).
     - **Address Reuse:** Flags transparent address reuse across batch payouts.
   - Emits a standardized `0-100` privacy score and `is_safe_to_broadcast` approval gate.

3. **Strict Fail-Closed Security (Zero Silent Defaults):**
   - Prohibits silent substitution of default treasury addresses in payment requests (`generate_zip321_uri` strictly requires an explicit destination address).
   - Prohibits silent substitution of demonstration viewing keys (`parse_zip316_ufvk` requires an explicit key string or explicit `use_demo_fixture=True`).
   - Automatically rejects encrypted memos attached to transparent-only receivers.

4. **Zero-Knowledge AI Host Memo Redaction:**
   - Complete scrubbing of sensitive 512-byte memo payloads (`[REDACTED_BY_ZECSHIELD_FOR_AI_PRIVACY]`) when queried by AI hosts (`fetch_shielded_history`, `read_memo_contents`).
   - Scrubs invoice references, vendor names, and cryptographic hashes to prevent correlation across AI model context windows.

5. **Live Regtest Blockchain Workflow & Provenance Transparency:**
   - Every RPC and query response explicitly tags provenance: `PROVENANCE: LIVE_NODE_RPC` (when connected to live local node) vs `PROVENANCE: DEMO_FIXTURE` (offline deterministic cryptographic vault).
   - Includes a built-in local JSON-RPC regtest harness (`python live_node_client.py --regtest-demo`) that broadcasts authentic shielded transactions, mines regtest blocks, verifies on-chain confirmations, and reconciles balances.

6. **Independent Standards Reference Vector Test Suite:**
   - 35 passing tests including BIP 350 Bech32m canonical vectors, RFC 4648 unpadded base64url memo vectors, ZIP 317 proportional fee vectors, and F4Jumble Feistel invertibility bounds.

---

## 02 // EXPOSED `@mcp.tool` STANDARD LIBRARY REGISTRY

| Tool Name | Input Parameters | Description |
| :--- | :--- | :--- |
| `route_shielded_pool` | `address: str, target_pool: str = "auto"` | **ZIP 326 Router:** Resolves destination pool (`ironwood`, `orchard`, `sapling`, `auto`) using standard Orchard (0x03) and Sapling (0x02) receivers. |
| `detect_privacy_leaks` | `address: str, amount_zec: str, memo_utf8: str, fee_zatoshis: Optional[int], recipients: Optional[List]` | **ZecShield Security Guard:** Scans for transparent fallback, cleartext PII in memos, amount precision fingerprinting, fee anomalies, and address reuse. |
| `validate_zip316_unified_address` | `address: str` | Verifies Bech32m checksum (`0x2bc830a3`), inverts `F4Jumble`, validates 16-byte HRP padding, extracts TLVs, and returns canonical Orchard -> Sapling -> Transparent priority. |
| `generate_zip316_unified_address` | `seed_identifier: str, network: str = "mainnet", include_orchard: bool = True, include_sapling: bool = True, include_transparent_p2pkh: bool = True` | Constructs a valid ZIP 316 Unified Address with ascending CompactSize TLVs + `F4Jumble` + Bech32m. Native ZIP 326 Ironwood compatibility via Orchard receiver. |
| `parse_zip316_ufvk` | `ufvk: str, use_demo_fixture: bool = False` | Parses a ZIP 316 Unified Full Viewing Key (`uview1...`), isolating Orchard/Sapling viewing keys without exposing spending keys. Fails closed if input is missing. |
| `generate_zip321_uri` | `address: str, amount_zec: str, memo_utf8: str = "", label: str = "", message: str = "", require_shielded: bool = False` | Generates a single-recipient ZIP 321 URI with unpadded `base64url` memo and ZIP 317 fee calculation. Prohibits silent recipient substitution. |
| `construct_zip321_payout_batch` | `payments: List[Dict[str, str]]` | Builds a multi-recipient ZIP 321 batch URI for payroll/treasury settlements and computes batch fee savings. |
| `parse_zip321_uri` | `uri: str` | Parses and validates single- or multi-recipient ZIP 321 URIs and decodes all `base64url` memos back to UTF-8 and hex. |
| `estimate_zip317_fee` | `ironwood_actions: int = 0, orchard_actions: int = 2, sapling_spends: int = 0, sapling_outputs: int = 0, transparent_inputs: int = 0, transparent_outputs: int = 0` | Computes exact ZIP 317 conventional fees in zatoshis and ZEC. |
| `render_zip321_qr` | `uri: str, output_path: str = "assets/latest_zip321_qr.svg"` | Generates genuine ISO/IEC 18004 Reed-Solomon QR codes scannable by mobile shielded signers (Zashi, YWallet). |
| `fetch_shielded_history` | `ufvk: str, pool_filter: str = "all", direction_filter: str = "all", redact_sensitive_memos: bool = True` | Queries local `lightwalletd`/`zebrad` loopback for decrypted transactions, with AI memo redaction active by default. |
| `read_memo_contents` | `txid: str = "", redact_for_ai: bool = False` | Extracts 512-byte decrypted memos, invoice IDs, and Chart of Accounts mappings. Scrubs metadata when `redact_for_ai=True`. |
| `execute_trial_decryption` | `start_height: int, end_height: int, ufvk: str` | Runs trial decryption across compact block ranges for Orchard (Halo 2) and Sapling commitment trees. |
| `query_lightwalletd` | `endpoint: str = "GetLightdInfo", block_height: int = 2690500` | Queries local `lightwalletd` endpoints with explicit data provenance tracking (`LIVE_NODE_RPC` vs `DEMO_FIXTURE`). |
| `query_zebrad_rpc` | `method: str = "getblockchaininfo", params: Optional[List[Any]] = None` | Calls local `zebrad` JSON-RPC methods with loopback security and provenance disclosure. |
| `reconcile_shielded_ledger` | `ufvk: str` | **Project Aegis-Z Controller:** Reconciles decrypted UFVK memos against pending corporate obligations and emits a ready-to-sign ZIP 321 batch URI. |

---

## 03 // QUICKSTART & VERIFICATION

### 1. Run the Complete Verification Suite
```powershell
# Run the hackathon verification suite over the FastMCP client protocol
python run_verification_tests.py
```

### 2. Run All 35 Unit & Reference Vector Tests
```powershell
python -m pytest -v
```

### 3. Execute Authentic Live Regtest Workflow (`LIVE_NODE_RPC`)
```powershell
# Boots local regtest node on 127.0.0.1:8232, broadcasts transaction, mines block, confirms, and reconciles
python live_node_client.py --regtest-demo
```

### 4. Run the Brutalist Terminal CLI Demo
```powershell
# Full 6-stage demo (Aegis-Z accounting + ZecShield privacy audit)
python cli.py demo

# Route a payment to Ironwood per ZIP 326
python cli.py route-pool --target-pool ironwood

# Audit an individual payment request for privacy leaks
python cli.py leak-audit --address "t1VpYecBW4UudbGcy4ufh61eWxQCoFaUrPs" --memo "Payment to alice@cypherpunk.org"
```

### 5. Interactive Dark-Terminal Dashboard
Open [`dashboard.html`](./dashboard.html) in any local browser to inspect:
- Deterministic **26x26 pixel block identities** rendered on `<canvas width="26" height="26">`
- Decrypted Orchard (Halo 2) & Sapling 512-byte memos mapped to the Aegis-Z Chart of Accounts
- Interactive **ZIP 316 F4Jumble + Bech32m** receiver inspector
- Air-gapped **ZIP 321 Multi-Recipient Payment Request URI & ISO 18004 QR Matrix** generator with mobile scanner polarity toggle for Zashi / YWallet.
