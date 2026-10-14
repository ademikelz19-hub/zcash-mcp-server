# ZecShield MCP: Technical Audit & Repository Assessment
**Competition:** zkSNARKs ZECATHON 2026 | **Track:** Core & Tooling ($15,000)  
**Date:** October 2026 | **Audit Target:** `ademikelz19-hub/zcash-mcp-server`  
**Auditor:** Protocol Engineering & Security Review Team  

---

## Executive Summary

ZecShield MCP is an AI-native developer infrastructure toolkit designed to allow developers and LLM coding assistants to build, test, inspect, and protect Zcash applications without introducing accidental privacy leaks.

This audit evaluates the codebase across 10 critical technical criteria, distinguishing functional implementations from simulations, identifying security boundaries, and defining the path toward world-class hackathon readiness.

---

## 1. Feature-by-Feature Audit (10 Evaluation Criteria)

| Category | Component / Feature | Current Implementation Status | Provenance & Reality Level | Severity / Risk | Required Remediation |
|---|---|---|---|---|---|
| **1. Functional Features** | ZIP 316 Unified Addresses (Bech32m + F4Jumble + TLV) | Fully functional in `server.py`. Passes BIP 350 Bech32m vectors, 4-round BLAKE2b Feistel invertibility tests. | Real cryptographic implementation | None (Low risk) | Maintain existing tested logic. Cross-verify against external vectors. |
| **1. Functional Features** | ZIP 321 Payment Requests & unpadded RFC 4648 base64url memos | Fully functional. Enforces 512-byte limit, rejects memos on transparent addresses, parses multi-payment batches. | Real specification implementation | None (Low risk) | Preserve. Expand parameter validation. |
| **1. Functional Features** | ZIP 317 Fee Calculation | Fully functional. 5000 zatoshis marginal fee, 2 grace actions, P2PKH/Orchard/Sapling/Ironwood logical actions. | Real mathematical implementation | None (Low risk) | Verify action counting against NU6.3 rules. |
| **2. Simulated Features Presented as Live** | Local Regtest Daemon (`live_node_client.py:RegtestRPCServer`) | Built-in Python `BaseHTTPRequestHandler` listening on `127.0.0.1:8232`. Fabricated txids via double-SHA256, mocked block generation. | **SIMULATION** (Mislabeled as `PROVENANCE: LIVE_NODE_RPC`) | **CRITICAL** | Formally re-label as `SIMULATED_MOCK_REGTEST`. Provide official Z3 Docker stack integration (`zebrad:29232`, `zallet:50232`, router `8181`). Never claim synthetic Python blocks are real consensus. |
| **3. Protocol Behavior** | ZIP 326 Ironwood Pool Support & Receiver Selection | Corrected from invalid `0x04` typecode. Now uses Orchard receiver `0x03` and wallet-level pool routing (`route_shielded_pool`). | Real protocol specification compliance | Moderate | Ensure clear distinction between receiver types (ZIP 316) and transaction action bundles (ZIP 326). |
| **4. Metadata vs. Real Operations** | Shielded Ledger & History (`fetch_shielded_history`, `execute_trial_decryption`) | Scans static in-memory lists rather than trial-decrypting compact blocks via Halo 2 / Jubjub. | Simulated / Deterministic Test Vault | Moderate | Explicitly tag data provenance as `DEMO_FIXTURE` or `OFFLINE_TEST_VAULT`. |
| **5. Sensitive Info in MCP Responses** | AI Host Memo Redaction | Successfully redacts memo text to `[REDACTED_BY_ZECSHIELD_FOR_AI_PRIVACY]`. | Secure | Low | Prevent invoice ID correlation leaks. Audit all tools to ensure spending keys (`secret-extended-key...`) never leak into tool results. |
| **6. Cryptographic Primitives** | Manual `F4Jumble` & `Bech32m` | Manual implementations in Python using `hashlib.blake2b`. | Functional, passes unit tests | Low | Retain Python implementation for air-gapped portability, but rigorously test boundary conditions and edge cases. |
| **7. Test Assertions** | Test Suite Coverage | 35 passing pytest tests (unit + reference vectors). | Good baseline | Moderate | Add adversarial test layer (prompt injection, malicious payloads, corrupted addresses, simulated network faults). |
| **8. Architecture & Complexity** | FastMCP Server Architecture | FastMCP decorator style with air-gapped fallback class. | Clean & decoupled | Low | Categorize tools into Developer Utilities, Privacy Firewall, Blockchain Integration, and CI Automation. |
| **9. Competitive Differentiation** | Comparison with Wallet MCPs | Existing wallet MCPs help agents *spend* ZEC. ZecShield provides *developer infrastructure* to test and secure apps. | Distinctive positioning | High Value | Anchor product identity on the **Privacy Firewall** and CI testing. |
| **10. Strongest Unique Contribution** | **ZecShield Privacy Firewall** | Pre-flight inspection blocking transparent fallbacks, cleartext PII, viewing key leaks, and precision bugs before broadcast. | Signature Innovation | Maximum Value | Formalize with standard JSON schema, adversarial test suite, and GitHub Action CI workflow. |

---

## 2. Deep Dive: Live Blockchain vs. Simulation

### The Issue
`live_node_client.py` contained an embedded HTTP server that listened on `http://127.0.0.1:8232` and responded to standard Zcash JSON-RPC methods (`getblockchaininfo`, `sendrawtransaction`, `generate`, `z_viewtransaction`).
While this was intended as an offline test harness, presenting its outputs as `PROVENANCE: LIVE_NODE_RPC` creates a misleading claim that a real Zcash node was executing cryptographic proofs.

### The Remediation
1. **Clear Provenance Taxonomy:**
   - `GENUINE_Z3_REGTEST`: Authentic connection to the Zcash Foundation Z3 stack (`zebrad`, `zallet`, and RPC router).
   - `GENUINE_ZEBRA_NODE`: Authentic connection to a standalone Zebra full node.
   - `SIMULATED_MOCK_REGTEST`: The local Python mock harness, strictly labeled as a mock for development and testing when Docker is unavailable.
   - `DEMO_FIXTURE`: Deterministic offline test fixtures.
2. **Fail-Closed Live Probes:**
   When a tool is asked to interact with a live node, if the node is offline, it must fail safely with an explanatory message or return explicit provenance tags—never silently spoofing real transactions.
3. **Turnkey Z3 Integration:**
   Provide `docker-compose.yml` configured according to the official Zcash Foundation Z3 documentation with clear WSL2/Docker setup instructions.

---

## 3. The Signature Innovation: ZecShield Privacy Firewall

### Core Threat Model
Developers and LLM agents building on Zcash frequently introduce subtle privacy breaks:
1. **Transparent Fallbacks:** When a shielded address format is misunderstood, falling back to a `t1...` transparent address eliminates zero-knowledge privacy for the sender and receiver.
2. **PII in Encrypted Memos:** While memos are encrypted on-chain, storing cleartext emails, phone numbers, or IP addresses inside memos allows anyone with viewing key access (e.g., auditors, downstream microservices, third-party viewers) to de-anonymize users.
3. **Viewing Key / Secret Leakage:** Accidental inclusion of Unified Full Viewing Keys (UFVK) or spending keys in logs, LLM chat prompts, or telemetry exposes historical or spending authority.
4. **Amount Fingerprinting:** Non-standard amounts (e.g., `49.99991234 ZEC`) create persistent on-chain transaction correlation graphs.
5. **Non-Conformant Fees:** Violating ZIP 317 fee rules creates unique fingerprintable transactions or leads to transaction rejection by mempools.

### Firewall Scope
The ZecShield Privacy Firewall evaluates transactions before broadcast across 10 deterministic checks:
- Check 01: Transparent Transaction Exposure
- Check 02: Silent Privacy Downgrades
- Check 03: Cleartext PII & Sensitive Identifiers in Memos
- Check 04: Viewing Key Exposure in Outputs/Logs
- Check 05: Spending Key & Seed Protection (Zero Model Exposure)
- Check 06: Insecure / Remote RPC Target Policy
- Check 07: Unified Address & Receiver Compatibility
- Check 08: Exact Satoshi Arithmetic & Precision Bounds
- Check 09: Transaction Policy Enforcement (Read-Only vs. State Mutating)
- Check 10: Metadata & Correlation Identifier Leakage

---

## 4. Remediation Plan & Execution Milestones

- [x] Complete technical audit and publish `docs/TECHNICAL_AUDIT.md`.
- [ ] Implement Z3 Docker Compose stack and update node client with honest provenance taxonomy.
- [ ] Upgrade ZecShield Privacy Firewall engine with structured JSON schema and comprehensive heuristic rules.
- [ ] Implement Agent Security & Human Authorization Boundary (spending token requirement, prompt injection protection).
- [ ] Reorganize MCP tools into clear developer categories and generate client configs for Claude Desktop, Cursor, Antigravity.
- [ ] Expand multi-layered test suite (Unit, Reference Vectors, Adversarial Firewall, Regtest Integration, Failure Recovery).
- [ ] Enhance Developer Dashboard with Privacy Firewall visualizer and honest provenance indicators.
- [ ] Build GitHub Action and CI workflow with sample vulnerable and fixed fixtures.
- [ ] Author complete documentation suite and 2-3 minute Judge Demonstration script.
