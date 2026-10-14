# ZecShield MCP: Known Limitations & Future Scope

In the spirit of complete engineering honesty, this document details the current technical boundaries of ZecShield MCP:

---

## 1. Zero-Knowledge Proof Construction
- **Current Limitation:** Generating recursive zero-knowledge SNARK proofs (Halo 2 / Groth16) requires compiled Rust binaries (`librustzcash`, `zcash_primitives`). In the Python runtime, ZecShield delegates actual cryptographic proof construction to the official Zcash Foundation Z3 stack (`zallet` and `zebrad`).
- **Mitigation:** When Docker / Z3 is absent on the host machine, ZecShield operates in deterministic verification mode (`SIMULATED_MOCK_REGTEST` or `DEMO_FIXTURE`) and explicitly labels data provenance.

---

## 2. In-Memory Mock Regtest Daemon
- **Current Limitation:** The built-in mock server in `live_node_client.py` simulates JSON-RPC responses (`getblockchaininfo`, `sendrawtransaction`, `generate`, `z_viewtransaction`) for fast local unit testing. It does not execute consensus rules or mine real proof-of-work/equihash blocks.
- **Remediation:** It is explicitly labeled `SIMULATED_MOCK_REGTEST` and never presented as genuine Zebra consensus.

---

## 3. Privacy Firewall Heuristic Boundaries
- **Current Limitation:** While the Privacy Firewall detects known PII patterns (emails, IPv4, IPv6, phone numbers, SSNs, credit cards, UUIDs, spending keys, prompt injections), it cannot mathematically prove that an arbitrary string does not contain an obscure steganographic or off-chain identifier.
- **Guidance:** Developers are reminded that pre-flight linting is a defense-in-depth tool, not a mathematical substitute for zero-knowledge encryption.

---

## 4. Mainnet Execution
- **Current Limitation:** Autonomous spending on mainnet is strictly disabled by default (`MAINNET_SPENDING_LOCKED`). ZecShield is designed as a developer and testing tool, not a custodial wallet.
- **Future Scope:** Support for threshold multi-signature (FROST) authorization boundaries.
