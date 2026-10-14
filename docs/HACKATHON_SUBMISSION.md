# ZecShield MCP: Zecathon 2026 Submission Document

**Track:** Core & Tooling ($15,000)  
**Project Name:** ZecShield MCP  
**Tagline:** "Build on Zcash with AI. Test everything. Leak nothing unnecessarily."  
**Repository:** `https://github.com/ademikelz19-hub/zcash-mcp-server`  
**License:** MIT  

---

## 1. The Core Problem

As autonomous AI agents and coding assistants (Claude Desktop, Cursor, Antigravity) are increasingly tasked with writing Web3 applications, they present a double-edged sword for Zcash:
1. **Accidental De-Anonymization:** LLMs frequently default to transparent addresses (`t1...`) or include cleartext customer emails and IPs in on-chain transaction memos.
2. **Context Key Leaking:** Traditional wallet MCPs give models spending keys, creating severe risk of key exfiltration via model telemetry.
3. **Developer Friction:** Developers lack automated tooling to detect privacy bugs in CI pipelines before deployment.

---

## 2. The Solution: ZecShield MCP

ZecShield MCP is an AI-native development and privacy-testing toolkit that enables developers and coding agents to build, test, inspect, and debug Zcash applications without introducing avoidable privacy vulnerabilities:
- **ZecShield Privacy Firewall:** 10 pre-broadcast checks catching transparent fallbacks, cleartext PII, viewing key leaks, prompt injections, and precision bugs.
- **Official Zcash Foundation Z3 Integration:** Out-of-the-box Docker Compose stack for genuine Zebra full node consensus and Zallet wallet proofs.
- **Strict Cryptographic Honesty:** Unambiguous provenance tagging (`GENUINE_Z3_REGTEST`, `SIMULATED_MOCK_REGTEST`, `DEMO_FIXTURE`).
- **Zero-Knowledge AI Security Boundary:** Redacted model memos (`[REDACTED_BY_ZECSHIELD_FOR_AI_PRIVACY]`), zero exposed keys, and human authorization tokens for spending.
- **Automated CI/CD Action:** A reusable GitHub Action that scans Zcash apps and fails CI builds on privacy breaks.

---

## 3. Verified Standards Implemented

- **ZIP 316:** Unified Addresses (Bech32m + F4Jumble + TLV CompactSize) & Unified Full Viewing Keys (UFVK).
- **ZIP 326:** Ironwood Shielded Pool support and Orchard receiver reuse.
- **ZIP 321:** Standardized Payment Request URIs with unpadded RFC 4648 Base64URL memos.
- **ZIP 317:** Proportional Transfer Fee Mechanism (5,000 zatoshis per logical action).
- **ISO/IEC 18004:** Reed-Solomon scannable QR codes for mobile wallets (Zashi, YWallet).
- **FastMCP:** Model Context Protocol stdio interface with 14 exposed tools.

---

## 4. Verification Evidence

- **47 / 47 passing tests (100% pass rate)** across Unit, Reference Vectors, and Adversarial Privacy suites.
- Negative and positive verification fixtures in CI.
- Brutalist dark developer dashboard (`dashboard.html`) with interactive Privacy Firewall Lab.
