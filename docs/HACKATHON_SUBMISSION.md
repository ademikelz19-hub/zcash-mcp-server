# ZecShield MCP: Zecathon 2026 Submission Document

**Track:** Core & Tooling ($15,000)  
**Project Name:** ZecShield MCP  
**Tagline:** "Build on Zcash with AI. Test everything. Leak nothing unnecessarily."  
**Repository:** `https://github.com/ademikelz19-hub/zcash-mcp-server`  
**Latest CI Run:** [GitHub Actions Run #38799032412](https://github.com/ademikelz19-hub/zcash-mcp-server/actions) (100% Passing)  
**Demonstration Video:** Included in repository as [`zecshield_demo_video.mp4`](../zecshield_demo_video.mp4) (1080p Full HD with synchronized voiceover narration, 2m 32s)  
**License:** MIT  

---

## 1. Project Overview & Elevator Pitch

ZecShield MCP is an AI-native Zcash developer infrastructure and privacy-enforcement toolkit. It enables AI coding assistants (Claude Desktop, Cursor, Google Antigravity, OpenDevin) and developers to interact with Zcash infrastructure, construct shielded payment requests, validate cryptographic implementations, and detect privacy leaks before they reach the blockchain.

Most developer tools focus exclusively on enabling agents to *spend* funds. ZecShield provides the missing security and privacy immune system: **guarding against transparent address fallbacks, preventing cleartext PII memo leakage, and enforcing human-in-the-loop authorization so autonomous agents cannot drain wallets or compromise user anonymity.**

---

## 2. The Core Problems Solved

1. **Catastrophic AI Privacy Fallbacks:**  
   LLMs writing Web3 code frequently fall back to transparent addresses (`t1...`) when encountering shielded address errors, or embed unhashed customer emails/IPs directly into transaction memos. These mistakes permanently de-anonymize users on public block explorers.
2. **The Autonomous AI Spend Dilemma:**  
   Giving autonomous AI models wallet private keys creates an existential risk of key exfiltration via model telemetry or autonomous unauthorized draining.
3. **Absence of Pre-Broadcast CI Linting:**  
   Until now, the Zcash ecosystem lacked a lightweight, turnkey tool that teams could drop into GitHub Actions to scan applications for privacy anti-patterns.

---

## 3. The Technical Solution: ZecShield Architecture

- **10-Check Pre-Broadcast Privacy Firewall:** Intercepts candidate transactions and blocks transparent fallbacks, cleartext PII (emails, IPs, phones, SSNs), viewing key leaks, exposed spending keys, prompt injections, and precision errors.
- **Fail-Closed Human-in-the-Loop (HITL) Authorization:** The AI model can request a payment intent ticket, but has zero credentials to authorize it. An out-of-band human operator must cryptographically approve tickets via interactive CLI (`python cli.py approve <ticket_id>`) with an Ed25519 signature.
- **ZIP 326 (Ironwood) & ZIP 316 Conformance:** Implements authentic ZIP 316 Unified Addresses (Bech32m + F4Jumble Feistel permutation) and correctly routes to the 2026 Ironwood shielded pool via Orchard-protocol receivers (0x03) per ZIP 326.
- **Turnkey Z3 Docker Integration:** Direct integration with the official Zcash Foundation Z3 stack (`docker-compose.yml`) running authentic Zebra 2.1.0 full node and Zallet 0.1.0 wallet services.
- **Absolute Cryptographic Honesty:** Zero hallucination. Every response declares its exact data provenance (`GENUINE_Z3_REGTEST`, `SIMULATED_MOCK_REGTEST`, or `DEMO_FIXTURE`).
- **Turnkey CI GitHub Action (`action.yml`):** Allows any Zcash repository to add automated privacy linting with a single YAML step.

---

## 4. Verified Zcash Standards Implemented

- **ZIP 316:** Unified Addresses (Bech32m + F4Jumble + TLV CompactSize) & Unified Full Viewing Keys (UFVK).
- **ZIP 326:** NU6.3 Ironwood Shielded Pool support and Orchard receiver reuse.
- **ZIP 321:** Standardized Payment Request URIs with unpadded RFC 4648 Base64URL memos.
- **ZIP 317:** Proportional Transfer Fee Mechanism (5,000 zatoshis per logical action).
- **ISO/IEC 18004:** Reed-Solomon scannable QR codes for mobile wallets (Zashi, YWallet).
- **FastMCP Protocol:** Model Context Protocol stdio interface with **22 exposed developer tools**.

---

## 5. Verification Evidence & Quality Assurance

- **62 / 62 passing automated tests (100% pass rate)** in pytest across Unit, Reference Vectors, Adversarial Privacy, and Multi-Process Concurrency.
- **6 / 6 Adversarial Attack Scenarios Verified Fail-Closed:**
  1. *Privacy Leak:* Flags cleartext PII; blocks exposed spending keys.
  2. *Unauthorized Payment:* Blocks autonomous broadcasts with `AWAITING_HUMAN_APPROVAL`.
  3. *Intent Tampering:* Catches recipient/amount modification with `INTENT_TAMPERING_DETECTED`.
  4. *Replay Attacks:* Consumed tickets rejected with `TICKET_ALREADY_CONSUMED`.
  5. *AI Self-Approval:* Non-interactive subshells blocked; direct vault tampering caught with `FORGERY_DETECTED`.
  6. *Node Outage:* Offline nodes return honest provenance (`DEMO_FIXTURE`) without hallucination.
- **Multi-Process Concurrency Tested:** Safe under 20-thread simultaneous broadcast collision (double-spend prevention) and cross-process OS file locks (`msvcrt`/`fcntl`).
- **Automated CI Fixture Verification:** Exits `1` on `fixtures/vulnerable_app`, exits `0` on `fixtures/fixed_app`.

---

## 6. How Judges Can Verify in 60 Seconds

Judges can reproduce the entire verification suite on any machine:

```bash
# 1. Clone repository
git clone https://github.com/ademikelz19-hub/zcash-mcp-server.git
cd zcash-mcp-server

# 2. Run full test suite (62 tests, 0 MB data needed)
python -m pytest -v

# 3. Test privacy audit on sample apps
python cli.py audit-ci fixtures/vulnerable_app   # Exits 1 (caught 5 leaks)
python cli.py audit-ci fixtures/fixed_app        # Exits 0 (clean)

# 4. Run the 5 FastMCP verification scenarios
python run_verification_tests.py

# 5. Run full developer demonstration
python cli.py demo
```
