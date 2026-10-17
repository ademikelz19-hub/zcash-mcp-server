# ZecShield MCP: Multi-Layer Testing & Verification

ZecShield MCP enforces multi-layer verification: **62 / 62 passing tests (100% pass rate)**.

---

## 1. Test Layer Breakdown

| Layer | Verification Target | Test Suite | Test Count | Pass Rate |
|---|---|---|---|---|
| **Layer A: Unit & Protocol** | ZIP 316, F4Jumble Feistel roundtrips, CompactSize canonical boundaries, ZIP 321 memo encoding, ZIP 317 fee math, AI memo redaction, FastMCP protocol calls. | `tests/test_server.py` | 26 tests | **100%** |
| **Layer B: Reference Vectors** | BIP 350 Bech32m valid/invalid test vectors, RFC 4648 unpadded Base64URL vectors, ZIP 317 official fee reference vectors. | `tests/test_reference_vectors.py` | 9 tests | **100%** |
| **Layer C: Adversarial Privacy** | Transparent fallback, cleartext email/IP detection, spending key leaks, seed phrases, prompt injection attacks, sub-zatoshi precision bugs, human approval gates, vault persistence across restarts. | `tests/test_privacy_firewall.py` | 20 tests | **100%** |
| **Layer D: Concurrency & Isolation** | Multi-process OS file locking (msvcrt/fcntl), Ed25519 asymmetric operator signature verification, subshell TTY boundary defense, 20-thread simultaneous broadcast collision (double-spend prevention), and atomic 2-phase state crash recovery. | `tests/test_concurrency.py` | 7 tests | **100%** |
| **Layer E: Regtest Integration** | End-to-end regtest node probing, shielded payment construction, mempool broadcast, mining, confirmation, and wallet balance reconciliation. | `live_node_client.py` | Multi-stage | **100%** |

---

## 2. Running the Test Suite

```bash
# Run all unit, reference, and adversarial tests
python -m pytest tests/ -v

# Run only the ZecShield Privacy Firewall adversarial tests
python -m pytest tests/test_privacy_firewall.py -v

# Run reference vector compliance tests
python -m pytest tests/test_reference_vectors.py -v

# Execute live regtest workflow
python live_node_client.py --regtest-demo
```

---

## 3. Negative & Positive CI Testing

ZecShield verifies both negative (vulnerable) and positive (hardened) configurations:

```bash
# Negative Test: Must fail with exit code 1
python cli.py audit-ci fixtures/vulnerable_app
# Output: [X] CI BUILD FAILED: 5 CRITICAL privacy violation(s) detected.

# Positive Test: Must pass with exit code 0
python cli.py audit-ci fixtures/fixed_app
# Output: [+] CI BUILD PASSED: Zero critical privacy leaks detected.
```
