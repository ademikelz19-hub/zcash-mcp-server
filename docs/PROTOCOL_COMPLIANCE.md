# ZecShield MCP: Zcash Protocol Compliance

ZecShield MCP implements and cross-verifies official Zcash Improvement Proposals (ZIPs) and consensus standards:

---

## 1. ZIP 316: Unified Addresses & Unified Viewing Keys

### Specification Compliance
- **Encoding:** Bech32m checksum calculation (`0x2bc830a3`) per BIP 350.
- **Randomization:** 4-round Feistel permutation (`F4Jumble`) using BLAKE2b with personalized sub-functions:
  - `UA_F4Jumble_H` (`s12 = 16`, `s16 = 32`, `s32 = 64`)
  - `UA_F4Jumble_G`
- **Minimum Payload:** Strictly enforces 48-byte minimum length for F4Jumble invertibility.
- **CompactSize TLV:** Canonical Bitcoin/Zcash CompactSize encoding for receiver typecodes and lengths.
- **Canonical Receiver Registry:**
  - `0x00`: P2PKH (20 bytes)
  - `0x01`: P2SH (20 bytes)
  - `0x02`: Sapling (43 bytes)
  - `0x03`: Orchard (43 bytes)
  - `0x04`: **UNASSIGNED** (Rejected if encountered in address parsing)
- **Validation Rules:**
  - Rejects addresses containing only transparent receivers (prevents pseudo-unified transparent addresses).
  - Rejects addresses containing both P2PKH and P2SH receivers.
  - Priority fallback hierarchy: `Orchard (0x03) -> Sapling (0x02) -> Transparent (0x00)`.

---

## 2. ZIP 326: Ironwood Pool & Orchard Receiver Reuse

### Specification Compliance
- **Consensus Upgrade:** NU6.3 / Ironwood (July 2026).
- **Receiver Sharing:** Per ZIP 326, Ironwood reuses the `0x03` Orchard-protocol Unified Address receiver. It does **NOT** invent a `0x04` typecode.
- **Wallet-Level Pool Routing:** Resolved via `route_shielded_pool`. When routing to Ironwood, the transaction builder selects the Ironwood action bundle while addressing the transfer to the recipient's `0x03` Orchard receiver.

---

## 3. ZIP 321: Standardized Payment Request URIs

### Specification Compliance
- **URI Structure:** `zcash:<address>?amount=<val>&memo=<b64url>`
- **Memo Encoding:** Unpadded RFC 4648 Base64URL (no trailing `=` padding characters).
- **Size Bounds:** Strictly enforces 512 UTF-8 byte memo payload capacity.
- **Transparent Guard:** Rejects attempts to attach encrypted memos to transparent addresses (`t1...`, `t3...`).
- **Batch Payments:** Supports multi-recipient indices: `address`, `address.1`, `address.2`, etc.

---

## 4. ZIP 317: Proportional Transfer Fee Mechanism

### Specification Compliance
- **Marginal Fee Rate:** 5,000 zatoshis per logical action.
- **Grace Actions:** 2 logical actions.
- **Logical Action Formula:**
  ```
  logical_actions = max(ceil(tx_in / 150), ceil(tx_out / 34)) 
                    + max(sapling_spends, sapling_outputs) 
                    + orchard_actions 
                    + ironwood_actions
  conventional_fee = 5000 * max(2, logical_actions) zatoshis
  ```
- Transparent inputs account for 150 bytes (1 logical action per input).
- Shielded Orchard, Sapling, and Ironwood actions are accounted for in accordance with NU6.3 rules.

---

## 5. ISO/IEC 18004: QR Code Standard

- Generated using `segno 1.6.6` with Reed-Solomon Error Correction Level L/M.
- Output formats: SVG vector, pixel matrix array, and polarity-inverting canvas renderer for mobile camera compatibility.
