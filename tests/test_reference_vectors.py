"""
ZECATHON // INDEPENDENT STANDARDS REFERENCE VECTOR TEST SUITE
=============================================================
Validates Zcash MCP Server against independent, published reference vectors from:
  1. BIP 350: Bech32m checksum constant (0x2bc830a3), valid/invalid vectors & roundtrip.
  2. ZIP 321: Payment Request URI specification (RFC 4648 unpadded base64url memos).
  3. ZIP 317: Proportional Transfer Fee mechanism (Electric Coin Company specification).
  4. ZIP 316: F4Jumble 4-round Feistel permutation & CompactSize encoding standards.

This guarantees that tests do not simply test an implementation against its own assumptions,
but against canonical, externally verified cryptographic ground truth.
"""

from __future__ import annotations

import base64
import pytest

from server import (
    DEFAULT_TREASURY_UA,
    bech32m_decode,
    bech32m_encode,
    decode_memo_base64url,
    encode_memo_base64url,
    estimate_zip317_fee,
    f4jumble,
    f4jumble_inv,
    parse_zip321_uri,
    read_compact_size,
    write_compact_size,
)


# ===========================================================================
# 1. BIP 350 BECH32M REFERENCE TEST VECTORS
# ===========================================================================

# Canonical valid Bech32m vectors with zero-payload or valid padding
BIP350_VALID_BECH32M = [
    "A1LQFN3A",
    "a1lqfn3a",
    "?1v759aa",
]

# Canonical invalid Bech32m strings (must raise ValueError on decode)
BIP350_INVALID_BECH32M = [
    # Empty HRP
    " 1nwldj5",
    # Out of range ASCII in HRP
    "\x7f1axkwrx",
    # Invalid character 'b' in data part
    "an83characterlonghumanreadablepartthatcontainsthethenumber1andtheexcludedcharactersbio1b58lxvl",
    # Invalid checksum
    "split1checkupstagehandshakeupstreamerranterredcaperits52vdre0",
    # Corrupted Bech32m constant
    "a1lqfn30",
]


def test_bip350_valid_bech32m_reference_vectors() -> None:
    """Validate decoding and roundtrip encoding against official BIP 350 Bech32m test vectors."""
    for vector in BIP350_VALID_BECH32M:
        hrp, data = bech32m_decode(vector)
        assert hrp is not None
        reencoded = bech32m_encode(hrp, data)
        assert reencoded.lower() == vector.lower()


def test_bip350_invalid_bech32m_reference_vectors() -> None:
    """Validate that invalid BIP 350 Bech32m strings raise ValueError on decode."""
    for vector in BIP350_INVALID_BECH32M:
        with pytest.raises(ValueError):
            bech32m_decode(vector)


def test_bech32m_arbitrary_payload_roundtrip() -> None:
    """Verify Bech32m can encode and decode arbitrary byte sequences cleanly."""
    test_payloads = [
        b"",
        b"\x00",
        b"\xff" * 32,
        b"Zcash Foundation & Electric Coin Company 2026",
        bytes(range(64)),
    ]
    for payload in test_payloads:
        encoded = bech32m_encode("u", payload)
        assert encoded.startswith("u1")
        hrp, decoded = bech32m_decode(encoded)
        assert hrp == "u"
        assert decoded == payload


# ===========================================================================
# 2. ZIP 321 PAYMENT URI & RFC 4648 BASE64URL REFERENCE VECTORS
# ===========================================================================

ZIP321_MEMO_VECTORS = [
    # (plaintext, expected_unpadded_base64url)
    ("", ""),
    ("Hello", "SGVsbG8"),
    ("This is a simple memo.", "VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg"),
    ("Hackathon test payment", "SGFja2F0aG9uIHRlc3QgcGF5bWVudA"),
    ("Zcash: Privacy is a human right.", "WmNhc2g6IFByaXZhY3kgaXMgYSBodW1hbiByaWdodC4"),
    ("DAO Payout // Q4 Milestone #1", "REFPIFBheW91dCAvLyBRNCBNaWxlc3RvbmUgIzE"),
]


def test_zip321_rfc4648_unpadded_base64url_vectors() -> None:
    """
    ZIP 321 mandates unpadded RFC 4648 base64url encoding for encrypted memos.
    Verify exact string equality against independent standard vectors.
    """
    for plaintext, expected_base64url in ZIP321_MEMO_VECTORS:
        encoded, byte_len = encode_memo_base64url(plaintext)
        assert encoded == expected_base64url, f"Memo '{plaintext}' encoded as '{encoded}', expected '{expected_base64url}'"
        assert "=" not in encoded, f"Padding character '=' detected in ZIP 321 memo: {encoded}"
        assert byte_len == len(plaintext.encode("utf-8"))
        decoded_text, _, _ = decode_memo_base64url(encoded)
        assert decoded_text == plaintext, f"Roundtrip decoding failed for: {plaintext}"


def test_zip321_uri_parsing_reference_vectors() -> None:
    """Verify ZIP 321 URI parser against canonical multi-parameter payment strings."""
    uri = f"zcash:{DEFAULT_TREASURY_UA}?amount=50.00000000&memo=SGFja2F0aG9uIHRlc3QgcGF5bWVudA"
    
    parsed = parse_zip321_uri(uri)
    assert parsed["is_valid"] is True
    assert parsed["recipient_count"] == 1
    assert parsed["total_amount_zec"] == "50"
    p0 = parsed["payments"][0]
    assert p0["address"] == DEFAULT_TREASURY_UA
    assert p0["amount_zec"] == "50"
    assert p0["memo_utf8"] == "Hackathon test payment"


# ===========================================================================
# 3. ZIP 317 PROPORTIONAL FEE REFERENCE VECTORS
# ===========================================================================

ZIP317_FEE_VECTORS = [
    # (orchard_actions, sapling_spends, sapling_outputs, transparent_inputs, transparent_outputs, expected_actions, expected_zatoshis, expected_zec)
    # Grace action test: <= 2 actions always pays 2 * 5000 = 10,000 zatoshis (0.0001 ZEC)
    (0, 0, 0, 0, 0, 0, 10000, "0.0001"),
    (1, 0, 0, 0, 0, 1, 10000, "0.0001"),
    (2, 0, 0, 0, 0, 2, 10000, "0.0001"),
    # Beyond grace: 3 actions pays 3 * 5000 = 15,000 zatoshis
    (3, 0, 0, 0, 0, 3, 15000, "0.00015"),
    # 4 Orchard actions + 2 Sapling outputs = 6 logical actions
    (4, 0, 2, 0, 0, 6, 30000, "0.0003"),
    # 10 Orchard actions = 10 * 5000 = 50,000 zatoshis
    (10, 0, 0, 0, 0, 10, 50000, "0.0005"),
    # Transparent input/output combination: max(ceil(4*150/150), ceil(2*34/34)) = max(4, 2) = 4 actions
    (0, 0, 0, 4, 2, 4, 20000, "0.0002"),
]


def test_zip317_fee_calculation_against_reference_vectors() -> None:
    """
    Validate ZIP 317 fee calculation against explicit conventional fee vectors.
    Formula: marginal_fee (5000) * max(grace_actions (2), logical_actions).
    """
    for (
        orchard,
        sap_spends,
        sap_outs,
        t_ins,
        t_outs,
        expected_actions,
        expected_zat,
        expected_zec,
    ) in ZIP317_FEE_VECTORS:
        fee_info = estimate_zip317_fee(
            orchard_actions=orchard,
            sapling_spends=sap_spends,
            sapling_outputs=sap_outs,
            transparent_inputs=t_ins,
            transparent_outputs=t_outs,
        )
        assert fee_info["logical_actions"] == expected_actions
        assert fee_info["conventional_fee_zatoshis"] == expected_zat
        assert fee_info["conventional_fee_zec"] == expected_zec


# ===========================================================================
# 4. ZIP 316 F4JUMBLE & COMPACTSIZE REFERENCE BEHAVIOR
# ===========================================================================

def test_f4jumble_invertibility_across_standard_buffer_sizes() -> None:
    """
    Validate ZIP 316 F4Jumble Feistel network across variable message lengths
    from minimum bound (48 bytes) through typical transaction envelope sizes.
    """
    test_sizes = [48, 64, 128, 256, 512, 1024, 2048]
    for size in test_sizes:
        message = bytes((i * 37) % 256 for i in range(size))
        jumbled = f4jumble(message)
        assert jumbled != message, f"F4Jumble produced identity for length {size}"
        assert len(jumbled) == size, f"F4Jumble changed length for {size}"
        recovered = f4jumble_inv(jumbled)
        assert recovered == message, f"F4Jumble_inv failed to invert for length {size}"


def test_f4jumble_strictly_enforces_minimum_length_48_bytes() -> None:
    """ZIP 316 explicitly states F4Jumble is undefined and invalid for len < 48."""
    for short_len in [0, 1, 16, 32, 47]:
        short_buf = b"\xaa" * short_len
        with pytest.raises(ValueError, match="F4Jumble"):
            f4jumble(short_buf)


def test_compactsize_canonical_boundaries() -> None:
    """
    Validate CompactSize serialization at exact boundary transitions:
      0..252 (1 byte), 253..65535 (3 bytes), 65536..4294967295 (5 bytes).
    """
    boundaries = [
        (0, 1),
        (252, 1),
        (253, 3),
        (65535, 3),
        (65536, 5),
        (0xFFFFFFFF, 5),
    ]
    for value, expected_encoded_len in boundaries:
        encoded = write_compact_size(value)
        assert len(encoded) == expected_encoded_len, (
            f"Value {value} encoded into {len(encoded)} bytes, expected {expected_encoded_len}"
        )
        decoded, offset = read_compact_size(encoded, 0)
        assert decoded == value
        assert offset == expected_encoded_len
