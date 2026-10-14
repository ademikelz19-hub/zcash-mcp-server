"""
ZECATHON // UNIT & CRYPTOGRAPHIC COMPLIANCE TEST SUITE
======================================================
Verifies:
  1. ZIP 316 Bech32m (`0x2bc830a3`), 4-Round BLAKE2b F4Jumble & F4Jumble_inv,
     CompactSize TLV ordering, 16-byte HRP padding, and Receiver Priority Selection.
  2. ZIP 316 Unified Full Viewing Key (`uview1...`, `uviewtest1...`) parsing.
  3. ZIP 321 Single- & Multi-Recipient Payment Request URIs, unpadded RFC 4648
     `base64url` 512-byte encrypted memos, and rejection of memos on transparent addresses.
  4. ZIP 317 Proportional Transfer Fee calculation (`5000 * max(2, logical_actions)`).
  5. Air-Gap Loopback Security Policy (refusal of non-local RPC endpoints).
  6. Local Trial Decryption, Shielded History, Memo Extraction, and Aegis-Z Reconciliation.
"""

from __future__ import annotations

import os
import pytest

from server import (
    DEFAULT_TREASURY_UA,
    DEFAULT_TREASURY_UFVK,
    RECIPIENT_DIRECTORY,
    TYPECODE_IRONWOOD,
    TYPECODE_ORCHARD,
    TYPECODE_P2PKH,
    TYPECODE_P2SH,
    TYPECODE_SAPLING,
    _verify_loopback_url,
    bech32m_decode,
    bech32m_encode,
    construct_zip321_payout_batch,
    decode_memo_base64url,
    detect_privacy_leaks,
    encode_memo_base64url,
    encode_zip316_container,
    estimate_zip317_fee,
    execute_trial_decryption,
    f4jumble,
    f4jumble_inv,
    fetch_shielded_history,
    generate_zip316_unified_address,
    generate_zip321_uri,
    mcp,
    parse_zip316_ufvk,
    parse_zip321_uri,
    query_lightwalletd,
    query_zebrad_rpc,
    read_compact_size,
    read_memo_contents,
    reconcile_shielded_ledger,
    render_zip321_qr,
    validate_zip316_unified_address,
    write_compact_size,
)


def test_fastmcp_server_initialization() -> None:
    """Verify FastMCP server instance is named Zcash_MCP_Server per Appendix Requirement 1."""
    assert mcp.name == "Zcash_MCP_Server"


def test_f4jumble_feistel_roundtrip() -> None:
    """Verify the 4-round BLAKE2b Feistel F4Jumble and F4Jumble_inv are exact inverses."""
    original = bytes(range(64)) + b"ZCASH_ZIP316_F4JUMBLE_TEST_VECTOR"
    jumbled = f4jumble(original)
    assert jumbled != original
    assert len(jumbled) == len(original)
    recovered = f4jumble_inv(jumbled)
    assert recovered == original


def test_f4jumble_rejects_short_messages() -> None:
    """ZIP 316 specifies F4Jumble is only defined for lengths >= 48 bytes."""
    with pytest.raises(ValueError, match="F4Jumble"):
        f4jumble(b"too_short")


def test_compact_size_roundtrip() -> None:
    """Verify CompactSize integer encoding and canonical decoding across 1, 3, 5, and 9 byte ranges."""
    for val in [0, 1, 252, 253, 65535, 65536, 0xFFFFFFFF, 0x100000000]:
        encoded = write_compact_size(val)
        decoded, offset = read_compact_size(encoded, 0)
        assert decoded == val
        assert offset == len(encoded)


def test_zip316_unified_address_generation_and_validation() -> None:
    """Verify generated Unified Addresses pass Bech32m, F4Jumble_inv, HRP padding, and priority selection."""
    res = generate_zip316_unified_address(
        seed_identifier="TEST_USER_ORCHARD_SAPLING_P2PKH",
        network="mainnet",
        include_orchard=True,
        include_sapling=True,
        include_transparent_p2pkh=True,
    )
    ua = res["unified_address"]
    assert ua.startswith("u1")

    validation = validate_zip316_unified_address(ua)
    assert validation["is_valid"] is True
    assert validation["hrp"] == "u"
    assert validation["network"] == "mainnet"
    assert validation["bech32m_verified"] is True
    assert validation["f4jumble_inverted"] is True
    assert validation["hrp_padding_verified"] is True

    # Protocol-mandated priority order: Orchard (0x03) must be selected over Sapling (0x02) and P2PKH (0x00)
    priority = validation["selected_priority_receiver"]
    assert priority["typecode"] == TYPECODE_ORCHARD
    assert priority["pool"] == "orchard"
    assert priority["byte_length"] == 43


def test_zip316_rejects_both_p2pkh_and_p2sh() -> None:
    """ZIP 316 forbids a Unified Address from containing both P2PKH (0x00) and P2SH (0x01)."""
    invalid_ua = encode_zip316_container(
        "u",
        {
            TYPECODE_P2PKH: b"\x11" * 20,
            TYPECODE_P2SH: b"\x22" * 20,
            TYPECODE_ORCHARD: b"\x33" * 43,
        },
    )
    res = validate_zip316_unified_address(invalid_ua)
    assert res["is_valid"] is False
    assert "both P2PKH (0x00) and P2SH (0x01)" in res["error"]


def test_zip316_rejects_transparent_only_ua() -> None:
    """ZIP 316 requires at least one shielded receiver in a Unified Address."""
    # Pad transparent receiver artificially or test validation error
    hrp = "u"
    tlv = write_compact_size(TYPECODE_P2PKH) + write_compact_size(32) + (b"\xaa" * 32)
    padded = tlv + hrp.encode("ascii").ljust(16, b"\x00")
    ua = bech32m_encode(hrp, f4jumble(padded))
    res = validate_zip316_unified_address(ua)
    assert res["is_valid"] is False
    assert "shielded receiver" in res["error"]


def test_zip316_ufvk_parsing() -> None:
    """Verify ZIP 316 Unified Full Viewing Key (`uview1...`) extraction and selective disclosure metadata."""
    parsed = parse_zip316_ufvk(DEFAULT_TREASURY_UFVK)
    assert parsed["is_valid"] is True
    assert parsed["hrp"] == "uview"
    assert parsed["spending_key_exposed"] is False
    assert parsed["selective_disclosure_ready"] is True
    assert "orchard" in parsed["pools_supported"]
    assert "sapling" in parsed["pools_supported"]


def test_zip321_single_recipient_and_memo_roundtrip() -> None:
    """Verify ZIP 321 URI creation, unpadded base64url memo encoding, and URI parsing."""
    recipient = RECIPIENT_DIRECTORY["alice_core_dev"]
    memo_text = "INV-2026-777 // Zero-Knowledge Halo2 Proof Verification Retainer"
    uri_bundle = generate_zip321_uri(
        address=recipient,
        amount_zec="12.34567890",
        memo_utf8=memo_text,
        label="Alice Core Dev",
    )
    uri = uri_bundle["uri"]
    assert uri.startswith(f"zcash:{recipient}?")
    assert "=" not in uri_bundle["memo_base64url"]

    parsed = parse_zip321_uri(uri)
    assert parsed["is_valid"] is True
    assert parsed["recipient_count"] == 1
    assert parsed["total_amount_zec"] == "12.3456789"
    p0 = parsed["payments"][0]
    assert p0["address"] == recipient
    assert p0["memo_utf8"] == memo_text


def test_zip321_rejects_oversized_512_byte_memo() -> None:
    """ZIP 321 memos cannot exceed the 512-byte Zcash encrypted memo field limit."""
    oversized = "Z" * 513
    with pytest.raises(ValueError, match="512 bytes"):
        encode_memo_base64url(oversized)


def test_zip321_rejects_memo_on_transparent_address() -> None:
    """ZIP 321 forbids attaching an encrypted memo parameter to a transparent P2PKH/P2SH address."""
    with pytest.raises(ValueError, match="transparent-only"):
        generate_zip321_uri(
            address="t1VpYecBW4UudbGcy4ufh61eWxQCoFaUrPs",
            amount_zec="1.0",
            memo_utf8="Should fail on transparent address",
        )


def test_zip321_multi_recipient_payout_batch() -> None:
    """Verify multi-recipient ZIP 321 URI construction (`address=...&address.1=...`) and parsing."""
    batch = construct_zip321_payout_batch(
        [
            {
                "address": RECIPIENT_DIRECTORY["alice_core_dev"],
                "amount_zec": "42.00",
                "memo": "PAYROLL-01 // Alice",
            },
            {
                "address": RECIPIENT_DIRECTORY["bob_zk_auditor"],
                "amount_zec": "31.50",
                "memo": "AUDIT-02 // Bob",
            },
        ]
    )
    assert batch["recipient_count"] == 2
    assert batch["total_payout_zec"] == "73.5"
    assert "address=" in batch["uri"]
    assert "address.1=" in batch["uri"]

    parsed = parse_zip321_uri(batch["uri"])
    assert parsed["is_valid"] is True
    assert parsed["recipient_count"] == 2
    assert parsed["payments"][0]["memo_utf8"] == "PAYROLL-01 // Alice"
    assert parsed["payments"][1]["memo_utf8"] == "AUDIT-02 // Bob"


def test_zip317_proportional_fee_mechanism() -> None:
    """Verify ZIP 317 marginal fee (5000 zatoshis) and grace actions (2 actions = 10000 zatoshis)."""
    # 1 Orchard action falls within grace_actions=2 -> 10,000 zatoshis (0.0001 ZEC)
    f_grace = estimate_zip317_fee(orchard_actions=1)
    assert f_grace["conventional_fee_zatoshis"] == 10000
    assert f_grace["conventional_fee_zec"] == "0.0001"

    # 4 Orchard actions + 2 Sapling outputs = 6 logical actions -> 30,000 zatoshis (0.0003 ZEC)
    f_multi = estimate_zip317_fee(orchard_actions=4, sapling_outputs=2)
    assert f_multi["logical_actions"] == 6
    assert f_multi["conventional_fee_zatoshis"] == 30000
    assert f_multi["conventional_fee_zec"] == "0.0003"


def test_airgap_loopback_policy_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify non-loopback RPC URLs are blocked by default to uphold 'does not leak'."""
    monkeypatch.delenv("ZCASH_ALLOW_REMOTE_RPC", raising=False)
    with pytest.raises(PermissionError, match="AIR-GAP POLICY VIOLATION"):
        _verify_loopback_url("https://api.external-cloud-tracker.com:8232")

    # Loopback addresses must pass
    _verify_loopback_url("http://127.0.0.1:8232")
    _verify_loopback_url("http://localhost:9067")


def test_shielded_history_trial_decryption_and_aegis_reconciliation() -> None:
    """Verify the full Aegis-Z accounting pipeline: history -> memos -> trial decryption -> reconciliation."""
    history = fetch_shielded_history(DEFAULT_TREASURY_UFVK)
    assert history["air_gapped"] is True
    assert history["transaction_count"] == 5
    assert history["summary"]["net_shielded_balance_zec"] == "165.49955"

    memos = read_memo_contents()
    assert memos["count"] == 5

    decryption = execute_trial_decryption(2684000, 2690500, DEFAULT_TREASURY_UFVK)
    assert decryption["discovered_notes_count"] == 5

    reconciled = reconcile_shielded_ledger(DEFAULT_TREASURY_UFVK)
    assert reconciled["unpaid_obligations_count"] == 2
    batch_uri = reconciled["zip321_disbursement_batch"]["uri"]
    assert batch_uri.startswith("zcash:?")


def test_lightwalletd_and_zebrad_queries() -> None:
    """Verify lightwalletd and zebrad MCP query tools return structured state."""
    lwd = query_lightwalletd("GetLightdInfo")
    assert lwd["air_gapped_loopback"] is True
    assert lwd["data"]["chainName"] == "main"

    zebra = query_zebrad_rpc("getblockchaininfo")
    assert zebra["service"] == "zebrad"
    assert zebra["result"]["chain"] == "main"


def test_user_prompt_1_address_generation_and_priority_fallback() -> None:
    """
    Test 1: Generate a new ZIP 316 Unified Address and validate that same address
    to confirm its receiver priority falls back properly from Orchard -> Sapling -> Transparent.
    """
    gen_res = generate_zip316_unified_address()
    new_ua = gen_res["unified_address"]
    assert new_ua.startswith("u1")

    val_res = validate_zip316_unified_address(new_ua)
    assert val_res["is_valid"] is True
    assert val_res["selected_priority_receiver"]["pool"] == "orchard"
    assert val_res["fallback_order_summary"] == "ORCHARD (0x03) -> SAPLING (0x02) -> P2PKH (0x00)"
    chain = val_res["receiver_priority_fallback_chain"]
    assert [c["pool"] for c in chain] == ["orchard", "sapling", "p2pkh"]

    # Also verify fallback when Orchard is unavailable (degrades to Sapling -> Transparent)
    gen_no_orchard = generate_zip316_unified_address(
        seed_identifier="SAPLING_FALLBACK_TEST",
        include_orchard=False,
        include_sapling=True,
        include_transparent_p2pkh=True,
    )
    val_no_orchard = validate_zip316_unified_address(gen_no_orchard["unified_address"])
    assert val_no_orchard["is_valid"] is True
    assert val_no_orchard["selected_priority_receiver"]["pool"] == "sapling"
    assert val_no_orchard["fallback_order_summary"] == "SAPLING (0x02) -> P2PKH (0x00)"


def test_user_prompt_2_parse_ufvk_viewing_key() -> None:
    """
    Test 2: Parse a test Zcash Unified Full Viewing Key (UFVK), verify bundled
    receiver types, and confirm spending keys cannot be accessed.
    """
    for arg in ("test", DEFAULT_TREASURY_UFVK):
        parsed = parse_zip316_ufvk(arg)
        assert parsed["is_valid"] is True
        assert parsed["pools_supported"] == ["p2pkh", "sapling", "orchard"]
        assert parsed["spending_key_exposed"] is False
        assert parsed["can_spend_funds"] is False
        assert "read-only" in parsed["security_confirmation"]


def test_user_prompt_3_generate_50_zec_uri() -> None:
    """
    Test 3: Construct a ZIP 321 payment request URI for 50 ZEC with encrypted memo
    'Hackathon test payment' and verify the final URI string.
    """
    res = generate_zip321_uri(
        address=DEFAULT_TREASURY_UA,
        amount_zec="50",
        memo_utf8="Hackathon test payment",
    )
    assert res["amount_zec"] == "50"
    assert res["memo_utf8"] == "Hackathon test payment"
    assert res["memo_base64url"] == "SGFja2F0aG9uIHRlc3QgcGF5bWVudA"
    assert res["uri"].endswith("?amount=50&memo=SGFja2F0aG9uIHRlc3QgcGF5bWVudA")

    # Verify round-trip parsing of the generated URI
    parsed = parse_zip321_uri(res["uri"])
    assert parsed["is_valid"] is True
    assert parsed["total_amount_zec"] == "50"
    assert parsed["payments"][0]["memo_utf8"] == "Hackathon test payment"


@pytest.mark.asyncio
async def test_fastmcp_client_protocol_execution() -> None:
    """
    End-to-end MCP protocol verification using FastMCP's in-memory Client transport
    to execute Test 1, Test 2, and Test 3 exactly as an MCP host / LLM invokes them.
    """
    from fastmcp import Client

    async with Client(mcp) as client:
        tools = await client.list_tools()
        tool_names = {t.name for t in tools}
        assert "generate_zip316_unified_address" in tool_names
        assert "validate_zip316_unified_address" in tool_names
        assert "parse_zip316_ufvk" in tool_names
        assert "generate_zip321_uri" in tool_names
        assert "detect_privacy_leaks" in tool_names

        # Test 1 over MCP protocol
        t1_gen = await client.call_tool("generate_zip316_unified_address", {
            "seed_identifier": "HACKATHON_TEST_1_SEED",
            "network": "mainnet",
            "include_orchard": True,
            "include_sapling": True,
            "include_transparent_p2pkh": True,
        })
        assert not t1_gen.is_error

        # Test 2 over MCP protocol
        t2_ufvk = await client.call_tool("parse_zip316_ufvk", {"ufvk": "test"})
        assert not t2_ufvk.is_error

        # Test 3 over MCP protocol
        t3_uri = await client.call_tool("generate_zip321_uri", {
            "address": DEFAULT_TREASURY_UA,
            "amount_zec": "50",
            "memo_utf8": "Hackathon test payment",
        })
        assert not t3_uri.is_error

        # Test 5 over MCP protocol: Privacy leak detection
        t5_leak = await client.call_tool("detect_privacy_leaks", {
            "address": DEFAULT_TREASURY_UA,
            "amount_zec": "50",
            "memo_utf8": "Clean shielded transfer",
        })
        assert not t5_leak.is_error


def test_render_zip321_iso18004_qr() -> None:
    """Verify real ISO/IEC 18004 Reed-Solomon QR generation for a 50 ZEC ZIP 321 URI."""
    uri_res = generate_zip321_uri(
        address=DEFAULT_TREASURY_UA,
        amount_zec="50",
        memo_utf8="Hackathon test payment",
    )
    qr_res = render_zip321_qr(uri_res["uri"])
    assert qr_res["qr_code"]["scannable_by_zashi_ywallet"] is True
    assert qr_res["qr_code"]["standard"].startswith("ISO/IEC 18004")
    assert len(qr_res["matrix"]) >= 21
    assert qr_res["qr_code"]["svg_data_uri"].startswith("data:image/svg+xml;base64,")


def test_fail_closed_missing_address_in_zip321() -> None:
    """Verify generate_zip321_uri fails closed when address is empty or omitted."""
    with pytest.raises(ValueError, match="MISSING_RECIPIENT_ADDRESS"):
        generate_zip321_uri(address="", amount_zec="50")


def test_fail_closed_missing_ufvk_without_explicit_fixture() -> None:
    """Verify parse_zip316_ufvk refuses to silently substitute fixtures without authorization."""
    res = parse_zip316_ufvk("")
    assert res["is_valid"] is False
    assert "MISSING_INPUT" in res["error"]

    # Passing explicit fixture flag must succeed and declare DEMO_FIXTURE provenance
    fixture_res = parse_zip316_ufvk("", use_demo_fixture=True)
    assert fixture_res["is_valid"] is True
    assert fixture_res["provenance"] == "DEMO_FIXTURE"


def test_ironwood_pool_support_and_priority_selection() -> None:
    """Verify Ironwood (0x04) support, ascending TLV packing, and top priority in fallback hierarchy."""
    res = generate_zip316_unified_address(
        seed_identifier="IRONWOOD_VALIDATION_VECTOR_2026",
        network="mainnet",
        include_ironwood=True,
        include_orchard=True,
        include_sapling=True,
        include_transparent_p2pkh=True,
    )
    ua = res["unified_address"]
    val = validate_zip316_unified_address(ua)
    assert val["is_valid"] is True

    # Confirm Ironwood is present in bundled receivers
    pools = [r["pool"] for r in val["receivers"]]
    assert pools == ["p2pkh", "sapling", "orchard", "ironwood"]

    # Confirm Ironwood takes top precedence in fallback chain
    assert val["selected_priority_receiver"]["pool"] == "ironwood"
    assert val["selected_priority_receiver"]["typecode_hex"] == "0x04"
    assert val["fallback_order_summary"].startswith("IRONWOOD (0x04)")


def test_zecshield_privacy_leak_detector() -> None:
    """Verify detect_privacy_leaks flags transparent leaks, PII in memos, and fee fingerprinting."""
    # 1. Clean transaction
    clean = detect_privacy_leaks(
        address=DEFAULT_TREASURY_UA,
        amount_zec="50.0",
        memo_utf8="Shielded DAO contributor compensation",
        fee_zatoshis=10000,
    )
    assert clean["is_safe_to_broadcast"] is True
    assert clean["privacy_score"] == 100
    assert clean["findings_count"] == 0

    # 2. Leaky transaction (Transparent address + PII in memo + non-standard fee)
    leaky = detect_privacy_leaks(
        address="t1VpYecBW4UudbGcy4ufh61eWxQCoFaUrPs",
        amount_zec="1.23456789",
        memo_utf8="Send invoice to alice@cypherpunk.org at IP 192.168.1.1",
        fee_zatoshis=77700,
    )
    assert leaky["is_safe_to_broadcast"] is False
    assert leaky["privacy_score"] < 50
    categories = [f["category"] for f in leaky["findings"]]
    assert "TRANSPARENT_EXPOSURE" in categories
    assert "MEMO_PII_LEAKAGE" in categories
    assert "FEE_FINGERPRINTING" in categories
    assert "AMOUNT_FINGERPRINTING" in categories


def test_ai_memo_redaction_for_host_safety() -> None:
    """Verify fetch_shielded_history and read_memo_contents protect sensitive memos from host LLM leaks."""
    history = fetch_shielded_history(DEFAULT_TREASURY_UFVK, redact_sensitive_memos=True)
    assert history["ai_host_redaction_active"] is True
    for tx in history["transactions"]:
        assert tx["memo_sanitized"].startswith("[REDACTED_FOR_AI_PRIVACY")

    memos = read_memo_contents(redact_for_ai=True)
    assert memos["ai_host_redaction_active"] is True
    for m in memos["memos"]:
        assert m["memo_utf8"].startswith("[REDACTED_MEMO")





