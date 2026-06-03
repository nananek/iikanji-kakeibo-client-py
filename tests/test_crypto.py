"""E2EE 暗号コアのユニットテスト + サーバ JS との相互運用 golden vector。

GOLDEN_* 定数は server (`app/static/js/crypto/*.js`) の実装 — hash-wasm の
Argon2id + WebCrypto の AES-256-GCM + record.js buildAAD — に固定入力を与えて
生成した出力をそのまま埋め込んだもの。これらが Python (argon2-cffi +
cryptography) で再現できることを検証し、Web ↔ client-py のデータ互換を保証する。

生成スクリプト (server リポジトリで実行):
  node でvendored hash-wasm の argon2id を setArgon2idImpl し、
  deriveKeyFromPassphrase / WebCrypto AES-GCM / buildAAD に下記の固定入力を渡す。
"""

import base64
import json
import os
import struct

import pytest

from iikanji import crypto

# --- サーバ JS から取得した golden vector (固定入力) ---

GOLDEN_PASSPHRASE = "correct horse battery staple"
GOLDEN_SALT = base64.b64decode("AQIDBAUGBwgJCgsMDQ4PEA==")  # 01..10 (16B)
GOLDEN_KDF_PARAMS = {"memory": 65536, "iterations": 3, "parallelism": 1}
GOLDEN_DERIVED_HEX = (
    "d8ebeb50632cc1993711eda85db155a107f0fb1cafab88a3a79f3d4661ac7a0c"
)
GOLDEN_MK_HEX = (
    "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"
)
GOLDEN_WRAP_IV = base64.b64decode("ZGVmZ2hpamtsbW5v")
GOLDEN_WRAPPED_MK = base64.b64decode(
    "0ULw/l8wH8U4gTcRBTJTgVJ6sIEXUJ2BDmrxwBmOADlCiezLEjRtmRIapTfuHVDv"
)
GOLDEN_USER_ID = 42
GOLDEN_AAD_JE_HEX = "6a6500000000000000002a"
GOLDEN_REC_IV = base64.b64decode("yMnKy8zNzs/Q0dLT")
GOLDEN_REC_BLOB = base64.b64decode(
    "VfR2bWXZVhf6yQgyJTXo8aLBBbmQ8pfXlOtEW/EmJQp7Jy1V4ThM88rjKvHlgznLkWCEdEssLF26z2QvLneBHiyLff3BIdwJvg9s+dnXMVlZXsobo43qewv66TYDpo5chSpnjTd5FmD9XVTztU2K"
)
GOLDEN_RECORD = {
    "v": 1,
    "date": "2026-02-15",
    "description": "テスト摘要",
    "source": "api",
    "fiscal_period": None,
}


class TestInteropGoldenVectors:
    def test_argon2id_matches_js(self) -> None:
        derived = crypto.derive_key(
            GOLDEN_PASSPHRASE, GOLDEN_SALT, GOLDEN_KDF_PARAMS
        )
        assert derived.hex() == GOLDEN_DERIVED_HEX

    def test_unwrap_master_key_matches_js(self) -> None:
        derived = bytes.fromhex(GOLDEN_DERIVED_HEX)
        mk = crypto.unwrap_master_key(
            GOLDEN_WRAPPED_MK, GOLDEN_WRAP_IV, derived
        )
        assert mk.hex() == GOLDEN_MK_HEX

    def test_aad_matches_js(self) -> None:
        assert crypto.build_aad("je", GOLDEN_USER_ID).hex() == GOLDEN_AAD_JE_HEX

    def test_decrypt_record_matches_js(self) -> None:
        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("je", GOLDEN_USER_ID)
        body = crypto.decrypt_record(mk, GOLDEN_REC_BLOB, GOLDEN_REC_IV, aad)
        assert body == GOLDEN_RECORD

    def test_encrypt_record_byte_identical_to_js(self) -> None:
        """同じ MK / IV / AAD / record で JS と同じ暗号文を生成する。"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("je", GOLDEN_USER_ID)
        # JS の JSON.stringify と同じバイト列 (キー順・空白なし)
        pt = json.dumps(
            GOLDEN_RECORD, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        ct = AESGCM(mk).encrypt(GOLDEN_REC_IV, pt, aad)
        assert ct == GOLDEN_REC_BLOB


class TestAAD:
    def test_je_jel_me_no_extra_id(self) -> None:
        assert crypto.build_aad("je", 1) == b"je\x00" + struct.pack(">Q", 1)
        assert crypto.build_aad("jel", 1) == b"jel\x00" + struct.pack(">Q", 1)
        assert crypto.build_aad("me", 1) == b"me\x00" + struct.pack(">Q", 1)

    def test_bcb_with_one_id(self) -> None:
        aad = crypto.build_aad("bcb", 5, 202601)
        assert aad == (
            b"bcb\x00" + struct.pack(">Q", 5) + b"\x00" + struct.pack(">Q", 202601)
        )

    def test_wrong_id_count_raises(self) -> None:
        with pytest.raises(ValueError):
            crypto.build_aad("je", 1, 99)
        with pytest.raises(ValueError):
            crypto.build_aad("bcb", 1)

    def test_unsupported_table_raises(self) -> None:
        with pytest.raises(ValueError):
            crypto.build_aad("zzz", 1)

    def test_uint64_range(self) -> None:
        with pytest.raises(ValueError):
            crypto.uint64_be(-1)
        with pytest.raises(ValueError):
            crypto.uint64_be(2**64)


class TestRecordRoundTrip:
    def test_round_trip(self) -> None:
        mk = os.urandom(32)
        aad = crypto.build_aad("jel", 7)
        rec = {"v": 1, "account_code": "7010", "debit_amount": 1000, "credit_amount": 0, "description": "メモ"}
        blob, iv = crypto.encrypt_record(mk, rec, aad)
        assert len(iv) == 12
        assert crypto.decrypt_record(mk, blob, iv, aad) == rec

    def test_aad_mismatch_fails(self) -> None:
        from cryptography.exceptions import InvalidTag

        mk = os.urandom(32)
        blob, iv = crypto.encrypt_record(mk, {"v": 1}, crypto.build_aad("je", 1))
        with pytest.raises(InvalidTag):
            crypto.decrypt_record(mk, blob, iv, crypto.build_aad("je", 2))

    def test_random_iv_each_call(self) -> None:
        mk = os.urandom(32)
        aad = crypto.build_aad("je", 1)
        _, iv1 = crypto.encrypt_record(mk, {"v": 1}, aad)
        _, iv2 = crypto.encrypt_record(mk, {"v": 1}, aad)
        assert iv1 != iv2


class TestNormalizePassphrase:
    def test_nfkd_normalization(self) -> None:
        # 合成済み é (U+00E9) と 分解 é (U+0065 U+0301) は同じバイト列になる
        composed = crypto.normalize_passphrase_bytes("café")
        decomposed = crypto.normalize_passphrase_bytes("café")
        assert composed == decomposed

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            crypto.normalize_passphrase_bytes("")


class TestKeyring:
    def test_store_load_clear(self) -> None:
        base = "https://keyring.example.com"
        mk = os.urandom(32)
        assert crypto.load_mk(base) is None
        crypto.store_mk(base, 123, mk)
        loaded = crypto.load_mk(base)
        assert loaded is not None
        user_id, loaded_mk = loaded
        assert user_id == 123
        assert loaded_mk == mk
        crypto.clear_mk(base)
        assert crypto.load_mk(base) is None

    def test_clear_missing_is_noop(self) -> None:
        crypto.clear_mk("https://never-stored.example.com")  # should not raise
