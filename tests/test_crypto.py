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

# 医療費 (me) record の golden vector (同じ固定 MK / user_id=42)
GOLDEN_AAD_ME_HEX = "6d6500000000000000002a"
GOLDEN_ME_IV = base64.b64decode("MjM0NTY3ODk6Ozw9")
GOLDEN_ME_BLOB = base64.b64decode(
    "+JfBntJQcX7H2USNCzNkMAGQJqKBFNqcxx8hD23zuW9JGDaUKsGQnSTbSN99BIUCm+R2FFST4mOEltpKku4kcinM+FQcWxLO5zxw1iMbZsknKD7xMVLQPKXGD0xH39f053ZEidvCZLX9f7pNeCMuY70JcTdQiuPP67n3MubonM9iE4r0+w/foCi16LUMLhdSTlyoHIxiwInymPjNpH6ry7EKoiFm+cUvxu+zXRD/tmvNWbrF+/qboOnxNP0fUUiERuZfVbsAfrTeq0Z5OPAAhlz2RwVk0JqZAeZoiqM="
)
GOLDEN_ME_RECORD = {
    "v": 1,
    "date": "2026-03-20",
    "patient_name": "山田太郎",
    "hospital_name": "○○病院",
    "treatment_description": "歯科治療",
    "provider_type": "hospital",
    "amount_paid": 12000,
    "insurance_reimbursement": 4000,
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

    def test_me_aad_matches_js(self) -> None:
        assert crypto.build_aad("me", GOLDEN_USER_ID).hex() == GOLDEN_AAD_ME_HEX

    def test_me_decrypt_record_matches_js(self) -> None:
        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("me", GOLDEN_USER_ID)
        body = crypto.decrypt_record(mk, GOLDEN_ME_BLOB, GOLDEN_ME_IV, aad)
        assert body == GOLDEN_ME_RECORD

    def test_bcb_aad_matches_js(self) -> None:
        # bcb は id 1 個 (year*100 + period)
        aad = crypto.build_aad("bcb", GOLDEN_USER_ID, 2026 * 100 + 12)
        assert aad.hex() == "62636200000000000000002a000000000000031774"

    def test_bcb_decrypt_record_matches_js(self) -> None:
        mk = bytes.fromhex(GOLDEN_MK_HEX)
        iv = base64.b64decode("RkdISUpLTE1OT1BR")
        blob = base64.b64decode(
            "HYj9pOPTo5JfyAVoVekoC2vxpNl8/9zGtt1kTTymKfsxfYMPNKJsRffUkZzAz7VUmpUwaV1puQ=="
        )
        aad = crypto.build_aad("bcb", GOLDEN_USER_ID, 2026 * 100 + 12)
        rec = crypto.decrypt_record(mk, blob, iv, aad)
        # bcb は生マップ {account_code: [debit, credit]} ({v:1} 包みなし)
        assert rec == {"1010": [50000, 20000], "5010": [12000, 0]}


# 証憑画像 (E4 #111 Option C) の golden vector。同じ固定 MK、user_id=42、
# aad_id=123456789012345 で server JS (record.js buildAAD + WebCrypto AES-GCM) が
# 生成した値。vimg/vthumb は opaque blob (iv || ct || tag)、vmeta は record。
GOLDEN_VOUCHER_AAD_ID = 123456789012345
GOLDEN_VIMG_AAD_HEX = "76696d6700000000000000002a0000007048860ddf79"
GOLDEN_VTHUMB_AAD_HEX = "767468756d6200000000000000002a0000007048860ddf79"
GOLDEN_VMETA_AAD_HEX = "766d65746100000000000000002a0000007048860ddf79"
GOLDEN_IMAGE_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520102030405060708"
)
GOLDEN_VIMG_BLOB = base64.b64decode(
    "EBESExQVFhcYGRobN9Sdl3eCX+nTsitEWjuPERHghAkEPkADmxxWteRxsK3C2k33HOqxeg=="
)
GOLDEN_VMETA_IV = base64.b64decode("MDEyMzQ1Njc4OTo7")
GOLDEN_VMETA_BLOB = base64.b64decode(
    "TK72zlDWVQZcQYHf6TZUg1/8dkeB81VkrX9EZ57+ZI1rJ7UgQ2n+wKAvux4xVAdR5OoqkDSArTWTbTW5JQav4iAq0SiQl7qtOiiJaQNpHK78bytR"
)
GOLDEN_VMETA_RECORD = {
    "v": 1,
    "original_filename": "領収書.png",
    "image_mime": "image/png",
}


class TestVoucherInterop:
    def test_vimg_aad_matches_js(self) -> None:
        aad = crypto.build_aad("vimg", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        assert aad.hex() == GOLDEN_VIMG_AAD_HEX

    def test_vthumb_aad_matches_js(self) -> None:
        aad = crypto.build_aad("vthumb", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        assert aad.hex() == GOLDEN_VTHUMB_AAD_HEX

    def test_vmeta_aad_matches_js(self) -> None:
        aad = crypto.build_aad("vmeta", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        assert aad.hex() == GOLDEN_VMETA_AAD_HEX

    def test_decrypt_blob_matches_js(self) -> None:
        """JS が生成した opaque blob (iv||ct||tag) を Python が復号一致。"""
        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("vimg", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        assert crypto.decrypt_blob(mk, GOLDEN_VIMG_BLOB, aad) == GOLDEN_IMAGE_BYTES

    def test_encrypt_blob_byte_identical_to_js(self) -> None:
        """同じ MK / IV / AAD で JS と同じ opaque blob を生成する。"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("vimg", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        iv = GOLDEN_VIMG_BLOB[:12]
        ct = AESGCM(mk).encrypt(iv, GOLDEN_IMAGE_BYTES, aad)
        assert iv + ct == GOLDEN_VIMG_BLOB

    def test_decrypt_vmeta_record_matches_js(self) -> None:
        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("vmeta", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        rec = crypto.decrypt_record(mk, GOLDEN_VMETA_BLOB, GOLDEN_VMETA_IV, aad)
        assert rec == GOLDEN_VMETA_RECORD

    def test_encrypt_vmeta_byte_identical_to_js(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        mk = bytes.fromhex(GOLDEN_MK_HEX)
        aad = crypto.build_aad("vmeta", GOLDEN_USER_ID, GOLDEN_VOUCHER_AAD_ID)
        pt = json.dumps(
            GOLDEN_VMETA_RECORD, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        ct = AESGCM(mk).encrypt(GOLDEN_VMETA_IV, pt, aad)
        assert ct == GOLDEN_VMETA_BLOB


class TestVoucherBlob:
    def test_round_trip(self) -> None:
        mk = os.urandom(32)
        aad = crypto.build_aad("vimg", 7, 999)
        data = os.urandom(1234)
        blob = crypto.encrypt_blob(mk, data, aad)
        # 先頭 12B は IV。残りは ct||tag。
        assert len(blob) == 12 + len(data) + 16
        assert crypto.decrypt_blob(mk, blob, aad) == data

    def test_random_iv_each_call(self) -> None:
        mk = os.urandom(32)
        aad = crypto.build_aad("vthumb", 7, 999)
        b1 = crypto.encrypt_blob(mk, b"abc", aad)
        b2 = crypto.encrypt_blob(mk, b"abc", aad)
        assert b1[:12] != b2[:12]

    def test_aad_mismatch_fails(self) -> None:
        from cryptography.exceptions import InvalidTag

        mk = os.urandom(32)
        blob = crypto.encrypt_blob(mk, b"x", crypto.build_aad("vimg", 1, 5))
        with pytest.raises(InvalidTag):
            crypto.decrypt_blob(mk, blob, crypto.build_aad("vthumb", 1, 5))

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError):
            crypto.decrypt_blob(os.urandom(32), b"short", crypto.build_aad("vimg", 1, 5))

    def test_sha256_hex(self) -> None:
        assert crypto.sha256_hex(b"") == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )


class TestSniffImageMime:
    def test_jpeg(self) -> None:
        assert crypto.sniff_image_mime(b"\xff\xd8\xff\xe0xxxx") == "image/jpeg"

    def test_png(self) -> None:
        assert crypto.sniff_image_mime(b"\x89PNG\r\n\x1a\n") == "image/png"

    def test_gif(self) -> None:
        assert crypto.sniff_image_mime(b"GIF89a..") == "image/gif"

    def test_webp(self) -> None:
        assert crypto.sniff_image_mime(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"

    def test_unknown(self) -> None:
        assert crypto.sniff_image_mime(b"\x00\x01\x02\x03") == "application/octet-stream"
        assert crypto.sniff_image_mime(b"ab") == "application/octet-stream"


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


# ============================================================
# #385 ログイン派生 MK / リカバリシード 派生の byte 互換 golden vector
# (server tests/static/js/test_login_kdf.mjs / test_recovery_verifier.mjs と一致)
# ============================================================

# 固定 master = 0x00..0x1f の HKDF split (login_kdf.js golden vector)
GOLDEN_LOGIN_MASTER = bytes(range(32))
GOLDEN_LOGIN_VERIFIER_HEX = (
    "5df62d0f9062c895fbb78a5fa74744c747ee3b2611bbffd3e1c6c44633e69e15"
)
GOLDEN_MK_WRAP_KEY_HEX = (
    "c520a22f75dad5f2c2eccfef9363643241f139280e4cef69ec884238c883e12a"
)
# 全ゼロ entropy のニーモニック (BIP-39 公式ベクトル) からの seed 派生
GOLDEN_ZERO_MNEMONIC = "abandon " * 23 + "art"
GOLDEN_SEED_MK_HEX = (
    "616cd7daaa3802aab1372b6a88bb413f601fc76b135387cf7261b7e20fb84a80"
)
GOLDEN_RECOVERY_VERIFIER_HEX = (
    "68a6173b2cc1666e6c19e2dfe7315cd0fd3a2ec33688372adad79aedd478eb0c"
)


class TestLoginDerivedGoldenVectors:
    def test_hkdf_login_split_matches_js(self) -> None:
        lv, mw = crypto.hkdf_login_split(GOLDEN_LOGIN_MASTER)
        assert lv.hex() == GOLDEN_LOGIN_VERIFIER_HEX
        assert mw.hex() == GOLDEN_MK_WRAP_KEY_HEX

    def test_login_split_domain_separated(self) -> None:
        lv, mw = crypto.hkdf_login_split(bytes([7] * 32))
        assert lv != mw

    def test_hkdf_login_split_rejects_bad_length(self) -> None:
        with pytest.raises(ValueError):
            crypto.hkdf_login_split(bytes(16))

    def test_derive_login_material_matches_js(self) -> None:
        """master(=Argon2id) + HKDF split を合成: GOLDEN 入力で固定 master/split。"""
        material = crypto.derive_login_material(
            GOLDEN_PASSPHRASE, GOLDEN_SALT, GOLDEN_KDF_PARAMS
        )
        assert material["master"].hex() == GOLDEN_DERIVED_HEX
        # master から HKDF split した値が一致
        lv, mw = crypto.hkdf_login_split(bytes.fromhex(GOLDEN_DERIVED_HEX))
        assert material["login_verifier"] == lv
        assert material["mk_wrap_key"] == mw

    def test_seed_mk_unwrap_key_matches_js(self) -> None:
        assert (
            crypto.derive_mk_unwrap_key_from_seed(GOLDEN_ZERO_MNEMONIC).hex()
            == GOLDEN_SEED_MK_HEX
        )

    def test_recovery_verifier_matches_js(self) -> None:
        assert (
            crypto.derive_recovery_verifier(GOLDEN_ZERO_MNEMONIC).hex()
            == GOLDEN_RECOVERY_VERIFIER_HEX
        )

    def test_seed_derivations_domain_separated(self) -> None:
        """同一シードから MK unwrap 鍵と recovery_verifier は別値 (info 分離)。"""
        mk = crypto.derive_mk_unwrap_key_from_seed(GOLDEN_ZERO_MNEMONIC)
        rv = crypto.derive_recovery_verifier(GOLDEN_ZERO_MNEMONIC)
        assert mk != rv

    def test_mnemonic_normalization(self) -> None:
        """trim/大小/連続空白の正規化で同一 verifier (bip39.js と一致)。"""
        messy = "  " + GOLDEN_ZERO_MNEMONIC.upper().replace(" ", "   ") + "  "
        assert (
            crypto.derive_recovery_verifier(messy)
            == crypto.derive_recovery_verifier(GOLDEN_ZERO_MNEMONIC)
        )
