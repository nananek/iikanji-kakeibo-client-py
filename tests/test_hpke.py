"""HPKE 暗号基盤 (hpke.py) のユニットテスト + @hpke/core との golden interop。"""

import base64

import pytest

from iikanji import crypto, hpke

# server の vendored @hpke/core (hpke-1.8.0) が固定 recipient 公開鍵宛に seal した
# golden。pyhpke が byte 互換で open できることを検証する (Web ↔ client-py 相互運用)。
# recipient 秘密鍵 raw scalar = 01..20、AAD = packageAAD(grant=7, round=2)。
GOLDEN_RECIPIENT_PRIV = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)
GOLDEN_RECIPIENT_PUB = bytes.fromhex(
    "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
)
GOLDEN_AAD = bytes.fromhex("6170000000000000000700000002")
GOLDEN_ENC = base64.b64decode("LQSNPIQ9+OtSffEBLvT8dix5xgfD7NOoQhVr1fCwQ1s=")
GOLDEN_CT = base64.b64decode(
    "YqpoGB3SCjXK2Vuy9dOOuHTJ/5ZLTsLoHQleKq6P9NfAIKCxXj9FUvlIT3Y8l/lb0v6Dcuid7BZD/iIRuCA5FmYcZ11eg7eGmg=="
)
GOLDEN_PLAINTEXT = '{"v":1,"level":3,"note":"監査スナップショット"}'


class TestHpkeInterop:
    def test_open_web_golden(self) -> None:
        """@hpke/core が seal した暗号文を pyhpke が復号一致する。"""
        pt = hpke.hpke_open(
            GOLDEN_RECIPIENT_PRIV, GOLDEN_ENC, GOLDEN_CT, GOLDEN_AAD
        )
        assert pt.decode("utf-8") == GOLDEN_PLAINTEXT

    def test_golden_aad_matches_package_aad(self) -> None:
        assert hpke.package_aad(7, 2) == GOLDEN_AAD

    def test_wrong_aad_fails(self) -> None:
        with pytest.raises(Exception):
            hpke.hpke_open(
                GOLDEN_RECIPIENT_PRIV, GOLDEN_ENC, GOLDEN_CT,
                hpke.package_aad(7, 3),
            )


class TestHpkeRoundTrip:
    def test_seal_open(self) -> None:
        aad = hpke.response_aad(99)
        enc, ct = hpke.hpke_seal(GOLDEN_RECIPIENT_PUB, b"secret payload", aad)
        assert len(enc) == 32
        out = hpke.hpke_open(GOLDEN_RECIPIENT_PRIV, enc, ct, aad)
        assert out == b"secret payload"

    def test_aad_mismatch_fails(self) -> None:
        enc, ct = hpke.hpke_seal(GOLDEN_RECIPIENT_PUB, b"x", hpke.response_aad(1))
        with pytest.raises(Exception):
            hpke.hpke_open(GOLDEN_RECIPIENT_PRIV, enc, ct, hpke.response_aad(2))

    def test_generated_keypair_round_trip(self) -> None:
        pub, pkcs8 = hpke.generate_keypair()
        assert len(pub) == 32
        assert len(pkcs8) == 48
        scalar = hpke.pkcs8_to_raw_scalar(pkcs8)
        assert len(scalar) == 32
        enc, ct = hpke.hpke_seal(pub, b"hello", b"aad")
        assert hpke.hpke_open(scalar, enc, ct, b"aad") == b"hello"


class TestAad:
    def test_package_aad(self) -> None:
        assert hpke.package_aad(7, 2) == b"ap" + crypto.uint64_be(7) + hpke.uint32_be(2)
        assert len(hpke.package_aad(1, 1)) == 14

    def test_response_aad(self) -> None:
        assert hpke.response_aad(99) == b"ar" + crypto.uint64_be(99)
        assert len(hpke.response_aad(1)) == 10

    def test_uint32_be(self) -> None:
        assert hpke.uint32_be(2) == b"\x00\x00\x00\x02"
        assert hpke.uint32_be(0xFFFFFFFF) == b"\xff\xff\xff\xff"
        with pytest.raises(ValueError):
            hpke.uint32_be(-1)
        with pytest.raises(ValueError):
            hpke.uint32_be(2**32)

    def test_private_key_aad(self) -> None:
        assert hpke.private_key_aad(42) == b"x25519-priv\x00" + crypto.uint64_be(42)

    def test_snapshot_hash(self) -> None:
        import hashlib

        assert hpke.snapshot_hash(b"abc") == hashlib.sha256(b"abc").digest()
        assert len(hpke.snapshot_hash(b"")) == 32


class TestPkcs8ToRawScalar:
    def test_matches_cryptography_raw(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        priv = X25519PrivateKey.generate()
        pkcs8 = priv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        raw = priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        # pkcs8 末尾 32B が raw scalar (keypair.js: pkcs8ToRawScalar)
        assert hpke.pkcs8_to_raw_scalar(pkcs8) == raw
