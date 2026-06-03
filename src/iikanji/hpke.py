"""監査連携の HPKE 暗号基盤 (Web ``hpke_suite.js`` / ``audit_hpke.js`` / ``keypair.js``)。

RFC 9180 base mode、suite = DHKEM-X25519-HKDF-SHA256 / HKDF-SHA256 / AES-256-GCM。
Web の vendored ``@hpke/core`` と byte 互換 (pyhpke で実装)。

- seal (送信側): 相手の公開鍵 (raw 32B) 宛に暗号化。ephemeral 鍵はライブラリ内で
  生成・送付後破棄 (フォワードセクレシー)。秘密鍵不要。
- open (受信側): 自分の X25519 秘密鍵 (raw scalar 32B) で復号。

鍵フォーマット (keypair.js と一致):
  公開鍵 = raw 32B (平文で users.public_key)。
  秘密鍵 = pkcs8 (48B) を MK で AES-GCM 暗号化して保管。HPKE は raw scalar を
  要求するため pkcs8 末尾 32B を使う (:func:`pkcs8_to_raw_scalar`)。

AAD (audit_hpke.js):
  AuditPackage  = "ap" + uint64BE(audit_grant_id) + uint32BE(round_id)  (14B)
  AuditResponse = "ar" + uint64BE(audit_package_id)                     (10B)
"""

from __future__ import annotations

import hashlib
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto


# --- HPKE suite (pyhpke、遅延初期化) ---

_SUITE = None


def _suite():
    global _SUITE
    if _SUITE is None:
        from pyhpke import AEADId, CipherSuite, KDFId, KEMId

        _SUITE = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256,
            KDFId.HKDF_SHA256,
            AEADId.AES256_GCM,
        )
    return _SUITE


def hpke_seal(
    recipient_public_key_raw: bytes, plaintext: bytes, aad: bytes
) -> tuple[bytes, bytes]:
    """相手の公開鍵 (raw 32B) 宛に ``plaintext`` を seal する。

    Returns:
        ``(enc, ciphertext)``。enc = HPKE encapsulated key (ephemeral 公開鍵 32B)。
    """
    suite = _suite()
    pkr = suite.kem.deserialize_public_key(bytes(recipient_public_key_raw))
    enc, sender = suite.create_sender_context(pkr)
    ciphertext = sender.seal(bytes(plaintext), aad=bytes(aad))
    return enc, ciphertext


def hpke_open(
    raw_private_scalar: bytes, enc: bytes, ciphertext: bytes, aad: bytes
) -> bytes:
    """自分の X25519 秘密鍵 (raw scalar 32B) で open する。

    AAD / 鍵 / 暗号文の不一致は AEAD タグ検証で例外 (pyhpke の OpenError)。
    """
    suite = _suite()
    skr = suite.kem.deserialize_private_key(bytes(raw_private_scalar))
    recipient = suite.create_recipient_context(bytes(enc), skr)
    return recipient.open(bytes(ciphertext), aad=bytes(aad))


# --- AAD (audit_hpke.js) ---


def uint32_be(n: int) -> bytes:
    """非負整数を 4B big-endian にエンコード (audit_hpke.js uint32BE と一致)。"""
    if not isinstance(n, int) or n < 0 or n > 0xFFFFFFFF:
        raise ValueError(f"uint32_be: out of range: {n}")
    return struct.pack(">I", n)


def package_aad(grant_id: int, round_id: int) -> bytes:
    """AuditPackage 用 AAD: ``"ap" + uint64BE(grant_id) + uint32BE(round_id)`` (14B)。"""
    return b"ap" + crypto.uint64_be(grant_id) + uint32_be(round_id)


def response_aad(package_id: int) -> bytes:
    """AuditResponse 用 AAD: ``"ar" + uint64BE(package_id)`` (10B)。"""
    return b"ar" + crypto.uint64_be(package_id)


def snapshot_hash(plaintext: bytes) -> bytes:
    """SHA-256(plaintext) を 32B で返す (§14.3 の snapshot_hash)。"""
    return hashlib.sha256(bytes(plaintext)).digest()


# --- X25519 鍵ペア (keypair.js) ---


def generate_keypair() -> tuple[bytes, bytes]:
    """X25519 鍵ペアを生成する。

    Returns:
        ``(public_raw, private_pkcs8)``。public_raw = 32B raw 公開鍵、
        private_pkcs8 = pkcs8 (48B) 秘密鍵 (機密、MK で暗号化して保管する)。
    """
    priv = X25519PrivateKey.generate()
    public_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    private_pkcs8 = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return public_raw, private_pkcs8


def private_key_aad(user_id: int) -> bytes:
    """秘密鍵ラップ用 AAD: ``"x25519-priv" + b"\\x00" + uint64BE(user_id)`` (keypair.js)。"""
    return b"x25519-priv\x00" + crypto.uint64_be(user_id)


def pkcs8_to_raw_scalar(pkcs8: bytes) -> bytes:
    """pkcs8 (48B) の末尾 32B = X25519 raw scalar (keypair.js: pkcs8ToRawScalar)。

    X25519 の pkcs8 DER は固定 16B ヘッダ + 32B raw scalar。
    """
    pkcs8 = bytes(pkcs8)
    if len(pkcs8) < 32:
        raise ValueError("pkcs8 too short")
    return pkcs8[-32:]
