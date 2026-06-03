"""いいかんじ家計簿 E2EE 暗号コア (client-py)。

サーバ Web (``server/app/static/js/crypto/*.js``) と完全互換の暗号方式を
Python で再現する。E2EE Phase E6 §15.1 トラック3。

対応 JS:
  - ``argon2.js``        : パスフレーズ → Argon2id 派生鍵
  - ``primitives.js``    : AES-256-GCM encrypt/decrypt, MK wrap/unwrap
  - ``record.js``        : AAD 構築 (Option B), JSON-then-encrypt record
  - ``entries_builder.js``: 仕訳 record body スキーマ (models.py 側で利用)

暗号パラメータ (JS と厳密一致):
  - Argon2id: type=ID, hash_len=32, NFKD 正規化 + UTF-8。memory(KiB)/iterations/
    parallelism は wrapped_keys.kdf_params から取得。
  - AES-256-GCM: key 32B / IV 12B ランダム / tag 16B (ciphertext 末尾)。
  - MK unwrap: AES-GCM 復号 (AAD なし)。
  - AAD: ``tableType(ascii) + b"\\x00" + uint64_be(user_id) [+ b"\\x00" + uint64_be(id)]*``。
"""

from __future__ import annotations

import base64
import json
import os
import struct
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- base64 ヘルパー ---


def b64encode(data: bytes) -> str:
    """bytes → base64 ASCII 文字列 (JS b64.js と同形式、標準アルファベット)。"""
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    """base64 文字列 → bytes。"""
    return base64.b64decode(s)


# --- Argon2id 鍵派生 (argon2.js) ---


def normalize_passphrase_bytes(passphrase: str) -> bytes:
    """パスフレーズを NFKD 正規化して UTF-8 バイト列にする (argon2.js と一致)。"""
    if not isinstance(passphrase, str) or passphrase == "":
        raise ValueError("passphrase must be a non-empty string")
    return unicodedata.normalize("NFKD", passphrase).encode("utf-8")


def derive_key(passphrase: str, salt: bytes, kdf_params: dict) -> bytes:
    """パスフレーズ + salt + kdf_params から 32B の derived_key を派生する。

    Args:
        passphrase: ユーザー入力 (NFKD 正規化後に UTF-8 化される)
        salt: per-user salt (16B、wrapped_keys.salt)
        kdf_params: ``{"memory": KiB, "iterations": int, "parallelism": int}``
            (wrapped_keys の passphrase 行が持つ JSON)

    Returns:
        32B derived_key (MK のアンラップ鍵)
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    try:
        memory = int(kdf_params["memory"])
        iterations = int(kdf_params["iterations"])
        parallelism = int(kdf_params["parallelism"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "kdf_params must contain int memory/iterations/parallelism"
        ) from exc
    return hash_secret_raw(
        secret=normalize_passphrase_bytes(passphrase),
        salt=bytes(salt),
        time_cost=iterations,
        memory_cost=memory,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )


# --- MK アンラップ (primitives.js: unwrapMasterKey) ---


def unwrap_master_key(
    wrapped_mk: bytes, wrap_iv: bytes, derived_key: bytes
) -> bytes:
    """wrapped_master_key を derived_key で AES-GCM 復号 → 32B の MK を返す。

    primitives.js の wrap/unwrap は AAD を使わない。
    """
    if len(derived_key) != 32:
        raise ValueError("derived_key must be 32 bytes")
    if len(wrap_iv) != 12:
        raise ValueError("wrap_iv must be 12 bytes")
    mk = AESGCM(derived_key).decrypt(bytes(wrap_iv), bytes(wrapped_mk), None)
    if len(mk) != 32:
        raise ValueError(f"unwrapped master key must be 32 bytes (got {len(mk)})")
    return mk


# --- AAD 構築 (record.js: buildAAD, Option B) ---


# テーブル種別ごとの追加 ID 個数 (record.js TABLE_ID_COUNT と一致)。
# je/jel/me は Option B で user_id のみ (0 個)。bcb / voucher 系は 1 個。
TABLE_ID_COUNT = {
    "je": 0,      # journal_entries
    "jel": 0,     # journal_entry_lines
    "me": 0,      # medical_expenses
    "bcb": 1,     # balance_cache_blobs (year*100+period)
    "vimg": 1,    # vouchers 画像本体 (voucher_id)
    "vthumb": 1,  # vouchers サムネイル (voucher_id)
    "vmeta": 1,   # vouchers メタ情報 (voucher_id)
    "valog": 1,   # voucher_audit_logs detail (voucher_id)
}


def uint64_be(n: int) -> bytes:
    """非負整数を 8B big-endian にエンコード (record.js uint64BE と一致)。"""
    if not isinstance(n, int):
        raise TypeError("uint64_be expects an int")
    if n < 0 or n > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"uint64_be: out of range: {n}")
    return struct.pack(">Q", n)


def build_aad(table_type: str, user_id: int, *ids: int) -> bytes:
    """AAD バイト列を構築 (record.js buildAAD と一致)。

    形式: ``tableType + b"\\x00" + uint64_be(user_id) [+ b"\\x00" + uint64_be(id)]*``
    """
    if table_type not in TABLE_ID_COUNT:
        raise ValueError(f"build_aad: unsupported tableType: {table_type}")
    expected = TABLE_ID_COUNT[table_type]
    if len(ids) != expected:
        raise ValueError(
            f"build_aad: {table_type} expects {expected} id(s), got {len(ids)}"
        )
    parts = [table_type.encode("ascii"), b"\x00", uint64_be(user_id)]
    for i in ids:
        parts.append(b"\x00")
        parts.append(uint64_be(i))
    return b"".join(parts)


# --- record 暗号化 (record.js: encryptRecord / decryptRecord) ---


def encrypt_record(mk: bytes, record: dict, aad: bytes) -> tuple[bytes, bytes]:
    """record (dict) を JSON 化 → MK で AES-GCM 暗号化。

    Returns:
        ``(blob, iv)`` — blob = ciphertext + 16B GCM tag, iv = 12B ランダム。
    """
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    iv = os.urandom(12)
    # JS の JSON.stringify は空白なし。ensure_ascii=False で非 ASCII も UTF-8 の
    # まま (どちらでも復号互換だが JS と同じ最小バイト列にする)。
    plaintext = json.dumps(
        record, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    blob = AESGCM(mk).encrypt(iv, plaintext, aad)
    return blob, iv


def decrypt_record(mk: bytes, blob: bytes, iv: bytes, aad: bytes) -> dict:
    """blob + iv + aad を AES-GCM 復号 → JSON parse して dict を返す。

    AAD 不一致 / 改ざんは GCM tag 検証失敗で ``InvalidTag`` を送出する。
    """
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    plaintext = AESGCM(mk).decrypt(bytes(iv), bytes(blob), aad)
    return json.loads(plaintext.decode("utf-8"))


# --- OS keyring への MK 永続化 (§15.1) ---

KEYRING_SERVICE = "iikanji-kakeibo"


def store_mk(base_url: str, user_id: int, mk: bytes) -> None:
    """MK と user_id を OS keyring に保存する。

    keyring バックエンドが無い (headless CI 等) 環境では黙って失敗を無視し、
    呼出側のメモリ保持のみにフォールバックする。
    """
    try:
        import keyring

        keyring.set_password(
            KEYRING_SERVICE,
            base_url,
            json.dumps({"user_id": int(user_id), "mk": b64encode(mk)}),
        )
    except Exception:
        # keyring バックエンド不在・権限エラー等は永続化スキップ (メモリ保持で継続)
        pass


def load_mk(base_url: str) -> tuple[int, bytes] | None:
    """OS keyring から ``(user_id, mk)`` を復元する。無ければ None。"""
    try:
        import keyring

        raw = keyring.get_password(KEYRING_SERVICE, base_url)
    except Exception:
        return None
    if not raw:
        return None
    try:
        d = json.loads(raw)
        return int(d["user_id"]), b64decode(d["mk"])
    except (ValueError, KeyError, TypeError):
        return None


def clear_mk(base_url: str) -> None:
    """OS keyring から MK を削除する (存在しなくてもエラーにしない)。"""
    try:
        import keyring

        keyring.delete_password(KEYRING_SERVICE, base_url)
    except Exception:
        pass
