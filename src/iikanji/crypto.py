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
import hashlib
import json
import os
import struct
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

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


# --- ログイン派生 MK: HKDF split (#385, login_kdf.js / bip39.js) ---
#
# #385 でパスワード由来鍵は HKDF split する:
#   master         = Argon2id(login_password, login_salt)        (= derive_key の出力)
#   login_verifier = HKDF-SHA256(master, info="iikanji-login-v1")   サーバ照合用
#   mk_wrap_key    = HKDF-SHA256(master, info="iikanji-mk-wrap-v1")  MK の wrap/unwrap 用
# passphrase 方式の wrapped_master_key は **mk_wrap_key** で wrap されるため、解錠も
# mk_wrap_key で行う (master を直接使う旧方式ではない)。HKDF は salt=zero(32B), L=32。

# HKDF info (ドメイン分離)。サーバ JS (login_kdf.js / bip39.js) と byte 一致させる。
LOGIN_VERIFIER_INFO = b"iikanji-login-v1"
MK_WRAP_KEY_INFO = b"iikanji-mk-wrap-v1"
SEED_MK_INFO = b"iikanji-master-key-v1"          # リカバリシード → MK unwrap 鍵
RECOVERY_VERIFIER_INFO = b"iikanji-recovery-login-v1"  # リカバリシード → 検証値 (§3.4.1)


def _hkdf32(ikm: bytes, info: bytes) -> bytes:
    """HKDF-SHA256(ikm, salt=zero(32B), info, L=32) → 32B (login_kdf.js と一致)。"""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=info,
    ).derive(bytes(ikm))


def hkdf_login_split(master: bytes) -> tuple[bytes, bytes]:
    """master (32B) を (login_verifier, mk_wrap_key) に HKDF split する。

    login_kdf.js hkdfLoginSplit と byte 互換。golden vector で凍結。
    """
    if not isinstance(master, (bytes, bytearray)) or len(master) != 32:
        raise ValueError("master must be 32 bytes")
    return _hkdf32(master, LOGIN_VERIFIER_INFO), _hkdf32(master, MK_WRAP_KEY_INFO)


def derive_login_material(
    password: str, salt: bytes, kdf_params: dict
) -> dict[str, bytes]:
    """ログインパスワード + salt + kdf_params から master/login_verifier/mk_wrap_key を派生。

    login_kdf.js deriveLoginMaterial と byte 互換。

    Returns:
        ``{"master": 32B, "login_verifier": 32B, "mk_wrap_key": 32B}``
    """
    master = derive_key(password, salt, kdf_params)  # = Argon2id 出力
    login_verifier, mk_wrap_key = hkdf_login_split(master)
    return {
        "master": master,
        "login_verifier": login_verifier,
        "mk_wrap_key": mk_wrap_key,
    }


def normalize_mnemonic(mnemonic: str) -> bytes:
    """ニーモニックを trim → lowercase → 連続空白畳み → UTF-8 (bip39.js と一致)。"""
    if not isinstance(mnemonic, str):
        raise TypeError("mnemonic must be a string")
    return " ".join(mnemonic.strip().lower().split()).encode("utf-8")


def derive_mk_unwrap_key_from_seed(mnemonic: str) -> bytes:
    """リカバリシード (24 語) → MK unwrap 鍵 (32B)。bip39.js deriveKeyFromMnemonic と一致。"""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=SEED_MK_INFO,
    ).derive(normalize_mnemonic(mnemonic))


def derive_recovery_verifier(mnemonic: str) -> bytes:
    """リカバリシード → サーバ照合用 recovery_verifier (32B)。

    bip39.js deriveRecoveryVerifier と一致 (§3.4.1)。同一シードから MK unwrap 鍵とは
    別 info で独立導出する。
    """
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32,
        info=RECOVERY_VERIFIER_INFO,
    ).derive(normalize_mnemonic(mnemonic))


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


# --- 証憑画像の opaque blob 暗号化 (voucher_upload.js / voucher_download.js) ---
#
# 画像/サムネ本体は DB ではなくストレージに格納するため、record (JSON+別送 IV)
# ではなく ``iv(12B) || ciphertext || GCM tag`` を連結した opaque blob にする
# (WebCrypto の encrypt は ct||tag を返すため Python の AESGCM.encrypt と同形)。
# Web の ``voucher_upload.js: _encryptBlob`` (= iv ‖ ciphertext) と byte 互換。

# AES-GCM の最小オーバーヘッド (12B IV + 16B tag)。これ未満の blob は不正。
GCM_OVERHEAD = 12 + 16

# 平文画像の上限 (サーバ vouchers.MAX_IMAGE_SIZE / voucher_upload.js と一致)。
MAX_IMAGE_BYTES = 10 * 1024 * 1024


def encrypt_blob(mk: bytes, data: bytes, aad: bytes) -> bytes:
    """生バイト列を MK で暗号化し ``iv(12B) || ciphertext || tag`` を返す。

    IV を blob 先頭に inline で連結する (証憑画像/サムネはストレージ保存のため
    DB の IV 列を持たない)。Web ``voucher_upload.js`` の ``_encryptBlob`` と互換。
    """
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    iv = os.urandom(12)
    ct = AESGCM(mk).encrypt(iv, bytes(data), aad)
    return iv + ct


def decrypt_blob(mk: bytes, blob: bytes, aad: bytes) -> bytes:
    """``iv(12B) || ciphertext || tag`` の opaque blob を復号して平文を返す。

    配信エンドポイント (``GET /api/v1/vouchers/<id>/image``) が octet-stream で
    返す blob をそのまま渡す。AAD 不一致 / 改ざんは ``InvalidTag`` を送出する。
    """
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    if len(blob) < GCM_OVERHEAD:
        raise ValueError("blob too short (iv+tag 未満)")
    iv = bytes(blob[:12])
    ct = bytes(blob[12:])
    return AESGCM(mk).decrypt(iv, ct, aad)


def encrypt_gcm(mk: bytes, data: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """生バイト列を MK で AES-GCM 暗号化し ``(ciphertext+tag, iv)`` を別々に返す。

    iv と ciphertext を別フィールドで保管する用途 (X25519 秘密鍵の MK ラップ等、
    Web ``client.encrypt`` の ``{ciphertext, iv}`` と同形)。record/blob と違い
    JSON 化も iv inline 連結もしない素の GCM。
    """
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    iv = os.urandom(12)
    ct = AESGCM(mk).encrypt(iv, bytes(data), aad)
    return ct, iv


def decrypt_gcm(mk: bytes, ciphertext: bytes, iv: bytes, aad: bytes) -> bytes:
    """:func:`encrypt_gcm` の逆。``ciphertext+tag`` と ``iv`` を別々に受けて復号する。"""
    if len(mk) != 32:
        raise ValueError("mk must be 32 bytes")
    return AESGCM(mk).decrypt(bytes(iv), bytes(ciphertext), aad)


def sha256_hex(data: bytes) -> str:
    """SHA-256 を hex 文字列 (64 桁) で返す (voucher_upload.js: sha256Hex と一致)。"""
    return hashlib.sha256(bytes(data)).hexdigest()


def sniff_image_mime(data: bytes) -> str:
    """先頭バイト (マジックナンバー) から MIME を判定する。

    Web ``voucher_download.js: sniffImageMime`` と同じ判定。判定不能なら
    ``application/octet-stream`` を返す (許可は jpeg/png/gif/webp)。
    """
    b = bytes(data)
    if len(b) < 4:
        return "application/octet-stream"
    if b[0] == 0xFF and b[1] == 0xD8 and b[2] == 0xFF:
        return "image/jpeg"
    if b[0] == 0x89 and b[1] == 0x50 and b[2] == 0x4E and b[3] == 0x47:
        return "image/png"
    if b[0] == 0x47 and b[1] == 0x49 and b[2] == 0x46:
        return "image/gif"
    if (
        len(b) >= 12
        and b[0] == 0x52 and b[1] == 0x49 and b[2] == 0x46 and b[3] == 0x46
        and b[8] == 0x57 and b[9] == 0x45 and b[10] == 0x42 and b[11] == 0x50
    ):
        return "image/webp"
    return "application/octet-stream"


# --- .ikbackup 暗号化アーカイブ (backup_archive.js, v5 BU-3) ---
#
# パスフレーズ Argon2id + AES-256-GCM。MK と独立した「災害時用の鍵」。
# バイナリレイアウト (すべて big-endian):
#   offset size field
#   0      8    magic    = "IKBKP\0\0\0"
#   8      1    version  = 0x01
#   9      3    reserved = 0x000000
#   12     4    argon2_memory_kib  (uint32 BE)
#   16     4    argon2_iterations  (uint32 BE)
#   20     4    argon2_parallelism (uint32 BE)
#   24     16   salt
#   40     12   iv
#   52     4    ciphertext_len_low32  (uint32 BE)
#   56     4    ciphertext_len_high32 (uint32 BE, 現状常に 0)
#   60     ...  ciphertext + 16B GCM tag
# AAD = 先頭 40 bytes (magic+version+reserved+argon2_*+salt)。

_IKBACKUP_MAGIC = b"IKBKP\x00\x00\x00"
_IKBACKUP_VERSION = 1
_IKBACKUP_HEADER_LEN = 60
IKBACKUP_PASSPHRASE_MIN_LEN = 8

# Argon2id デフォルト (argon2.js ARGON2ID_DEFAULTS)。memory は KiB。
BACKUP_ARGON2_DEFAULTS = {"memory": 65536, "iterations": 3, "parallelism": 1}


def _assert_backup_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string")
    if len(passphrase) < IKBACKUP_PASSPHRASE_MIN_LEN:
        raise ValueError(
            f"passphrase must be at least {IKBACKUP_PASSPHRASE_MIN_LEN} characters"
        )


def _ikbackup_header(salt: bytes, iv: bytes, ct_len: int, params: dict) -> bytes:
    """60B ヘッダを組み立てる。先頭 40B が AAD になる。"""
    return (
        _IKBACKUP_MAGIC
        + bytes([_IKBACKUP_VERSION])
        + b"\x00\x00\x00"  # reserved
        + struct.pack(
            ">III",
            int(params["memory"]),
            int(params["iterations"]),
            int(params["parallelism"]),
        )
        + bytes(salt)
        + bytes(iv)
        + struct.pack(">I", ct_len & 0xFFFFFFFF)
        + struct.pack(">I", ct_len >> 32)
    )


def encrypt_backup_archive(
    plaintext: bytes, passphrase: str, *, params: dict | None = None
) -> bytes:
    """plaintext をパスフレーズで暗号化し ``.ikbackup`` バイナリを返す。

    Web ``backup_archive.js: encryptBackupArchive`` と byte 互換。鍵導出は MK と
    独立した Argon2id (デフォルト memory=64MiB/iterations=3/parallelism=1)。

    Args:
        plaintext: 暗号化対象 (例: ``json.dumps(backup).encode("utf-8")``)
        passphrase: 8 文字以上のパスフレーズ
        params: Argon2id パラメータ ``{"memory","iterations","parallelism"}`` を
            上書き (省略時 :data:`BACKUP_ARGON2_DEFAULTS`)。
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    _assert_backup_passphrase(passphrase)
    p = {**BACKUP_ARGON2_DEFAULTS, **(params or {})}
    salt = os.urandom(16)
    iv = os.urandom(12)
    # AAD は ciphertext 長を含まないヘッダ先頭 40B。ct 長確定前に組める。
    header = _ikbackup_header(salt, iv, 0, p)
    aad = header[:40]
    derived = derive_key(passphrase, salt, p)
    ct = AESGCM(derived).encrypt(iv, bytes(plaintext), aad)
    return _ikbackup_header(salt, iv, len(ct), p) + ct


def decrypt_backup_archive(archive: bytes, passphrase: str) -> bytes:
    """``.ikbackup`` バイナリをパスフレーズで復号して平文を返す。

    パスフレーズ違い / 改ざん / フォーマット不一致は例外を送出する。
    """
    _assert_backup_passphrase(passphrase)
    archive = bytes(archive)
    if len(archive) < _IKBACKUP_HEADER_LEN:
        raise ValueError("archive too short")
    if archive[:8] != _IKBACKUP_MAGIC:
        raise ValueError("invalid magic (not a .ikbackup file)")
    if archive[8] != _IKBACKUP_VERSION:
        raise ValueError(f"unsupported version: {archive[8]}")
    memory, iterations, parallelism = struct.unpack(">III", archive[12:24])
    salt = archive[24:40]
    iv = archive[40:52]
    len_lo, len_hi = struct.unpack(">II", archive[52:60])
    ct_len = (len_hi << 32) + len_lo
    if len(archive) != _IKBACKUP_HEADER_LEN + ct_len:
        raise ValueError("archive length mismatch")
    aad = archive[:40]
    derived = derive_key(
        passphrase, salt,
        {"memory": memory, "iterations": iterations, "parallelism": parallelism},
    )
    return AESGCM(derived).decrypt(iv, archive[_IKBACKUP_HEADER_LEN:], aad)


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
