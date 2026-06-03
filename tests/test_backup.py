"""全データバックアップ (.ikbackup アーカイブ + decrypt_backup) のテスト。"""

import base64
import json
import struct

import pytest
from cryptography.exceptions import InvalidTag

from iikanji import crypto
from iikanji.backup import decrypt_backup

# server の実コード (backup_archive.js: encryptBackupArchive + vendored hash-wasm
# argon2id) が生成した golden .ikbackup。byte 互換を保証する。
# Argon2 params は速度のため小さく (memory=512, iterations=1, parallelism=1)。
GOLDEN_IKBACKUP_B64 = (
    "SUtCS1AAAAABAAAAAAACAAAAAAEAAAABSbhLqGCdL2h3E5HWQIpNTriXvqrx4topxnwzggAAAE0AAA"
    "AAYD1I+2+9xh4Ksktr7dG2Cle7gQ70BO6K0v4WV5oklHExCIz+71I+4HNND/mb3hr4ueZ2/WNKFO0G"
    "YfvdiLmWrQhJpnNdVYpLdUc0BuA="
)
GOLDEN_PASSPHRASE = "correct horse battery staple"
GOLDEN_PLAINTEXT = '{"version":"1.0","note":"バックアップテスト","n":42}'


class TestIkbackupInterop:
    def test_decrypt_web_golden(self) -> None:
        archive = base64.b64decode(GOLDEN_IKBACKUP_B64)
        out = crypto.decrypt_backup_archive(archive, GOLDEN_PASSPHRASE)
        assert out.decode("utf-8") == GOLDEN_PLAINTEXT

    def test_golden_header(self) -> None:
        archive = base64.b64decode(GOLDEN_IKBACKUP_B64)
        assert archive[:8] == b"IKBKP\x00\x00\x00"
        assert archive[8] == 1
        mem, it, par = struct.unpack(">III", archive[12:24])
        assert (mem, it, par) == (512, 1, 1)


class TestIkbackupArchive:
    SMALL = {"memory": 512, "iterations": 1, "parallelism": 1}

    def test_round_trip(self) -> None:
        pt = json.dumps({"a": 1, "x": "テスト"}, ensure_ascii=False).encode("utf-8")
        arc = crypto.encrypt_backup_archive(pt, "passphrase123", params=self.SMALL)
        assert arc[:8] == b"IKBKP\x00\x00\x00"
        assert len(arc) == 60 + len(pt) + 16  # header + ct + tag
        assert crypto.decrypt_backup_archive(arc, "passphrase123") == pt

    def test_header_layout(self) -> None:
        params = {"memory": 1024, "iterations": 2, "parallelism": 1}
        arc = crypto.encrypt_backup_archive(b"hello world", "passphrase123", params=params)
        assert arc[8] == 1
        assert arc[9:12] == b"\x00\x00\x00"
        mem, it, par = struct.unpack(">III", arc[12:24])
        assert (mem, it, par) == (1024, 2, 1)
        lo, hi = struct.unpack(">II", arc[52:60])
        assert hi == 0
        assert lo == len(arc) - 60

    def test_default_params(self) -> None:
        # params 省略時は Argon2id デフォルト (memory=64MiB) がヘッダに入る
        arc = crypto.encrypt_backup_archive(b"x" * 8, "passphrase123")
        mem, it, par = struct.unpack(">III", arc[12:24])
        assert (mem, it, par) == (65536, 3, 1)

    def test_short_passphrase_raises(self) -> None:
        with pytest.raises(ValueError):
            crypto.encrypt_backup_archive(b"data", "short")
        with pytest.raises(ValueError):
            crypto.decrypt_backup_archive(b"\x00" * 60, "short")

    def test_wrong_passphrase_fails(self) -> None:
        arc = crypto.encrypt_backup_archive(b"secret data", "rightpass123", params=self.SMALL)
        with pytest.raises(InvalidTag):
            crypto.decrypt_backup_archive(arc, "wrongpass123")

    def test_tamper_fails(self) -> None:
        arc = bytearray(
            crypto.encrypt_backup_archive(b"secret data", "rightpass123", params=self.SMALL)
        )
        arc[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            crypto.decrypt_backup_archive(bytes(arc), "rightpass123")

    def test_bad_magic_raises(self) -> None:
        with pytest.raises(ValueError):
            crypto.decrypt_backup_archive(b"X" * 60, "passphrase123")

    def test_length_mismatch_raises(self) -> None:
        arc = crypto.encrypt_backup_archive(b"hello", "passphrase123", params=self.SMALL)
        with pytest.raises(ValueError):
            crypto.decrypt_backup_archive(arc + b"\x00", "passphrase123")


def _build_encrypted_backup(mk: bytes, user_id: int) -> dict:
    """je/jel/me/bcb を暗号化した backup dict を組み立てる。"""
    def enc(rec, aad):
        blob, iv = crypto.encrypt_record(mk, rec, aad)
        return crypto.b64encode(blob), crypto.b64encode(iv)

    je_b, je_iv = enc(
        {"v": 1, "date": "2026-02-15", "description": "テスト摘要",
         "source": "api", "fiscal_period": None},
        crypto.build_aad("je", user_id),
    )
    jel_b, jel_iv = enc(
        {"v": 1, "account_code": "7010", "debit_amount": 1000,
         "credit_amount": 0, "description": "行メモ"},
        crypto.build_aad("jel", user_id),
    )
    me_b, me_iv = enc(
        {"v": 1, "date": "2026-03-20", "patient_name": "山田太郎"},
        crypto.build_aad("me", user_id),
    )
    bcb_b, bcb_iv = enc(
        {"1010": [50000, 20000]},
        crypto.build_aad("bcb", user_id, 2026 * 100 + 12),
    )
    return {
        "version": "1.0",
        "exported_at": "2026-06-03T00:00:00",
        "user_id": user_id,
        "data": {
            "accounts": [{"code": "1010", "name": "現金"}],
            "fiscal_closes": [{"year": 2026, "closed_period": 5}],
            "journal_entries": [
                {"id": 1, "entry_number": 7, "encrypted_blob": je_b, "blob_iv": je_iv},
            ],
            "journal_entry_lines": [
                {"id": 2, "journal_entry_id": 1, "account_code": "7010",
                 "encrypted_blob": jel_b, "blob_iv": jel_iv},
            ],
            "medical_expenses": [
                {"id": 3, "encrypted_blob": me_b, "blob_iv": me_iv},
            ],
            "balance_cache_blobs": [
                {"year": 2026, "period": 12, "encrypted_blob": bcb_b, "blob_iv": bcb_iv},
            ],
            "vouchers": [{"id": 5, "aad_id": "123456789012345"}],
            "ai_drafts": [{"id": 6}],
            "user_ai_config": {"provider": "openai"},
            "tax_form_mappings": [{"field": "a"}],
            "csv_column_profiles": [{"name": "bank"}],
        },
    }


class TestDecryptBackup:
    def test_decrypts_all_tables(self) -> None:
        mk = bytes(range(32))
        uid = 42
        out = decrypt_backup(mk, uid, _build_encrypted_backup(mk, uid))
        je = out["data"]["journal_entries"][0]
        assert je["date"] == "2026-02-15"
        assert je["description"] == "テスト摘要"
        assert "encrypted_blob" not in je and "blob_iv" not in je
        assert out["data"]["journal_entry_lines"][0]["debit_amount"] == 1000
        assert out["data"]["medical_expenses"][0]["patient_name"] == "山田太郎"
        bcb = out["data"]["balance_cache_blobs"][0]
        assert bcb["cumulative"] == {"1010": [50000, 20000]}
        assert bcb["year"] == 2026 and bcb["period"] == 12

    def test_passthrough_fields(self) -> None:
        mk = bytes(range(32))
        uid = 42
        out = decrypt_backup(mk, uid, _build_encrypted_backup(mk, uid))
        assert out["data"]["accounts"] == [{"code": "1010", "name": "現金"}]
        assert out["data"]["vouchers"][0]["aad_id"] == "123456789012345"
        assert out["data"]["user_ai_config"] == {"provider": "openai"}
        assert out["data"]["csv_column_profiles"] == [{"name": "bank"}]
        assert out["version"] == "1.0"
        assert out["user_id"] == uid

    def test_decrypt_error_localized(self) -> None:
        mk = bytes(range(32))
        backup = _build_encrypted_backup(mk, 42)
        # 異なる user_id で復号すると AAD 不一致 → 行ごとに _decryptError、中断しない
        out = decrypt_backup(mk, 999, backup)
        assert "_decryptError" in out["data"]["journal_entries"][0]
        assert "_decryptError" in out["data"]["medical_expenses"][0]
        assert "_decryptError" in out["data"]["balance_cache_blobs"][0]
        # passthrough は影響を受けない
        assert out["data"]["vouchers"][0]["aad_id"] == "123456789012345"

    def test_empty_data(self) -> None:
        out = decrypt_backup(bytes(range(32)), 42, {"version": "1.0", "data": {}})
        assert out["data"]["journal_entries"] == []
        assert out["data"]["user_ai_config"] is None

    def test_rejects_non_dict(self) -> None:
        with pytest.raises(TypeError):
            decrypt_backup(bytes(range(32)), 42, [])
        with pytest.raises(TypeError):
            decrypt_backup(bytes(range(32)), 42, {"version": "1.0"})
