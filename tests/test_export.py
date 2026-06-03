"""export.build_export_zip の統合テスト (実 KakeiboClient + MockTransport)。"""

import io
import json
import zipfile

import httpx
import pytest

from iikanji import KakeiboClient, crypto
from iikanji.export import build_export_zip

TEST_MK = bytes(range(32))
TEST_USER_ID = 42
BASE_URL = "https://test.example.com"
VOUCHER_AAD_ID = 555


def _png() -> bytes:
    from PIL import Image

    img = Image.new("RGB", (40, 30), (1, 2, 3))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _enc_record(rec: dict, table: str, *ids: int) -> tuple[str, str]:
    blob, iv = crypto.encrypt_record(TEST_MK, rec, crypto.build_aad(table, TEST_USER_ID, *ids))
    return crypto.b64encode(blob), crypto.b64encode(iv)


def _raw_backup(png: bytes) -> dict:
    je_b, je_iv = _enc_record(
        {"v": 1, "date": "2026-02-15", "description": "弁当", "source": "api",
         "fiscal_period": None}, "je")
    jel1_b, jel1_iv = _enc_record(
        {"v": 1, "account_code": "7010", "debit_amount": 3000, "credit_amount": 0,
         "description": ""}, "jel")
    me_b, me_iv = _enc_record(
        {"v": 1, "date": "2026-03-20", "patient_name": "山田", "hospital_name": "病院",
         "treatment_description": "歯科", "provider_type": "hospital",
         "amount_paid": 12000, "insurance_reimbursement": 4000}, "me")
    vimg = crypto.encrypt_blob(TEST_MK, png, crypto.build_aad("vimg", TEST_USER_ID, VOUCHER_AAD_ID))
    return {
        "version": "1.0",
        "exported_at": "2026-06-03T12:00:00",
        "user_id": TEST_USER_ID,
        "data": {
            "accounts": [{"code": "7010", "name": "食費"}, {"code": "1010", "name": "現金"}],
            "fiscal_closes": [],
            "journal_entries": [
                {"id": 1, "entry_number": 5, "fiscal_year": 2026, "fiscal_month": 2,
                 "encrypted_blob": je_b, "blob_iv": je_iv},
            ],
            "journal_entry_lines": [
                {"id": 10, "journal_entry_id": 1, "account_code": "7010",
                 "debit_amount": 3000, "credit_amount": 0,
                 "encrypted_blob": jel1_b, "blob_iv": jel1_iv},
            ],
            "medical_expenses": [
                {"id": 20, "journal_entry_id": 1, "encrypted_blob": me_b, "blob_iv": me_iv},
            ],
            "balance_cache_blobs": [],
            "vouchers": [
                {"id": 5, "journal_entry_id": 1, "image_data": crypto.b64encode(vimg),
                 "aad_id": str(VOUCHER_AAD_ID), "file_hash": "cipherhash",
                 "file_size": len(png), "uploaded_at": "2026-06-01T00:00:00"},
            ],
            "ai_drafts": [],
            "user_ai_config": None,
            "tax_form_mappings": [],
            "csv_column_profiles": [],
        },
    }


def _client(raw: dict) -> KakeiboClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/backup/export":
            return httpx.Response(200, json=raw)
        return httpx.Response(404, json={"error": "nf"})

    hc = httpx.Client(transport=httpx.MockTransport(handler), base_url=BASE_URL,
                      headers={"Authorization": "Bearer x"})
    client = KakeiboClient(BASE_URL, "x", http_client=hc)
    client._mk = TEST_MK
    client._user_id = TEST_USER_ID
    return client


class TestBuildExportZip:
    def test_zip_structure_and_contents(self) -> None:
        png = _png()
        client = _client(_raw_backup(png))
        with client:
            result = build_export_zip(client)
        assert result.decrypt_failures == 0
        assert result.image_failures == 0

        zf = zipfile.ZipFile(io.BytesIO(result.zip_bytes))
        names = set(zf.namelist())
        assert {"journal.csv", "accounts.csv", "medical.csv", "vouchers.csv",
                "backup.json", "README.txt", "vouchers/voucher_5.png"} <= names

        # CSV は UTF-8 BOM 付き
        journal = zf.read("journal.csv")
        assert journal[:3] == b"\xef\xbb\xbf"
        text = journal.decode("utf-8-sig")
        assert "弁当" in text and "食費" in text and "3000" in text

        # 証憑画像は復号されて元 PNG に戻る
        assert zf.read("vouchers/voucher_5.png") == png

        # vouchers.csv にファイル名が載る
        assert "voucher_5.png" in zf.read("vouchers.csv").decode("utf-8-sig")

        # 医療費 CSV
        assert "山田" in zf.read("medical.csv").decode("utf-8-sig")

        # backup.json は暗号文 backup をそのまま含む (restore 可能)
        backup = json.loads(zf.read("backup.json"))
        assert backup["data"]["journal_entries"][0]["encrypted_blob"]

    def test_image_failure_counted(self) -> None:
        raw = _raw_backup(_png())
        raw["data"]["vouchers"][0] = {"id": 5, "journal_entry_id": 1, "_imageError": "boom"}
        client = _client(raw)
        with client:
            result = build_export_zip(client)
        assert result.image_failures == 1
        zf = zipfile.ZipFile(io.BytesIO(result.zip_bytes))
        assert "(取得失敗)" in zf.read("vouchers.csv").decode("utf-8-sig")

    def test_decrypt_failure_counted(self) -> None:
        # user_id を取り違えた client で復号すると全行 _decryptError
        png = _png()
        client = _client(_raw_backup(png))
        client._user_id = 999  # AAD 不一致
        with client:
            result = build_export_zip(client)
        assert result.decrypt_failures >= 1
        zf = zipfile.ZipFile(io.BytesIO(result.zip_bytes))
        assert "(復号失敗)" in zf.read("journal.csv").decode("utf-8-sig")
