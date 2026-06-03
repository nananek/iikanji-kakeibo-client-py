"""csv_export (csv.js 移植) のユニットテスト。"""

from iikanji import csv_export as c


class TestEscapeCell:
    def test_plain(self) -> None:
        assert c.escape_cell("abc") == "abc"
        assert c.escape_cell(123) == "123"

    def test_none_empty(self) -> None:
        assert c.escape_cell(None) == ""

    def test_quoting(self) -> None:
        assert c.escape_cell("a,b") == '"a,b"'
        assert c.escape_cell('a"b') == '"a""b"'
        assert c.escape_cell("a\nb") == '"a\nb"'
        assert c.escape_cell("a\rb") == '"a\rb"'


class TestToCsv:
    def test_crlf_and_trailing(self) -> None:
        out = c.to_csv(["x", "y"], [[1, 2], [3, 4]])
        assert out == "x,y\r\n1,2\r\n3,4\r\n"


class TestJournalCsv:
    def _data(self) -> dict:
        return {
            "accounts": [{"code": "7010", "name": "食費"}, {"code": "1010", "name": "現金"}],
            "journal_entries": [
                {"id": 1, "entry_number": 5, "fiscal_year": 2026, "fiscal_month": 2,
                 "date": "2026-02-15", "description": "弁当", "source": "api"},
            ],
            "journal_entry_lines": [
                {"journal_entry_id": 1, "account_code": "7010", "debit_amount": 3000, "credit_amount": 0},
                {"journal_entry_id": 1, "account_code": "1010", "debit_amount": 0, "credit_amount": 3000},
            ],
        }

    def test_columns_and_values(self) -> None:
        out = c.build_journal_csv(self._data())
        lines = out.rstrip("\r\n").split("\r\n")
        assert lines[0] == "仕訳ID,日付,伝票番号,摘要,source,年度,月,科目コード,科目名,借方金額,貸方金額"
        assert lines[1] == "1,2026-02-15,5,弁当,api,2026,2,7010,食費,3000,0"
        assert lines[2] == "1,2026-02-15,5,弁当,api,2026,2,1010,現金,0,3000"

    def test_decrypt_failed_marker(self) -> None:
        data = self._data()
        data["journal_entries"][0] = {"id": 1, "entry_number": 5, "fiscal_year": 2026,
                                      "fiscal_month": 2, "_decryptError": "InvalidTag"}
        out = c.build_journal_csv(data)
        assert "(復号失敗)" in out

    def test_missing_entry(self) -> None:
        data = self._data()
        data["journal_entries"] = []  # 親仕訳なし
        out = c.build_journal_csv(data)
        # 日付/摘要は空、金額は出る
        assert ",,," in out


class TestAccountsCsv:
    def test_active_flag_and_columns(self) -> None:
        data = {"accounts": [
            {"code": "7010", "name": "食費", "tax_category": "課税", "is_active": True},
            {"code": "9999", "name": "旧科目", "is_active": False, "deactivated_year": 2024},
        ]}
        out = c.build_accounts_csv(data)
        lines = out.rstrip("\r\n").split("\r\n")
        assert lines[0] == "コード,名称,説明,税区分,原価区分,system_role,有効,廃止年"
        assert lines[1] == "7010,食費,,課税,,,1,"
        assert lines[2] == "9999,旧科目,,,,,0,2024"


class TestMedicalCsv:
    def test_values(self) -> None:
        data = {"medical_expenses": [
            {"journal_entry_id": 1, "date": "2026-03-20", "patient_name": "山田",
             "hospital_name": "○○病院", "treatment_description": "歯科", "provider_type": "hospital",
             "amount_paid": 12000, "insurance_reimbursement": 4000},
        ]}
        out = c.build_medical_csv(data)
        lines = out.rstrip("\r\n").split("\r\n")
        assert lines[0] == "仕訳ID,日付,受診者,医療機関,内容,区分,支払額,補填額"
        assert lines[1] == "1,2026-03-20,山田,○○病院,歯科,hospital,12000,4000"

    def test_decrypt_failed(self) -> None:
        data = {"medical_expenses": [{"journal_entry_id": 1, "_decryptError": "x"}]}
        out = c.build_medical_csv(data)
        assert "(復号失敗)" in out


class TestVouchersCsv:
    def test_filename_and_columns(self) -> None:
        data = {"vouchers": [
            {"id": 5, "journal_entry_id": 1, "file_hash": "abc", "file_size": 123,
             "uploaded_at": "2026-06-01T00:00:00"},
            {"id": 6, "journal_entry_id": None, "_imageError": "boom"},
        ]}
        out = c.build_vouchers_csv(data, {5: "voucher_5.png"})
        lines = out.rstrip("\r\n").split("\r\n")
        assert lines[0] == "証憑ID,仕訳ID,ファイル名,file_hash,サイズ(bytes),アップロード日時"
        assert lines[1] == "5,1,voucher_5.png,abc,123,2026-06-01T00:00:00"
        assert lines[2] == "6,,(取得失敗),,,"
