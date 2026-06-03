"""KakeiboClient のユニットテスト (E2EE: MK 解錠 + 暗号 wire)"""

import json

import httpx
import pytest

from iikanji import (
    AnalyzeResponse,
    AuthenticationError,
    DraftDetail,
    DraftListItem,
    DraftListResponse,
    JournalCreateResponse,
    JournalDetail,
    JournalLine,
    JournalListResponse,
    KakeiboAPIError,
    KakeiboClient,
    LockedError,
    MedicalExpense,
    MedicalExpenseListResponse,
    crypto,
)

# 固定のテスト用 MK / user_id。E2EE では仕訳の暗号化/復号に必要。
TEST_MK = bytes(range(32))  # 00..1f
TEST_USER_ID = 42
BASE_URL = "https://test.example.com"


def _make_transport(status_code: int, body: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return httpx.MockTransport(handler)


def _make_client(
    status_code: int, body: dict, *, unlocked: bool = True
) -> KakeiboClient:
    transport = _make_transport(status_code, body)
    http_client = httpx.Client(
        transport=transport,
        base_url=BASE_URL,
        headers={"Authorization": "Bearer ik_testkey"},
    )
    client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
    if unlocked:
        _set_mk(client)
    return client


def _set_mk(client: KakeiboClient) -> None:
    """テスト用に MK を直接セット (unlock のサーバ往復を省く)。"""
    client._mk = TEST_MK
    client._user_id = TEST_USER_ID


def _enc_entry_wire(
    entry_id: int,
    *,
    date: str = "2026-02-15",
    description: str = "テスト仕訳",
    source: str = "api",
    fiscal_period=None,
    lines: list[dict] | None = None,
    is_closing: bool = False,
    encrypt: bool = True,
) -> dict:
    """API レスポンス相当の (暗号化済み) journal dict を生成する。"""
    fiscal_year = int(date[:4])
    fiscal_month = fiscal_period if fiscal_period is not None else int(date[5:7])
    wire: dict = {
        "id": entry_id,
        "entry_number": 7,
        "fiscal_year": fiscal_year,
        "fiscal_month": fiscal_month,
        "is_closing": is_closing,
        "encrypted_blob": None,
        "blob_iv": None,
        "lines": [],
        "vouchers": [],
    }
    if encrypt and not is_closing:
        body = {
            "v": 1,
            "date": date,
            "description": description,
            "source": source,
            "fiscal_period": fiscal_period,
        }
        blob, iv = crypto.encrypt_record(
            TEST_MK, body, crypto.build_aad("je", TEST_USER_ID)
        )
        wire["encrypted_blob"] = crypto.b64encode(blob)
        wire["blob_iv"] = crypto.b64encode(iv)
    for ln in lines or []:
        line_body = {
            "v": 1,
            "account_code": ln["account_code"],
            "debit_amount": int(ln.get("debit", 0)),
            "credit_amount": int(ln.get("credit", 0)),
            "description": ln.get("description", ""),
        }
        lblob, liv = crypto.encrypt_record(
            TEST_MK, line_body, crypto.build_aad("jel", TEST_USER_ID)
        )
        wire["lines"].append({
            "id": ln.get("id", 1),
            "account_code": ln["account_code"],
            "debit": int(ln.get("debit", 0)),
            "credit": int(ln.get("credit", 0)),
            "encrypted_blob": crypto.b64encode(lblob),
            "blob_iv": crypto.b64encode(liv),
        })
    return wire


SAMPLE_LINES = [
    {"account_code": "7010", "debit": 1000, "credit": 0, "description": ""},
    {"account_code": "1010", "debit": 0, "credit": 1000, "description": "メモ"},
]


class TestCreateJournal:
    def test_success(self) -> None:
        client = _make_client(201, {"ok": True, "id": 42, "entry_number": 7})

        with client:
            result = client.create_journal(
                date="2026-02-15",
                description="テスト仕訳",
                lines=[
                    JournalLine(account_code="7010", debit=1000),
                    JournalLine(account_code="1010", credit=1000),
                ],
            )

        assert isinstance(result, JournalCreateResponse)
        assert result.id == 42
        assert result.entry_number == 7

    def test_requires_unlock(self) -> None:
        """MK 未解錠だと LockedError (サーバに送信しない)。"""
        client = _make_client(201, {"ok": True, "id": 1, "entry_number": 1}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.create_journal(
                date="2026-02-15",
                description="x",
                lines=[JournalLine(account_code="1010", debit=100)],
            )

    def test_sends_encrypted_payload(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )

        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.create_journal(
                date="2026-01-10",
                description="食材",
                lines=[
                    JournalLine(account_code="7010", debit=500, description="メモ"),
                    JournalLine(account_code="1010", credit=500),
                ],
                source="custom",
            )

        payload = captured[0]
        # 平文メタは fiscal_year / fiscal_month のみ。date/description/source は wire に無い
        assert payload["fiscal_year"] == 2026
        assert payload["fiscal_month"] == 1
        assert "date" not in payload and "description" not in payload and "source" not in payload
        assert "encrypted_blob" in payload and "blob_iv" in payload
        # entry blob を復号すると元の値が取れる
        body = crypto.decrypt_record(
            TEST_MK,
            crypto.b64decode(payload["encrypted_blob"]),
            crypto.b64decode(payload["blob_iv"]),
            crypto.build_aad("je", TEST_USER_ID),
        )
        assert body["date"] == "2026-01-10"
        assert body["description"] == "食材"
        assert body["source"] == "custom"
        # line: 平文は account_code/debit/credit のみ、description は暗号化
        assert len(payload["lines"]) == 2
        line0 = payload["lines"][0]
        assert line0["account_code"] == "7010" and line0["debit"] == 500
        assert "description" not in line0
        lbody = crypto.decrypt_record(
            TEST_MK,
            crypto.b64decode(line0["encrypted_blob"]),
            crypto.b64decode(line0["blob_iv"]),
            crypto.build_aad("jel", TEST_USER_ID),
        )
        assert lbody["description"] == "メモ"
        assert lbody["debit_amount"] == 500

    def test_fiscal_period_overrides_month(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )
        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.create_journal(
                date="2026-05-10",
                description="期首",
                lines=[JournalLine(account_code="1010", debit=1), JournalLine(account_code="1020", credit=1)],
                fiscal_period=0,
            )
        assert captured[0]["fiscal_month"] == 0

    def test_with_draft_id(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1, "draft_id": 10})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )

        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.create_journal(
                date="2026-01-10",
                description="下書きから確定",
                lines=[
                    JournalLine(account_code="7010", debit=500),
                    JournalLine(account_code="1010", credit=500),
                ],
                draft_id=10,
            )

        assert captured[0]["draft_id"] == 10

    def test_without_draft_id(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )

        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.create_journal(
                date="2026-01-10",
                description="通常の仕訳",
                lines=[
                    JournalLine(account_code="7010", debit=500),
                    JournalLine(account_code="1010", credit=500),
                ],
            )

        assert "draft_id" not in captured[0]

    def test_authentication_error(self) -> None:
        client = _make_client(401, {"error": "無効な API キーです。"})

        with client, pytest.raises(AuthenticationError) as exc_info:
            client.create_journal(
                date="2026-02-15",
                description="テスト",
                lines=[JournalLine(account_code="1010", debit=100)],
            )

        assert exc_info.value.status_code == 401
        assert "無効な API キー" in exc_info.value.message

    def test_validation_error(self) -> None:
        client = _make_client(400, {"error": "貸借が一致しません（借方: 1000, 貸方: 500）"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.create_journal(
                date="2026-02-15",
                description="テスト",
                lines=[
                    JournalLine(account_code="1010", debit=1000),
                    JournalLine(account_code="1020", credit=500),
                ],
            )

        assert exc_info.value.status_code == 400
        assert "貸借が一致しません" in exc_info.value.message

    def test_context_manager(self) -> None:
        client = _make_client(201, {"ok": True, "id": 1, "entry_number": 1})

        with client as c:
            assert c is client

    def test_date_object(self) -> None:
        from datetime import date

        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )

        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.create_journal(
                date=date(2026, 3, 1),
                description="date objectテスト",
                lines=[JournalLine(account_code="1010", debit=100), JournalLine(account_code="1020", credit=100)],
            )

        assert captured[0]["fiscal_year"] == 2026 and captured[0]["fiscal_month"] == 3

    def test_datetime_object(self) -> None:
        from datetime import datetime

        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )

        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.create_journal(
                date=datetime(2026, 3, 1, 14, 30, 0),
                description="datetimeテスト",
                lines=[JournalLine(account_code="1010", debit=100), JournalLine(account_code="1020", credit=100)],
            )

        assert captured[0]["fiscal_month"] == 3


class TestGetJournal:
    def test_success(self) -> None:
        journal = _enc_entry_wire(42, lines=SAMPLE_LINES)
        client = _make_client(200, {"ok": True, "journal": journal})

        with client:
            result = client.get_journal(42)

        assert isinstance(result, JournalDetail)
        assert result.id == 42
        assert result.date == "2026-02-15"
        assert result.entry_number == 7
        assert result.description == "テスト仕訳"
        assert result.source == "api"
        assert len(result.lines) == 2
        assert result.lines[0].account_code == "7010"
        assert result.lines[0].debit == 1000
        assert result.lines[1].description == "メモ"

    def test_requires_unlock(self) -> None:
        client = _make_client(200, {"ok": True, "journal": {}}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.get_journal(42)

    def test_closing_entry_synthesized(self) -> None:
        """closing 仕訳 (encrypted_blob=None) は fiscal_year から合成する。"""
        journal = _enc_entry_wire(99, is_closing=True, date="2026-01-01")
        client = _make_client(200, {"ok": True, "journal": journal})
        with client:
            result = client.get_journal(99)
        assert result.is_closing is True
        assert result.date == "2026-12-31"
        assert result.source == "closing"
        assert "損益振替" in result.description

    def test_not_found(self) -> None:
        client = _make_client(404, {"error": "仕訳が見つかりません。"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.get_journal(999)

        assert exc_info.value.status_code == 404

    def test_forbidden(self) -> None:
        client = _make_client(403, {"error": "この API キーには journals:read 権限がありません。"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.get_journal(1)

        assert exc_info.value.status_code == 403


class TestListJournals:
    def test_success(self) -> None:
        body = {
            "ok": True,
            "journals": [_enc_entry_wire(42, lines=SAMPLE_LINES)],
            "total": 1,
            "page": 1,
            "per_page": 20,
        }
        client = _make_client(200, body)

        with client:
            result = client.list_journals()

        assert isinstance(result, JournalListResponse)
        assert result.total == 1
        assert result.page == 1
        assert result.per_page == 20
        assert len(result.journals) == 1
        assert result.journals[0].id == 42
        assert result.journals[0].description == "テスト仕訳"

    def test_requires_unlock(self) -> None:
        client = _make_client(200, {"ok": True, "journals": [], "total": 0, "page": 1, "per_page": 20}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.list_journals()

    def test_sends_query_params(self) -> None:
        captured_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_urls.append(str(request.url))
            return httpx.Response(200, json={
                "ok": True, "journals": [], "total": 0, "page": 2, "per_page": 10,
            })

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )

        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.list_journals(fiscal_year=2026, page=2, per_page=10)

        url = captured_urls[0]
        assert "fiscal_year=2026" in url
        assert "page=2" in url
        assert "per_page=10" in url


def _enc_me_wire(
    expense_id: int,
    journal_entry_id: int,
    *,
    date: str = "2026-03-20",
    patient_name: str = "山田太郎",
    hospital_name: str = "○○病院",
    treatment_description: str = "歯科治療",
    provider_type: str | None = "hospital",
    amount_paid: int = 12000,
    insurance_reimbursement: int = 4000,
) -> dict:
    """GET /api/v1/medical-expenses の (暗号化済み) expense dict を生成する。"""
    body = {
        "v": 1,
        "date": date,
        "patient_name": patient_name,
        "hospital_name": hospital_name,
        "treatment_description": treatment_description,
        "provider_type": provider_type,
        "amount_paid": amount_paid,
        "insurance_reimbursement": insurance_reimbursement,
    }
    blob, iv = crypto.encrypt_record(
        TEST_MK, body, crypto.build_aad("me", TEST_USER_ID)
    )
    return {
        "id": expense_id,
        "journal_entry_id": journal_entry_id,
        "encrypted_blob": crypto.b64encode(blob),
        "blob_iv": crypto.b64encode(iv),
    }


class TestMedicalExpense:
    def test_upsert_success(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(200, json={"ok": True, "id": 5})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )
        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            me_id = client.upsert_medical_expense(
                journal_entry_id=42,
                date="2026-03-20",
                patient_name="山田太郎",
                hospital_name="○○病院",
                treatment_description="歯科治療",
                provider_type="hospital",
                amount_paid=12000,
                insurance_reimbursement=4000,
            )
        assert me_id == 5
        payload = captured[0]
        # 平文 wire は journal_entry_id のみ
        assert payload["journal_entry_id"] == 42
        assert "patient_name" not in payload and "amount_paid" not in payload
        assert "encrypted_blob" in payload and "blob_iv" in payload
        body = crypto.decrypt_record(
            TEST_MK,
            crypto.b64decode(payload["encrypted_blob"]),
            crypto.b64decode(payload["blob_iv"]),
            crypto.build_aad("me", TEST_USER_ID),
        )
        assert body["patient_name"] == "山田太郎"
        assert body["amount_paid"] == 12000
        assert body["provider_type"] == "hospital"

    def test_upsert_requires_unlock(self) -> None:
        client = _make_client(200, {"ok": True, "id": 1}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.upsert_medical_expense(journal_entry_id=1)

    def test_negative_amount_raises(self) -> None:
        client = _make_client(200, {"ok": True, "id": 1})
        with client, pytest.raises(ValueError):
            client.upsert_medical_expense(journal_entry_id=1, amount_paid=-100)

    def test_journal_not_found(self) -> None:
        client = _make_client(404, {"error": "仕訳が見つかりません。"})
        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.upsert_medical_expense(journal_entry_id=999)
        assert exc_info.value.status_code == 404

    def test_list_success(self) -> None:
        body = {
            "ok": True,
            "expenses": [_enc_me_wire(5, 42), _enc_me_wire(6, 43, patient_name="花子")],
            "total": 2,
        }
        client = _make_client(200, body)
        with client:
            result = client.list_medical_expenses(fiscal_year=2026)
        assert isinstance(result, MedicalExpenseListResponse)
        assert result.total == 2
        assert result.expenses[0].id == 5
        assert result.expenses[0].journal_entry_id == 42
        assert result.expenses[0].patient_name == "山田太郎"
        assert result.expenses[0].amount_paid == 12000
        assert result.expenses[1].patient_name == "花子"

    def test_list_sends_fiscal_year(self) -> None:
        urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            urls.append(str(request.url))
            return httpx.Response(200, json={"ok": True, "expenses": [], "total": 0})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )
        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        _set_mk(client)
        with client:
            client.list_medical_expenses(fiscal_year=2026)
        assert "fiscal_year=2026" in urls[0]

    def test_list_requires_unlock(self) -> None:
        client = _make_client(200, {"ok": True, "expenses": [], "total": 0}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.list_medical_expenses()

    def test_from_api_decrypt_failure_falls_back(self) -> None:
        """復号失敗 (壊れた blob) でもフィールドは既定値で復元する。"""
        bad = {
            "id": 9,
            "journal_entry_id": 1,
            "encrypted_blob": crypto.b64encode(b"not-a-valid-ciphertext-xxxxxxxxxx"),
            "blob_iv": crypto.b64encode(b"0" * 12),
        }
        me = MedicalExpense.from_api(bad, TEST_MK, TEST_USER_ID)
        assert me.id == 9 and me.journal_entry_id == 1
        assert me.patient_name == "" and me.amount_paid == 0


def _acct(code, name, account_type, normal_balance, display_order=0, system_role=None):
    type_names = {
        "asset": "資産", "liability": "負債", "equity": "純資産",
        "revenue": "収益", "expense": "費用",
    }
    return {
        "code": code, "name": name, "account_type": account_type,
        "account_type_name": type_names.get(account_type, ""),
        "normal_balance": normal_balance, "is_active": True,
        "system_role": system_role, "tax_category": None, "cost_type": None,
        "display_order": display_order,
    }


def _enc_bcb_blob(period: int, balances: dict, year: int = 2026) -> dict:
    blob, iv = crypto.encrypt_record(
        TEST_MK, balances,
        crypto.build_aad("bcb", TEST_USER_ID, year * 100 + period),
    )
    return {
        "year": year, "period": period,
        "encrypted_blob": crypto.b64encode(blob),
        "blob_iv": crypto.b64encode(iv),
        "updated_at": "2026-12-31T00:00:00",
    }


def _router_client(routes: dict) -> KakeiboClient:
    """パスごとに body を返すモッククライアント (unlocked)。

    routes: {path: body} or {path: callable(request)->body}。journals は
    ページング非対応の単発レスポンスを想定 (total <= per_page)。
    """
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = routes.get(path)
        if callable(body):
            body = body(request)
        if body is None:
            return httpx.Response(404, json={"error": f"no route: {path}"})
        return httpx.Response(200, json=body)

    http_client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url=BASE_URL,
        headers={"Authorization": "Bearer ik_testkey"},
    )
    client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
    _set_mk(client)
    return client


class TestLedgerContext:
    """AI Round 2 用クライアント側元帳構築 (JS ledger_context.js 互換)。"""

    def test_build_accounts_ledger_context_matches_js(self) -> None:
        from iikanji import llm

        entries = [
            JournalDetail(id=2, date="2026-02-25", entry_number=2,
                          description="2月給与", source="", lines=[
                              JournalLine("1010", 200000, 0),
                              JournalLine("4010", 0, 200000)]),
            JournalDetail(id=1, date="2026-01-25", entry_number=1,
                          description="1月給与", source="", lines=[
                              JournalLine("1010", 200000, 0),
                              JournalLine("4010", 0, 200000)]),
        ]
        got = llm.build_accounts_ledger_context(
            account_names=["給料収入"], journal_entries=entries,
            account_list_text="5010 食費\n1010 現金\n4010 給料収入",
        )
        # JS buildAccountsLedgerContext が同入力で生成した golden 出力と byte 一致
        golden = (
            "\n【給料収入】（4010）\n日付 | 摘要 | 借方 | 貸方\n"
            + "-" * 50
            + "\n2026-02-25 | 2月給与 | - | ¥200,000"
            + "\n2026-01-25 | 1月給与 | - | ¥200,000"
        )
        assert got == golden

    def test_no_match_returns_empty(self) -> None:
        from iikanji import llm
        assert llm.build_accounts_ledger_context(
            account_names=["存在しない科目"], journal_entries=[],
            account_list_text="1010 現金",
        ) == ""

    def test_empty_account_names_returns_empty(self) -> None:
        from iikanji import llm
        assert llm.build_accounts_ledger_context(
            account_names=[], journal_entries=[], account_list_text="1010 現金",
        ) == ""


class TestReports:
    def test_list_accounts(self) -> None:
        body = {"ok": True, "accounts": [
            _acct("1010", "現金", "asset", "debit", 10),
            _acct("5010", "食費", "expense", "debit", 80),
        ]}
        client = _router_client({"/api/v1/accounts": body})
        with client:
            accts = client.list_accounts()
        assert len(accts) == 2
        assert accts[0].code == "1010" and accts[0].name == "現金"
        assert accts[0].account_type == "asset" and accts[0].normal_balance == "debit"
        assert accts[1].account_type_name == "費用"

    def test_list_accounts_no_mk_required(self) -> None:
        body = {"ok": True, "accounts": [_acct("1010", "現金", "asset", "debit")]}
        client = _make_client(200, body, unlocked=False)
        with client:
            accts = client.list_accounts()  # MK 不要
        assert accts[0].code == "1010"

    def test_list_balance_cache_blobs(self) -> None:
        body = {"blobs": [
            _enc_bcb_blob(0, {"1010": [10000, 0]}),
            _enc_bcb_blob(12, {"1010": [50000, 20000], "5010": [12000, 0]}),
        ]}
        client = _router_client({"/api/v1/balance-cache-blobs": body})
        with client:
            cache = client.list_balance_cache_blobs(2026)
        assert cache[0]["1010"] == (10000, 0)
        assert cache[12]["1010"] == (50000, 20000)
        assert cache[12]["5010"] == (12000, 0)

    def test_balance_cache_requires_unlock(self) -> None:
        client = _make_client(200, {"blobs": []}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.list_balance_cache_blobs(2026)

    def test_search_journals_filters(self) -> None:
        journals = [
            _enc_entry_wire(1, date="2026-01-05", description="スーパー食材",
                            lines=[{"account_code": "5010", "debit": 3000, "description": ""},
                                   {"account_code": "1010", "credit": 3000, "description": ""}]),
            _enc_entry_wire(2, date="2026-03-20", description="電気代",
                            lines=[{"account_code": "5020", "debit": 8000, "description": ""},
                                   {"account_code": "1010", "credit": 8000, "description": ""}]),
        ]
        body = {"ok": True, "journals": journals, "total": 2, "page": 1, "per_page": 100}
        # date_from で絞り込み
        client = _router_client({"/api/v1/journals": body})
        with client:
            r = client.search_journals(fiscal_year=2026, date_from="2026-02-01")
        assert [e.id for e in r] == [2]
        # text で絞り込み
        client = _router_client({"/api/v1/journals": body})
        with client:
            r = client.search_journals(fiscal_year=2026, text="食材")
        assert [e.id for e in r] == [1]
        # account_code で絞り込み
        client = _router_client({"/api/v1/journals": body})
        with client:
            r = client.search_journals(fiscal_year=2026, account_code="5020")
        assert [e.id for e in r] == [2]

    def test_trial_balance_excludes_closing_by_default(self) -> None:
        accounts_body = {"ok": True, "accounts": [
            _acct("1010", "現金", "asset", "debit", 10),
            _acct("4010", "給与収入", "revenue", "credit", 70),
            _acct("5010", "食費", "expense", "debit", 80),
        ]}
        journals = [
            _enc_entry_wire(1, date="2026-01-05",
                            lines=[{"account_code": "5010", "debit": 3000, "description": ""},
                                   {"account_code": "1010", "credit": 3000, "description": ""}]),
            _enc_entry_wire(2, date="2026-02-25",
                            lines=[{"account_code": "1010", "debit": 200000, "description": ""},
                                   {"account_code": "4010", "credit": 200000, "description": ""}]),
            # closing 仕訳 (除外されるべき)
            _enc_entry_wire(99, is_closing=True, date="2026-12-31"),
        ]
        # closing 仕訳に line を 1 つ付ける (除外確認用)
        journals[2]["lines"] = [{
            "id": 1, "account_code": "5010", "debit": 0, "credit": 999,
            "encrypted_blob": None, "blob_iv": None,
        }]
        jbody = {"ok": True, "journals": journals, "total": 3, "page": 1, "per_page": 100}
        client = _router_client({
            "/api/v1/accounts": accounts_body,
            "/api/v1/journals": jbody,
        })
        with client:
            tb = client.trial_balance(fiscal_year=2026)
        by_code = {r.code: r for r in tb.rows}
        # closing の 5010 credit 999 は含まれない
        assert by_code["5010"].debit == 3000 and by_code["5010"].credit == 0
        assert by_code["5010"].balance == 3000  # 費用=借方正常
        assert by_code["1010"].debit == 200000 and by_code["1010"].credit == 3000
        assert by_code["1010"].balance == 197000  # 資産=借方正常
        assert by_code["4010"].credit == 200000
        assert by_code["4010"].balance == 200000  # 収益=貸方正常
        # 貸借合計一致
        assert tb.total_debit == tb.total_credit == 203000

    def test_trial_balance_include_closing(self) -> None:
        accounts_body = {"ok": True, "accounts": [_acct("5010", "食費", "expense", "debit", 80)]}
        j = _enc_entry_wire(99, is_closing=True, date="2026-12-31")
        j["lines"] = [{"id": 1, "account_code": "5010", "debit": 0, "credit": 999,
                       "encrypted_blob": None, "blob_iv": None}]
        jbody = {"ok": True, "journals": [j], "total": 1, "page": 1, "per_page": 100}
        client = _router_client({"/api/v1/accounts": accounts_body, "/api/v1/journals": jbody})
        with client:
            tb = client.trial_balance(fiscal_year=2026, include_closing=True)
        assert tb.rows[0].credit == 999

    def test_trial_balance_requires_unlock(self) -> None:
        client = _make_client(200, {"ok": True, "accounts": []}, unlocked=False)
        with client, pytest.raises(LockedError):
            client.trial_balance(fiscal_year=2026)


def _wrapped_keys_body() -> dict:
    """GET /api/v1/wrapped-keys のモックレスポンス (passphrase 方式)。

    GOLDEN_* と同じ固定入力で MK を導出できる wrapped_master_key を返す。
    """
    from tests.test_crypto import (
        GOLDEN_KDF_PARAMS,
        GOLDEN_SALT,
        GOLDEN_WRAP_IV,
        GOLDEN_WRAPPED_MK,
    )

    return {
        "user_id": 99,
        "wrapped_keys": [
            {
                "id": 1,
                "method": "passphrase",
                "wrapped_master_key": crypto.b64encode(GOLDEN_WRAPPED_MK),
                "wrap_iv": crypto.b64encode(GOLDEN_WRAP_IV),
                "salt": crypto.b64encode(GOLDEN_SALT),
                "kdf_params": GOLDEN_KDF_PARAMS,
            }
        ],
    }


class TestUnlock:
    def test_unlock_derives_and_persists(self) -> None:
        from tests.test_crypto import GOLDEN_MK_HEX, GOLDEN_PASSPHRASE

        client = _make_client(200, _wrapped_keys_body(), unlocked=False)
        assert client.is_unlocked is False
        with client:
            client.unlock(GOLDEN_PASSPHRASE)
            assert client.is_unlocked is True
            assert client._mk.hex() == GOLDEN_MK_HEX
            assert client._user_id == 99
            # keyring に永続化されている
            assert crypto.load_mk(BASE_URL) == (99, client._mk)

    def test_wrong_passphrase_raises(self) -> None:
        client = _make_client(200, _wrapped_keys_body(), unlocked=False)
        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.unlock("wrong passphrase")
        assert "パスフレーズ" in exc_info.value.message
        assert client.is_unlocked is False

    def test_no_passphrase_method_raises(self) -> None:
        body = {"user_id": 99, "wrapped_keys": [{"id": 1, "method": "passkey_prf"}]}
        client = _make_client(200, body, unlocked=False)
        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.unlock("x")
        assert "passphrase" in exc_info.value.message

    def test_lock_clears_state(self) -> None:
        from tests.test_crypto import GOLDEN_PASSPHRASE

        client = _make_client(200, _wrapped_keys_body(), unlocked=False)
        with client:
            client.unlock(GOLDEN_PASSPHRASE)
            assert client.is_unlocked is True
            client.lock()
            assert client.is_unlocked is False
            assert crypto.load_mk(BASE_URL) is None


class TestClientInit:
    def test_restores_mk_from_keyring(self) -> None:
        mk = bytes(range(32))
        crypto.store_mk(BASE_URL, 77, mk)
        http_client = httpx.Client(
            transport=_make_transport(200, {"ok": True}),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )
        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        assert client.is_unlocked is True
        assert client._user_id == 77
        assert client._mk == mk

    def test_starts_locked_without_keyring(self) -> None:
        http_client = httpx.Client(
            transport=_make_transport(200, {"ok": True}),
            base_url=BASE_URL,
            headers={"Authorization": "Bearer ik_testkey"},
        )
        client = KakeiboClient(BASE_URL, "ik_testkey", http_client=http_client)
        assert client.is_unlocked is False


class TestDeleteJournal:
    def test_success(self) -> None:
        client = _make_client(200, {"ok": True})

        with client:
            client.delete_journal(42)  # should not raise

    def test_not_found(self) -> None:
        client = _make_client(404, {"error": "仕訳が見つかりません。"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.delete_journal(999)

        assert exc_info.value.status_code == 404

    def test_locked_period(self) -> None:
        client = _make_client(400, {"error": "2026年1月は確定済みのため変更できません。"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.delete_journal(42)

        assert exc_info.value.status_code == 400
        assert "確定済み" in exc_info.value.message

    def test_sends_delete_method(self) -> None:
        captured_methods: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_methods.append(request.method)
            return httpx.Response(200, json={"ok": True})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
            client.delete_journal(1)

        assert captured_methods[0] == "DELETE"


# --- AI 証憑仕訳 ---


SAMPLE_SUGGESTIONS = [
    {
        "title": "食費",
        "date": "2026-02-19",
        "description": "レシート",
        "entry_description": "スーパーで食材購入",
        "lines": [
            {"account_code": "7010", "account_name": "食費", "debit_amount": 3000, "credit_amount": 0},
            {"account_code": "1010", "account_name": "現金", "debit_amount": 0, "credit_amount": 3000},
        ],
    }
]

SAMPLE_DRAFT = {
    "id": 10,
    "status": "analyzed",
    "comment": "テスト",
    "created_at": "2026-02-19T12:00:00",
    "summary": {
        "title": "食費",
        "date": "2026-02-19",
        "description": "スーパーで食材購入",
        "amount": 3000,
        "suggestion_count": 1,
    },
}


class TestAnalyze:
    """E2 PR-D-a: クライアント完結 2-step + OpenAI 呼出フロー。"""

    _PROMPT_CTX = {
        "ok": True,
        "round1_prompt": "DOC_PROMPT",
        "compliance_prompt": "",
        "compliance_check_enabled": False,
        "round2_prompt_template_no_ledger": "R2NL __ACCOUNT_LIST_TEXT__",
        "round2_prompt_template_with_ledger":
            "R2WL __ACCOUNT_LIST_TEXT__ L __LEDGER_TEXT__",
        "account_list_text": "5010 食費\n1010 現金",
        "custom_prompt": "",
        "default_model_by_provider": {
            "openai": "gpt-4o",
            "anthropic": "claude-sonnet-4-20250514",
            "google": "gemini-2.0-flash",
        },
    }

    def _make_openai_response(self, content: dict) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": json.dumps(content)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        })

    def test_requires_openai_api_key(self) -> None:
        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            http_client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda r: httpx.Response(200, json={}),
                ),
                base_url="https://test.example.com",
            ),
        ) as client:
            with pytest.raises(ValueError, match="openai_api_key"):
                client.analyze(b"\xff\xd8")

    def test_requires_anthropic_api_key(self) -> None:
        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            http_client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda r: httpx.Response(200, json={}),
                ),
                base_url="https://test.example.com",
            ),
        ) as client:
            with pytest.raises(ValueError, match="anthropic_api_key"):
                client.analyze(b"\xff\xd8", provider="anthropic")

    def test_unsupported_provider_raises(self) -> None:
        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            openai_api_key="sk-x",  # 何か一つはキーを設定
            http_client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda r: httpx.Response(200, json={}),
                ),
                base_url="https://test.example.com",
            ),
        ) as client:
            with pytest.raises(ValueError, match="evil_api_key"):
                client.analyze(b"\xff\xd8", provider="evil")

    def test_success_full_flow(self) -> None:
        """2-step フロー: uploads → prompt-context → Round 1 → Round 2 → save."""
        server_calls: list[httpx.Request] = []

        def server_handler(request: httpx.Request) -> httpx.Response:
            server_calls.append(request)
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={
                    "ok": True, "draft_id": 42, "status": "pending",
                })
            if path == "/api/v1/ai/prompt-context":
                return httpx.Response(200, json=self._PROMPT_CTX)
            if path == "/api/v1/ai/drafts/42/suggestions":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        # Round 1 + Round 2 の OpenAI 応答
        openai_responses = [
            self._make_openai_response({
                "date": "2026-02-15", "description": "セブン",
                "amount": 500, "document_type": "receipt",
                "needs_ledger": False, "requested_accounts": [],
            }),
            self._make_openai_response({
                "suggestions": [{
                    "title": "食費",
                    "description": "コンビニで食料品購入",
                    "date": "2026-02-15",
                    "entry_description": "セブン",
                    "lines": [
                        {"account_code": "5010", "account_name": "食費",
                         "debit_amount": 500, "credit_amount": 0},
                        {"account_code": "1010", "account_name": "現金",
                         "debit_amount": 0, "credit_amount": 500},
                    ],
                }],
            }),
        ]

        def openai_handler(request: httpx.Request) -> httpx.Response:
            return openai_responses.pop(0)

        server_client = httpx.Client(
            transport=httpx.MockTransport(server_handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )
        openai_client = httpx.Client(
            transport=httpx.MockTransport(openai_handler),
        )

        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            openai_api_key="sk-test",
            http_client=server_client,
            llm_http_client=openai_client,
        ) as client:
            result = client.analyze(b"\xff\xd8\xff\xe0", comment="テストメモ")

        assert isinstance(result, AnalyzeResponse)
        assert result.draft_id == 42
        assert len(result.suggestions) == 1
        assert result.suggestions[0]["title"] == "食費"
        assert result.suggestions[0]["lines"][0]["account_code"] == "5010"

        # サーバ呼出順: uploads → prompt-context → PATCH suggestions
        server_paths = [r.url.path for r in server_calls]
        assert server_paths == [
            "/api/v1/ai/uploads",
            "/api/v1/ai/prompt-context",
            "/api/v1/ai/drafts/42/suggestions",
        ]
        # PATCH ボディに provider/model 含む
        patch_body = json.loads(server_calls[2].content)
        assert patch_body["provider"] == "openai"
        assert patch_body["model"] == "gpt-4o"
        assert len(patch_body["suggestions"]) == 1

    def test_needs_ledger_builds_client_side(self) -> None:
        """needs_ledger=true なら復号仕訳から元帳をクライアント側で構築する。

        E2EE 化で旧 POST /api/v1/ai/ledger-context は撤去された。MK 解錠済みなら
        /api/v1/journals を取得・復号して元帳文脈を組み立て、Round 2 プロンプトに
        埋め込む。
        """
        server_calls: list[httpx.Request] = []
        # 給料収入(4010) の元帳になる仕訳 (年度 2026)
        year_journals = [
            _enc_entry_wire(2, date="2026-02-25", description="2月給与",
                            lines=[{"account_code": "1010", "debit": 200000, "description": ""},
                                   {"account_code": "4010", "credit": 200000, "description": ""}]),
        ]

        def server_handler(request: httpx.Request) -> httpx.Response:
            server_calls.append(request)
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={"ok": True, "draft_id": 7})
            if path == "/api/v1/ai/prompt-context":
                ctx = dict(self._PROMPT_CTX)
                ctx["account_list_text"] = "1010 現金\n4010 給料収入"
                return httpx.Response(200, json=ctx)
            if path == "/api/v1/journals":
                return httpx.Response(200, json={
                    "ok": True, "journals": year_journals,
                    "total": 1, "page": 1, "per_page": 100,
                })
            if path.endswith("/suggestions"):
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        openai_responses = [
            self._make_openai_response({
                "date": "2026-02-15", "description": "給与",
                "amount": 250000, "document_type": "payslip",
                "needs_ledger": True, "requested_accounts": ["給料収入"],
            }),
            self._make_openai_response({
                "suggestions": [{
                    "title": "給与", "description": "",
                    "date": "2026-02-15", "entry_description": "給与",
                    "lines": [
                        {"account_code": "4010", "debit_amount": 0,
                         "credit_amount": 250000},
                        {"account_code": "1010", "debit_amount": 250000,
                         "credit_amount": 0},
                    ],
                }],
            }),
        ]
        round2_seen_prompt: list[str] = []

        def openai_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            prompt = body["messages"][0]["content"][0]["text"]
            round2_seen_prompt.append(prompt)
            return openai_responses.pop(0)

        client = KakeiboClient(
            "https://test.example.com", "ik_testkey",
            openai_api_key="sk-x",
            http_client=httpx.Client(
                transport=httpx.MockTransport(server_handler),
                base_url="https://test.example.com",
                headers={"Authorization": "Bearer ik_testkey"},
            ),
            llm_http_client=httpx.Client(
                transport=httpx.MockTransport(openai_handler),
            ),
        )
        _set_mk(client)  # 元帳構築には MK 解錠が必要
        with client:
            client.analyze(b"\xff\xd8")

        # 廃止された ledger-context は呼ばれない
        assert all(
            r.url.path != "/api/v1/ai/ledger-context" for r in server_calls
        )
        # 仕訳を取得して元帳を構築している
        assert any(r.url.path == "/api/v1/journals" for r in server_calls)
        # Round 2 プロンプトにクライアント構築の元帳 (科目名/明細) が含まれる
        assert "【給料収入】（4010）" in round2_seen_prompt[1]
        assert "2月給与" in round2_seen_prompt[1]

    def test_needs_ledger_without_mk_skips_ledger(self) -> None:
        """MK 未解錠なら元帳なしで継続する (graceful degrade、journals は叩かない)。"""
        server_calls: list[httpx.Request] = []

        def server_handler(request: httpx.Request) -> httpx.Response:
            server_calls.append(request)
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={"ok": True, "draft_id": 7})
            if path == "/api/v1/ai/prompt-context":
                return httpx.Response(200, json=self._PROMPT_CTX)
            if path.endswith("/suggestions"):
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        openai_responses = [
            self._make_openai_response({
                "date": "2026-02-15", "description": "給与", "amount": 250000,
                "document_type": "payslip", "needs_ledger": True,
                "requested_accounts": ["給料収入"],
            }),
            self._make_openai_response({"suggestions": [{
                "title": "給与", "date": "2026-02-15", "entry_description": "給与",
                "lines": [{"account_code": "5010", "debit_amount": 250000, "credit_amount": 0},
                          {"account_code": "1010", "debit_amount": 0, "credit_amount": 250000}],
            }]}),
        ]

        def openai_handler(request: httpx.Request) -> httpx.Response:
            return openai_responses.pop(0)

        client = KakeiboClient(
            "https://test.example.com", "ik_testkey", openai_api_key="sk-x",
            http_client=httpx.Client(
                transport=httpx.MockTransport(server_handler),
                base_url="https://test.example.com",
                headers={"Authorization": "Bearer ik_testkey"},
            ),
            llm_http_client=httpx.Client(transport=httpx.MockTransport(openai_handler)),
        )
        # MK 未解錠のまま (unlocked にしない)
        with client:
            client.analyze(b"\xff\xd8")
        # journals は取得しない (元帳スキップ)
        assert all(r.url.path != "/api/v1/journals" for r in server_calls)

    def test_uploads_error_propagates(self) -> None:
        """uploads が失敗したら早期 raise。"""
        def server_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(413, json={"error": "too large"})

        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            openai_api_key="sk-x",
            http_client=httpx.Client(
                transport=httpx.MockTransport(server_handler),
                base_url="https://test.example.com",
                headers={"Authorization": "Bearer ik_testkey"},
            ),
        ) as client:
            with pytest.raises(KakeiboAPIError):
                client.analyze(b"\xff\xd8")

    def test_anthropic_provider(self) -> None:
        """provider=anthropic で Anthropic API を呼ぶ。"""
        server_calls: list[httpx.Request] = []

        def server_handler(request: httpx.Request) -> httpx.Response:
            server_calls.append(request)
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={"draft_id": 1})
            if path == "/api/v1/ai/prompt-context":
                return httpx.Response(200, json=self._PROMPT_CTX)
            if path.endswith("/suggestions"):
                body = json.loads(request.content)
                assert body["provider"] == "anthropic"
                assert body["model"] == "claude-sonnet-4-20250514"
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        llm_calls: list[httpx.Request] = []

        def anthropic_handler(request: httpx.Request) -> httpx.Response:
            llm_calls.append(request)
            return httpx.Response(200, json={
                "content": [{"text": json.dumps({
                    "needs_ledger": False,
                    "suggestions": [{
                        "title": "x", "lines": [
                            {"account_code": "5010", "debit_amount": 100,
                             "credit_amount": 0},
                            {"account_code": "1010", "debit_amount": 0,
                             "credit_amount": 100},
                        ],
                    }],
                })}],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            })

        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            anthropic_api_key="sk-ant-x",
            http_client=httpx.Client(
                transport=httpx.MockTransport(server_handler),
                base_url="https://test.example.com",
                headers={"Authorization": "Bearer ik_testkey"},
            ),
            llm_http_client=httpx.Client(
                transport=httpx.MockTransport(anthropic_handler),
            ),
        ) as client:
            client.analyze(b"\xff\xd8", provider="anthropic")

        # x-api-key + anthropic-version ヘッダで呼ばれている
        assert llm_calls[0].headers["x-api-key"] == "sk-ant-x"
        assert llm_calls[0].headers["anthropic-version"] == "2023-06-01"
        assert "api.anthropic.com" in str(llm_calls[0].url)

    def test_google_provider(self) -> None:
        """provider=google で Gemini API を呼ぶ (URL クエリで認証)。"""

        def server_handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={"draft_id": 1})
            if path == "/api/v1/ai/prompt-context":
                return httpx.Response(200, json=self._PROMPT_CTX)
            if path.endswith("/suggestions"):
                body = json.loads(request.content)
                assert body["provider"] == "google"
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        llm_calls: list[httpx.Request] = []

        def google_handler(request: httpx.Request) -> httpx.Response:
            llm_calls.append(request)
            return httpx.Response(200, json={
                "candidates": [{"content": {"parts": [
                    {"text": json.dumps({
                        "needs_ledger": False,
                        "suggestions": [{
                            "title": "x", "lines": [
                                {"account_code": "5010", "debit_amount": 100,
                                 "credit_amount": 0},
                                {"account_code": "1010", "debit_amount": 0,
                                 "credit_amount": 100},
                            ],
                        }],
                    })},
                ]}}],
                "usageMetadata": {"promptTokenCount": 10,
                                   "candidatesTokenCount": 5},
            })

        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            google_api_key="goog-key",
            http_client=httpx.Client(
                transport=httpx.MockTransport(server_handler),
                base_url="https://test.example.com",
                headers={"Authorization": "Bearer ik_testkey"},
            ),
            llm_http_client=httpx.Client(
                transport=httpx.MockTransport(google_handler),
            ),
        ) as client:
            client.analyze(b"\xff\xd8", provider="google")

        # URL クエリに ?key= が含まれる
        assert "key=goog-key" in str(llm_calls[0].url)
        assert "generativelanguage.googleapis.com" in str(llm_calls[0].url)

    def test_custom_model_used(self) -> None:
        """model 引数指定でデフォルトモデルを上書き。"""

        def server_handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={"draft_id": 1})
            if path == "/api/v1/ai/prompt-context":
                return httpx.Response(200, json=self._PROMPT_CTX)
            if path.endswith("/suggestions"):
                # PATCH body の model を検証
                body = json.loads(request.content)
                assert body["model"] == "gpt-4-vision-preview"
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        seen_models: list[str] = []

        def openai_handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            seen_models.append(body["model"])
            return httpx.Response(200, json={
                "choices": [{"message": {"content": json.dumps({
                    "needs_ledger": False, "requested_accounts": [],
                    "suggestions": [{
                        "title": "x", "lines": [
                            {"account_code": "5010", "debit_amount": 100,
                             "credit_amount": 0},
                            {"account_code": "1010", "debit_amount": 0,
                             "credit_amount": 100},
                        ],
                    }],
                })}}],
            })

        with KakeiboClient(
            "https://test.example.com", "ik_testkey",
            openai_api_key="sk-x",
            http_client=httpx.Client(
                transport=httpx.MockTransport(server_handler),
                base_url="https://test.example.com",
                headers={"Authorization": "Bearer ik_testkey"},
            ),
            llm_http_client=httpx.Client(
                transport=httpx.MockTransport(openai_handler),
            ),
        ) as client:
            client.analyze(b"\xff\xd8", model="gpt-4-vision-preview")

        # Round 1 と Round 2 両方で custom model が使われている
        assert seen_models == ["gpt-4-vision-preview", "gpt-4-vision-preview"]


class TestListDrafts:
    def test_success(self) -> None:
        body = {"ok": True, "drafts": [SAMPLE_DRAFT], "total": 1, "page": 1, "per_page": 50}
        client = _make_client(200, body)

        with client:
            result = client.list_drafts()

        assert isinstance(result, DraftListResponse)
        assert result.total == 1
        assert result.page == 1
        assert len(result.drafts) == 1
        assert isinstance(result.drafts[0], DraftListItem)
        assert result.drafts[0].id == 10
        assert result.drafts[0].status == "analyzed"
        assert result.drafts[0].summary is not None
        assert result.drafts[0].summary.amount == 3000

    def test_sends_status_param(self) -> None:
        captured_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_urls.append(str(request.url))
            return httpx.Response(200, json={"ok": True, "drafts": [], "total": 0, "page": 1, "per_page": 50})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
            client.list_drafts(status="all")

        assert "status=all" in captured_urls[0]


class TestGetDraft:
    def test_success(self) -> None:
        draft_with_suggestions = {**SAMPLE_DRAFT, "suggestions": SAMPLE_SUGGESTIONS}
        body = {"ok": True, "draft": draft_with_suggestions}
        client = _make_client(200, body)

        with client:
            result = client.get_draft(10)

        assert isinstance(result, DraftDetail)
        assert result.id == 10
        assert len(result.suggestions) == 1
        assert result.suggestions[0]["title"] == "食費"

    def test_not_found(self) -> None:
        client = _make_client(404, {"error": "下書きが見つかりません。"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.get_draft(999)

        assert exc_info.value.status_code == 404


class TestDeleteDraft:
    def test_success(self) -> None:
        client = _make_client(200, {"ok": True})

        with client:
            client.delete_draft(10)  # should not raise

    def test_not_found(self) -> None:
        client = _make_client(404, {"error": "下書きが見つかりません。"})

        with client, pytest.raises(KakeiboAPIError) as exc_info:
            client.delete_draft(999)

        assert exc_info.value.status_code == 404
