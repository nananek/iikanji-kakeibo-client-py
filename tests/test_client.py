"""KakeiboClient のユニットテスト"""

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
)


def _make_transport(status_code: int, body: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return httpx.MockTransport(handler)


def _make_client(status_code: int, body: dict) -> KakeiboClient:
    transport = _make_transport(status_code, body)
    http_client = httpx.Client(
        transport=transport,
        base_url="https://test.example.com",
        headers={"Authorization": "Bearer ik_testkey"},
    )
    return KakeiboClient(
        "https://test.example.com",
        "ik_testkey",
        http_client=http_client,
    )


SAMPLE_JOURNAL = {
    "id": 42,
    "date": "2026-02-15",
    "entry_number": 7,
    "description": "テスト仕訳",
    "source": "api",
    "lines": [
        {"account_code": "7010", "debit": 1000, "credit": 0, "description": ""},
        {"account_code": "1010", "debit": 0, "credit": 1000, "description": "メモ"},
    ],
}


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

    def test_sends_correct_payload(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
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
        assert payload["date"] == "2026-01-10"
        assert payload["description"] == "食材"
        assert payload["source"] == "custom"
        assert len(payload["lines"]) == 2
        assert payload["lines"][0] == {"account_code": "7010", "debit": 500, "description": "メモ"}
        assert payload["lines"][1] == {"account_code": "1010", "credit": 500}

    def test_with_draft_id(self) -> None:
        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1, "draft_id": 10})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
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
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
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
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
            client.create_journal(
                date=date(2026, 3, 1),
                description="date objectテスト",
                lines=[JournalLine(account_code="1010", debit=100), JournalLine(account_code="1020", credit=100)],
            )

        assert captured[0]["date"] == "2026-03-01"

    def test_datetime_object(self) -> None:
        from datetime import datetime

        captured: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, json={"ok": True, "id": 1, "entry_number": 1})

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
            client.create_journal(
                date=datetime(2026, 3, 1, 14, 30, 0),
                description="datetimeテスト",
                lines=[JournalLine(account_code="1010", debit=100), JournalLine(account_code="1020", credit=100)],
            )

        assert captured[0]["date"] == "2026-03-01"


class TestGetJournal:
    def test_success(self) -> None:
        client = _make_client(200, {"ok": True, "journal": SAMPLE_JOURNAL})

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
            "journals": [SAMPLE_JOURNAL],
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

    def test_sends_query_params(self) -> None:
        captured_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_urls.append(str(request.url))
            return httpx.Response(200, json={
                "ok": True, "journals": [], "total": 0, "page": 2, "per_page": 10,
            })

        http_client = httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://test.example.com",
            headers={"Authorization": "Bearer ik_testkey"},
        )

        with KakeiboClient("https://test.example.com", "ik_testkey", http_client=http_client) as client:
            client.list_journals(date_from="2026-01-01", date_to="2026-01-31", page=2, per_page=10)

        url = captured_urls[0]
        assert "date_from=2026-01-01" in url
        assert "date_to=2026-01-31" in url
        assert "page=2" in url
        assert "per_page=10" in url


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

    def test_needs_ledger_fetches_ledger_context(self) -> None:
        """Round 1 で needs_ledger=true なら ledger-context POST を挟む。"""
        server_calls: list[httpx.Request] = []

        def server_handler(request: httpx.Request) -> httpx.Response:
            server_calls.append(request)
            path = request.url.path
            if path == "/api/v1/ai/uploads":
                return httpx.Response(201, json={"ok": True, "draft_id": 7})
            if path == "/api/v1/ai/prompt-context":
                return httpx.Response(200, json=self._PROMPT_CTX)
            if path == "/api/v1/ai/ledger-context":
                return httpx.Response(200, json={"ledger_text": "LEDGER_DATA"})
            if path.endswith("/suggestions"):
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(404)

        openai_responses = [
            self._make_openai_response({
                "date": "2026-02-15", "description": "給与",
                "amount": 250000, "document_type": "payslip",
                "needs_ledger": True, "requested_accounts": ["給料手当"],
            }),
            self._make_openai_response({
                "suggestions": [{
                    "title": "給与", "description": "",
                    "date": "2026-02-15", "entry_description": "給与",
                    "lines": [
                        {"account_code": "5010", "debit_amount": 250000,
                         "credit_amount": 0},
                        {"account_code": "1010", "debit_amount": 0,
                         "credit_amount": 250000},
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
            client.analyze(b"\xff\xd8")

        # ledger-context が呼ばれた
        assert any(
            r.url.path == "/api/v1/ai/ledger-context" for r in server_calls
        )
        # Round 2 プロンプトに LEDGER_DATA が含まれる
        assert "LEDGER_DATA" in round2_seen_prompt[1]

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
