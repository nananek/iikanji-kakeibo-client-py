"""E2 PR-D-a: クライアント完結 E2EE フロー用 LLM ヘルパー (OpenAI)。

サーバ側 ai_receipt.analyze_and_suggest (E2 PR-C-4i で削除済) と等価の
Round 1 + Round 2 ロジックを Python で再実装する。

設計:
- client-py オーナーが OpenAI API キーをローカル保持する前提
  (サーバ E2EE blob の復号は browser SharedWorker でのみ可能)
- prompt 材料は /api/v1/ai/prompt-context から取得 (サーバ実装と整合)
- 画像 + プロンプトは OpenAI API に直接送る (サーバを通らない)

Anthropic / Google 対応は E2 PR-D-b で追加予定。
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx


OPENAI_URL = "https://api.openai.com/v1/chat/completions"


# ============ JSON 抽出 ============

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def extract_json(text: str) -> dict[str, Any]:
    """LLM 応答 (markdown コードブロック等を含むことがある) から JSON を抽出。

    サーバ側 ai_receipt._extract_json と等価。
    """
    text = text.strip()
    # コードブロック抽出
    m = _JSON_FENCE.search(text)
    if m:
        text = m.group(1).strip()
    # 最後の `}` で切る (LLM が余計な文字列を後ろに付ける場合の保険)
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in response")
    end = text.rfind("}")
    if end < 0 or end <= start:
        raise ValueError("invalid JSON range in response")
    return json.loads(text[start:end + 1])


# ============ OpenAI 画像 呼出 ============

def call_openai_image(
    *,
    api_key: str,
    model: str,
    image_bytes: bytes,
    mime_type: str,
    prompt: str,
    max_tokens: int = 2000,
    timeout: float = 60.0,
    http_client: httpx.Client | None = None,
) -> dict[str, Any]:
    """OpenAI Chat Completions API (画像 + テキスト) を呼んで JSON を返す。"""
    if not api_key:
        raise ValueError("api_key is required")
    b64 = base64.b64encode(image_bytes).decode("ascii")
    body = {
        "model": model,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:{mime_type};base64,{b64}"},
                },
            ],
        }],
        "max_tokens": max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if http_client is not None:
        resp = http_client.post(OPENAI_URL, json=body, headers=headers,
                                 timeout=timeout)
    else:
        resp = httpx.post(OPENAI_URL, json=body, headers=headers,
                           timeout=timeout)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"OpenAI API error: HTTP {resp.status_code} {resp.text[:200]}",
        )
    data = resp.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content")
    if not isinstance(content, str):
        raise RuntimeError("OpenAI response missing content")
    return extract_json(content)


# ============ Round 1 / Round 2 ============

@dataclass
class DocumentAnalysis:
    """Round 1 解析結果 (サーバ側 ai_receipt.DocumentAnalysis と同形)。"""

    date: str | None = None
    description: str = ""
    amount: int = 0
    document_type: str = "other"
    items: list[dict[str, Any]] = field(default_factory=list)
    needs_ledger: bool = False
    requested_accounts: list[str] = field(default_factory=list)


def build_round1_prompt(
    *,
    round1_prompt: str,
    compliance_check_enabled: bool = False,
    compliance_prompt: str = "",
    custom_prompt: str = "",
    comment: str = "",
) -> str:
    """サーバ側 ai_receipt.analyze_and_suggest の Round 1 プロンプト組立と等価。"""
    p = round1_prompt
    if compliance_check_enabled and compliance_prompt:
        p += compliance_prompt
    if custom_prompt:
        p += f"\n\n## ユーザー定型情報\n{custom_prompt}"
    if comment:
        p += f"\n\nユーザーからのコメント: {comment}"
    return p


def parse_document_analysis(raw: dict[str, Any]) -> DocumentAnalysis:
    """LLM 応答を DocumentAnalysis に整形。"""
    amount = raw.get("amount", 0)
    try:
        amount_int = int(amount) if amount is not None else 0
    except (TypeError, ValueError):
        amount_int = 0
    return DocumentAnalysis(
        date=raw.get("date"),
        description=raw.get("description", "") or "",
        amount=amount_int,
        document_type=raw.get("document_type", "other") or "other",
        items=raw.get("items", []) if isinstance(raw.get("items"), list) else [],
        needs_ledger=raw.get("needs_ledger") is True,
        requested_accounts=(
            raw.get("requested_accounts", [])
            if isinstance(raw.get("requested_accounts"), list) else []
        ),
    )


def parse_compliance_result(raw: Any) -> dict[str, Any] | None:
    """compliance フィールド整形。pass/warn/fail 以外は pass に正規化。"""
    if not isinstance(raw, dict):
        return None
    status = raw.get("status", "pass")
    if status not in ("pass", "warn", "fail"):
        status = "pass"
    return {
        "status": status,
        "warnings": (
            raw.get("warnings", [])
            if isinstance(raw.get("warnings"), list) else []
        ),
        "details": (
            raw.get("details", [])
            if isinstance(raw.get("details"), list) else []
        ),
    }


def build_round2_prompt(
    *,
    prompt_context: dict[str, Any],
    needs_ledger: bool,
    ledger_text: str = "",
) -> str:
    """Round 2 プロンプトを構築。needs_ledger に応じて 2 テンプレートを切替。

    サーバ側 ai_prompt_context endpoint が返す
    round2_prompt_template_no_ledger / round2_prompt_template_with_ledger
    の __ACCOUNT_LIST_TEXT__ (および with_ledger 版は __LEDGER_TEXT__) を
    置換する。
    """
    account_list = prompt_context.get("account_list_text", "")
    if needs_ledger:
        tpl = prompt_context.get("round2_prompt_template_with_ledger", "")
        return (
            tpl
            .replace("__ACCOUNT_LIST_TEXT__", account_list)
            .replace("__LEDGER_TEXT__", ledger_text)
        )
    tpl = prompt_context.get("round2_prompt_template_no_ledger", "")
    return tpl.replace("__ACCOUNT_LIST_TEXT__", account_list)


def validate_suggestions(
    raw: dict[str, Any], valid_codes: set[str],
) -> list[dict[str, Any]]:
    """LLM 応答の suggestions を整形 + account_code バリデーション。

    サーバ側 analyze_and_suggest の最終整形と等価。lines がすべて
    valid_codes 内になければその suggestion を捨てる。空なら RuntimeError。
    """
    suggestions_raw = raw.get("suggestions", [])
    if not isinstance(suggestions_raw, list):
        return []
    result: list[dict[str, Any]] = []
    for s in suggestions_raw:
        if not isinstance(s, dict):
            continue
        lines = []
        for line in s.get("lines", []) or []:
            if not isinstance(line, dict):
                continue
            acode = str(line.get("account_code", ""))
            if acode not in valid_codes:
                continue
            try:
                d = int(line.get("debit_amount", 0) or 0)
                c = int(line.get("credit_amount", 0) or 0)
            except (TypeError, ValueError):
                continue
            lines.append({
                "account_code": acode,
                "account_name": line.get("account_name", "") or "",
                "debit_amount": d,
                "credit_amount": c,
            })
        if lines:
            result.append({
                "title": s.get("title", "仕訳案") or "仕訳案",
                "description": s.get("description", "") or "",
                "date": s.get("date"),
                "entry_description": s.get("entry_description", "") or "",
                "lines": lines,
            })
    return result
