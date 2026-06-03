"""人間可読 CSV の生成 (Web ``export/csv.js`` の Python 移植)。

:func:`iikanji.backup.decrypt_backup` が返す復号済み dict (``out["data"][*]``) を、
表計算で開ける CSV 文字列へ変換する純粋関数群。暗号文 body 由来の値は復号失敗時に
``_decryptError`` が立つ行があり、その場合は欠落を握りつぶさず ``(復号失敗)`` を
出力して可視化する。

改行は RFC 4180 の CRLF。BOM は付けない (呼び出し側が UTF-8 BOM を付与する)。
"""

from __future__ import annotations

DECRYPT_FAILED = "(復号失敗)"


def escape_cell(value: object) -> str:
    """1 セルを RFC 4180 でエスケープする。``"`` ``,`` 改行を含む値は ``"`` で囲む。"""
    if value is None:
        return ""
    s = str(value)
    if any(c in s for c in ('"', ",", "\r", "\n")):
        return '"' + s.replace('"', '""') + '"'
    return s


def to_csv(headers: list[str], rows: list[list[object]]) -> str:
    """ヘッダ + データ行を CSV 文字列にする (改行 CRLF、末尾にも CRLF)。"""
    lines = [",".join(escape_cell(h) for h in headers)]
    for row in rows:
        lines.append(",".join(escape_cell(c) for c in row))
    return "\r\n".join(lines) + "\r\n"


def build_account_name_map(accounts: list[dict] | None) -> dict:
    """accounts から ``code -> name`` の dict を作る。"""
    return {a.get("code"): a.get("name") for a in (accounts or [])}


def _coalesce(value: object) -> object:
    """JS の ``x ?? ""`` 相当 (None を空文字に)。"""
    return "" if value is None else value


def _body_val(row: dict | None, key: str) -> object:
    """暗号文 body 由来の値を取り出す。復号失敗行は ``(復号失敗)``。"""
    if row and row.get("_decryptError"):
        return DECRYPT_FAILED
    v = row.get(key) if row else None
    return "" if v is None else v


def build_journal_csv(data: dict) -> str:
    """仕訳帳 CSV。明細 1 行 = CSV 1 行 (伝票レベル列は反復)。"""
    account_names = build_account_name_map(data.get("accounts"))
    entry_by_id = {e.get("id"): e for e in data.get("journal_entries") or []}
    headers = [
        "仕訳ID", "日付", "伝票番号", "摘要", "source", "年度", "月",
        "科目コード", "科目名", "借方金額", "貸方金額",
    ]
    rows = []
    for line in data.get("journal_entry_lines") or []:
        e = entry_by_id.get(line.get("journal_entry_id"))
        code = line.get("account_code")
        rows.append([
            line.get("journal_entry_id"),
            _body_val(e, "date"),
            _coalesce(e.get("entry_number")) if e else "",
            _body_val(e, "description"),
            _body_val(e, "source"),
            _coalesce(e.get("fiscal_year")) if e else "",
            _coalesce(e.get("fiscal_month")) if e else "",
            _coalesce(code),
            _coalesce(account_names.get(code)),
            _coalesce(line.get("debit_amount")) if line.get("debit_amount") is not None else 0,
            _coalesce(line.get("credit_amount")) if line.get("credit_amount") is not None else 0,
        ])
    return to_csv(headers, rows)


def build_accounts_csv(data: dict) -> str:
    """勘定科目マスタ CSV。"""
    headers = [
        "コード", "名称", "説明", "税区分", "原価区分", "system_role",
        "有効", "廃止年",
    ]
    rows = []
    for a in data.get("accounts") or []:
        rows.append([
            _coalesce(a.get("code")),
            _coalesce(a.get("name")),
            _coalesce(a.get("description")),
            _coalesce(a.get("tax_category")),
            _coalesce(a.get("cost_type")),
            _coalesce(a.get("system_role")),
            "1" if a.get("is_active") else "0",
            _coalesce(a.get("deactivated_year")),
        ])
    return to_csv(headers, rows)


def build_medical_csv(data: dict) -> str:
    """医療費 CSV。値は暗号文 body 由来 (復号失敗時 ``(復号失敗)``)。"""
    headers = [
        "仕訳ID", "日付", "受診者", "医療機関", "内容", "区分",
        "支払額", "補填額",
    ]
    rows = []
    for m in data.get("medical_expenses") or []:
        rows.append([
            _coalesce(m.get("journal_entry_id")),
            _body_val(m, "date"),
            _body_val(m, "patient_name"),
            _body_val(m, "hospital_name"),
            _body_val(m, "treatment_description"),
            _body_val(m, "provider_type"),
            _body_val(m, "amount_paid"),
            _body_val(m, "insurance_reimbursement"),
        ])
    return to_csv(headers, rows)


def build_vouchers_csv(data: dict, image_names: dict | None = None) -> str:
    """証憑メタデータ CSV (画像本体は zip の vouchers/ に別途格納)。"""
    headers = [
        "証憑ID", "仕訳ID", "ファイル名", "file_hash", "サイズ(bytes)",
        "アップロード日時",
    ]
    image_names = image_names or {}
    rows = []
    for v in data.get("vouchers") or []:
        name = image_names.get(v.get("id"))
        if name is None:
            name = "(取得失敗)" if v.get("_imageError") else ""
        rows.append([
            _coalesce(v.get("id")),
            _coalesce(v.get("journal_entry_id")),
            name,
            _coalesce(v.get("file_hash")),
            _coalesce(v.get("file_size")),
            _coalesce(v.get("uploaded_at")),
        ])
    return to_csv(headers, rows)
