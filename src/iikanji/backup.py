"""全データバックアップの復号 (backup_export_client.js の Python 移植)。

``GET /api/v1/backup/export`` は暗号文を含む JSON を返す。本モジュールはそれを
本人 MK で復号して **平文の dict** に変換する (人間可読 / レポート集計用)。

復号失敗は当該行のみ局所化し、失敗行には ``_decryptError`` を記録する
(1 件の失敗で全体を中断しない。Web ``decryptBackup`` と同じ方針)。

リストアには暗号文をそのまま使う (:meth:`KakeiboClient.restore_backup`) ため、
本モジュールの復号は読み出し専用の用途に限る。
"""

from __future__ import annotations

from . import crypto


def _period_key(year: int, period: int) -> int:
    return year * 100 + period


def _decrypt_one(
    mk: bytes, blob_b64: str | None, iv_b64: str | None, aad: bytes
) -> tuple[dict | None, str | None]:
    """1 件の暗号文を復号する。``(body, error)`` を返す (両方 None なら blob 無し)。"""
    if not blob_b64 or not iv_b64:
        return None, None
    try:
        body = crypto.decrypt_record(
            mk, crypto.b64decode(blob_b64), crypto.b64decode(iv_b64), aad
        )
        return body, None
    except Exception as exc:  # noqa: BLE001 - 局所化して _decryptError に記録
        # InvalidTag は str() が空文字列になるため型名でフォールバック
        return None, str(exc) or type(exc).__name__


def decrypt_backup(mk: bytes, user_id: int, backup: dict) -> dict:
    """サーバから取得した backup JSON を本人 MK で復号する。

    je / jel / me / bcb の ``encrypted_blob`` を復号して各行に展開する。
    vouchers / ai_drafts / user_ai_config / 各種設定は暗号文/画像をそのまま通す
    (画像はサーバストレージに保存、AI 設定の api_key_blob は MK 復号せずパススルー)。

    Args:
        mk: マスターキー (32B)
        user_id: AAD 構築用の数値 user_id
        backup: ``/api/v1/backup/export`` のレスポンス JSON

    Returns:
        同じ shape の dict (各 row の暗号文を平文 body に展開、bcb は ``cumulative``)。
    """
    if not isinstance(backup, dict):
        raise TypeError("backup must be a dict")
    data = backup.get("data")
    if not isinstance(data, dict):
        raise TypeError("backup.data must be a dict")

    out_data: dict = {
        "accounts": data.get("accounts") or [],
        "fiscal_closes": data.get("fiscal_closes") or [],
        "journal_entries": [],
        "journal_entry_lines": [],
        "medical_expenses": [],
        "balance_cache_blobs": [],
        # 画像はサーバストレージに保存・復号不要のためそのまま通す
        "vouchers": data.get("vouchers") or [],
        "ai_drafts": data.get("ai_drafts") or [],
        # api_key_blob (暗号文) を含む。MK 復号せずパススルー
        "user_ai_config": data.get("user_ai_config"),
        "tax_form_mappings": data.get("tax_form_mappings") or [],
        "csv_column_profiles": data.get("csv_column_profiles") or [],
    }

    for e in data.get("journal_entries") or []:
        body, err = _decrypt_one(
            mk, e.get("encrypted_blob"), e.get("blob_iv"),
            crypto.build_aad("je", user_id),
        )
        row = {k: v for k, v in e.items() if k not in ("encrypted_blob", "blob_iv")}
        if body:
            row.update(body)
        elif err:
            row["_decryptError"] = err
        out_data["journal_entries"].append(row)

    for line in data.get("journal_entry_lines") or []:
        body, err = _decrypt_one(
            mk, line.get("encrypted_blob"), line.get("blob_iv"),
            crypto.build_aad("jel", user_id),
        )
        row = {
            k: v for k, v in line.items()
            if k not in ("encrypted_blob", "blob_iv")
        }
        if body:
            row.update(body)
        elif err:
            row["_decryptError"] = err
        out_data["journal_entry_lines"].append(row)

    for m in data.get("medical_expenses") or []:
        body, err = _decrypt_one(
            mk, m.get("encrypted_blob"), m.get("blob_iv"),
            crypto.build_aad("me", user_id),
        )
        row = {k: v for k, v in m.items() if k not in ("encrypted_blob", "blob_iv")}
        if body:
            row.update(body)
        elif err:
            row["_decryptError"] = err
        out_data["medical_expenses"].append(row)

    for b in data.get("balance_cache_blobs") or []:
        body, err = _decrypt_one(
            mk, b.get("encrypted_blob"), b.get("blob_iv"),
            crypto.build_aad("bcb", user_id, _period_key(b["year"], b["period"])),
        )
        row: dict = {
            "year": b.get("year"),
            "period": b.get("period"),
            "updated_at": b.get("updated_at"),
        }
        if body is not None:
            row["cumulative"] = body
        elif err:
            row["_decryptError"] = err
        out_data["balance_cache_blobs"].append(row)

    return {
        "version": backup.get("version"),
        "exported_at": backup.get("exported_at"),
        "user_id": user_id,
        "data": out_data,
    }
