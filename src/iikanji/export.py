"""全データを CSV + 証憑画像 + backup.json の zip にエクスポート (Web ``export/`` 移植)。

``export_renderer.mjs`` の Python 再現。本人 MK で復号した人間可読 CSV、復号した
証憑画像、機械可読な暗号文 backup.json、README を 1 つの zip にまとめる。

zip 構造 (Web と同一):
  journal.csv / accounts.csv / medical.csv / vouchers.csv  (UTF-8 BOM 付き)
  vouchers/voucher_<id>.<ext>                                (復号済み画像)
  backup.json                                                (暗号文パススルー)
  README.txt
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass

from . import crypto, csv_export

# sniff_image_mime の結果 → 拡張子 (export_renderer.mjs: MIME_EXT)。
MIME_EXT = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
}


@dataclass
class ExportResult:
    """:func:`build_export_zip` の結果。"""

    zip_bytes: bytes
    decrypt_failures: int  # CSV 上 (復号失敗) になった件数
    image_failures: int  # 取得/復号できなかった証憑画像の件数


def _count_decrypt_failures(decrypted: dict) -> int:
    n = 0
    data = decrypted.get("data", {})
    for tbl in ("journal_entries", "journal_entry_lines", "medical_expenses"):
        for r in data.get(tbl) or []:
            if r.get("_decryptError"):
                n += 1
    return n


def _build_voucher_images(client, vouchers: list[dict]) -> tuple[dict, dict, int]:
    """証憑画像を復号して ``{zip パス: bytes}`` を作る。

    Returns:
        ``(files, image_names, image_failures)``。image_names は ``voucher.id -> 名前``。
    """
    files: dict[str, bytes] = {}
    image_names: dict = {}
    image_fail = 0
    for v in vouchers:
        if v.get("_imageError") or not v.get("image_data"):
            image_fail += 1
            continue
        try:
            enc = crypto.b64decode(v["image_data"])
            aad_id = v.get("aad_id")
            # E4 (#111) 以降は aad_id ありで暗号化済。aad_id なしは旧平文。
            if aad_id:
                plain = client.decrypt_voucher_image_blob(enc, int(aad_id))
            else:
                plain = enc
            ext = MIME_EXT.get(crypto.sniff_image_mime(plain), "bin")
            base = f"voucher_{v.get('id')}.{ext}"
            files["vouchers/" + base] = plain
            image_names[v.get("id")] = base
        except Exception:
            image_fail += 1
    return files, image_names, image_fail


def _readme(exported_at: str | None, decrypt_failures: int, image_fail: int) -> str:
    return (
        "いいかんじ™家計簿 データエクスポート\n"
        f"生成日時: {exported_at or '(不明)'}\n"
        "\n"
        "【内容】\n"
        "- journal.csv   : 仕訳帳 (明細 1 行 = 1 レコード)\n"
        "- accounts.csv  : 勘定科目マスタ\n"
        "- medical.csv   : 医療費\n"
        "- vouchers.csv  : 証憑メタデータ\n"
        "- vouchers/     : 証憑画像ファイル\n"
        "- backup.json   : 機械可読バックアップ (暗号文のまま)。\n"
        "                  restore_backup() で再取り込みできます。\n"
        "\n"
        "【注意】\n"
        "- CSV は UTF-8 (BOM 付き) です。Excel でそのまま開けます。\n"
        "- backup.json はサーバが保持する暗号文をそのまま含みます。復号には\n"
        "  本人のマスター鍵 (MK) が必要です。\n"
        '- 復号できなかったレコードは CSV 上 "(復号失敗)" と表示されます。\n'
        "\n"
        f"復号失敗: {decrypt_failures} 件\n"
        f"画像取得失敗: {image_fail} 件\n"
    )


def build_export_zip(client) -> ExportResult:
    """全データを取得・復号して CSV/画像/backup.json/README の zip を作る。

    事前に ``client`` が MK 解錠済みである必要がある (証憑画像と CSV の復号に必要)。
    必要なスコープ: ``journals:read``。

    Args:
        client: 解錠済み :class:`~iikanji.client.KakeiboClient`

    Returns:
        ExportResult: zip バイト列 + 復号失敗 / 画像取得失敗の件数
    """
    raw = client.export_backup()
    decrypted = client.export_backup_decrypted(raw)
    data = decrypted.get("data", {})

    voucher_files, image_names, image_fail = _build_voucher_images(
        client, data.get("vouchers") or []
    )
    decrypt_failures = _count_decrypt_failures(decrypted)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        def text_file(name: str, body: str) -> None:
            # UTF-8 BOM を付与 (Excel が文字化けしないように)
            zf.writestr(name, ("﻿" + body).encode("utf-8"))

        text_file("journal.csv", csv_export.build_journal_csv(data))
        text_file("accounts.csv", csv_export.build_accounts_csv(data))
        text_file("medical.csv", csv_export.build_medical_csv(data))
        text_file("vouchers.csv", csv_export.build_vouchers_csv(data, image_names))
        zf.writestr(
            "backup.json", json.dumps(raw, ensure_ascii=False).encode("utf-8")
        )
        # 画像は既に圧縮済みなので無圧縮で格納する
        for name, content in voucher_files.items():
            zf.writestr(name, content, compress_type=zipfile.ZIP_STORED)
        text_file(
            "README.txt",
            _readme(decrypted.get("exported_at"), decrypt_failures, image_fail),
        )

    return ExportResult(
        zip_bytes=buf.getvalue(),
        decrypt_failures=decrypt_failures,
        image_failures=image_fail,
    )
