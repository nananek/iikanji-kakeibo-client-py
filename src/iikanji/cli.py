"""``iikanji`` コマンドライン (薄い CLI 基盤 + ``export`` サブコマンド)。

例::

    iikanji export --base-url https://example.com --api-key ik_xxx \
        --passphrase 'あなたのパスフレーズ' -o backup.zip

``--base-url`` / ``--api-key`` / ``--passphrase`` はそれぞれ環境変数
``IIKANJI_BASE_URL`` / ``IIKANJI_API_KEY`` / ``IIKANJI_PASSPHRASE`` で代替できる。
MK が既に OS keyring に保存済みなら ``--passphrase`` は省略できる。
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from . import export as export_mod
from .client import KakeiboClient
from .exceptions import KakeiboAPIError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iikanji",
        description="いいかんじ家計簿 Python クライアント CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser(
        "export",
        help="全データを CSV + 証憑画像 + backup.json の zip にエクスポートする",
    )
    p_export.add_argument(
        "--base-url", default=os.environ.get("IIKANJI_BASE_URL"),
        help="サーバ URL (env: IIKANJI_BASE_URL)",
    )
    p_export.add_argument(
        "--api-key", default=os.environ.get("IIKANJI_API_KEY"),
        help="Bearer API キー (env: IIKANJI_API_KEY)",
    )
    p_export.add_argument(
        "--passphrase", default=os.environ.get("IIKANJI_PASSPHRASE"),
        help="MK 解錠パスフレーズ (env: IIKANJI_PASSPHRASE)。keyring 保存済みなら不要",
    )
    p_export.add_argument(
        "-o", "--out", default=None,
        help="出力 zip パス (省略時 iikanji-export-<timestamp>.zip)",
    )
    return parser


def _cmd_export(args: argparse.Namespace) -> int:
    if not args.base_url or not args.api_key:
        print(
            "error: --base-url と --api-key (または環境変数) が必要です。",
            file=sys.stderr,
        )
        return 2

    out = args.out or f"iikanji-export-{datetime.now():%Y%m%d-%H%M%S}.zip"

    try:
        with KakeiboClient(args.base_url, args.api_key) as client:
            if not client.is_unlocked:
                if not args.passphrase:
                    print(
                        "error: マスター鍵が未解錠です。--passphrase または "
                        "IIKANJI_PASSPHRASE を指定してください。",
                        file=sys.stderr,
                    )
                    return 2
                client.unlock(args.passphrase)
            result = export_mod.build_export_zip(client)
    except KakeiboAPIError as exc:
        print(f"error: API エラー ({exc.status_code}): {exc}", file=sys.stderr)
        return 1

    Path(out).write_bytes(result.zip_bytes)
    print(
        f"エクスポート完了: {out} "
        f"(復号失敗 {result.decrypt_failures} 件 / "
        f"画像取得失敗 {result.image_failures} 件)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI エントリポイント。終了コードを返す。"""
    args = _build_parser().parse_args(argv)
    if args.command == "export":
        return _cmd_export(args)
    return 2  # argparse の required=True で通常到達しない


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
