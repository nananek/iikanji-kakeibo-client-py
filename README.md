# iikanji — いいかんじ家計簿 Python クライアント

いいかんじ家計簿サーバーの API を Python から呼び出すためのクライアントライブラリです。
仕訳の起票・閲覧・削除、AI 証憑仕訳（画像解析・下書き管理）、証憑画像の E2EE
保存（アップロード・取得・サムネ生成）、全データバックアップ / リストア（`.ikbackup`
パスフレーズアーカイブ）に対応しています。

## E2EE（エンドツーエンド暗号化）について

いいかんじ家計簿 v5.0 以降、仕訳データ（日付・摘要・明細）はクライアント側で
**マスターキー（MK）による AES-256-GCM 暗号化**を行ってから送信されます。サーバー
は暗号文しか保持しません。そのため、仕訳の起票・閲覧の前に **パスフレーズで MK を
解錠** する必要があります。

- MK の解錠: `client.unlock("あなたのパスフレーズ")`
- パスフレーズは Web の **設定 → 暗号鍵管理** で登録したものと同じです
- 解錠した MK は **OS のキーリング**（macOS Keychain / Windows 資格情報マネージャー /
  Linux Secret Service）に保存され、次回以降は自動で復元されます
- `client.lock()` でメモリとキーリングから MK を消去できます

## インストール

```bash
uv add iikanji
```

## クイックスタート

```python
from iikanji import KakeiboClient, JournalLine

with KakeiboClient("https://your-server.example.com", "ik_your_api_key") as client:
    # 初回のみ: パスフレーズで MK を解錠 (以後は OS キーリングから自動復元)
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")

    result = client.create_journal(
        date="2026-02-15",
        description="スーパーで食材購入",
        lines=[
            JournalLine(account_code="7010", debit=3000),   # 食費（借方）
            JournalLine(account_code="1010", credit=3000),  # 現金（貸方）
        ],
    )
    print(f"仕訳ID: {result.id}, 伝票番号: {result.entry_number}")
```

### AI 証憑仕訳

```python
with KakeiboClient("https://your-server.example.com", "ik_your_api_key") as client:
    # レシート画像を AI 解析して下書き作成
    result = client.analyze("receipt.jpg", comment="コンビニ")
    print(f"下書きID: {result.draft_id}, 候補数: {len(result.suggestions)}")

    # 下書き一覧（ページネーション対応）
    result = client.list_drafts()
    drafts = result.drafts

    # 候補を確認して仕訳確定
    draft = client.get_draft(result.draft_id)
    s = draft.suggestions[0]
    client.create_journal(
        date=s["date"],
        description=s["entry_description"],
        lines=[
            JournalLine(
                account_code=line["account_code"],
                debit=line["debit_amount"],
                credit=line["credit_amount"],
            )
            for line in s["lines"]
        ],
        draft_id=result.draft_id,  # 下書きを確定済みにする
    )
```

### 証憑画像の E2EE 保存

```python
from iikanji import KakeiboClient, crypto

with KakeiboClient("https://your-server.example.com", "ik_your_api_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")

    # 画像を暗号化して 2 段階アップロード（サムネは Pillow で自動生成）
    v = client.upload_voucher("receipt.jpg", journal_entry_id=123)
    print(f"証憑ID: {v.voucher_id}, aad_id: {v.aad_id}")

    # 一覧から aad_id を取得して画像を復号取得
    for item in client.list_vouchers().vouchers:
        if item.aad_id is not None:  # E2EE 証憑のみ復号可能
            data = client.download_voucher_image(item.id, item.aad_id)
            ext = crypto.sniff_image_mime(data).split("/")[-1]  # jpeg / png ...
            with open(f"voucher_{item.id}.{ext}", "wb") as f:
                f.write(data)
```

画像・サムネ・メタはクライアントで暗号化され、サーバーには暗号文しか渡りません。`aad_id`
は画像の再取得・復号に必須なので保存しておいてください（backup/restore で `voucher_id` が
再採番されても `aad_id` は保持されます）。

API キーはサーバーの **設定 > API キー管理** から発行できます。必要なスコープ（`journals:create`, `journals:read`, `journals:delete`, `ai:analyze`）を選択してください。

## ドキュメント

- [はじめに](docs/getting-started.md) — インストールと基本的な使い方
- [API リファレンス](docs/api-reference.md) — クラス・メソッド・例外の詳細
- [使用例](docs/examples.md) — CSV 一括登録、AI 証憑仕訳など実践的なサンプル

## 要件

- Python 3.12+
- いいかんじ家計簿サーバーの API キー

## 開発

```bash
uv sync --extra dev
uv run pytest
```

GitHub Actions でも push/PR 時にテストが自動実行されます。

## ライセンス

[MIT License](LICENSE) — Copyright (c) 2026- nananek

このクライアントライブラリは MIT License で配布されており、本サーバー向け以外
の用途にも自由に利用できます。サーバー本体 (`iikanji-kakeibo`) は別途
Sustainable Use License v1.0 で配布されており、商用 SaaS としての提供は
制限されますが、本クライアントには制限はかかりません。
