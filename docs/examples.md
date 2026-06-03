# 使用例

## 食費の記録（現金払い）

```python
from iikanji import KakeiboClient, JournalLine

with KakeiboClient("https://example.com", "ik_your_key") as client:
    client.create_journal(
        date="2026-02-15",
        description="スーパーで食材購入",
        lines=[
            JournalLine(account_code="7010", debit=3500),   # 食費
            JournalLine(account_code="1010", credit=3500),  # 現金
        ],
    )
```

## 給与の記録（複数行）

```python
from datetime import date
from iikanji import KakeiboClient, JournalLine

with KakeiboClient("https://example.com", "ik_your_key") as client:
    client.create_journal(
        date=date(2026, 2, 25),
        description="2月分給与",
        lines=[
            JournalLine(account_code="1020", debit=300000),    # 普通預金（手取り）
            JournalLine(account_code="3010", debit=45000),    # 源泉所得税
            JournalLine(account_code="3020", debit=25000),    # 住民税
            JournalLine(account_code="3030", debit=30000),    # 社会保険料
            JournalLine(account_code="5010", credit=400000),  # 給与収入
        ],
    )
```

## CSV からの一括登録

```python
import csv
from iikanji import KakeiboClient, JournalLine, KakeiboAPIError

ACCOUNT_MAP = {
    "食費": "7010",
    "交通費": "7030",
    "日用品": "7040",
}

with KakeiboClient("https://example.com", "ik_your_key") as client:
    with open("expenses.csv") as f:
        reader = csv.DictReader(f)
        for row in reader:
            category = row["カテゴリ"]
            account_code = ACCOUNT_MAP.get(category)
            if not account_code:
                print(f"不明なカテゴリ: {category}, スキップ")
                continue

            try:
                result = client.create_journal(
                    date=row["日付"],
                    description=row["摘要"],
                    lines=[
                        JournalLine(account_code=account_code, debit=int(row["金額"])),
                        JournalLine(account_code="1010", credit=int(row["金額"])),
                    ],
                )
                print(f"登録完了: 伝票#{result.entry_number}")
            except KakeiboAPIError as e:
                print(f"エラー: {row['摘要']} - {e.message}")
```

## 仕訳の閲覧

```python
from iikanji import KakeiboClient

with KakeiboClient("https://example.com", "ik_your_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")

    # 一覧取得（年度で絞り込み）。日付での絞り込みは取得後に行う
    result = client.list_journals(fiscal_year=2026)
    print(f"全{result.total}件中 {len(result.journals)}件取得")

    for j in result.journals:
        if j.date and "2026-02" <= j.date <= "2026-02-28":
            print(f"  #{j.entry_number} {j.date} {j.description}")

    # 1件取得
    detail = client.get_journal(journal_id=42)
    print(f"伝票#{detail.entry_number}: {detail.description}")
    for line in detail.lines:
        print(f"  科目{line.account_code}: 借方{line.debit} 貸方{line.credit}")
```

## 医療費明細（医療費控除）

医療費明細は仕訳に紐付けて登録します（1 仕訳に 1 件、`journal_entry_id` で upsert）。

```python
from iikanji import KakeiboClient

with KakeiboClient("https://example.com", "ik_your_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")

    # まず医療費の支払い仕訳を作成し、その仕訳に医療費明細を紐付ける
    me_id = client.upsert_medical_expense(
        journal_entry_id=42,
        date="2026-03-20",
        patient_name="山田太郎",
        hospital_name="○○歯科クリニック",
        treatment_description="歯科治療",
        provider_type="hospital",   # hospital / pharmacy / nursing / other
        amount_paid=12000,
        insurance_reimbursement=4000,
    )

    # 年度の医療費明細を一覧（医療費控除の集計などに利用）
    result = client.list_medical_expenses(fiscal_year=2026)
    total = sum(e.amount_paid - e.insurance_reimbursement for e in result.expenses)
    print(f"{result.total}件 / 自己負担合計 {total}円")
```

## 検索・試算表

復号はクライアント側で行うため、検索や集計もローカルで完結します。

```python
from iikanji import KakeiboClient

with KakeiboClient("https://example.com", "ik_your_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")

    # 摘要・科目・日付で検索
    hits = client.search_journals(fiscal_year=2026, text="食材", account_code="5010")
    for e in hits:
        print(f"{e.date} {e.description}")

    # 試算表（決算振替前）
    tb = client.trial_balance(fiscal_year=2026)
    for row in tb.rows:
        print(f"  {row.code} {row.name}（{row.account_type}）残高 {row.balance}")
    print(f"借方合計 {tb.total_debit} / 貸方合計 {tb.total_credit}")

    # 勘定科目の一覧（科目名・区分の参照に）
    accounts = client.list_accounts()

    # 確定済み期間の残高キャッシュ（読み込みのみ）
    cache = client.list_balance_cache_blobs(2026)
    # cache[period][account_code] == (累計借方, 累計貸方)
```

## 仕訳の削除

```python
from iikanji import KakeiboClient, KakeiboAPIError

with KakeiboClient("https://example.com", "ik_your_key") as client:
    try:
        client.delete_journal(journal_id=42)
        print("削除しました")
    except KakeiboAPIError as e:
        print(f"削除できません: {e.message}")
```

## AI 証憑仕訳 — レシートから自動仕訳

```python
from iikanji import KakeiboClient, JournalLine

with KakeiboClient("https://example.com", "ik_your_key") as client:
    # 画像を AI 解析（ファイルパス指定）
    result = client.analyze("receipt.jpg", comment="コンビニで購入")
    print(f"下書きID: {result.draft_id}")

    # 最初の候補を確認
    s = result.suggestions[0]
    print(f"候補: {s['entry_description']} ({s['date']})")
    for line in s["lines"]:
        print(f"  {line['account_name']}: 借方{line['debit_amount']} 貸方{line['credit_amount']}")

    # そのまま仕訳として確定
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

## AI 証憑仕訳 — 下書き一覧から処理

```python
from iikanji import KakeiboClient, JournalLine

with KakeiboClient("https://example.com", "ik_your_key") as client:
    # 未確定の下書き一覧
    result = client.list_drafts(status="analyzed")
    print(f"未処理の下書き: {result.total}件")

    for item in result.drafts:
        # 詳細を取得
        draft = client.get_draft(item.id)
        s = draft.suggestions[0]
        print(f"  [{item.id}] {s['date']} {s['entry_description']}")

        # 仕訳確定
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
            draft_id=item.id,
        )
        print(f"    → 確定しました")
```

## AI 証憑仕訳 — バイト列から解析

```python
from iikanji import KakeiboClient

with KakeiboClient("https://example.com", "ik_your_key") as client:
    # カメラやHTTPレスポンスから取得したバイト列を直接渡す
    image_bytes = b"..."  # 画像のバイト列
    result = client.analyze(
        image_bytes,
        mime_type="image/png",
        comment="経費精算",
        notify=True,  # Webhook 通知を送信
    )
```

## タイムアウトの変更

```python
# AI 解析は時間がかかることがあるのでタイムアウトを延長
client = KakeiboClient(
    "https://example.com",
    "ik_your_key",
    timeout=60.0,
)
```

## 行レベルの摘要

仕訳全体の摘要とは別に、各明細行に摘要を付けられます。

```python
with KakeiboClient("https://example.com", "ik_your_key") as client:
    client.create_journal(
        date="2026-02-15",
        description="日用品購入",
        lines=[
            JournalLine(account_code="7040", debit=500, description="洗剤"),
            JournalLine(account_code="7040", debit=300, description="ゴミ袋"),
            JournalLine(account_code="1010", credit=800),
        ],
    )
```

## 証憑画像の E2EE アップロードと取得

レシート等の証憑画像をクライアント側で暗号化して保存し、後で復号して取り出します。
画像・サムネ・メタはサーバーに暗号文のまま保存され、復号には MK（パスフレーズ解錠）が
必要です。

```python
from iikanji import KakeiboClient, crypto

with KakeiboClient("https://example.com", "ik_your_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")

    # 仕訳に紐付けて証憑をアップロード（サムネは Pillow で自動生成）
    v = client.upload_voucher("receipt.jpg", journal_entry_id=123)
    print(v.voucher_id, v.aad_id, v.file_hash_cipher)

    # 本体画像を復号取得
    data = client.download_voucher_image(v.voucher_id, v.aad_id)
    ext = crypto.sniff_image_mime(data).split("/")[-1]
    with open(f"voucher.{ext}", "wb") as f:
        f.write(data)

    # サムネを復号取得（has_thumbnail が True のときのみ）
    if v.has_thumbnail:
        thumb = client.download_voucher_image(v.voucher_id, v.aad_id, thumb=True)

    # 一覧（amount で絞り込み可。aad_id が None の証憑はレガシー平文で復号不可）
    for item in client.list_vouchers(amount_from=1000).vouchers:
        print(item.id, item.aad_id, item.amount)

    # 改ざん検知（サーバー側で暗号文ハッシュを再計算、MK 不要）
    print(client.verify_voucher(v.voucher_id)["verified"])
```

`aad_id` は画像を再取得・復号する際の AAD 束縛に必須です。`voucher_id` は backup/restore で
再採番されることがありますが、`aad_id` は保持されるため復号互換が保たれます。

## 全データバックアップ / リストア

`.ikbackup`（MK と独立したパスフレーズで暗号化したアーカイブ）で全データを保存・復元します。
アーカイブは暗号文 backup をそのまま包むため、サーバーは平文を一切持ちません。

```python
from iikanji import KakeiboClient, crypto

with KakeiboClient("https://example.com", "ik_your_key") as client:
    # 暗号文 backup をパスフレーズアーカイブ (.ikbackup) として保存 (MK 不要)
    client.save_encrypted_backup("backup.ikbackup", "disaster-passphrase")

    # アーカイブから全置換リストア (backup:restore スコープが必要)
    restored = client.restore_encrypted_backup("backup.ikbackup", "disaster-passphrase")
    print(restored)  # {"tables": {...}} 復元件数
```

中身を人間可読に取り出したいときは MK 解錠して復号エクスポートします（復元には使えません）。

```python
with KakeiboClient("https://example.com", "ik_your_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")
    decrypted = client.export_backup_decrypted()
    for e in decrypted["data"]["journal_entries"]:
        print(e.get("date"), e.get("description"))
```

`.ikbackup` のアーカイブ形式（Argon2id + AES-256-GCM）は Web の設定画面（バックアップ）と
共通で、どちら側でも復号できます。ただし中身は異なります — client-py は**暗号文 backup**
（復元可能）を包むのに対し、Web のエクスポートは**復号済み平文**（人間可読、復元には不向き）
を包みます。パスフレーズは 8 文字以上が必要です。

## CSV + 画像 zip エクスポート

CLI（`iikanji export`）と同じ zip をプログラムから生成できます。

```python
from iikanji import KakeiboClient
from iikanji.export import build_export_zip

with KakeiboClient("https://example.com", "ik_your_key") as client:
    if not client.is_unlocked:
        client.unlock("あなたのパスフレーズ")
    result = build_export_zip(client)  # journals:read スコープ
    with open("export.zip", "wb") as f:
        f.write(result.zip_bytes)
    print(f"復号失敗 {result.decrypt_failures} 件 / 画像取得失敗 {result.image_failures} 件")
```

zip には `journal.csv` / `accounts.csv` / `medical.csv` / `vouchers.csv`（UTF-8 BOM）、
復号済みの証憑画像（`vouchers/voucher_<id>.<ext>`）、`backup.json`（暗号文・リストア用）、
`README.txt` が含まれます。復号できなかったレコードは CSV 上 `(復号失敗)` と表示されます。

## 監査連携（HPKE 非同期ワークフロー）

owner が MK 復号したスナップショットを監査者の公開鍵で HPKE 暗号化して送り、監査者が
秘密鍵で復号して修正案を暗号化返信します。MK は共有しません。

```python
from iikanji import KakeiboClient

# --- owner 側: Lv3 スナップショットを送信 ---
with KakeiboClient("https://example.com", "ik_owner_key") as owner:
    owner.unlock("ownerのパスフレーズ")
    owner.ensure_keypair()  # 初回のみ鍵ペアを生成・保管
    pkg = owner.send_lv3_snapshot(audit_grant_id=1, round_id=1, auditor_user_id=8)
    print("送信:", pkg["id"])

# --- auditor 側: 受信・復号して修正案を返信 ---
import json
with KakeiboClient("https://example.com", "ik_auditor_key") as auditor:
    auditor.unlock("auditorのパスフレーズ")
    auditor.ensure_keypair()
    for pkg in auditor.list_audit_packages(role="auditor"):
        snapshot = json.loads(auditor.open_audit_package(pkg))  # 自分の秘密鍵で復号
        owner_pub = auditor.get_peer_public_key(pkg["owner_user_id"])
        auditor.send_audit_response(
            audit_package_id=pkg["id"], response_type="revision",
            recipient_public_key=owner_pub, plaintext=b'{"note": "ここを修正してください"}',
        )

# --- owner 側: 返信を復号して確認 ---
with KakeiboClient("https://example.com", "ik_owner_key") as owner:
    owner.unlock("ownerのパスフレーズ")
    for resp in owner.list_audit_responses():
        body = owner.open_audit_response(resp)
        print(resp["response_type"], body)
        owner.acknowledge_audit_response(resp["id"])
```

上の例は Lv3（本人同等）の送信です。Lv1（集計のみ）/ Lv2（税務科目 + 集計）は
`send_snapshot(..., level=1, fiscal_year=2026)` のように送れます。

```python
with KakeiboClient("https://example.com", "ik_owner_key") as owner:
    owner.unlock("ownerのパスフレーズ")
    owner.ensure_keypair()
    owner.send_snapshot(audit_grant_id=1, round_id=1, auditor_user_id=8,
                        level=1, fiscal_year=2026)   # Lv1 集計のみ
    owner.send_snapshot(audit_grant_id=2, round_id=1, auditor_user_id=9,
                        level=2, fiscal_year=2026)   # Lv2 税務科目限定
```

スナップショットの暗号化は suite = DHKEM-X25519-HKDF-SHA256 / HKDF-SHA256 / AES-256-GCM
（RFC 9180）で、Web の `@hpke/core` と相互運用できます。集計（試算表 / P/L / B/S / 月次 /
税務集計）は Web の `crypto/reports/*.js` と出力構造が一致します。

## レポート集計（試算表 / P/L / B/S / 元帳）

仕訳を復号してクライアント側で各種レポートを集計します（要 MK 解錠、`journals:read`）。

```python
from iikanji import KakeiboClient

with KakeiboClient("https://example.com", "ik_your_key") as client:
    client.unlock("あなたのパスフレーズ")

    tb = client.trial_balance(fiscal_year=2026)          # 試算表
    print(tb.total_debit, tb.total_credit)

    pl = client.profit_loss(fiscal_year=2026)            # 損益計算書 (年間)
    print("当期純利益:", pl.net_income)
    pl_jan = client.profit_loss(fiscal_year=2026, month=1)  # 1月のみ

    bs = client.balance_sheet(fiscal_year=2026)          # 貸借対照表
    print("資産合計:", bs.total_assets)

    led = client.ledger(fiscal_year=2026, account_code="1010")  # 現金の元帳
    for row in led.rows:
        print(row.date, row.debit, row.credit, row.balance, row.counterparts)
    print("期末残高:", led.closing_balance)
```

集計ロジック（`iikanji.reports` の純粋関数）は Web の `crypto/reports/*.js` と出力構造が
一致します。元帳は date が暗号化されているため `entry.id` 昇順（作成順 ≈ 時系列）で並びます。
