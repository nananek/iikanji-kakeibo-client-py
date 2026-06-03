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
