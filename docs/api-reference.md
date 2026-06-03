# API リファレンス

## KakeiboClient

メインのクライアントクラス。コンテキストマネージャ（`with` 文）に対応。

### コンストラクタ

```python
KakeiboClient(
    base_url: str,
    api_key: str,
    *,
    timeout: float = 30.0,
    http_client: httpx.Client | None = None,
)
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `base_url` | `str` | サーバーの URL（例: `"https://example.com"`） |
| `api_key` | `str` | API キー（`ik_` プレフィックス付き） |
| `timeout` | `float` | HTTP タイムアウト秒数（デフォルト: 30.0） |
| `http_client` | `httpx.Client \| None` | カスタム httpx クライアント（テスト用） |

コンストラクタ実行時、OS キーリングに保存済みの MK があれば自動的に復元されます。

### E2EE マスターキー管理

仕訳の起票・閲覧は MK（マスターキー）の解錠が必要です（未解錠時は `LockedError`）。

#### `unlock`

```python
unlock(passphrase: str) -> None
```

`GET /api/v1/wrapped-keys` から passphrase 方式の wrapped_master_key を取得し、
Argon2id で派生した鍵で MK をアンラップして OS キーリングに保存します。パスフレーズ
は Web の **設定 → 暗号鍵管理** で登録したものと同じです。

**例外:** wrapped-keys 取得失敗、passphrase 方式未登録、パスフレーズ誤り → `KakeiboAPIError`

#### `lock`

```python
lock() -> None
```

MK をメモリと OS キーリングから消去します。

#### `is_unlocked`

```python
is_unlocked: bool  # プロパティ
```

MK が解錠済み（暗号化/復号が可能）かどうかを返します。

### メソッド

#### `create_journal`

仕訳を起票する。必要なスコープ: `journals:create`（要 MK 解錠）

```python
create_journal(
    *,
    date: date | datetime | str,
    description: str,
    lines: list[JournalLine],
    source: str = "api",
    fiscal_period: int | None = None,
    draft_id: int | None = None,
) -> JournalCreateResponse
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `date` | `date \| datetime \| str` | 日付。`date`, `datetime`, または `"YYYY-MM-DD"` 文字列 |
| `description` | `str` | 摘要 |
| `lines` | `list[JournalLine]` | 仕訳明細行のリスト |
| `source` | `str` | ソース種別（デフォルト: `"api"`） |
| `fiscal_period` | `int \| None` | 0=期首 / 1-12=月 / 13-15=決算整理（省略時は date の月） |
| `draft_id` | `int \| None` | 確定する下書き ID（省略可）。指定すると下書きの status が done になる |

仕訳本体（date/description/source/fiscal_period）と各明細行の摘要は MK で暗号化されて
送信されます。

**戻り値:** `JournalCreateResponse`

#### `get_journal`

仕訳を1件取得する。必要なスコープ: `journals:read`

```python
get_journal(journal_id: int) -> JournalDetail
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `journal_id` | `int` | 仕訳 ID |

**戻り値:** `JournalDetail`

#### `list_journals`

仕訳一覧を取得する。必要なスコープ: `journals:read`（要 MK 解錠）

```python
list_journals(
    *,
    fiscal_year: int | None = None,
    page: int = 1,
    per_page: int = 20,
) -> JournalListResponse
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `fiscal_year` | `int \| None` | 年度フィルタ（省略可、1900〜2200） |
| `page` | `int` | ページ番号（デフォルト: 1） |
| `per_page` | `int` | 1ページあたりの件数（デフォルト: 20, 上限: 100） |

サーバー側の絞り込みは年度単位です（E2EE のため日付は暗号化されており、日付での
絞り込みは取得後にクライアント側で行います）。取得した各仕訳は MK で復号されます。

**戻り値:** `JournalListResponse`

#### `delete_journal`

仕訳を削除する。必要なスコープ: `journals:delete`

```python
delete_journal(journal_id: int) -> None
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `journal_id` | `int` | 仕訳 ID |

**例外:** 確定済み期間や提出ロック中の仕訳は削除不可（`KakeiboAPIError` 400）

#### `upsert_medical_expense`

医療費明細を作成または更新する。必要なスコープ: `journals:create`（要 MK 解錠）

`journal_entry_id` で upsert します（1 仕訳につき医療費明細は 1 件）。本体は MK で
暗号化して送信されます。

```python
upsert_medical_expense(
    *,
    journal_entry_id: int,
    date: str | None = None,
    patient_name: str = "",
    hospital_name: str = "",
    treatment_description: str = "",
    provider_type: str | None = None,
    amount_paid: int = 0,
    insurance_reimbursement: int = 0,
) -> int
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `journal_entry_id` | `int` | 紐付ける仕訳 ID（必須、その仕訳が存在すること） |
| `date` | `str \| None` | 受診日（`"YYYY-MM-DD"`）または None |
| `patient_name` | `str` | 受診者名 |
| `hospital_name` | `str` | 病院・薬局名 |
| `treatment_description` | `str` | 治療内容 |
| `provider_type` | `str \| None` | `"hospital"` / `"pharmacy"` / `"nursing"` / `"other"` または None |
| `amount_paid` | `int` | 支払額（非負整数） |
| `insurance_reimbursement` | `int` | 保険などの補填額（非負整数） |

**戻り値:** `int`（医療費明細の ID）
**例外:** 仕訳が見つからない（404）、確定済み期間（400）、未解錠（`LockedError`）

#### `list_medical_expenses`

医療費明細の一覧を取得する。必要なスコープ: `journals:read`（要 MK 解錠）

```python
list_medical_expenses(*, fiscal_year: int | None = None) -> MedicalExpenseListResponse
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `fiscal_year` | `int \| None` | 年度フィルタ（省略可、紐付く仕訳の年度で絞り込み） |

取得した各明細は MK で復号されます。

**戻り値:** `MedicalExpenseListResponse`（`expenses: list[MedicalExpense]`, `total: int`）

#### `list_accounts`

勘定科目の一覧を取得する。必要なスコープ: `journals:read`（MK 解錠は不要 — 科目は
E2EE 対象外で平文）

```python
list_accounts() -> list[Account]
```

**戻り値:** `list[Account]`（`code` / `name` / `account_type`（asset/liability/equity/
revenue/expense）/ `account_type_name` / `normal_balance`（debit/credit）/ `is_active`
/ `system_role` / `tax_category` / `cost_type` / `display_order`）

#### `list_balance_cache_blobs`

月次確定済み期間の残高キャッシュを取得・復号する（**読み込みのみ**）。必要なスコープ:
`journals:read`（要 MK 解錠）

```python
list_balance_cache_blobs(year: int) -> dict[int, dict[str, tuple[int, int]]]
```

**戻り値:** `{period: {account_code: (debit, credit)}}`（period: 0=期首 / 1-12=月 /
13-16=決算整理・損益振替）。キャッシュの生成・更新は owner（Web）の月次確定で行います。

#### `search_journals`

仕訳を取得し、クライアント側で復号後にフィルタする。必要なスコープ: `journals:read`
（要 MK 解錠）

```python
search_journals(
    *,
    fiscal_year: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    text: str | None = None,
    account_code: str | None = None,
) -> list[JournalDetail]
```

E2EE のためサーバー側の絞り込みは年度単位のみ。日付・摘要・科目での絞り込みは復号後に
クライアント側で行います（`text` は仕訳・明細いずれかの摘要の部分一致、`account_code`
はいずれかの明細が一致）。

#### `trial_balance`

試算表（科目単位の借方/貸方合計 + 残高）を集計する。必要なスコープ: `journals:read`
（要 MK 解錠）

```python
trial_balance(*, fiscal_year: int, include_closing: bool = False) -> TrialBalance
```

明細の `account_code` / `debit` / `credit`（平文メタ）を集計し、科目名・区分・正常残高を
`list_accounts` から付与します。残高は各科目の `normal_balance` に従い、借方科目は
`debit - credit`、貸方科目は `credit - debit` を正とします。`include_closing=False`
（既定）では損益振替（`is_closing`）仕訳を除外した決算振替前の試算表になります。

**戻り値:** `TrialBalance`（`fiscal_year`, `rows: list[TrialBalanceRow]`,
`total_debit`, `total_credit`）。`TrialBalanceRow` = `code` / `name` / `account_type`
/ `debit` / `credit` / `balance`。

#### `analyze`

画像を AI 解析して下書きを作成する。必要なスコープ: `ai:analyze`

クライアント完結フロー（画像と LLM API キーはサーバーを経由せず、このプロセスから
直接 LLM へ送信）。LLM API キーは `KakeiboClient(..., openai_api_key=/anthropic_api_key=
/google_api_key=...)` で渡します。

```python
analyze(
    image: str | Path | bytes,
    *,
    comment: str = "",
    mime_type: str | None = None,
    provider: str = "openai",
    model: str | None = None,
) -> AnalyzeResponse
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `image` | `str \| Path \| bytes` | 画像ファイルパスまたはバイト列 |
| `comment` | `str` | メモ（省略可、最大500文字） |
| `mime_type` | `str \| None` | バイト列渡し時の MIME タイプ（デフォルト: `image/jpeg`） |
| `provider` | `str` | `"openai"` / `"anthropic"` / `"google"`（デフォルト openai） |
| `model` | `str \| None` | 使用モデル名（省略時はサーバーの provider 別デフォルト） |

**元帳コンテキスト（E2EE）:** Round 1 で AI が元帳参照を要求した場合（`needs_ledger`）、
E2EE のためサーバーは元帳を生成できないので、**MK が解錠済みなら**該当年度の仕訳を
復号して元帳コンテキストをクライアント側で構築し Round 2 に渡します。MK 未解錠時は
元帳なしで続行します（解析自体は MK 不要）。

**戻り値:** `AnalyzeResponse`

#### `list_drafts`

下書き一覧を取得する。必要なスコープ: `ai:analyze`

```python
list_drafts(
    *,
    status: str = "analyzed",
    page: int = 1,
    per_page: int = 50,
) -> DraftListResponse
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `status` | `str` | フィルタ: `"analyzed"` / `"done"` / `"all"`（デフォルト: `"analyzed"`） |
| `page` | `int` | ページ番号（デフォルト: 1） |
| `per_page` | `int` | 1ページあたりの件数（デフォルト: 50, 上限: 100） |

**戻り値:** `DraftListResponse`

#### `get_draft`

下書き詳細を取得する（候補データ含む）。必要なスコープ: `ai:analyze`

```python
get_draft(draft_id: int) -> DraftDetail
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `draft_id` | `int` | 下書き ID |

**戻り値:** `DraftDetail`

#### `delete_draft`

下書きを削除する。必要なスコープ: `ai:analyze`

```python
delete_draft(draft_id: int) -> None
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `draft_id` | `int` | 下書き ID |

#### `upload_voucher`

証憑画像を E2EE で 2 段階アップロードする。必要なスコープ: `journals:create`（要 MK 解錠）

画像・サムネ・メタはクライアントで AES-GCM 暗号化され、サーバーには暗号文しか渡りません
（設計書 §13）。フロー: `POST /vouchers/init` で `voucher_id` + `aad_id` を採番 → `aad_id`
を AAD に束縛して暗号化（`vimg` 本体 / `vthumb` サムネ / `vmeta` メタ）→ `PUT /vouchers/<id>`
で暗号文を multipart upload。

```python
upload_voucher(
    image: str | Path | bytes,
    *,
    journal_entry_id: int | None = None,
    make_thumbnail: bool = True,
    original_filename: str | None = None,
    image_mime: str | None = None,
) -> VoucherUploadResult
```

| 引数 | 型 | 説明 |
|------|-----|------|
| `image` | `str \| Path \| bytes` | 画像ファイルパスまたはバイト列（平文上限 10MB） |
| `journal_entry_id` | `int \| None` | 紐付ける仕訳 ID（孤立証憑なら None） |
| `make_thumbnail` | `bool` | True なら Pillow で長辺 200px JPEG サムネを生成して同梱 |
| `original_filename` | `str \| None` | メタに保存する元ファイル名（パス渡しなら自動） |
| `image_mime` | `str \| None` | メタの MIME（省略時はマジックナンバーから判定） |

**戻り値:** `VoucherUploadResult`（`voucher_id` / `aad_id` / `file_hash_cipher` /
`file_hash_plain` / `has_thumbnail`）。`aad_id` は後で画像を再取得・復号する際に必須です。

#### `download_voucher_image`

証憑画像（またはサムネ）を取得して MK で復号し、平文バイト列を返す。必要なスコープ:
`journals:read`（要 MK 解錠）

```python
download_voucher_image(voucher_id: int, aad_id: int, *, thumb: bool = False) -> bytes
```

`aad_id` は `upload_voucher` の戻り値、または `list_vouchers` の各 `VoucherListItem.aad_id`
から得ます。`thumb=True` はサムネ（`?size=thumb`）を取得しますが、サムネが存在しない証憑に
渡すとサーバーが本体にフォールバックするため復号に失敗する点に注意してください。MIME は
`crypto.sniff_image_mime(bytes)` で判定できます。

#### `list_vouchers`

証憑一覧を取得する。必要なスコープ: `journals:read`（MK 解錠は不要 — 一覧メタのみ）

```python
list_vouchers(
    *,
    page: int = 1,
    per_page: int = 20,
    amount_from: int | None = None,
    amount_to: int | None = None,
) -> VoucherListResponse
```

各件の `aad_id` を `download_voucher_image` に渡して画像を復号します。`amount_from` /
`amount_to` は紐付く仕訳の借方合計での絞り込みです。

#### `verify_voucher`

サーバー側で暗号文ハッシュ（`file_hash_cipher`）を再計算して検証する（電帳法の改ざん検知）。
必要なスコープ: `journals:read`（MK 不要 — サーバーは平文に触れません）

```python
verify_voucher(voucher_id: int) -> dict
```

**戻り値:** `{"ok", "verified", "stored_hash", "computed_hash"}` 等の生 JSON。

#### `close`

内部の HTTP クライアントを閉じる。コンテキストマネージャ使用時は自動的に呼ばれる。

```python
close() -> None
```

---

## データモデル

### JournalLine

仕訳の1明細行を表すデータクラス。

```python
@dataclass
class JournalLine:
    account_code: str
    debit: int = 0
    credit: int = 0
    description: str = ""
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `account_code` | `str` | 勘定科目コード（必須） |
| `debit` | `int` | 借方金額（デフォルト: 0） |
| `credit` | `int` | 貸方金額（デフォルト: 0） |
| `description` | `str` | 行レベルの摘要（省略可） |

**注意:** 仕訳全体で借方合計と貸方合計が一致する必要があります（複式簿記）。

### JournalCreateResponse

仕訳起票の成功レスポンス。

```python
@dataclass
class JournalCreateResponse:
    id: int
    entry_number: int
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `id` | `int` | 作成された仕訳の内部 ID |
| `entry_number` | `int` | ユーザー内で一意の伝票番号 |

### JournalDetail

仕訳の詳細情報。`get_journal` / `list_journals` の戻り値で使用。

```python
@dataclass
class JournalDetail:
    id: int
    date: str
    entry_number: int
    description: str
    source: str
    lines: list[JournalLine]
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `id` | `int` | 仕訳 ID |
| `date` | `str` | 日付（YYYY-MM-DD） |
| `entry_number` | `int` | 伝票番号 |
| `description` | `str` | 摘要 |
| `source` | `str` | ソース種別（`"journal"`, `"api"`, `"cashbook"` 等） |
| `lines` | `list[JournalLine]` | 明細行のリスト |

### JournalListResponse

仕訳一覧のレスポンス。

```python
@dataclass
class JournalListResponse:
    journals: list[JournalDetail]
    total: int
    page: int
    per_page: int
```

### AnalyzeResponse

AI 解析レスポンス。

```python
@dataclass
class AnalyzeResponse:
    draft_id: int
    suggestions: list[dict]
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `draft_id` | `int` | 作成された下書きの ID |
| `suggestions` | `list[dict]` | 仕訳候補のリスト（各候補に `title`, `date`, `entry_description`, `lines` 等を含む） |

### DraftSummary

下書きのサマリー情報。

```python
@dataclass
class DraftSummary:
    title: str = ""
    date: str = ""
    description: str = ""
    amount: int = 0
    suggestion_count: int = 0
```

### DraftListItem

下書き一覧の1件。`list_drafts` の戻り値で使用。

```python
@dataclass
class DraftListItem:
    id: int
    status: str
    comment: str
    created_at: str
    summary: DraftSummary | None = None
```

### DraftListResponse

下書き一覧のレスポンス。

```python
@dataclass
class DraftListResponse:
    drafts: list[DraftListItem]
    total: int
    page: int
    per_page: int
```

### DraftDetail

下書きの詳細。`get_draft` の戻り値で使用。候補データを含む。

```python
@dataclass
class DraftDetail:
    id: int
    status: str
    comment: str
    created_at: str
    summary: DraftSummary | None = None
    suggestions: list[dict] = field(default_factory=list)
```

---

## 例外クラス

### KakeiboAPIError

API がエラーレスポンスを返した場合の基底例外。

```python
class KakeiboAPIError(Exception):
    status_code: int   # HTTP ステータスコード
    message: str       # サーバーからのエラーメッセージ
```

### AuthenticationError

`KakeiboAPIError` のサブクラス。401 レスポンス時に送出。

```python
class AuthenticationError(KakeiboAPIError):
    # status_code は常に 401
```

**主なエラーメッセージ（サーバーから返される）:**

| ステータス | メッセージ | 原因 |
|-----------|-----------|------|
| 401 | `Authorization ヘッダーが必要です。` | Bearer トークン未指定 |
| 401 | `無効な API キーです。` | キーが無効または無効化済み |
| 403 | `この API キーには ai:analyze 権限がありません。` | スコープ不足 |
| 400 | `date は必須です。` | 日付が未指定 |
| 400 | `description は必須です。` | 摘要が未指定 |
| 400 | `lines は必須です（配列）。` | 明細行が未指定 |
| 400 | `AI API設定が未登録です。` | サーバーでAI設定未完了 |
| 400 | `下書き(id=N)が見つからないか、既に確定済みです。` | 無効な draft_id |
| 404 | `仕訳が見つかりません。` | 指定 ID の仕訳が存在しない |
| 404 | `下書きが見つかりません。` | 指定 ID の下書きが存在しない |

---

## API キーのスコープ

サーバー側で API キー発行時にスコープを設定できます。

| スコープ | 説明 | 依存 |
|---------|------|------|
| `journals:create` | 仕訳起票 | — |
| `journals:read` | 仕訳閲覧（一覧・詳細） | — |
| `journals:delete` | 仕訳削除 | `journals:read` が必要 |
| `ai:analyze` | AI証憑仕訳（解析・下書き一覧・詳細・削除） | — |
