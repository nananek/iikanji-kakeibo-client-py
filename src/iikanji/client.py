"""いいかんじ家計簿 API クライアント"""

from __future__ import annotations

from datetime import date, datetime
from typing import TYPE_CHECKING

import httpx

import json

from . import backup as backup_mod
from . import crypto, hpke, reports, thumbnail
from .exceptions import AuthenticationError, KakeiboAPIError, LockedError
from pathlib import Path

from .models import (
    Account,
    AnalyzeResponse,
    DraftDetail,
    DraftListItem,
    DraftListResponse,
    JournalCreateRequest,
    JournalCreateResponse,
    JournalDetail,
    JournalLine,
    JournalListResponse,
    BalanceSheet,
    BalanceSheetRow,
    Ledger,
    LedgerRow,
    MedicalExpense,
    MedicalExpenseListResponse,
    ProfitLoss,
    ProfitLossRow,
    TrialBalance,
    TrialBalanceRow,
    VoucherListItem,
    VoucherListResponse,
    VoucherUploadResult,
)

if TYPE_CHECKING:
    from types import TracebackType


class KakeiboClient:
    """いいかんじ家計簿 API クライアント

    Usage::

        with KakeiboClient("https://example.com", "ik_abc...") as client:
            result = client.create_journal(
                date="2026-02-15",
                description="食材購入",
                lines=[
                    JournalLine(account_code="7010", debit=3000),
                    JournalLine(account_code="1010", credit=3000),
                ],
            )
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        openai_api_key: str | None = None,
        anthropic_api_key: str | None = None,
        google_api_key: str | None = None,
        timeout: float = 30.0,
        http_client: httpx.Client | None = None,
        llm_http_client: httpx.Client | None = None,
    ) -> None:
        """E2 PR-D-a/b: 各 provider の API キーを保持してクライアント完結 AI 解析。

        Args:
            base_url: いいかんじ家計簿サーバの URL
            api_key: Bearer API キー (サーバ認証用)
            openai_api_key / anthropic_api_key / google_api_key:
                対応する provider の API キー。analyze() で実際に呼ばれる
                provider のキーが必須。サーバ E2EE blob はブラウザ
                SharedWorker でしか復号できないため、Python クライアントは
                オーナーが直接 LLM API キーを保持する設計。
            timeout / http_client: サーバ通信用
            llm_http_client: LLM 通信用 (テスト DI、省略時は httpx 標準)
        """
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._llm_api_keys = {
            "openai": openai_api_key,
            "anthropic": anthropic_api_key,
            "google": google_api_key,
        }
        self._llm_http_client = llm_http_client
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                base_url=self._base_url,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=timeout,
            )
            self._owns_client = True

        # E2EE: マスターキー (MK) と数値 user_id。仕訳の暗号化/復号に使う。
        # init 時に OS keyring から復元を試みる (無ければ None = 要 unlock)。
        self._mk: bytes | None = None
        self._user_id: int | None = None
        restored = crypto.load_mk(self._base_url)
        if restored is not None:
            self._user_id, self._mk = restored

    def __enter__(self) -> KakeiboClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # --- E2EE マスターキー (MK) 管理 ---

    @property
    def is_unlocked(self) -> bool:
        """MK が解錠済み (仕訳の暗号化/復号が可能) かどうか。"""
        return self._mk is not None and self._user_id is not None

    def unlock(self, passphrase: str) -> None:
        """パスフレーズで MK を解錠し、OS keyring に永続化する。

        ``GET /api/v1/wrapped-keys`` で passphrase 方式の wrapped_master_key を
        取得し、Argon2id で派生した鍵で MK をアンラップする。成功すると以後の
        仕訳 CRUD が暗号化/復号付きで動作する。

        Args:
            passphrase: Web で暗号鍵を設定した際のパスフレーズ

        Raises:
            KakeiboAPIError: wrapped-keys 取得失敗、passphrase 方式が未登録、
                またはパスフレーズ誤り (アンラップ失敗) の場合
        """
        resp = self._client.get("/api/v1/wrapped-keys")
        if resp.status_code != 200:
            self._raise_for_error(resp)
        body = resp.json()
        user_id = body.get("user_id")
        if user_id is None:
            raise KakeiboAPIError(
                500, "サーバが user_id を返しませんでした (要サーバ更新)。"
            )
        rows = body.get("wrapped_keys", [])
        row = next(
            (r for r in rows if r.get("method") == "passphrase"), None
        )
        if row is None:
            raise KakeiboAPIError(
                400,
                "passphrase 方式の暗号鍵が未登録です。Web の設定 → 暗号鍵管理 "
                "でパスフレーズを登録してください。",
            )
        try:
            derived = crypto.derive_key(
                passphrase,
                crypto.b64decode(row["salt"]),
                row["kdf_params"],
            )
            mk = crypto.unwrap_master_key(
                crypto.b64decode(row["wrapped_master_key"]),
                crypto.b64decode(row["wrap_iv"]),
                derived,
            )
        except Exception as exc:
            raise KakeiboAPIError(
                400, "パスフレーズが正しくありません (MK のアンラップに失敗)。"
            ) from exc

        self._mk = mk
        self._user_id = int(user_id)
        crypto.store_mk(self._base_url, self._user_id, self._mk)

    def lock(self) -> None:
        """MK をメモリと OS keyring から消去する。"""
        self._mk = None
        self._user_id = None
        crypto.clear_mk(self._base_url)

    def _require_mk(self) -> tuple[bytes, int]:
        if self._mk is None or self._user_id is None:
            raise LockedError()
        return self._mk, self._user_id

    # --- 仕訳起票 ---

    def create_journal(
        self,
        *,
        date: date | datetime | str,
        description: str,
        lines: list[JournalLine],
        source: str = "api",
        fiscal_period: int | None = None,
        draft_id: int | None = None,
    ) -> JournalCreateResponse:
        """仕訳を起票する (E2EE: MK で暗号化して送信)。

        事前に :meth:`unlock` で MK を解錠しておく必要がある。

        Args:
            date: 日付 (date, datetime, または YYYY-MM-DD 文字列)
            description: 摘要
            lines: 仕訳明細行のリスト
            source: ソース種別 (デフォルト "api")
            fiscal_period: 0=期首 / 1-12=月 / 13-15=決算整理 (省略時は date の月)
            draft_id: 確定する下書き ID (省略可)。指定すると下書きの status が done になる

        Returns:
            JournalCreateResponse: 作成された仕訳の ID と伝票番号

        Raises:
            LockedError: MK が未解錠の場合
            AuthenticationError: APIキーが無効な場合
            KakeiboAPIError: バリデーションエラー等
        """
        mk, user_id = self._require_mk()
        req = JournalCreateRequest(
            date=date,
            description=description,
            lines=lines,
            source=source,
            fiscal_period=fiscal_period,
            draft_id=draft_id,
        )
        resp = self._client.post(
            "/api/v1/journals", json=req.to_wire(mk, user_id)
        )
        if resp.status_code == 201:
            data = resp.json()
            return JournalCreateResponse(
                id=data["id"],
                entry_number=data["entry_number"],
            )
        self._raise_for_error(resp)

    # --- 仕訳閲覧 ---

    def get_journal(self, journal_id: int) -> JournalDetail:
        """仕訳を1件取得する。

        Args:
            journal_id: 仕訳 ID

        Returns:
            JournalDetail: 仕訳の詳細情報

        Raises:
            LockedError: MK が未解錠の場合
            KakeiboAPIError: 仕訳が見つからない場合 (404) 等
        """
        mk, user_id = self._require_mk()
        resp = self._client.get(f"/api/v1/journals/{journal_id}")
        if resp.status_code == 200:
            return JournalDetail.from_dict(
                resp.json()["journal"], mk, user_id
            )
        self._raise_for_error(resp)

    def list_journals(
        self,
        *,
        fiscal_year: int | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> JournalListResponse:
        """仕訳一覧を取得する (E2EE: MK で各仕訳を復号して返す)。

        E3-F PR-D-6 以降、サーバの絞り込みは年度 (fiscal_year) 単位。日付での
        絞り込みは復号後にクライアント側で行う。

        Args:
            fiscal_year: 年度フィルタ (省略可、1900〜2200)
            page: ページ番号 (デフォルト 1)
            per_page: 1ページあたりの件数 (デフォルト 20, 上限 100)

        Returns:
            JournalListResponse: 仕訳一覧とページネーション情報

        Raises:
            LockedError: MK が未解錠の場合
        """
        mk, user_id = self._require_mk()
        params: dict[str, str | int] = {"page": page, "per_page": per_page}
        if fiscal_year is not None:
            params["fiscal_year"] = fiscal_year

        resp = self._client.get("/api/v1/journals", params=params)
        if resp.status_code == 200:
            data = resp.json()
            return JournalListResponse(
                journals=[
                    JournalDetail.from_dict(j, mk, user_id)
                    for j in data["journals"]
                ],
                total=data["total"],
                page=data["page"],
                per_page=data["per_page"],
            )
        self._raise_for_error(resp)

    # --- 仕訳削除 ---

    def delete_journal(self, journal_id: int) -> None:
        """仕訳を削除する。

        Args:
            journal_id: 仕訳 ID

        Raises:
            KakeiboAPIError: 仕訳が見つからない (404)、期間ロック (400) 等
        """
        resp = self._client.delete(f"/api/v1/journals/{journal_id}")
        if resp.status_code == 200:
            return
        self._raise_for_error(resp)

    # --- 医療費 ---

    def upsert_medical_expense(
        self,
        *,
        journal_entry_id: int,
        date: str | None = None,
        patient_name: str = "",
        hospital_name: str = "",
        treatment_description: str = "",
        provider_type: str | None = None,
        amount_paid: int = 0,
        insurance_reimbursement: int = 0,
    ) -> int:
        """医療費明細を作成または更新する (E2EE: MK で暗号化して送信)。

        ``journal_entry_id`` で upsert する（1 仕訳につき医療費明細は 1 件）。
        事前に :meth:`unlock` で MK を解錠しておく必要がある。

        Args:
            journal_entry_id: 紐付ける仕訳 ID（必須、その仕訳が存在すること）
            date: 受診日 (YYYY-MM-DD) または None
            patient_name: 受診者名
            hospital_name: 病院・薬局名
            treatment_description: 治療内容
            provider_type: ``"hospital"`` / ``"pharmacy"`` / ``"nursing"`` /
                ``"other"`` または None
            amount_paid: 支払額（非負整数）
            insurance_reimbursement: 保険などで補填される額（非負整数）

        Returns:
            int: 作成・更新された医療費明細の ID

        Raises:
            LockedError: MK が未解錠の場合
            KakeiboAPIError: 仕訳が見つからない (404)、確定済み期間 (400) 等
        """
        mk, user_id = self._require_mk()
        me = MedicalExpense(
            journal_entry_id=journal_entry_id,
            date=date,
            patient_name=patient_name,
            hospital_name=hospital_name,
            treatment_description=treatment_description,
            provider_type=provider_type,
            amount_paid=amount_paid,
            insurance_reimbursement=insurance_reimbursement,
        )
        resp = self._client.post(
            "/api/v1/medical-expenses", json=me.to_wire(mk, user_id)
        )
        if resp.status_code == 200:
            return resp.json()["id"]
        self._raise_for_error(resp)

    def list_medical_expenses(
        self, *, fiscal_year: int | None = None
    ) -> MedicalExpenseListResponse:
        """医療費明細の一覧を取得する (E2EE: MK で各明細を復号して返す)。

        Args:
            fiscal_year: 年度フィルタ（省略可、紐付く仕訳の年度で絞り込み）

        Returns:
            MedicalExpenseListResponse: 医療費明細の一覧

        Raises:
            LockedError: MK が未解錠の場合
        """
        mk, user_id = self._require_mk()
        params: dict[str, str | int] = {}
        if fiscal_year is not None:
            params["fiscal_year"] = fiscal_year
        resp = self._client.get("/api/v1/medical-expenses", params=params)
        if resp.status_code == 200:
            data = resp.json()
            return MedicalExpenseListResponse(
                expenses=[
                    MedicalExpense.from_api(e, mk, user_id)
                    for e in data["expenses"]
                ],
                total=data["total"],
            )
        self._raise_for_error(resp)

    # --- 勘定科目 ---

    def list_accounts(self) -> list[Account]:
        """勘定科目の一覧を取得する。必要なスコープ: ``journals:read``

        科目は E2EE 対象外（平文）のため MK の解錠は不要。

        Returns:
            list[Account]: display_order / code 順
        """
        resp = self._client.get("/api/v1/accounts")
        if resp.status_code == 200:
            return [Account.from_dict(a) for a in resp.json()["accounts"]]
        self._raise_for_error(resp)

    # --- 残高キャッシュ (読み込みのみ) ---

    def list_balance_cache_blobs(
        self, year: int
    ) -> dict[int, dict[str, tuple[int, int]]]:
        """指定年の残高キャッシュ blob を取得・復号する (E2EE)。

        月次確定済み期間の累計残高キャッシュ。生成・更新は owner（Web）の月次
        確定ワークフローが行うため、client-py は **読み込みのみ**対応する。

        Args:
            year: 対象年度

        Returns:
            ``{period: {account_code: (debit, credit)}}``
            （period = 0=期首 / 1-12=月 / 13-16=決算整理・損益振替）

        Raises:
            LockedError: MK が未解錠の場合
        """
        mk, user_id = self._require_mk()
        resp = self._client.get(
            "/api/v1/balance-cache-blobs", params={"year": year}
        )
        if resp.status_code != 200:
            self._raise_for_error(resp)
        out: dict[int, dict[str, tuple[int, int]]] = {}
        for b in resp.json()["blobs"]:
            period = b["period"]
            try:
                # bcb record は生マップ {account_code: [debit, credit]}。
                # AAD = buildAAD("bcb", user_id, year*100 + period)。
                rec = crypto.decrypt_record(
                    mk,
                    crypto.b64decode(b["encrypted_blob"]),
                    crypto.b64decode(b["blob_iv"]),
                    crypto.build_aad("bcb", user_id, year * 100 + period),
                )
            except Exception:
                # 1 件の復号失敗で全体を壊さない (空マップにフォールバック)
                rec = {}
            out[period] = {
                code: (int(pair[0]), int(pair[1]))
                for code, pair in rec.items()
            }
        return out

    # --- 検索 / レポート集計 (クライアント側) ---

    def _iter_all_journals(self, fiscal_year: int | None) -> list[JournalDetail]:
        """指定年度の全仕訳をページングで取得する (復号済み)。"""
        mk, user_id = self._require_mk()
        all_entries: list[JournalDetail] = []
        page = 1
        per_page = 100
        while True:
            params: dict[str, str | int] = {"page": page, "per_page": per_page}
            if fiscal_year is not None:
                params["fiscal_year"] = fiscal_year
            resp = self._client.get("/api/v1/journals", params=params)
            if resp.status_code != 200:
                self._raise_for_error(resp)
            data = resp.json()
            all_entries.extend(
                JournalDetail.from_dict(j, mk, user_id) for j in data["journals"]
            )
            total = data.get("total", len(all_entries))
            if not data["journals"] or len(all_entries) >= total:
                break
            page += 1
            if page > 1000:  # 暴走防止
                break
        return all_entries

    def search_journals(
        self,
        *,
        fiscal_year: int | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        text: str | None = None,
        account_code: str | None = None,
    ) -> list[JournalDetail]:
        """仕訳を取得し、クライアント側で復号後にフィルタする (E2EE)。

        E2EE のためサーバ側の絞り込みは年度単位のみ。日付・摘要・科目での絞り込みは
        復号後にここで行う。

        Args:
            fiscal_year: 年度フィルタ（サーバ側、省略可）
            date_from / date_to: 日付範囲 (YYYY-MM-DD、両端含む)
            text: 摘要（仕訳・明細いずれか）に含まれる部分文字列
            account_code: いずれかの明細がこの科目を含む

        Returns:
            list[JournalDetail]: 条件に一致した仕訳

        Raises:
            LockedError: MK が未解錠の場合
        """
        entries = self._iter_all_journals(fiscal_year)
        result: list[JournalDetail] = []
        for e in entries:
            if date_from is not None and (e.date is None or e.date < date_from):
                continue
            if date_to is not None and (e.date is None or e.date > date_to):
                continue
            if account_code is not None and not any(
                ln.account_code == account_code for ln in e.lines
            ):
                continue
            if text is not None:
                hay = (e.description or "") + "\n" + "\n".join(
                    ln.description or "" for ln in e.lines
                )
                if text not in hay:
                    continue
            result.append(e)
        return result

    def trial_balance(
        self, *, fiscal_year: int, include_closing: bool = False
    ) -> TrialBalance:
        """試算表（科目単位の借方/貸方合計 + 残高）を集計する (E2EE)。

        仕訳明細の account_code / debit / credit は平文メタなので集計可能。科目名・
        区分・正常残高は ``GET /api/v1/accounts`` から付与する。残高は各科目の
        normal_balance に従い、借方科目は ``debit - credit``、貸方科目は
        ``credit - debit`` を正とする。

        Args:
            fiscal_year: 対象年度
            include_closing: True で損益振替（is_closing）仕訳も合算する
                （既定 False = 決算振替前の試算表）

        Returns:
            TrialBalance

        Raises:
            LockedError: MK が未解錠の場合
        """
        self._require_mk()  # 仕訳取得前に fail-fast
        accounts = {a.code: a for a in self.list_accounts()}
        entries = self._iter_all_journals(fiscal_year)

        debit_by_code: dict[str, int] = {}
        credit_by_code: dict[str, int] = {}
        for e in entries:
            if e.is_closing and not include_closing:
                continue
            for ln in e.lines:
                code = ln.account_code
                if code is None:
                    continue
                debit_by_code[code] = debit_by_code.get(code, 0) + int(ln.debit or 0)
                credit_by_code[code] = credit_by_code.get(code, 0) + int(ln.credit or 0)

        rows: list[TrialBalanceRow] = []
        for code in sorted(
            set(debit_by_code) | set(credit_by_code),
            key=lambda c: (accounts[c].display_order if c in accounts else 9999, c),
        ):
            debit = debit_by_code.get(code, 0)
            credit = credit_by_code.get(code, 0)
            acct = accounts.get(code)
            normal = acct.normal_balance if acct else "debit"
            balance = (debit - credit) if normal == "debit" else (credit - debit)
            rows.append(TrialBalanceRow(
                code=code,
                name=acct.name if acct else "",
                account_type=acct.account_type if acct else "",
                debit=debit,
                credit=credit,
                balance=balance,
            ))

        return TrialBalance(
            fiscal_year=fiscal_year,
            rows=rows,
            total_debit=sum(r.debit for r in rows),
            total_credit=sum(r.credit for r in rows),
        )

    def profit_loss(
        self, *, fiscal_year: int, month: int | None = None
    ) -> ProfitLoss:
        """損益計算書 (P/L) を集計する (E2EE)。必要なスコープ: ``journals:read``

        収益・費用科目の発生額を集計します。``month`` (1-12) を指定すると当該月のみ、
        未指定なら年間 (期首/通常月/決算整理を含み、損益振替と closing 仕訳は除外)。

        Args:
            fiscal_year: 対象年度
            month: 1-12 を指定すると当該月の P/L (未指定で年間)

        Returns:
            ProfitLoss

        Raises:
            LockedError: MK が未解錠の場合
        """
        self._require_mk()
        meta = self._accounts_meta()
        type_by = {c: m["type"] for c, m in meta.items()}
        name_by = {c: m["name"] for c, m in meta.items()}
        entries = [
            self._entry_to_report_dict(jd)
            for jd in self._iter_all_journals(fiscal_year)
        ]
        pl = reports.compute_profit_loss(
            entries, account_type_by_code=type_by,
            account_name_by_code=name_by, month=month,
        )
        return ProfitLoss(
            fiscal_year=fiscal_year,
            income_total=pl["income_total"],
            expense_total=pl["expense_total"],
            net_income=pl["net_income"],
            income_breakdown=[ProfitLossRow(**r) for r in pl["income_breakdown"]],
            expense_breakdown=[ProfitLossRow(**r) for r in pl["expense_breakdown"]],
            month=month,
        )

    def balance_sheet(self, *, fiscal_year: int) -> BalanceSheet:
        """貸借対照表 (B/S) を集計する (E2EE)。必要なスコープ: ``journals:read``

        資産・負債・純資産の残高を集計します。前年末 (year-1, period=15) の残高
        キャッシュを期首累計に流すため、過去分も反映した年度末残高になります
        (キャッシュ欠落時は当年度の仕訳のみで degraded 集計)。損益振替前は当期純利益
        を純資産側に加算します。

        Returns:
            BalanceSheet

        Raises:
            LockedError: MK が未解錠の場合
        """
        self._require_mk()
        meta = self._accounts_meta()
        type_by = {c: m["type"] for c, m in meta.items()}
        nb_by = {c: m["normal_balance"] for c, m in meta.items()}
        name_by = {c: m["name"] for c, m in meta.items()}
        entries = [
            self._entry_to_report_dict(jd)
            for jd in self._iter_all_journals(fiscal_year)
        ]
        try:
            prior = self.list_balance_cache_blobs(fiscal_year - 1).get(15, {})
        except Exception:
            prior = {}
        bs = reports.compute_balance_sheet(
            entries, account_type_by_code=type_by,
            normal_balance_by_code=nb_by, account_name_by_code=name_by,
            prior_cumulative=prior,
        )
        return BalanceSheet(
            fiscal_year=fiscal_year,
            assets=[BalanceSheetRow(**r) for r in bs["assets"]],
            liabilities=[BalanceSheetRow(**r) for r in bs["liabilities"]],
            equities=[BalanceSheetRow(**r) for r in bs["equities"]],
            total_assets=bs["total_assets"],
            total_liabilities=bs["total_liabilities"],
            total_equity=bs["total_equity"],
            net_income=bs["net_income"],
            has_closing=bs["has_closing"],
            total_liability_and_equity=bs["total_liability_and_equity"],
        )

    def ledger(
        self,
        *,
        fiscal_year: int,
        account_code: str,
        opening_balance: int = 0,
        include_closing: bool = True,
    ) -> Ledger:
        """指定科目の総勘定元帳を集計する (E2EE)。必要なスコープ: ``journals:read``

        当該科目の明細を ``entry.id`` 昇順 (作成順 ≈ 時系列。date は暗号化のため
        サーバの日付順は再現不可) で並べ、各行で running balance を計算します。

        Args:
            fiscal_year: 対象年度
            account_code: 対象勘定科目コード
            opening_balance: 期首残高 (前期繰越)。前年度元帳の ``closing_balance``
                を渡すと累計表示になる。
            include_closing: 損益振替 (is_closing) 仕訳を含めるか (既定 True)

        Returns:
            Ledger

        Raises:
            LockedError: MK が未解錠の場合
            KakeiboAPIError: account_code が存在しない場合 (404)
        """
        self._require_mk()
        accounts = {a.code: a for a in self.list_accounts()}
        acct = accounts.get(account_code)
        if acct is None:
            raise KakeiboAPIError(404, f"科目 {account_code} が見つかりません。")
        entries = [
            self._entry_to_report_dict(jd)
            for jd in self._iter_all_journals(fiscal_year)
        ]
        led = reports.compute_ledger(
            entries, account_code=account_code,
            normal_balance=acct.normal_balance,
            opening_balance=opening_balance, include_closing=include_closing,
        )
        return Ledger(
            fiscal_year=fiscal_year,
            account_code=account_code,
            account_name=acct.name,
            opening_balance=led["opening_balance"],
            rows=[LedgerRow(**r) for r in led["rows"]],
            closing_balance=led["closing_balance"],
            total_debit=led["total_debit"],
            total_credit=led["total_credit"],
        )

    # --- AI 証憑仕訳 ---

    def analyze(
        self,
        image: str | Path | bytes,
        *,
        comment: str = "",
        mime_type: str | None = None,
        provider: str = "openai",
        model: str | None = None,
    ) -> AnalyzeResponse:
        """画像を AI 解析して下書きを作成する。必要なスコープ: ``ai:analyze``

        E2 PR-D-a/b: クライアント完結 E2EE フロー。provider に応じた LLM API
        キーは KakeiboClient(__init__, openai_api_key= / anthropic_api_key= /
        google_api_key=...) で渡す。サーバには画像とメタデータのみ送信され、
        LLM 呼出はこのプロセスから直接行われる。

        Args:
            image: 画像ファイルパス (str/Path) またはバイト列
            comment: メモ (省略可、最大500文字)
            mime_type: バイト列渡し時の MIME タイプ (デフォルト: image/jpeg)
            provider: "openai" / "anthropic" / "google" (デフォルト openai)
            model: 使用モデル名 (省略時はサーバの default_model_by_provider)

        Returns:
            AnalyzeResponse: 作成された下書き ID と候補リスト
        """
        from . import llm

        llm_api_key = self._llm_api_keys.get(provider)
        if llm_api_key is None:
            raise ValueError(
                f"{provider}_api_key が未設定です。KakeiboClient(__init__, "
                f"{provider}_api_key=...) で API キーを渡してください。"
            )
        if provider not in llm.IMAGE_HANDLERS:
            raise ValueError(
                f"unsupported provider: {provider} (supported: "
                f"{', '.join(sorted(llm.IMAGE_HANDLERS))})"
            )

        if isinstance(image, (str, Path)):
            path = Path(image)
            image_bytes = path.read_bytes()
            filename = path.name
        else:
            image_bytes = image
            filename = "image.jpg"
        actual_mime = mime_type or "image/jpeg"

        # 1. POST /api/v1/ai/uploads — サーバが画像を保存し draft_id を返す
        files = {"image": (filename, image_bytes, actual_mime)}
        data: dict[str, str] = {}
        if comment:
            data["comment"] = comment[:500]
        resp = self._client.post("/api/v1/ai/uploads", files=files, data=data)
        if resp.status_code != 201:
            self._raise_for_error(resp)
        draft_id = resp.json()["draft_id"]

        # 2. GET /api/v1/ai/prompt-context — Round 1+2 プロンプト材料取得
        ctx_resp = self._client.get("/api/v1/ai/prompt-context")
        if ctx_resp.status_code != 200:
            self._raise_for_error(ctx_resp)
        prompt_context = ctx_resp.json()

        # 3. Round 1 (画像 → DocumentAnalysis)
        actual_model = model or prompt_context.get(
            "default_model_by_provider", {}
        ).get(provider)
        if not actual_model:
            raise ValueError(
                f"provider {provider} のデフォルトモデルが取得できません。"
                "model 引数を明示してください。"
            )
        compliance_check_enabled = bool(
            prompt_context.get("compliance_check_enabled"),
        )
        round1_prompt = llm.build_round1_prompt(
            round1_prompt=prompt_context.get("round1_prompt", ""),
            compliance_check_enabled=compliance_check_enabled,
            compliance_prompt=prompt_context.get("compliance_prompt", ""),
            custom_prompt=prompt_context.get("custom_prompt", ""),
            comment=comment,
        )
        max_tokens_r1 = 1500 if compliance_check_enabled else 1000
        r1_raw = llm.call_image_llm(
            provider=provider,
            api_key=llm_api_key,
            model=actual_model,
            image_bytes=image_bytes,
            mime_type=actual_mime,
            prompt=round1_prompt,
            max_tokens=max_tokens_r1,
            http_client=self._llm_http_client,
        )
        analysis = llm.parse_document_analysis(r1_raw)
        compliance_result = (
            llm.parse_compliance_result(r1_raw.get("compliance"))
            if compliance_check_enabled else None
        )

        # 4. needs_ledger なら元帳文脈をクライアント側で構築する。
        #    E2EE 化で旧 POST /api/v1/ai/ledger-context は撤去された (サーバは
        #    仕訳を復号できない)。MK 解錠済みなら復号仕訳から組み立て、未解錠なら
        #    元帳なしで継続する (graceful degrade)。
        ledger_text = ""
        if (
            analysis.needs_ledger
            and analysis.requested_accounts
            and self.is_unlocked
        ):
            if analysis.date and analysis.date[:4].isdigit():
                ledger_year = int(analysis.date[:4])
            else:
                ledger_year = date.today().year
            entries = self._iter_all_journals(ledger_year)
            ledger_text = llm.build_accounts_ledger_context(
                account_names=analysis.requested_accounts,
                journal_entries=entries,
                account_list_text=prompt_context.get("account_list_text", ""),
            )

        # 5. Round 2 (画像 + 元帳 → suggestions)
        round2_prompt = llm.build_round2_prompt(
            prompt_context=prompt_context,
            needs_ledger=analysis.needs_ledger,
            ledger_text=ledger_text,
        )
        r2_raw = llm.call_image_llm(
            provider=provider,
            api_key=llm_api_key,
            model=actual_model,
            image_bytes=image_bytes,
            mime_type=actual_mime,
            prompt=round2_prompt,
            max_tokens=2000,
            http_client=self._llm_http_client,
        )
        valid_codes = {
            line.split()[0]
            for line in prompt_context.get("account_list_text", "").split("\n")
            if line.strip() and line.strip()[0].isdigit()
        }
        suggestions = llm.validate_suggestions(r2_raw, valid_codes)
        if compliance_result is not None:
            for s in suggestions:
                s["compliance"] = compliance_result

        # 6. PATCH /api/v1/ai/drafts/<id>/suggestions — 結果保存 + AIUsageLog
        save_resp = self._client.patch(
            f"/api/v1/ai/drafts/{draft_id}/suggestions",
            json={
                "suggestions": suggestions,
                "provider": provider,
                "model": actual_model,
            },
        )
        if save_resp.status_code != 200:
            self._raise_for_error(save_resp)

        return AnalyzeResponse(
            draft_id=draft_id,
            suggestions=suggestions,
        )

    def list_drafts(
        self,
        *,
        status: str = "analyzed",
        page: int = 1,
        per_page: int = 50,
    ) -> DraftListResponse:
        """下書き一覧を取得する。必要なスコープ: ``ai:analyze``

        Args:
            status: フィルタ ("analyzed" / "done" / "all", デフォルト: "analyzed")
            page: ページ番号 (デフォルト 1)
            per_page: 1ページあたりの件数 (デフォルト 50, 上限 100)

        Returns:
            DraftListResponse: 下書き一覧とページネーション情報
        """
        params: dict[str, str | int] = {
            "status": status,
            "page": page,
            "per_page": per_page,
        }
        resp = self._client.get("/api/v1/ai/drafts", params=params)
        if resp.status_code == 200:
            data = resp.json()
            return DraftListResponse(
                drafts=[DraftListItem.from_dict(d) for d in data["drafts"]],
                total=data["total"],
                page=data["page"],
                per_page=data["per_page"],
            )
        self._raise_for_error(resp)

    def get_draft(self, draft_id: int) -> DraftDetail:
        """下書き詳細を取得する（候補データ含む）。必要なスコープ: ``ai:analyze``

        Args:
            draft_id: 下書き ID

        Returns:
            DraftDetail: 下書きの詳細と候補リスト
        """
        resp = self._client.get(f"/api/v1/ai/drafts/{draft_id}")
        if resp.status_code == 200:
            return DraftDetail.from_dict(resp.json()["draft"])
        self._raise_for_error(resp)

    def delete_draft(self, draft_id: int) -> None:
        """下書きを削除する。必要なスコープ: ``ai:analyze``

        Args:
            draft_id: 下書き ID
        """
        resp = self._client.delete(f"/api/v1/ai/drafts/{draft_id}")
        if resp.status_code == 200:
            return
        self._raise_for_error(resp)

    # --- 証憑画像 (E2EE, E4 #111 Option C) ---

    def upload_voucher(
        self,
        image: str | Path | bytes,
        *,
        journal_entry_id: int | None = None,
        make_thumbnail: bool = True,
        original_filename: str | None = None,
        image_mime: str | None = None,
    ) -> VoucherUploadResult:
        """証憑画像を E2EE で 2 段階アップロードする。必要なスコープ: ``journals:create``

        事前に :meth:`unlock` で MK を解錠しておく必要がある。画像/サムネ/メタは
        クライアントで暗号化され、サーバには暗号文しか渡らない (設計書 §13)。

        フロー (Option A 2 段階 upload):
          1. ``POST /api/v1/vouchers/init`` で voucher_id + aad_id を採番
          2. aad_id を AAD に束縛して画像(vimg)/サムネ(vthumb)/メタ(vmeta)を暗号化
          3. ``PUT /api/v1/vouchers/<id>`` で暗号文の実体を multipart upload

        Args:
            image: 画像ファイルパス (str/Path) またはバイト列
            journal_entry_id: 紐付ける仕訳 ID (孤立証憑なら None)
            make_thumbnail: True なら Pillow で長辺200px JPEG サムネを生成して同梱
            original_filename: メタに保存する元ファイル名 (パス渡しなら自動)
            image_mime: メタに保存する MIME (省略時はマジックナンバーから判定)

        Returns:
            VoucherUploadResult: voucher_id / aad_id / ハッシュ / サムネ有無

        Raises:
            LockedError: MK が未解錠の場合
            KakeiboAPIError: init / PUT のエラー (上書き 409 等)
        """
        mk, user_id = self._require_mk()

        if isinstance(image, (str, Path)):
            path = Path(image)
            image_bytes = path.read_bytes()
            if original_filename is None:
                original_filename = path.name
        else:
            image_bytes = bytes(image)
        if not image_bytes:
            raise ValueError("画像が空です。")
        if len(image_bytes) > crypto.MAX_IMAGE_BYTES:
            raise ValueError("画像が 10MB の上限を超えています。")
        if image_mime is None:
            image_mime = crypto.sniff_image_mime(image_bytes)

        # 1. init で voucher_id + aad_id を採番 (aad_id は文字列 → int)
        init_resp = self._client.post(
            "/api/v1/vouchers/init",
            json={"journal_entry_id": journal_entry_id},
        )
        if init_resp.status_code != 201:
            self._raise_for_error(init_resp)
        init_data = init_resp.json()
        voucher_id = init_data["voucher_id"]
        aad_id = int(init_data["aad_id"])

        # 2. 暗号化 (vimg/vthumb/vmeta、AAD は aad_id 束縛)
        image_ct = crypto.encrypt_blob(
            mk, image_bytes, crypto.build_aad("vimg", user_id, aad_id),
        )
        thumb_ct = None
        if make_thumbnail:
            thumb_bytes = thumbnail.make_thumbnail(image_bytes)
            if thumb_bytes:
                thumb_ct = crypto.encrypt_blob(
                    mk, thumb_bytes,
                    crypto.build_aad("vthumb", user_id, aad_id),
                )
        meta_record = {
            "v": 1,
            "original_filename": original_filename,
            "image_mime": image_mime,
        }
        meta_blob, meta_iv = crypto.encrypt_record(
            mk, meta_record, crypto.build_aad("vmeta", user_id, aad_id),
        )
        file_hash_plain = crypto.sha256_hex(image_bytes)

        # 3. PUT multipart で暗号文を upload
        files: dict[str, tuple[str, bytes, str]] = {
            "image_ct": ("image.bin", image_ct, "application/octet-stream"),
        }
        if thumb_ct is not None:
            files["thumb_ct"] = (
                "thumb.bin", thumb_ct, "application/octet-stream",
            )
        data = {
            "meta_blob": crypto.b64encode(meta_blob),
            "meta_iv": crypto.b64encode(meta_iv),
            "file_hash_plain": file_hash_plain,
        }
        put_resp = self._client.put(
            f"/api/v1/vouchers/{voucher_id}", files=files, data=data,
        )
        if put_resp.status_code != 200:
            self._raise_for_error(put_resp)
        put_data = put_resp.json()

        return VoucherUploadResult(
            voucher_id=voucher_id,
            aad_id=aad_id,
            file_hash_cipher=put_data.get("file_hash_cipher", ""),
            file_hash_plain=file_hash_plain,
            has_thumbnail=thumb_ct is not None,
        )

    def download_voucher_image(
        self, voucher_id: int, aad_id: int, *, thumb: bool = False,
    ) -> bytes:
        """証憑画像 (または サムネ) を fetch して MK で復号し平文バイト列を返す。

        必要なスコープ: ``journals:read``。事前に :meth:`unlock` が必要。

        ``aad_id`` は :meth:`upload_voucher` の戻り値、または :meth:`list_vouchers`
        の各 :class:`VoucherListItem.aad_id` から得る (AAD 束縛に必須)。

        Args:
            voucher_id: 証憑 ID (URL/fetch 用)
            aad_id: AAD 束縛用安定識別子
            thumb: True ならサムネ (``?size=thumb``, vthumb AAD)。サムネが存在
                しない証憑に True を渡すとサーバが本体にフォールバックするため
                復号 (vthumb AAD) に失敗する点に注意。

        Returns:
            復号した平文画像バイト列。MIME は :func:`crypto.sniff_image_mime`
            で判定できる。

        Raises:
            LockedError: MK が未解錠の場合
            cryptography.exceptions.InvalidTag: AAD/MK 不一致・改ざん時
        """
        mk, user_id = self._require_mk()
        params = {"size": "thumb"} if thumb else None
        resp = self._client.get(
            f"/api/v1/vouchers/{voucher_id}/image", params=params,
        )
        if resp.status_code != 200:
            self._raise_for_error(resp)
        table = "vthumb" if thumb else "vimg"
        aad = crypto.build_aad(table, user_id, int(aad_id))
        return crypto.decrypt_blob(mk, resp.content, aad)

    def list_vouchers(
        self,
        *,
        page: int = 1,
        per_page: int = 20,
        amount_from: int | None = None,
        amount_to: int | None = None,
    ) -> VoucherListResponse:
        """証憑一覧を取得する。必要なスコープ: ``journals:read``

        MK は不要 (一覧メタのみ)。各件の ``aad_id`` を
        :meth:`download_voucher_image` に渡して画像を復号する。

        Args:
            page / per_page: ページネーション (per_page 上限 100)
            amount_from / amount_to: 紐付く仕訳の借方合計での絞り込み (任意)

        Returns:
            VoucherListResponse: 証憑一覧とページネーション情報
        """
        params: dict[str, int] = {"page": page, "per_page": per_page}
        if amount_from is not None:
            params["amount_from"] = amount_from
        if amount_to is not None:
            params["amount_to"] = amount_to
        resp = self._client.get("/api/v1/vouchers", params=params)
        if resp.status_code == 200:
            data = resp.json()
            return VoucherListResponse(
                vouchers=[
                    VoucherListItem.from_dict(v) for v in data["vouchers"]
                ],
                total=data["total"],
                page=data["page"],
                per_page=data["per_page"],
            )
        self._raise_for_error(resp)

    def verify_voucher(self, voucher_id: int) -> dict:
        """サーバ側で暗号文ハッシュ (file_hash_cipher) を再計算して検証する。

        必要なスコープ: ``journals:read``。電帳法の改ざん検知用。サーバは保存済み
        の暗号文を SHA-256 し、保存ハッシュと一致するかを返す (MK 不要、平文には
        触れない)。``GET /api/v1/vouchers/<id>/verify``。

        Returns:
            ``{"ok", "verified", "stored_hash", "computed_hash"}`` 等の生 JSON。
        """
        resp = self._client.get(f"/api/v1/vouchers/{voucher_id}/verify")
        if resp.status_code == 200:
            return resp.json()
        self._raise_for_error(resp)

    # --- 全データバックアップ / リストア (v5 BU) ---

    def export_backup(self) -> dict:
        """全データバックアップ (暗号文のまま) を取得する。必要なスコープ: ``journals:read``

        ``GET /api/v1/backup/export`` のレスポンスをそのまま返す。各 record は
        ``encrypted_blob`` を保持した **暗号文** で、サーバーは平文を持ちません。
        この形式は :meth:`restore_backup` でそのまま復元できます。中身を人間可読に
        したい場合は :meth:`export_backup_decrypted` を使ってください (要 MK)。

        Returns:
            backup dict (``version`` / ``exported_at`` / ``user_id`` / ``data``)。
        """
        resp = self._client.get("/api/v1/backup/export")
        if resp.status_code == 200:
            return resp.json()
        self._raise_for_error(resp)

    def export_backup_decrypted(self, raw: dict | None = None) -> dict:
        """全データバックアップを取得し MK で復号して平文 dict にする。要 MK 解錠。

        必要なスコープ: ``journals:read``。je/jel/me/bcb の暗号文を復号して各行に
        展開します (復号できない行は ``_decryptError`` を付与)。**この形式は復元には
        使えません** (暗号文が落ちるため)。復元用は :meth:`export_backup` を使います。

        Args:
            raw: 既に取得済みの :meth:`export_backup` レスポンス。指定すると再取得
                せずにそれを復号する (レート制限の節約)。省略時は GET する。
        """
        mk, user_id = self._require_mk()
        if raw is None:
            raw = self.export_backup()
        return backup_mod.decrypt_backup(mk, user_id, raw)

    def decrypt_voucher_image_blob(
        self, blob: bytes, aad_id: int, *, thumb: bool = False
    ) -> bytes:
        """手元の証憑画像暗号文 (``iv||ct||tag``) を MK 復号する。要 MK 解錠。

        :meth:`download_voucher_image` が再 fetch して復号するのに対し、本メソッドは
        既に取得済みの blob (backup export の ``image_data`` など) を再 fetch せず
        復号する用途。

        Args:
            blob: ``iv(12B) || ciphertext || GCM tag`` の opaque blob
            aad_id: AAD 束縛用安定識別子
            thumb: True なら vthumb AAD で復号する
        """
        mk, user_id = self._require_mk()
        table = "vthumb" if thumb else "vimg"
        return crypto.decrypt_blob(
            mk, blob, crypto.build_aad(table, user_id, int(aad_id))
        )

    def restore_backup(self, backup_data: dict) -> dict:
        """バックアップで全データを全置換リストアする。必要なスコープ: ``backup:restore``

        ``backup_data`` は :meth:`export_backup` が返す **暗号文** backup
        (``encrypted_blob`` を保持) を渡します。``POST /api/v1/backup/restore`` で
        本人の全関連データを delete → INSERT で再構築します (1 トランザクション)。

        Returns:
            復元件数 (``{"tables": {...}}`` 等のサーバー JSON の ``restored``)。

        Raises:
            KakeiboAPIError: 検証エラー (貸借不一致・不正 FK 等は 400)
        """
        resp = self._client.post("/api/v1/backup/restore", json=backup_data)
        if resp.status_code == 200:
            return resp.json().get("restored", {})
        self._raise_for_error(resp)

    def save_encrypted_backup(self, path: str | Path, passphrase: str) -> None:
        """暗号文バックアップを取得し ``.ikbackup`` パスフレーズアーカイブとして保存する。

        必要なスコープ: ``journals:read``（MK 不要）。暗号文 backup を MK と独立した
        パスフレーズ (Argon2id + AES-256-GCM) でさらに包んで保存します。保存物は
        ``encrypted_blob`` を保持するため :meth:`restore_encrypted_backup` で
        そのまま復元できます。

        Args:
            path: 出力先 (例: ``backup.ikbackup``)
            passphrase: 8 文字以上のパスフレーズ (MK とは別の災害用鍵)
        """
        raw = self.export_backup()
        data = json.dumps(raw, ensure_ascii=False).encode("utf-8")
        archive = crypto.encrypt_backup_archive(data, passphrase)
        Path(path).write_bytes(archive)

    def restore_encrypted_backup(
        self, path: str | Path, passphrase: str
    ) -> dict:
        """``.ikbackup`` アーカイブを復号して全置換リストアする。

        必要なスコープ: ``backup:restore``。:meth:`save_encrypted_backup` で保存した
        アーカイブをパスフレーズで復号し、暗号文 backup を
        :meth:`restore_backup` に渡します。

        Returns:
            復元件数 (サーバー JSON の ``restored``)。
        """
        archive = Path(path).read_bytes()
        data = crypto.decrypt_backup_archive(archive, passphrase)
        backup_data = json.loads(data.decode("utf-8"))
        return self.restore_backup(backup_data)

    # --- 監査連携 (HPKE 非同期ワークフロー, E5 #112) ---

    def ensure_keypair(self) -> bytes:
        """X25519 鍵ペアが未設定なら生成・保管し、自分の公開鍵 (raw 32B) を返す。

        必要なスコープ: ``journals:read`` + ``journals:write``（要 MK 解錠）。秘密鍵は
        pkcs8 を MK で AES-GCM 暗号化して ``PUT /api/v1/keypair`` に保管します
        (サーバーは秘密鍵平文も MK も持ちません)。既に鍵ペアがあれば既存公開鍵を返す
        (回転は非対応)。

        Returns:
            自分の X25519 公開鍵 (raw 32B)。
        """
        mk, user_id = self._require_mk()
        existing = self._client.get("/api/v1/keypair")
        if existing.status_code != 200:
            self._raise_for_error(existing)
        data = existing.json()
        if data.get("public_key"):
            return crypto.b64decode(data["public_key"])

        public_raw, private_pkcs8 = hpke.generate_keypair()
        ct, iv = crypto.encrypt_gcm(
            mk, private_pkcs8, hpke.private_key_aad(user_id)
        )
        put = self._client.put(
            "/api/v1/keypair",
            json={
                "public_key": crypto.b64encode(public_raw),
                "encrypted_private_key": crypto.b64encode(ct),
                "private_key_iv": crypto.b64encode(iv),
            },
        )
        if put.status_code != 200:
            self._raise_for_error(put)
        return public_raw

    def _private_scalar(self) -> bytes:
        """自分の X25519 秘密鍵 raw scalar (32B) を MK 復号して返す。要 MK。"""
        mk, user_id = self._require_mk()
        r = self._client.get("/api/v1/keypair")
        if r.status_code != 200:
            self._raise_for_error(r)
        d = r.json()
        if not d.get("encrypted_private_key") or not d.get("private_key_iv"):
            raise KakeiboAPIError(
                404, "鍵ペアが未設定です。先に ensure_keypair() を呼んでください。"
            )
        pkcs8 = crypto.decrypt_gcm(
            mk,
            crypto.b64decode(d["encrypted_private_key"]),
            crypto.b64decode(d["private_key_iv"]),
            hpke.private_key_aad(user_id),
        )
        return hpke.pkcs8_to_raw_scalar(pkcs8)

    def get_peer_public_key(self, user_id: int) -> bytes:
        """監査相手 (owner ⇄ auditor) の X25519 公開鍵 (raw 32B) を取得する。

        必要なスコープ: ``journals:read``。失効していない AuditGrant で結ばれた相手
        のみ取得できます (それ以外は 404)。``GET /api/v1/keypair/<id>/public``。
        """
        r = self._client.get(f"/api/v1/keypair/{user_id}/public")
        if r.status_code != 200:
            self._raise_for_error(r)
        pk = r.json().get("public_key")
        if not pk:
            raise KakeiboAPIError(404, "相手の公開鍵が未設定です。")
        return crypto.b64decode(pk)

    def send_audit_package(
        self,
        *,
        audit_grant_id: int,
        round_id: int,
        permission_level: int,
        recipient_public_key: bytes,
        plaintext: bytes,
    ) -> dict:
        """スナップショット平文を監査者の公開鍵宛に HPKE 暗号化して送信する。

        必要なスコープ: ``journals:write``。AAD は ``audit_grant_id`` /
        ``round_id`` に束縛されます。``POST /api/v1/audit-packages``。

        Returns:
            作成された AuditPackage の JSON。
        """
        enc, ct = hpke.hpke_seal(
            recipient_public_key, plaintext,
            hpke.package_aad(audit_grant_id, round_id),
        )
        r = self._client.post(
            "/api/v1/audit-packages",
            json={
                "audit_grant_id": audit_grant_id,
                "round_id": round_id,
                "permission_level": permission_level,
                "ephemeral_pubkey": crypto.b64encode(enc),
                "ciphertext": crypto.b64encode(ct),
                "snapshot_hash": crypto.b64encode(hpke.snapshot_hash(plaintext)),
            },
        )
        if r.status_code == 201:
            return r.json()
        self._raise_for_error(r)

    def list_audit_packages(self, *, role: str | None = None) -> list[dict]:
        """自分が関係する AuditPackage 一覧。``role="owner"|"auditor"`` で絞込。"""
        params = {"role": role} if role else None
        r = self._client.get("/api/v1/audit-packages", params=params)
        if r.status_code == 200:
            return r.json().get("audit_packages", [])
        self._raise_for_error(r)

    def open_audit_package(self, package: dict) -> bytes:
        """受信した AuditPackage を自分の秘密鍵で HPKE 復号して平文を返す。要 MK。

        ``package`` は :meth:`list_audit_packages` の 1 要素。AAD は package の
        ``audit_grant_id`` / ``round_id`` から再構築します。
        """
        scalar = self._private_scalar()
        aad = hpke.package_aad(package["audit_grant_id"], package["round_id"])
        return hpke.hpke_open(
            scalar,
            crypto.b64decode(package["ephemeral_pubkey"]),
            crypto.b64decode(package["ciphertext"]),
            aad,
        )

    def accept_audit_package(self, package_id: int) -> dict:
        """owner が監査パッケージを採用確定する (``owner_accepted_at`` 記録)。"""
        r = self._client.post(f"/api/v1/audit-packages/{package_id}/accept")
        if r.status_code == 200:
            return r.json()
        self._raise_for_error(r)

    def delete_audit_package(self, package_id: int) -> None:
        """AuditPackage を削除する (responses も CASCADE)。"""
        r = self._client.delete(f"/api/v1/audit-packages/{package_id}")
        if r.status_code == 204:
            return
        self._raise_for_error(r)

    def send_audit_response(
        self,
        *,
        audit_package_id: int,
        response_type: str,
        recipient_public_key: bytes,
        plaintext: bytes,
    ) -> dict:
        """auditor が修正案 / 差戻しを owner の公開鍵宛に HPKE 暗号化して返す。

        必要なスコープ: ``journals:write``。``response_type`` は ``"revision"``
        (修正案) か ``"rejection"`` (差戻し)。AAD は ``audit_package_id`` に束縛。
        """
        enc, ct = hpke.hpke_seal(
            recipient_public_key, plaintext,
            hpke.response_aad(audit_package_id),
        )
        r = self._client.post(
            "/api/v1/audit-responses",
            json={
                "audit_package_id": audit_package_id,
                "response_type": response_type,
                "ephemeral_pubkey": crypto.b64encode(enc),
                "ciphertext": crypto.b64encode(ct),
            },
        )
        if r.status_code == 201:
            return r.json()
        self._raise_for_error(r)

    def list_audit_responses(self) -> list[dict]:
        """自分が関係する AuditResponse 一覧 (package 経由で owner/auditor)。"""
        r = self._client.get("/api/v1/audit-responses")
        if r.status_code == 200:
            return r.json().get("audit_responses", [])
        self._raise_for_error(r)

    def open_audit_response(self, response: dict) -> bytes:
        """受信した AuditResponse を自分の秘密鍵で HPKE 復号して平文を返す。要 MK。

        AAD は response の ``audit_package_id`` から再構築します。
        """
        scalar = self._private_scalar()
        aad = hpke.response_aad(response["audit_package_id"])
        return hpke.hpke_open(
            scalar,
            crypto.b64decode(response["ephemeral_pubkey"]),
            crypto.b64decode(response["ciphertext"]),
            aad,
        )

    def acknowledge_audit_response(self, response_id: int) -> dict:
        """owner が修正案 / 差戻しを確認済みにする (``owner_acknowledged_at``)。"""
        r = self._client.post(
            f"/api/v1/audit-responses/{response_id}/acknowledge"
        )
        if r.status_code == 200:
            return r.json()
        self._raise_for_error(r)

    def build_lv3_snapshot(self) -> dict:
        """Lv3 (本人同等) 監査スナップショットを構築する。要 MK 解錠。

        必要なスコープ: ``journals:read``。全台帳を復号し、証憑画像を inline
        base64 で同梱します (Web ``audit_snapshot.js: buildSnapshotLv3`` 相当)。
        設定系 (AI 設定等) は監査に不要なので含めません。

        Returns:
            スナップショット dict。:meth:`send_audit_package` の ``plaintext`` に
            ``json.dumps(...).encode("utf-8")`` で渡せます。
        """
        decrypted = self.export_backup_decrypted()
        d = decrypted.get("data", {})
        accounts_meta = {
            a.code: {
                "type": a.account_type,
                "normal_balance": a.normal_balance,
                "name": a.name,
                "tax_category": a.tax_category,
            }
            for a in self.list_accounts()
        }
        return {
            "v": 1,
            "level": 3,
            "accounts_meta": accounts_meta,
            "accounts": d.get("accounts", []),
            "fiscal_closes": d.get("fiscal_closes", []),
            "journal_entries": d.get("journal_entries", []),
            "journal_entry_lines": d.get("journal_entry_lines", []),
            "medical_expenses": d.get("medical_expenses", []),
            "balance_cache_blobs": d.get("balance_cache_blobs", []),
            "vouchers": self._snapshot_vouchers(d.get("vouchers", [])),
        }

    def _snapshot_vouchers(self, vouchers: list[dict]) -> list[dict]:
        """Lv3 スナップショット用に証憑画像を復号して inline base64 同梱する。"""
        out = []
        for v in vouchers:
            base = {
                "voucher_id": v.get("id"),
                "journal_entry_id": v.get("journal_entry_id"),
                "aad_id": v.get("aad_id"),
                "file_hash": v.get("file_hash"),
                "uploaded_at": v.get("uploaded_at"),
            }
            if not v.get("image_data") or not v.get("aad_id"):
                out.append({**base, "_imageError": True})
                continue
            try:
                plain = self.decrypt_voucher_image_blob(
                    crypto.b64decode(v["image_data"]), int(v["aad_id"])
                )
                out.append({
                    **base,
                    "mime": crypto.sniff_image_mime(plain),
                    "image_base64": crypto.b64encode(plain),
                })
            except Exception:
                out.append({**base, "_imageError": True})
        return out

    def _accounts_meta(self) -> dict:
        """``code → {type, normal_balance, name, tax_category}`` を構築する。"""
        return {
            a.code: {
                "type": a.account_type,
                "normal_balance": a.normal_balance,
                "name": a.name,
                "tax_category": a.tax_category,
            }
            for a in self.list_accounts()
        }

    @staticmethod
    def _entry_to_report_dict(jd) -> dict:
        """JournalDetail を reports / スナップショット用の正規化 entry dict に変換。"""
        return {
            "id": jd.id,
            "entry_number": jd.entry_number,
            "fiscal_year": jd.fiscal_year,
            "date": jd.date,
            "description": jd.description,
            "source": jd.source,
            "is_closing": jd.is_closing,
            "fiscal_month": jd.fiscal_month,
            "lines": [
                {
                    "account_code": line.account_code,
                    "debit": line.debit,
                    "credit": line.credit,
                    "description": line.description,
                }
                for line in jd.lines
            ],
        }

    def _year_reports(self, fiscal_year: int, accounts_meta: dict) -> dict:
        """指定年度の仕訳を復号し、試算表 / P/L / B/S / 月次比較を計算する。

        B/S は前年末 (year-1, period=15) の残高キャッシュを priorCumulative に流す
        (audit_snapshot.js: _yearReports と同方針)。BCB 欠落時は ``{}`` で degraded。
        """
        entries = [
            self._entry_to_report_dict(jd)
            for jd in self._iter_all_journals(fiscal_year)
        ]
        type_by = {c: m["type"] for c, m in accounts_meta.items()}
        nb_by = {c: m["normal_balance"] for c, m in accounts_meta.items()}
        name_by = {c: m["name"] for c, m in accounts_meta.items()}
        try:
            prior = self.list_balance_cache_blobs(fiscal_year - 1).get(15, {})
        except Exception:
            prior = {}
        return {
            "entries": entries,
            "trial_balance": reports.compute_trial_balance(entries),
            "profit_loss": reports.compute_profit_loss(
                entries, account_type_by_code=type_by, account_name_by_code=name_by
            ),
            "balance_sheet": reports.compute_balance_sheet(
                entries, account_type_by_code=type_by,
                normal_balance_by_code=nb_by, account_name_by_code=name_by,
                prior_cumulative=prior,
            ),
            "monthly": reports.compute_monthly_comparison(
                entries, account_type_by_code=type_by, account_name_by_code=name_by
            ),
        }

    def build_lv1_snapshot(self, fiscal_year: int) -> dict:
        """Lv1 (集計のみ) 監査スナップショットを構築する。要 MK 解錠。

        必要なスコープ: ``journals:read``。試算表 / P/L / B/S / 月次比較のみで、
        仕訳本体は含めません (audit_snapshot.js: buildSnapshotLv1 相当)。
        """
        self._require_mk()
        accounts_meta = self._accounts_meta()
        r = self._year_reports(fiscal_year, accounts_meta)
        return {
            "v": 1,
            "level": 1,
            "fiscal_year": fiscal_year,
            "accounts_meta": accounts_meta,
            "trial_balance": r["trial_balance"],
            "profit_loss": r["profit_loss"],
            "balance_sheet": r["balance_sheet"],
            "monthly": r["monthly"],
        }

    def build_lv2_snapshot(self, fiscal_year: int) -> dict:
        """Lv2 (税務科目限定) 監査スナップショットを構築する。要 MK 解錠。

        必要なスコープ: ``journals:read``。Lv1 + 税務科目 (tax_category 付き) を含む
        仕訳のみ + 税務集計。フィルタは owner 側で強制します (§14.5、E2EE と矛盾なし)。
        """
        self._require_mk()
        accounts_meta = self._accounts_meta()
        tax_by = {c: m["tax_category"] for c, m in accounts_meta.items()}
        name_by = {c: m["name"] for c, m in accounts_meta.items()}
        r = self._year_reports(fiscal_year, accounts_meta)
        tax_entries = [
            e for e in r["entries"]
            if any(
                line.get("account_code") is not None
                and tax_by.get(line.get("account_code")) is not None
                for line in (e.get("lines") or [])
            )
        ]
        return {
            "v": 1,
            "level": 2,
            "fiscal_year": fiscal_year,
            "accounts_meta": accounts_meta,
            "trial_balance": r["trial_balance"],
            "profit_loss": r["profit_loss"],
            "balance_sheet": r["balance_sheet"],
            "monthly": r["monthly"],
            "tax_summary": reports.compute_tax_summary(
                r["entries"], tax_category_by_code=tax_by,
                account_name_by_code=name_by,
            ),
            "entries": tax_entries,
        }

    def send_snapshot(
        self,
        *,
        audit_grant_id: int,
        round_id: int,
        auditor_user_id: int,
        level: int,
        fiscal_year: int | None = None,
    ) -> dict:
        """指定レベルのスナップショットを構築し監査者宛に HPKE 暗号化して送信する。要 MK。

        ``build_lv{level}_snapshot`` → :meth:`get_peer_public_key` →
        :meth:`send_audit_package` (permission_level=level) を一括で行う。Lv1/Lv2 は
        ``fiscal_year`` が必須です。
        """
        if level == 1:
            if fiscal_year is None:
                raise ValueError("Lv1 スナップショットには fiscal_year が必要です。")
            snapshot = self.build_lv1_snapshot(fiscal_year)
        elif level == 2:
            if fiscal_year is None:
                raise ValueError("Lv2 スナップショットには fiscal_year が必要です。")
            snapshot = self.build_lv2_snapshot(fiscal_year)
        elif level == 3:
            snapshot = self.build_lv3_snapshot()
        else:
            raise ValueError(f"level must be 1, 2, or 3: {level}")
        plaintext = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
        recipient = self.get_peer_public_key(auditor_user_id)
        return self.send_audit_package(
            audit_grant_id=audit_grant_id,
            round_id=round_id,
            permission_level=level,
            recipient_public_key=recipient,
            plaintext=plaintext,
        )

    def send_lv3_snapshot(
        self, *, audit_grant_id: int, round_id: int, auditor_user_id: int
    ) -> dict:
        """Lv3 スナップショットを構築し監査者宛に送信する (:meth:`send_snapshot` の薄い別名)。"""
        return self.send_snapshot(
            audit_grant_id=audit_grant_id, round_id=round_id,
            auditor_user_id=auditor_user_id, level=3,
        )

    # --- 内部ヘルパー ---

    @staticmethod
    def _raise_for_error(resp: httpx.Response) -> None:
        data = resp.json()
        message = data.get("error", "不明なエラー")
        if resp.status_code == 401:
            raise AuthenticationError(message)
        raise KakeiboAPIError(resp.status_code, message)
