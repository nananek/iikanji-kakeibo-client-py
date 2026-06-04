"""いいかんじ家計簿 API データモデル

E2EE (Phase E6 §15.1): 仕訳本体 (date/description/source/fiscal_period) と各
明細行 (account_code/debit/credit/description のうち description) は MK で
AES-GCM 暗号化して ``encrypted_blob`` / ``blob_iv`` (base64) で送受信する。
平文 wire には ``fiscal_year`` / ``fiscal_month`` と集計用の line
``account_code`` / ``debit`` / ``credit`` のみ載せる
(server/app/static/js/crypto/entries_builder.js と一致)。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

from . import crypto


@dataclass
class JournalLine:
    """仕訳明細行"""

    account_code: str
    debit: int = 0
    credit: int = 0
    description: str = ""

    def _record_body(self) -> dict:
        """jel record body (entries_builder.js _encryptEntry と一致)。"""
        return {
            "v": 1,
            "account_code": self.account_code,
            "debit_amount": int(self.debit or 0),
            "credit_amount": int(self.credit or 0),
            "description": self.description or "",
        }

    def to_wire(self, mk: bytes, user_id: int) -> dict:
        """暗号化 line wire を生成する。

        平文メタは account_code / debit / credit (集計用)。description は
        encrypted_blob (jel) にのみ格納する。
        """
        blob, iv = crypto.encrypt_record(
            mk, self._record_body(), crypto.build_aad("jel", user_id)
        )
        return {
            "account_code": self.account_code,
            "debit": int(self.debit or 0),
            "credit": int(self.credit or 0),
            "encrypted_blob": crypto.b64encode(blob),
            "blob_iv": crypto.b64encode(iv),
        }

    @classmethod
    def from_api(cls, line: dict, mk: bytes, user_id: int) -> JournalLine:
        """API レスポンスの line を復号して JournalLine に復元する。

        #338 item4: サーバは line の平文 account_code / debit / credit を返さなく
        なった。encrypted_blob (jel) を復号して body から取得する。description も同様。
        旧サーバ (平文応答) との後方互換のため、復号 body を優先しつつ平文応答へ
        フォールバックする (journals_client.js _normalizeLine と同方針)。復号失敗
        (MK 不一致等) かつ平文も無い場合は account_code=None / 金額0。
        """
        description = ""
        account_code = line.get("account_code")
        debit = int(line.get("debit", 0) or 0)
        credit = int(line.get("credit", 0) or 0)
        blob = line.get("encrypted_blob")
        iv = line.get("blob_iv")
        if blob and iv:
            try:
                body = crypto.decrypt_record(
                    mk,
                    crypto.b64decode(blob),
                    crypto.b64decode(iv),
                    crypto.build_aad("jel", user_id),
                )
                description = body.get("description", "")
                account_code = body.get("account_code", account_code)
                debit = int(body.get("debit_amount", debit) or 0)
                credit = int(body.get("credit_amount", credit) or 0)
            except Exception:
                description = ""
        return cls(
            account_code=account_code,
            debit=debit,
            credit=credit,
            description=description,
        )


@dataclass
class JournalCreateRequest:
    """仕訳起票リクエスト"""

    date: date | datetime | str
    description: str
    lines: list[JournalLine]
    source: str = "api"
    fiscal_period: int | None = None

    draft_id: int | None = None

    def _date_str(self) -> str:
        if isinstance(self.date, str):
            return self.date
        if isinstance(self.date, datetime):
            return self.date.date().isoformat()
        return self.date.isoformat()

    def to_wire(self, mk: bytes, user_id: int) -> dict:
        """暗号化済みの POST /api/v1/journals wire を生成する。

        entry 本体 (date/description/source/fiscal_period) を ``je`` record で
        暗号化し、平文メタ fiscal_year / fiscal_month を算出して付与する
        (entries_builder.js _encryptEntry と一致)。
        """
        d = self._date_str()
        fiscal_year = int(d[:4])
        fiscal_month = (
            self.fiscal_period
            if self.fiscal_period is not None
            else int(d[5:7])
        )
        entry_body = {
            "v": 1,
            "date": d,
            "description": self.description,
            "source": self.source,
            "fiscal_period": self.fiscal_period,
        }
        blob, iv = crypto.encrypt_record(
            mk, entry_body, crypto.build_aad("je", user_id)
        )
        result: dict = {
            "fiscal_year": fiscal_year,
            "fiscal_month": fiscal_month,
            "encrypted_blob": crypto.b64encode(blob),
            "blob_iv": crypto.b64encode(iv),
            "lines": [line.to_wire(mk, user_id) for line in self.lines],
        }
        if self.draft_id is not None:
            result["draft_id"] = self.draft_id
        return result


@dataclass
class JournalCreateResponse:
    """仕訳起票レスポンス"""

    id: int
    entry_number: int


@dataclass
class JournalDetail:
    """仕訳詳細"""

    id: int
    date: str
    entry_number: int
    description: str
    source: str
    lines: list[JournalLine]
    fiscal_year: int | None = None
    fiscal_month: int | None = None
    is_closing: bool = False

    @classmethod
    def from_dict(cls, data: dict, mk: bytes, user_id: int) -> JournalDetail:
        """API レスポンスの journal を復号して JournalDetail に復元する。

        通常仕訳は ``je`` blob を復号して date/description/source を得る。
        closing 仕訳 (is_closing=True, encrypted_blob=None) は fiscal_year から
        合成する (journals_client.js decryptEntryMeta と一致)。
        """
        fiscal_year = data.get("fiscal_year")
        is_closing = bool(data.get("is_closing", False))
        date_val: str | None = None
        description = ""
        source = ""

        blob = data.get("encrypted_blob")
        iv = data.get("blob_iv")
        if blob and iv:
            try:
                body = crypto.decrypt_record(
                    mk,
                    crypto.b64decode(blob),
                    crypto.b64decode(iv),
                    crypto.build_aad("je", user_id),
                )
                date_val = body.get("date")
                description = body.get("description", "")
                source = body.get("source", "")
            except Exception:
                # 復号失敗は局所化 (closing 以外は date=None / 空のままにする)
                pass

        if date_val is None and is_closing and fiscal_year is not None:
            date_val = f"{fiscal_year}-12-31"
            description = description or "損益振替仕訳（自動生成）"
            source = source or "closing"

        return cls(
            id=data["id"],
            date=date_val,
            entry_number=data.get("entry_number"),
            description=description,
            source=source,
            lines=[
                JournalLine.from_api(line, mk, user_id)
                for line in data.get("lines", [])
            ],
            fiscal_year=fiscal_year,
            fiscal_month=data.get("fiscal_month"),
            is_closing=is_closing,
        )


@dataclass
class JournalListResponse:
    """仕訳一覧レスポンス"""

    journals: list[JournalDetail]
    total: int
    page: int
    per_page: int


# --- 医療費 (MedicalExpense) ---


@dataclass
class MedicalExpense:
    """医療費明細 (1 仕訳に 1 件)。

    本体 (date/patient_name/hospital_name/treatment_description/provider_type/
    amount_paid/insurance_reimbursement) は MK で暗号化して送受信する
    (medical_expense_builder.js / medical_expenses_client.js と一致)。平文 wire
    には journal_entry_id のみ載せる。
    """

    journal_entry_id: int
    date: str | None = None
    patient_name: str = ""
    hospital_name: str = ""
    treatment_description: str = ""
    provider_type: str | None = None
    amount_paid: int = 0
    insurance_reimbursement: int = 0
    id: int | None = None

    def _record_body(self) -> dict:
        """me record body (medical_expense_builder.js buildMedicalExpense と一致)。"""
        return {
            "v": 1,
            "date": self.date or None,
            "patient_name": self.patient_name or "",
            "hospital_name": self.hospital_name or "",
            "treatment_description": self.treatment_description or "",
            "provider_type": self.provider_type or None,
            "amount_paid": int(self.amount_paid or 0),
            "insurance_reimbursement": int(self.insurance_reimbursement or 0),
        }

    def to_wire(self, mk: bytes, user_id: int) -> dict:
        """暗号化済みの POST /api/v1/medical-expenses wire を生成する。"""
        if int(self.amount_paid or 0) < 0 or int(self.insurance_reimbursement or 0) < 0:
            raise ValueError("amount_paid / insurance_reimbursement は非負整数です。")
        blob, iv = crypto.encrypt_record(
            mk, self._record_body(), crypto.build_aad("me", user_id)
        )
        return {
            "journal_entry_id": int(self.journal_entry_id),
            "encrypted_blob": crypto.b64encode(blob),
            "blob_iv": crypto.b64encode(iv),
        }

    @classmethod
    def from_api(cls, d: dict, mk: bytes, user_id: int) -> MedicalExpense:
        """API レスポンスの expense を復号して MedicalExpense に復元する。

        id / journal_entry_id は平文メタを採用。本体は encrypted_blob (me) を
        復号して取り出す。復号失敗時は各フィールドを既定値にフォールバックする
        (medical_expenses_client.js _normalize と同方針)。
        """
        body: dict = {}
        blob = d.get("encrypted_blob")
        iv = d.get("blob_iv")
        if blob and iv:
            try:
                body = crypto.decrypt_record(
                    mk,
                    crypto.b64decode(blob),
                    crypto.b64decode(iv),
                    crypto.build_aad("me", user_id),
                )
            except Exception:
                body = {}
        return cls(
            journal_entry_id=d.get("journal_entry_id"),
            date=body.get("date"),
            patient_name=body.get("patient_name", ""),
            hospital_name=body.get("hospital_name", ""),
            treatment_description=body.get("treatment_description", ""),
            provider_type=body.get("provider_type"),
            amount_paid=int(body.get("amount_paid", 0) or 0),
            insurance_reimbursement=int(body.get("insurance_reimbursement", 0) or 0),
            id=d.get("id"),
        )


@dataclass
class MedicalExpenseListResponse:
    """医療費一覧レスポンス"""

    expenses: list[MedicalExpense]
    total: int


# --- 勘定科目 / レポート集計 ---


@dataclass
class Account:
    """勘定科目 (E2EE 対象外・平文)。"""

    code: str
    name: str
    account_type: str  # asset / liability / equity / revenue / expense
    account_type_name: str  # 資産 / 負債 / 純資産 / 収益 / 費用
    normal_balance: str  # "debit" / "credit"
    is_active: bool = True
    system_role: str | None = None
    tax_category: str | None = None
    cost_type: str | None = None
    display_order: int = 0

    @classmethod
    def from_dict(cls, d: dict) -> Account:
        return cls(
            code=d["code"],
            name=d.get("name", ""),
            account_type=d.get("account_type", ""),
            account_type_name=d.get("account_type_name", ""),
            normal_balance=d.get("normal_balance", "debit"),
            is_active=bool(d.get("is_active", True)),
            system_role=d.get("system_role"),
            tax_category=d.get("tax_category"),
            cost_type=d.get("cost_type"),
            display_order=int(d.get("display_order", 0) or 0),
        )


@dataclass
class TrialBalanceRow:
    """試算表の 1 科目行。"""

    code: str
    name: str
    account_type: str
    debit: int  # 借方合計
    credit: int  # 貸方合計
    balance: int  # 正常残高側を正とした残高 (normal_balance に従う)


@dataclass
class TrialBalance:
    """試算表 (account_code 単位の借方/貸方合計 + 科目名・区分付き)。"""

    fiscal_year: int
    rows: list[TrialBalanceRow]
    total_debit: int
    total_credit: int


@dataclass
class ProfitLossRow:
    """損益計算書の 1 科目行 (収益 or 費用)。"""

    account_code: str
    account_name: str
    amount: int  # 収益=credit-debit、費用=debit-credit (いずれも >0)


@dataclass
class ProfitLoss:
    """損益計算書。"""

    fiscal_year: int
    income_total: int
    expense_total: int
    net_income: int  # income_total - expense_total
    income_breakdown: list[ProfitLossRow]
    expense_breakdown: list[ProfitLossRow]
    month: int | None = None  # 月指定集計なら 1-12、年間なら None


@dataclass
class BalanceSheetRow:
    """貸借対照表の 1 科目行。"""

    account_code: str
    account_name: str
    balance: int


@dataclass
class BalanceSheet:
    """貸借対照表。"""

    fiscal_year: int
    assets: list[BalanceSheetRow]
    liabilities: list[BalanceSheetRow]
    equities: list[BalanceSheetRow]
    total_assets: int
    total_liabilities: int
    total_equity: int
    net_income: int  # 損益振替前なら当期純利益、振替後は 0
    has_closing: bool
    total_liability_and_equity: int


@dataclass
class LedgerRow:
    """総勘定元帳の 1 行。"""

    entry_id: int
    fiscal_period: int
    date: str | None
    description: str
    debit: int
    credit: int
    balance: int  # running balance (normal_balance 側を正)
    counterparts: str  # 相手科目コードのカンマ区切り


@dataclass
class Ledger:
    """総勘定元帳 (指定科目の時系列明細 + running balance)。"""

    fiscal_year: int
    account_code: str
    account_name: str
    opening_balance: int
    rows: list[LedgerRow]
    closing_balance: int
    total_debit: int
    total_credit: int


# --- 証憑画像 (E2EE, E4 #111 Option C) ---


@dataclass
class VoucherUploadResult:
    """証憑アップロード結果 (init → encrypt → PUT)。

    ``aad_id`` は voucher_id と独立した安定識別子で、後で画像を再 fetch して
    復号する (:meth:`KakeiboClient.download_voucher_image`) 際に AAD 束縛に使う。
    backup/restore で PK が再採番されても aad_id は保持されるため復号互換を保つ。
    """

    voucher_id: int
    aad_id: int  # AAD 束縛用安定識別子 (63bit)
    file_hash_cipher: str  # サーバ計算の SHA-256(暗号文)
    file_hash_plain: str  # クライアント計算の SHA-256(平文画像)
    has_thumbnail: bool


@dataclass
class VoucherListItem:
    """証憑一覧の 1 件 (``GET /api/v1/vouchers``)。"""

    id: int
    journal_entry_id: int | None
    aad_id: int | None  # 平文レガシー証憑は None (E2EE 証憑のみ復号可)
    uploaded_at: str | None
    # #338 item4: 紐付く仕訳の借方合計。サーバが平文金額を SUM する経路だったため
    # 撤去された (新サーバは journal.amount を返さないので常に None)。旧サーバ互換の
    # ため from_dict は journal.amount があれば読む (deprecated)。
    amount: int | None

    @classmethod
    def from_dict(cls, d: dict) -> VoucherListItem:
        raw_aad = d.get("aad_id")
        journal = d.get("journal") or {}
        return cls(
            id=d["id"],
            journal_entry_id=d.get("journal_entry_id"),
            aad_id=int(raw_aad) if raw_aad is not None else None,
            uploaded_at=d.get("uploaded_at"),
            amount=journal.get("amount"),
        )


@dataclass
class VoucherListResponse:
    """証憑一覧レスポンス"""

    vouchers: list[VoucherListItem]
    total: int
    page: int
    per_page: int


# --- AI 証憑仕訳 ---


@dataclass
class DraftSummary:
    """下書きのサマリー情報"""

    title: str = ""
    date: str = ""
    description: str = ""
    amount: int = 0
    suggestion_count: int = 0


@dataclass
class DraftListItem:
    """下書き一覧の1件"""

    id: int
    status: str
    comment: str
    created_at: str
    summary: DraftSummary | None = None

    @classmethod
    def from_dict(cls, data: dict) -> DraftListItem:
        summary = None
        if "summary" in data and data["summary"]:
            s = data["summary"]
            summary = DraftSummary(
                title=s.get("title", ""),
                date=s.get("date", ""),
                description=s.get("description", ""),
                amount=s.get("amount", 0),
                suggestion_count=s.get("suggestion_count", 0),
            )
        return cls(
            id=data["id"],
            status=data["status"],
            comment=data.get("comment", ""),
            created_at=data["created_at"],
            summary=summary,
        )


@dataclass
class DraftDetail:
    """下書きの詳細（候補データ含む）"""

    id: int
    status: str
    comment: str
    created_at: str
    summary: DraftSummary | None = None
    suggestions: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> DraftDetail:
        summary = None
        if "summary" in data and data["summary"]:
            s = data["summary"]
            summary = DraftSummary(
                title=s.get("title", ""),
                date=s.get("date", ""),
                description=s.get("description", ""),
                amount=s.get("amount", 0),
                suggestion_count=s.get("suggestion_count", 0),
            )
        return cls(
            id=data["id"],
            status=data["status"],
            comment=data.get("comment", ""),
            created_at=data["created_at"],
            summary=summary,
            suggestions=data.get("suggestions", []),
        )


@dataclass
class DraftListResponse:
    """下書き一覧レスポンス"""

    drafts: list[DraftListItem]
    total: int
    page: int
    per_page: int


@dataclass
class AnalyzeResponse:
    """AI解析レスポンス"""

    draft_id: int
    suggestions: list[dict]
