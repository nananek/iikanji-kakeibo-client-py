"""レポート集計のクライアントサイド計算 (Web ``crypto/reports/*.js`` の移植)。

監査スナップショット Lv1/Lv2 で使う試算表 / P/L / B/S / 月次比較 / 税務集計の純粋
関数群。入力 ``entries`` は ``fetchJournalsForYear`` 正規化形式と同じ::

    [{id, fiscal_year, fiscal_month, is_closing,
      lines: [{account_code, debit, credit, description}]}]

出力構造は Web の各 ``compute*`` と一致させ、監査者 (Web) がそのまま描画できる。
account_code 昇順ソートは ASCII 科目コードのため JS ``localeCompare`` と一致する。
"""

from __future__ import annotations


def compute_trial_balance(
    entries: list[dict],
    *,
    fiscal_period_from: int = 0,
    fiscal_period_to: int = 16,
    include_closing: bool = False,
) -> list[dict]:
    """試算表の借方/貸方合計を科目別に計算 (trial_balance.js: computeTrialBalance)。"""
    sums: dict[str, dict] = {}
    for entry in entries:
        fp = entry.get("fiscal_month") or 0
        if fp < fiscal_period_from or fp > fiscal_period_to:
            continue
        if not include_closing and entry.get("is_closing"):
            continue
        for line in entry.get("lines") or []:
            code = line.get("account_code")
            if code is None:
                continue
            cur = sums.setdefault(code, {"debit": 0, "credit": 0})
            cur["debit"] += line.get("debit") or 0
            cur["credit"] += line.get("credit") or 0
    return [
        {"account_code": code, "debit": v["debit"], "credit": v["credit"]}
        for code, v in sorted(sums.items())
    ]


def balance_of(row: dict, normal_balance: str) -> int:
    """normal_balance に基づく残高 (trial_balance.js: balanceOf)。"""
    if normal_balance == "debit":
        return row["debit"] - row["credit"]
    if normal_balance == "credit":
        return row["credit"] - row["debit"]
    raise ValueError(f"balance_of: unsupported normal_balance: {normal_balance}")


def compute_profit_loss(
    entries: list[dict],
    *,
    account_type_by_code: dict,
    account_name_by_code: dict | None = None,
    month: int | None = None,
) -> dict:
    """損益計算書 (profit_loss.js: computeProfitLoss)。"""
    names = account_name_by_code or {}
    sums: dict[str, dict] = {}
    for entry in entries:
        fp = entry.get("fiscal_month") or 0
        if entry.get("is_closing"):
            continue
        if month is not None:
            if fp != month:
                continue
        elif fp == 16:
            continue
        for line in entry.get("lines") or []:
            code = line.get("account_code")
            if code is None:
                continue
            t = account_type_by_code.get(code)
            if t not in ("revenue", "expense"):
                continue
            cur = sums.setdefault(code, {"debit": 0, "credit": 0, "type": t})
            cur["debit"] += line.get("debit") or 0
            cur["credit"] += line.get("credit") or 0

    income_breakdown = []
    expense_breakdown = []
    for code, v in sums.items():
        amount = (
            v["credit"] - v["debit"] if v["type"] == "revenue"
            else v["debit"] - v["credit"]
        )
        if amount == 0:
            continue
        row = {"account_code": code, "account_name": names.get(code, code), "amount": amount}
        (income_breakdown if v["type"] == "revenue" else expense_breakdown).append(row)
    income_breakdown.sort(key=lambda r: r["account_code"])
    expense_breakdown.sort(key=lambda r: r["account_code"])

    income_total = sum(r["amount"] for r in income_breakdown)
    expense_total = sum(r["amount"] for r in expense_breakdown)
    return {
        "income_total": income_total,
        "expense_total": expense_total,
        "net_income": income_total - expense_total,
        "income_breakdown": income_breakdown,
        "expense_breakdown": expense_breakdown,
    }


def compute_balance_sheet(
    entries: list[dict],
    *,
    account_type_by_code: dict,
    normal_balance_by_code: dict,
    account_name_by_code: dict | None = None,
    prior_cumulative: dict | None = None,
) -> dict:
    """貸借対照表 (balance_sheet.js: computeBalanceSheet)。

    ``prior_cumulative`` = 前年末 (year-1, period=15) の累計
    ``{account_code: [debit, credit]}`` (tuple 可)。
    """
    names = account_name_by_code or {}
    prior = prior_cumulative or {}
    bs_types = ("asset", "liability", "equity")

    sums: dict[str, dict] = {}
    for code, pair in prior.items():
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        t = account_type_by_code.get(code)
        if t not in bs_types:
            continue
        sums[code] = {"debit": pair[0] or 0, "credit": pair[1] or 0, "type": t}

    has_closing = False
    for entry in entries:
        if entry.get("is_closing"):
            has_closing = True
        for line in entry.get("lines") or []:
            code = line.get("account_code")
            if code is None:
                continue
            t = account_type_by_code.get(code)
            if t not in bs_types:
                continue
            cur = sums.setdefault(code, {"debit": 0, "credit": 0, "type": t})
            cur["debit"] += line.get("debit") or 0
            cur["credit"] += line.get("credit") or 0

    assets, liabilities, equities = [], [], []
    for code, v in sums.items():
        normal = normal_balance_by_code.get(code)
        if normal not in ("debit", "credit"):
            continue
        balance = v["debit"] - v["credit"] if normal == "debit" else v["credit"] - v["debit"]
        if balance == 0:
            continue
        row = {"account_code": code, "account_name": names.get(code, code), "balance": balance}
        if v["type"] == "asset":
            assets.append(row)
        elif v["type"] == "liability":
            liabilities.append(row)
        elif v["type"] == "equity":
            equities.append(row)
    assets.sort(key=lambda r: r["account_code"])
    liabilities.sort(key=lambda r: r["account_code"])
    equities.sort(key=lambda r: r["account_code"])

    total_assets = sum(r["balance"] for r in assets)
    total_liabilities = sum(r["balance"] for r in liabilities)
    total_equity = sum(r["balance"] for r in equities)

    net_income = 0
    if not has_closing:
        pl = compute_profit_loss(
            entries,
            account_type_by_code=account_type_by_code,
            account_name_by_code=names,
        )
        net_income = pl["net_income"]

    return {
        "assets": assets,
        "liabilities": liabilities,
        "equities": equities,
        "total_assets": total_assets,
        "total_liabilities": total_liabilities,
        "total_equity": total_equity,
        "net_income": net_income,
        "has_closing": has_closing,
        "total_liability_and_equity": (
            total_liabilities + total_equity + (0 if has_closing else net_income)
        ),
    }


def compute_monthly_comparison(
    entries: list[dict],
    *,
    account_type_by_code: dict,
    account_name_by_code: dict | None = None,
) -> dict:
    """12 ヶ月の月次比較 (monthly_comparison.js: computeMonthlyComparison)。"""
    names = account_name_by_code or {}
    expense_by_code: dict[str, dict] = {}
    income_by_code: dict[str, dict] = {}

    for entry in entries:
        if entry.get("is_closing"):
            continue
        fp = entry.get("fiscal_month")
        if not isinstance(fp, int) or isinstance(fp, bool):
            continue
        if fp < 1 or fp > 12:
            continue
        month_idx = fp - 1
        for line in entry.get("lines") or []:
            code = line.get("account_code")
            if code is None:
                continue
            t = account_type_by_code.get(code)
            if t == "expense":
                cur = expense_by_code.setdefault(
                    code, {"code": code, "name": names.get(code, code),
                           "months": [0] * 12, "total": 0})
                net = (line.get("debit") or 0) - (line.get("credit") or 0)
                cur["months"][month_idx] += net
                cur["total"] += net
            elif t == "revenue":
                cur = income_by_code.setdefault(
                    code, {"code": code, "name": names.get(code, code),
                           "months": [0] * 12, "total": 0})
                net = (line.get("credit") or 0) - (line.get("debit") or 0)
                cur["months"][month_idx] += net
                cur["total"] += net

    expense_accounts = sorted(expense_by_code.values(), key=lambda a: a["code"])
    income_accounts = sorted(income_by_code.values(), key=lambda a: a["code"])

    expense_totals = [0] * 12
    for a in expense_accounts:
        for i in range(12):
            expense_totals[i] += a["months"][i]
    income_totals = [0] * 12
    for a in income_accounts:
        for i in range(12):
            income_totals[i] += a["months"][i]
    net_totals = [income_totals[i] - expense_totals[i] for i in range(12)]

    return {
        "expense_accounts": expense_accounts,
        "income_accounts": income_accounts,
        "expense_totals": expense_totals,
        "income_totals": income_totals,
        "net_totals": net_totals,
    }


def compute_ledger(
    entries: list[dict],
    *,
    account_code: str,
    normal_balance: str,
    opening_balance: int = 0,
    fiscal_period_from: int = 0,
    fiscal_period_to: int = 16,
    include_closing: bool = True,
) -> dict:
    """指定科目の総勘定元帳 (ledger.js: computeLedger)。

    date は暗号化のためサーバの ``ORDER BY date`` を再現できず、``entry.id`` 昇順
    (作成順 ≈ 時系列) で並べる。``opening_balance`` (前期繰越) は呼出側が指定する。

    Returns:
        ``{opening_balance, rows, closing_balance, total_debit, total_credit}``。
        rows = ``{entry_id, fiscal_period, date, description, debit, credit,
        balance, counterparts}``。counterparts = 当該 entry 内の他 line の科目
        コードをカンマ区切り。
    """
    if normal_balance not in ("debit", "credit"):
        raise ValueError("normal_balance must be 'debit' or 'credit'")

    ordered = sorted(entries, key=lambda e: e.get("id") or 0)
    rows = []
    balance = opening_balance
    total_debit = 0
    total_credit = 0

    for entry in ordered:
        fp = entry.get("fiscal_month") or 0
        if fp < fiscal_period_from or fp > fiscal_period_to:
            continue
        if not include_closing and entry.get("is_closing"):
            continue

        entry_debit = 0
        entry_credit = 0
        has_match = False
        counterparts = set()
        for line in entry.get("lines") or []:
            code = line.get("account_code")
            if code == account_code:
                entry_debit += line.get("debit") or 0
                entry_credit += line.get("credit") or 0
                has_match = True
            elif code is not None:
                counterparts.add(code)
        if not has_match:
            continue

        if normal_balance == "debit":
            balance += entry_debit - entry_credit
        else:
            balance += entry_credit - entry_debit
        total_debit += entry_debit
        total_credit += entry_credit

        rows.append({
            "entry_id": entry.get("id"),
            "fiscal_period": fp,
            "date": entry.get("date"),
            "description": entry.get("description") or "",
            "debit": entry_debit,
            "credit": entry_credit,
            "balance": balance,
            "counterparts": ", ".join(sorted(counterparts)),
        })

    return {
        "opening_balance": opening_balance,
        "rows": rows,
        "closing_balance": balance,
        "total_debit": total_debit,
        "total_credit": total_credit,
    }


# 確定申告控除の表示ラベル (tax_summary.js: TAX_CATEGORY_LABELS と同一)。
TAX_CATEGORY_LABELS = {
    "social_insurance": "社会保険料控除",
    "life_insurance": "生命保険料控除",
    "earthquake_insurance": "地震保険料控除",
    "medical": "医療費控除",
    "donation": "寄附金控除",
    "ideco": "小規模企業共済等掛金控除",
    "withholding_tax": "源泉所得税",
    "resident_tax": "住民税",
}

# medical / resident_tax は専用集計があるため税務集計から除外。
_EXCLUDED_TAX_CATEGORIES = frozenset({"medical", "resident_tax"})


def compute_tax_summary(
    entries: list[dict],
    *,
    tax_category_by_code: dict,
    account_name_by_code: dict | None = None,
) -> dict:
    """確定申告控除集計 (tax_summary.js: computeTaxSummary)。

    Returns:
        tax_category をキーとする dict ``{cat: {label, accounts, total}}``
        (medical/resident_tax 除外、total==0 の category 除外、accounts は name 昇順)。
    """
    names = account_name_by_code or {}
    by_category: dict[str, dict] = {}

    for entry in entries:
        if entry.get("is_closing"):
            continue
        for line in entry.get("lines") or []:
            code = line.get("account_code")
            if code is None:
                continue
            cat = tax_category_by_code.get(code)
            if cat is None or cat in _EXCLUDED_TAX_CATEGORIES:
                continue
            bucket = by_category.setdefault(cat, {})
            cur = bucket.setdefault(code, {"debit": 0, "credit": 0})
            cur["debit"] += line.get("debit") or 0
            cur["credit"] += line.get("credit") or 0

    result: dict[str, dict] = {}
    for cat, bucket in by_category.items():
        accounts = []
        total = 0
        for code, v in bucket.items():
            amount = v["debit"] - v["credit"]
            if amount == 0:
                continue
            accounts.append({"name": names.get(code, code), "amount": amount})
            total += amount
        if total == 0:
            continue
        accounts.sort(key=lambda a: a["name"])
        result[cat] = {
            "label": TAX_CATEGORY_LABELS.get(cat, cat),
            "accounts": accounts,
            "total": total,
        }
    return result
