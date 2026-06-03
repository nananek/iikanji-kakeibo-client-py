"""reports.py (集計関数) のユニットテスト + Web compute* との構造一致 golden。"""

import json

from iikanji import reports

# server の実 JS (crypto/reports/*.js) が固定入力で出した golden。client-py の
# compute_* が同一構造を出すことを検証する (監査者が Web で描画するため)。
META = {
    "1010": {"type": "asset", "normal_balance": "debit", "name": "現金", "tax_category": None},
    "2010": {"type": "liability", "normal_balance": "credit", "name": "未払金", "tax_category": None},
    "3010": {"type": "equity", "normal_balance": "credit", "name": "元入金", "tax_category": None},
    "4010": {"type": "revenue", "normal_balance": "credit", "name": "売上", "tax_category": None},
    "7010": {"type": "expense", "normal_balance": "debit", "name": "消耗品費", "tax_category": None},
    "7020": {"type": "expense", "normal_balance": "debit", "name": "社会保険料", "tax_category": "social_insurance"},
}
TYPE_BY = {c: m["type"] for c, m in META.items()}
NB_BY = {c: m["normal_balance"] for c, m in META.items()}
NAME_BY = {c: m["name"] for c, m in META.items()}
TAX_BY = {c: m["tax_category"] for c, m in META.items()}

ENTRIES = [
    {"id": 1, "fiscal_year": 2026, "fiscal_month": 1, "is_closing": False,
     "lines": [{"account_code": "7010", "debit": 3000, "credit": 0},
               {"account_code": "1010", "debit": 0, "credit": 3000}]},
    {"id": 2, "fiscal_year": 2026, "fiscal_month": 1, "is_closing": False,
     "lines": [{"account_code": "1010", "debit": 5000, "credit": 0},
               {"account_code": "4010", "debit": 0, "credit": 5000}]},
    {"id": 3, "fiscal_year": 2026, "fiscal_month": 2, "is_closing": False,
     "lines": [{"account_code": "7020", "debit": 2000, "credit": 0},
               {"account_code": "1010", "debit": 0, "credit": 2000}]},
]
PRIOR = {"1010": [100000, 0], "3010": [0, 100000]}

GOLDEN = json.loads(
    '{"trial_balance":[{"account_code":"1010","debit":5000,"credit":5000},'
    '{"account_code":"4010","debit":0,"credit":5000},'
    '{"account_code":"7010","debit":3000,"credit":0},'
    '{"account_code":"7020","debit":2000,"credit":0}],'
    '"profit_loss":{"income_total":5000,"expense_total":5000,"net_income":0,'
    '"income_breakdown":[{"account_code":"4010","account_name":"売上","amount":5000}],'
    '"expense_breakdown":[{"account_code":"7010","account_name":"消耗品費","amount":3000},'
    '{"account_code":"7020","account_name":"社会保険料","amount":2000}]},'
    '"balance_sheet":{"assets":[{"account_code":"1010","account_name":"現金","balance":100000}],'
    '"liabilities":[],"equities":[{"account_code":"3010","account_name":"元入金","balance":100000}],'
    '"total_assets":100000,"total_liabilities":0,"total_equity":100000,"net_income":0,'
    '"has_closing":false,"total_liability_and_equity":100000},'
    '"monthly":{"expense_accounts":[{"code":"7010","name":"消耗品費","months":[3000,0,0,0,0,0,0,0,0,0,0,0],"total":3000},'
    '{"code":"7020","name":"社会保険料","months":[0,2000,0,0,0,0,0,0,0,0,0,0],"total":2000}],'
    '"income_accounts":[{"code":"4010","name":"売上","months":[5000,0,0,0,0,0,0,0,0,0,0,0],"total":5000}],'
    '"expense_totals":[3000,2000,0,0,0,0,0,0,0,0,0,0],'
    '"income_totals":[5000,0,0,0,0,0,0,0,0,0,0,0],'
    '"net_totals":[2000,-2000,0,0,0,0,0,0,0,0,0,0]},'
    '"tax_summary":{"social_insurance":{"label":"社会保険料控除",'
    '"accounts":[{"name":"社会保険料","amount":2000}],"total":2000}}}'
)


class TestReportsInterop:
    def test_trial_balance(self) -> None:
        assert reports.compute_trial_balance(ENTRIES) == GOLDEN["trial_balance"]

    def test_profit_loss(self) -> None:
        out = reports.compute_profit_loss(
            ENTRIES, account_type_by_code=TYPE_BY, account_name_by_code=NAME_BY)
        assert out == GOLDEN["profit_loss"]

    def test_balance_sheet(self) -> None:
        out = reports.compute_balance_sheet(
            ENTRIES, account_type_by_code=TYPE_BY, normal_balance_by_code=NB_BY,
            account_name_by_code=NAME_BY, prior_cumulative=PRIOR)
        assert out == GOLDEN["balance_sheet"]

    def test_monthly(self) -> None:
        out = reports.compute_monthly_comparison(
            ENTRIES, account_type_by_code=TYPE_BY, account_name_by_code=NAME_BY)
        assert out == GOLDEN["monthly"]

    def test_tax_summary(self) -> None:
        out = reports.compute_tax_summary(
            ENTRIES, tax_category_by_code=TAX_BY, account_name_by_code=NAME_BY)
        assert out == GOLDEN["tax_summary"]


class TestReportsBehaviour:
    def test_trial_balance_excludes_closing(self) -> None:
        entries = ENTRIES + [
            {"id": 9, "fiscal_month": 16, "is_closing": True,
             "lines": [{"account_code": "4010", "debit": 5000, "credit": 0}]},
        ]
        rows = reports.compute_trial_balance(entries)
        # closing 除外なので 4010 の debit は増えない
        r4010 = next(r for r in rows if r["account_code"] == "4010")
        assert r4010["debit"] == 0
        # include_closing=True なら含む
        rows2 = reports.compute_trial_balance(entries, include_closing=True)
        assert next(r for r in rows2 if r["account_code"] == "4010")["debit"] == 5000

    def test_balance_sheet_adds_net_income_when_no_closing(self) -> None:
        # closing が無ければ当期純利益 (P/L net) を負債+純資産側に加算
        bs = reports.compute_balance_sheet(
            ENTRIES, account_type_by_code=TYPE_BY, normal_balance_by_code=NB_BY,
            account_name_by_code=NAME_BY, prior_cumulative={})
        assert bs["has_closing"] is False
        # net_income == 0 (golden の entries は損益ゼロ)
        assert bs["net_income"] == 0

    def test_balance_sheet_has_closing_no_net_income_add(self) -> None:
        entries = ENTRIES + [
            {"id": 9, "fiscal_month": 16, "is_closing": True,
             "lines": [{"account_code": "1010", "debit": 1000, "credit": 0},
                       {"account_code": "3010", "debit": 0, "credit": 1000}]},
        ]
        bs = reports.compute_balance_sheet(
            entries, account_type_by_code=TYPE_BY, normal_balance_by_code=NB_BY,
            account_name_by_code=NAME_BY, prior_cumulative={})
        assert bs["has_closing"] is True
        assert bs["net_income"] == 0  # closing ありは P/L を加算しない

    def test_tax_summary_excludes_medical(self) -> None:
        tax_by = {"5010": "medical", "7020": "social_insurance"}
        names = {"5010": "医療費", "7020": "社会保険料"}
        entries = [
            {"id": 1, "fiscal_month": 1, "is_closing": False,
             "lines": [{"account_code": "5010", "debit": 8000, "credit": 0},
                       {"account_code": "7020", "debit": 2000, "credit": 0}]},
        ]
        out = reports.compute_tax_summary(
            entries, tax_category_by_code=tax_by, account_name_by_code=names)
        assert "medical" not in out
        assert out["social_insurance"]["total"] == 2000

    def test_monthly_skips_non_month_periods(self) -> None:
        entries = [
            {"id": 1, "fiscal_month": 0, "is_closing": False,
             "lines": [{"account_code": "7010", "debit": 100, "credit": 0}]},
            {"id": 2, "fiscal_month": 13, "is_closing": False,
             "lines": [{"account_code": "7010", "debit": 200, "credit": 0}]},
        ]
        out = reports.compute_monthly_comparison(
            entries, account_type_by_code=TYPE_BY, account_name_by_code=NAME_BY)
        assert out["expense_accounts"] == []  # fp=0/13 は月次から除外

    def test_balance_of(self) -> None:
        assert reports.balance_of({"debit": 1000, "credit": 300}, "debit") == 700
        assert reports.balance_of({"debit": 200, "credit": 500}, "credit") == 300
