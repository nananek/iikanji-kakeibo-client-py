"""iikanji CLI (cli.main の export サブコマンド) のテスト。"""

import pytest

from iikanji import cli
from iikanji.exceptions import KakeiboAPIError
from iikanji.export import ExportResult


class _FakeClient:
    def __init__(self, *, unlocked: bool = True) -> None:
        self._unlocked = unlocked
        self.unlocked_with: str | None = None

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *a) -> bool:
        return False

    @property
    def is_unlocked(self) -> bool:
        return self._unlocked

    def unlock(self, passphrase: str) -> None:
        self.unlocked_with = passphrase
        self._unlocked = True


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    for k in ("IIKANJI_BASE_URL", "IIKANJI_API_KEY", "IIKANJI_PASSPHRASE"):
        monkeypatch.delenv(k, raising=False)


def _patch(monkeypatch, client, result=None, raises=None):
    monkeypatch.setattr(cli, "KakeiboClient", lambda *a, **k: client)

    def fake_build(c):
        if raises is not None:
            raise raises
        return result or ExportResult(b"ZIPDATA", 0, 0)

    monkeypatch.setattr(cli.export_mod, "build_export_zip", fake_build)


class TestExportCommand:
    def test_happy_path(self, monkeypatch, tmp_path) -> None:
        out = tmp_path / "out.zip"
        _patch(monkeypatch, _FakeClient(unlocked=True))
        rc = cli.main(["export", "--base-url", "https://x", "--api-key", "k", "-o", str(out)])
        assert rc == 0
        assert out.read_bytes() == b"ZIPDATA"

    def test_unlocks_with_passphrase(self, monkeypatch, tmp_path) -> None:
        out = tmp_path / "out.zip"
        fc = _FakeClient(unlocked=False)
        _patch(monkeypatch, fc, result=ExportResult(b"Z", 1, 2))
        rc = cli.main([
            "export", "--base-url", "https://x", "--api-key", "k",
            "--passphrase", "pw", "-o", str(out),
        ])
        assert rc == 0
        assert fc.unlocked_with == "pw"

    def test_default_filename(self, monkeypatch, tmp_path) -> None:
        monkeypatch.chdir(tmp_path)
        _patch(monkeypatch, _FakeClient(unlocked=True))
        rc = cli.main(["export", "--base-url", "https://x", "--api-key", "k"])
        assert rc == 0
        produced = list(tmp_path.glob("iikanji-export-*.zip"))
        assert len(produced) == 1

    def test_env_vars(self, monkeypatch, tmp_path) -> None:
        out = tmp_path / "out.zip"
        monkeypatch.setenv("IIKANJI_BASE_URL", "https://env")
        monkeypatch.setenv("IIKANJI_API_KEY", "envkey")
        _patch(monkeypatch, _FakeClient(unlocked=True))
        rc = cli.main(["export", "-o", str(out)])
        assert rc == 0

    def test_missing_credentials(self) -> None:
        assert cli.main(["export"]) == 2

    def test_locked_without_passphrase(self, monkeypatch) -> None:
        _patch(monkeypatch, _FakeClient(unlocked=False))
        rc = cli.main(["export", "--base-url", "https://x", "--api-key", "k"])
        assert rc == 2

    def test_api_error_returns_1(self, monkeypatch) -> None:
        _patch(monkeypatch, _FakeClient(unlocked=True),
               raises=KakeiboAPIError(429, "レート制限"))
        rc = cli.main(["export", "--base-url", "https://x", "--api-key", "k"])
        assert rc == 1

    def test_no_subcommand_errors(self) -> None:
        with pytest.raises(SystemExit):
            cli.main([])
