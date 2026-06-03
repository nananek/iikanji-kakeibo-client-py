"""pytest 共通フィクスチャ。

OS keyring へ実際に書き込まないよう、テスト中はインメモリのキーリング
バックエンドに差し替える (各テストで隔離・leak 防止)。
"""

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class _MemoryKeyring(KeyringBackend):
    """テスト用インメモリ keyring バックエンド。"""

    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self._store[(service, username)]
        except KeyError:
            raise PasswordDeleteError("not found")


@pytest.fixture(autouse=True)
def memory_keyring():
    """各テストを新しいインメモリ keyring で実行する。"""
    prev = keyring.get_keyring()
    kr = _MemoryKeyring()
    keyring.set_keyring(kr)
    try:
        yield kr
    finally:
        keyring.set_keyring(prev)
