"""いいかんじ家計簿 API 例外クラス"""


class KakeiboAPIError(Exception):
    """APIがエラーレスポンスを返した場合の例外"""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"[{status_code}] {message}")


class AuthenticationError(KakeiboAPIError):
    """認証エラー (401)"""

    def __init__(self, message: str = "無効な API キーです。") -> None:
        super().__init__(401, message)


class LockedError(KakeiboAPIError):
    """MK (マスターキー) が未解錠の状態で暗号化が必要な操作を呼んだ場合の例外。

    E2EE: 仕訳の作成・取得は MK を要する。``KakeiboClient.unlock(passphrase)``
    で解錠してから呼ぶこと。
    """

    def __init__(
        self, message: str = "MK が未解錠です。unlock(passphrase) を先に呼んでください。"
    ) -> None:
        super().__init__(0, message)
