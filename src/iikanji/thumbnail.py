"""証憑サムネイル生成 (Pillow)。

Web (``vouchers/thumbnail.js``) は canvas で長辺 200px の JPEG サムネを生成し、
暗号化前にバイト列を作る (原画像はサーバから見えないため、サムネもクライアント
生成する。設計書 §13.3)。client-py は DOM/canvas が無いため Pillow で同等の
縮小を行う (サーバには暗号文しか渡らないので byte 完全一致は不要、長辺 200px の
JPEG という規約のみ合わせる)。
"""

from __future__ import annotations

import io

# 長辺の最大ピクセル (Web thumbnail.js: THUMB_MAX と一致)。
THUMB_MAX = 200
# JPEG 品質 (Web は quality=0.85)。
THUMB_QUALITY = 85


def make_thumbnail(
    image_bytes: bytes,
    max_size: int = THUMB_MAX,
    quality: int = THUMB_QUALITY,
) -> bytes | None:
    """画像バイト列を長辺 ``max_size`` の JPEG サムネに縮小して返す。

    Pillow が画像を開けない (未対応形式・破損) 場合は ``None`` を返し、呼出側は
    サムネなしで本体のみ upload する (Web の makeThumbnail 未注入時と同じ挙動)。

    Args:
        image_bytes: 平文画像バイト列
        max_size: 長辺の最大ピクセル
        quality: JPEG 品質 (0..100)

    Returns:
        JPEG サムネのバイト列。生成不能なら ``None``。
    """
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - Pillow は必須依存
        return None

    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            # JPEG は RGB(A) のみ保存可。透過 PNG/パレット等は RGB に変換する。
            if img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            # thumbnail はアスペクト比を保って長辺を max_size 以下に収める。
            img.thumbnail((max_size, max_size))
            out = io.BytesIO()
            img.save(out, format="JPEG", quality=quality)
            return out.getvalue()
    except Exception:
        # 破損画像・未対応形式は黙ってサムネなしにフォールバック。
        return None
