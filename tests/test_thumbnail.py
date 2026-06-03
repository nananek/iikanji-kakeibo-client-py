"""thumbnail.make_thumbnail (Pillow) のユニットテスト。"""

import io

from iikanji import thumbnail


def _png(size: tuple[int, int]) -> bytes:
    from PIL import Image

    img = Image.new("RGB", size, (200, 100, 50))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


class TestMakeThumbnail:
    def test_returns_jpeg_within_max_size(self) -> None:
        from PIL import Image

        out = thumbnail.make_thumbnail(_png((800, 400)))
        assert out is not None
        assert out[:3] == b"\xff\xd8\xff"  # JPEG magic
        with Image.open(io.BytesIO(out)) as img:
            assert max(img.size) <= thumbnail.THUMB_MAX
            # 長辺 800→200 に縮小、アスペクト比 (2:1) を保つ
            assert img.size == (200, 100)

    def test_small_image_not_upscaled(self) -> None:
        from PIL import Image

        out = thumbnail.make_thumbnail(_png((50, 30)))
        assert out is not None
        with Image.open(io.BytesIO(out)) as img:
            assert img.size == (50, 30)

    def test_rgba_png_converted(self) -> None:
        from PIL import Image

        img = Image.new("RGBA", (300, 300), (0, 0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        out = thumbnail.make_thumbnail(buf.getvalue())
        assert out is not None and out[:3] == b"\xff\xd8\xff"

    def test_invalid_image_returns_none(self) -> None:
        assert thumbnail.make_thumbnail(b"not an image at all") is None
