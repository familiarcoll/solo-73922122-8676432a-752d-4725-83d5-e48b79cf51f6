"""图片解码重编码测试：实际重编码、格式伪装拒绝、炸弹图保护、占位图。"""

import io

from PIL import Image

from app.images import MAX_IMAGE_PIXELS, placeholder, reencode
from tests.helpers import gif_bytes, jpeg_bytes, png_bytes


def test_png_roundtrip_reencoded():
    raw = png_bytes((10, 20, 30))
    result = reencode(raw, "image/png")
    assert result is not None and result.media_type == "image/png"
    # 输出必须能被 Pillow 重新打开，且字节与输入不同（经过重新编码）
    with Image.open(io.BytesIO(result.data)) as im:
        assert im.format == "PNG" and im.size == (32, 32)
    assert result.data != raw


def test_jpeg_roundtrip_reencoded():
    raw = jpeg_bytes()
    result = reencode(raw, "image/jpeg")
    assert result is not None and result.media_type == "image/jpeg"
    with Image.open(io.BytesIO(result.data)) as im:
        assert im.format == "JPEG"


def test_declared_png_but_actual_jpeg_rejected():
    raw = jpeg_bytes()  # 真实 JPEG 字节
    assert reencode(raw, "image/png") is None


def test_declared_jpeg_but_actual_png_rejected():
    raw = png_bytes()
    assert reencode(raw, "image/jpeg") is None


def test_gif_bytes_rejected_for_png_and_jpeg():
    raw = gif_bytes()
    assert reencode(raw, "image/png") is None
    assert reencode(raw, "image/jpeg") is None


def test_corrupt_bytes_return_none():
    assert reencode(b"not an image at all", "image/png") is None
    assert reencode(png_bytes()[:20], "image/png") is None


def test_unsupported_declared_type_returns_none():
    assert reencode(png_bytes(), "image/gif") is None
    assert reencode(png_bytes(), "image/webp") is None


def test_decompression_bomb_rejected():
    # 构造声明尺寸超过像素上限的 PNG（高度压缩，内存占用小但逻辑像素巨大）
    huge_side = int(MAX_IMAGE_PIXELS ** 0.5) + 100
    img = Image.new("RGB", (huge_side, huge_side), (0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    assert reencode(buf.getvalue(), "image/png") is None


def test_placeholder_is_valid_png_and_cached():
    p1 = placeholder()
    p2 = placeholder()
    assert p1.media_type == "image/png"
    assert p1.data == p2.data  # 缓存复用
    with Image.open(io.BytesIO(p1.data)) as im:
        assert im.format == "PNG"


def test_reencode_strips_trailing_polyglot_payload():
    # 在合法 PNG 尾部追加脚本字节：重编码输出不得包含该载荷
    raw = png_bytes() + b"<script>alert(1)</script>"
    result = reencode(raw, "image/png")
    assert result is not None
    assert b"<script>" not in result.data
