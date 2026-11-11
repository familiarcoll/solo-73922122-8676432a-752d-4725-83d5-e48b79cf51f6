"""内嵌图片的受控解码/重编码。

安全目标：

* 图片必须被 Pillow **实际解码成功**后重新编码输出，原始字节（可能夹带
  polyglot/恶意结构）永远不会被直接发给浏览器；
* 限制总像素数，阻断解压炸弹（Decompression Bomb）；
* 统一转成规范 PNG/JPEG，输出 MIME 与容器格式严格一致；
* 无法解码、格式不符或超尺寸时返回 None，由上层用占位图替代；
* 占位图由服务端自己生成，不引用任何外部资源。
"""

from __future__ import annotations

import io
import threading

from PIL import Image, ImageDraw, UnidentifiedImageError

# 单图最大像素数（约 1600 万像素，足够邮件插图，足以挡住炸弹图）
MAX_IMAGE_PIXELS = 16_000_000
# 重编码 JPEG 质量
JPEG_QUALITY = 85
# 占位图尺寸
PLACEHOLDER_SIZE = (240, 120)


class ReencodedImage:
    """重编码后的图片：字节、MIME 类型与建议扩展名。"""

    __slots__ = ("data", "media_type", "extension")

    def __init__(self, data: bytes, media_type: str, extension: str):
        self.data = data
        self.media_type = media_type
        self.extension = extension


def reencode(raw: bytes, declared_type: str) -> ReencodedImage | None:
    """把原始图片字节解码后重新编码。

    ``declared_type`` 是 MIME 声明类型；只有实际格式与声明一致（PNG/JPEG）
    才会产出结果，否则返回 ``None`` 让上层显示占位图。
    """
    if declared_type not in ("image/png", "image/jpeg"):
        return None
    try:
        with Image.open(io.BytesIO(raw)) as im:
            im.load()  # 强制实际解码，损坏数据在这里就会失败
            width, height = im.size
            if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                return None
            actual_fmt = (im.format or "").upper()
            if declared_type == "image/png" and actual_fmt != "PNG":
                return None
            if declared_type == "image/jpeg" and actual_fmt not in ("JPEG", "MPO"):
                return None

            out = io.BytesIO()
            if declared_type == "image/png":
                # 去掉 alpha 以外的一切元数据；保留 RGBA 能力
                im.save(out, format="PNG", optimize=True)
                media_type, ext = "image/png", "png"
            else:
                # JPEG 不支持透明通道，统一铺白底后重编码
                if im.mode in ("RGBA", "LA", "P"):
                    im = im.convert("RGBA")
                    background = Image.new("RGB", im.size, (255, 255, 255))
                    background.paste(im, mask=im.split()[-1])
                    im = background
                elif im.mode != "RGB":
                    im = im.convert("RGB")
                im.save(out, format="JPEG", quality=JPEG_QUALITY, optimize=True)
                media_type, ext = "image/jpeg", "jpg"
        encoded = out.getvalue()
        if not encoded:
            return None
        return ReencodedImage(encoded, media_type, ext)
    except (UnidentifiedImageError, OSError, ValueError):
        # 损坏、截断、伪装格式等全部落到占位图
        return None


_placeholder_lock = threading.Lock()
_placeholder_cache: ReencodedImage | None = None


def placeholder() -> ReencodedImage:
    """生成（并缓存）一张服务端自制的占位 PNG。"""
    global _placeholder_cache
    with _placeholder_lock:
        if _placeholder_cache is not None:
            return _placeholder_cache
        img = Image.new("RGB", PLACEHOLDER_SIZE, (226, 232, 240))
        draw = ImageDraw.Draw(img)
        draw.rectangle([0, 0, PLACEHOLDER_SIZE[0] - 1, PLACEHOLDER_SIZE[1] - 1],
                       outline=(100, 116, 139), width=2)
        # 用默认位图字体，避免依赖容器内字体文件
        line1, line2 = "BLOCKED IMAGE", "external / missing"
        draw.text((28, 38), line1, fill=(71, 85, 105))
        draw.text((24, 66), line2, fill=(100, 116, 139))
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        _placeholder_cache = ReencodedImage(buf.getvalue(), "image/png", "png")
        return _placeholder_cache
