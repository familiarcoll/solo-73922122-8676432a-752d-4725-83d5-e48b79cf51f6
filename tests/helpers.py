"""测试辅助：手工构造受控/畸形 .eml 与最小图片字节。"""

from __future__ import annotations

import io

from email.message import EmailMessage
from PIL import Image


def png_bytes(color=(30, 64, 175), size=(32, 32)) -> bytes:
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def jpeg_bytes(color=(175, 48, 48), size=(32, 32)) -> bytes:
    img = Image.new("RGB", size, color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80)
    return buf.getvalue()


def gif_bytes(size=(16, 16)) -> bytes:
    img = Image.new("P", size, 1)
    buf = io.BytesIO()
    img.save(buf, format="GIF")
    return buf.getvalue()


def _image_part(mime: str, payload: bytes, cid: str | None) -> EmailMessage:
    maintype, subtype = mime.split("/", 1)
    part = EmailMessage()
    part.set_content(payload, maintype=maintype, subtype=subtype, disposition="inline")
    if cid is not None:
        part.add_header("Content-ID", cid if cid.startswith("<") else f"<{cid}>")
    return part


def build_eml(
    html: str,
    images: list[tuple[str, str, bytes]],
    *,
    top_type: str = "multipart/related",
    charset: str = "utf-8",
    html_payload: bytes | None = None,
    extra_parts: list[tuple[str, bytes, str | None]] | None = None,
    extra_html: str | None = None,
) -> bytes:
    """构造测试用邮件。

    :param images: [(cid, mime, payload), ...]
    :param extra_parts: 额外的裸 MIME 部分 [(mime, payload, cid_or_None), ...]
    :param extra_html: 追加第二份 text/html（用于多正文拒绝测试）
    """
    msg = EmailMessage()
    if top_type == "multipart/related":
        msg.make_related()
    elif top_type == "multipart/mixed":
        msg.make_mixed()
    else:
        raise ValueError(top_type)

    page = EmailMessage()
    if html_payload is not None:
        # 原始字节（可能非法）：手工设置头部与 payload，不做编码转换
        page.set_type("text/html")
        page.set_param("charset", charset)
        page.set_payload(html_payload)
    else:
        page.set_content(html, subtype="html", charset=charset)
    msg.attach(page)

    if extra_html is not None:
        page2 = EmailMessage()
        page2.set_content(extra_html, subtype="html", charset="utf-8")
        msg.attach(page2)

    for cid, mime, payload in images:
        msg.attach(_image_part(mime, payload, cid))

    for mime, payload, cid in extra_parts or []:
        msg.attach(_image_part(mime, payload, cid))

    return msg.as_bytes()
