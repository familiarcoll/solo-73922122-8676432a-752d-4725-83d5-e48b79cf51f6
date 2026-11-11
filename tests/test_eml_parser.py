""".eml 解析器测试：结构约束、编码校验、重复 cid、嵌套拒绝。"""

import pytest

from app.eml_parser import (
    MAX_PARTS,
    MAX_UPLOAD_BYTES,
    EmlParseError,
    parse_eml,
)
from tests.helpers import build_eml, png_bytes, jpeg_bytes, gif_bytes


def test_valid_related_with_html_and_images():
    eml = build_eml(
        "<html><body><p>ok</p></body></html>",
        [("cid1", "image/png", png_bytes()), ("cid2", "image/jpeg", jpeg_bytes())],
    )
    parsed = parse_eml(eml)
    assert parsed.html.decode("utf-8").strip() == "<html><body><p>ok</p></body></html>"
    assert [p.cid for p in parsed.image_parts] == ["cid1", "cid2"]
    assert parsed.image_parts[0].part_type == "image/png"


def test_reject_non_related_top_level():
    eml = build_eml("<p>x</p>", [], top_type="multipart/mixed")
    with pytest.raises(EmlParseError, match="multipart/related"):
        parse_eml(eml)


def test_reject_plain_text_html_only():
    # 单 part text/html 不是 multipart/related
    msg = build_eml("<p>x</p>", [])
    # build_eml 总是 related；手工构造一个单 part 邮件
    from email.message import EmailMessage
    m = EmailMessage()
    m.set_content("<p>x</p>", subtype="html", charset="utf-8")
    with pytest.raises(EmlParseError, match="multipart/related"):
        parse_eml(m.as_bytes())


def test_reject_duplicate_content_id():
    eml = build_eml(
        "<p>x</p>",
        [("same", "image/png", png_bytes()), ("same", "image/jpeg", jpeg_bytes())],
    )
    with pytest.raises(EmlParseError, match="重复的 Content-ID"):
        parse_eml(eml)


def test_reject_duplicate_cid_with_angle_brackets():
    # 一个带尖括号、一个不带，归一化后相同
    eml = build_eml(
        "<p>x</p>",
        [("a@b", "image/png", png_bytes())],
        extra_parts=[("image/png", png_bytes(), "<a@b>")],
    )
    with pytest.raises(EmlParseError, match="重复的 Content-ID"):
        parse_eml(eml)


def test_reject_image_without_content_id():
    # 允许类型（PNG）但缺少 Content-ID
    eml = build_eml("<p>x</p>", [("c", "image/png", png_bytes())],
                    extra_parts=[("image/jpeg", jpeg_bytes(), None)])
    with pytest.raises(EmlParseError, match="Content-ID"):
        parse_eml(eml)


def test_reject_unsupported_mime_type():
    eml = build_eml(
        "<p>x</p>",
        [("c", "image/png", png_bytes())],
        extra_parts=[("application/zip", b"PK\x03\x04", "<z@x>")],
    )
    with pytest.raises(EmlParseError, match="不支持的 MIME"):
        parse_eml(eml)


def test_reject_gif_part():
    eml = build_eml("<p>x</p>", [("g", "image/gif", gif_bytes())])
    with pytest.raises(EmlParseError, match="不支持的 MIME"):
        parse_eml(eml)


def test_reject_nested_multipart():
    from email.message import EmailMessage
    outer = EmailMessage()
    outer.make_related()
    inner = EmailMessage()
    inner.make_mixed()
    page = EmailMessage()
    page.set_content("<p>x</p>", subtype="html", charset="utf-8")
    inner.attach(page)
    outer.attach(inner)
    with pytest.raises(EmlParseError, match="嵌套 multipart"):
        parse_eml(outer.as_bytes())


def test_reject_nested_message_rfc822():
    eml = build_eml(
        "<p>x</p>",
        [("c", "image/png", png_bytes())],
        extra_parts=[("message/rfc822", b"Subject: nested\r\n\r\nbody", "<n@x>")],
    )
    with pytest.raises(EmlParseError, match="嵌套"):
        parse_eml(eml)


def test_reject_non_utf8_charset():
    eml = build_eml(
        "<p>x</p>", [], charset="iso-8859-1", html_payload=b"<p>\xe4\xf6</p>"
    )
    with pytest.raises(EmlParseError, match="UTF-8"):
        parse_eml(eml)


def test_reject_invalid_utf8_bytes():
    # 声明 utf-8 但字节非法
    eml = build_eml("<p>x</p>", [], html_payload=b"<p>\xff\xfe</p>")
    with pytest.raises(EmlParseError, match="UTF-8"):
        parse_eml(eml)


def test_reject_multiple_html_parts():
    eml = build_eml(
        "<p>one</p>",
        [("c", "image/png", png_bytes())],
        extra_html="<p>two</p>",
    )
    with pytest.raises(EmlParseError, match="恰好包含一份"):
        parse_eml(eml)


def test_reject_too_many_parts():
    # 1 个 html + MAX_PARTS 个图片 => 超限
    images = [(f"c{i}", "image/png", png_bytes()) for i in range(MAX_PARTS)]
    eml = build_eml("<p>x</p>", images)
    with pytest.raises(EmlParseError, match=f"超过上限 {MAX_PARTS}"):
        parse_eml(eml)


def test_accept_exactly_max_parts():
    images = [(f"c{i}", "image/png", png_bytes()) for i in range(MAX_PARTS - 1)]
    parsed = parse_eml(build_eml("<p>x</p>", images))
    assert len(parsed.image_parts) == MAX_PARTS - 1


def test_reject_oversized_upload():
    with pytest.raises(EmlParseError, match="MiB"):
        parse_eml(b"x" * (MAX_UPLOAD_BYTES + 1))


def test_reject_empty_and_non_bytes():
    with pytest.raises(EmlParseError):
        parse_eml(b"")
    with pytest.raises(EmlParseError):
        parse_eml("not bytes")  # type: ignore[arg-type]


def test_malformed_mime_does_not_crash():
    # 畸形输入应抛受控错误而不是内部异常
    with pytest.raises(EmlParseError):
        parse_eml(b"this is not a mime message at all")


def test_base64_and_quoted_printable_transfer_encodings():
    from email.message import EmailMessage

    for cte in ("base64", "quoted-printable"):
        msg = EmailMessage()
        msg.make_related()
        page = EmailMessage()
        page.set_content("<p>编码测试 中文</p>", subtype="html",
                         charset="utf-8", cte=cte)
        img = EmailMessage()
        img.set_content(png_bytes(), maintype="image", subtype="png",
                        disposition="inline", cte=cte)
        img.add_header("Content-ID", "<c@x>")
        msg.attach(page)
        msg.attach(img)
        parsed = parse_eml(msg.as_bytes())
        assert "编码测试" in parsed.html.decode("utf-8")
        assert parsed.image_parts[0].payload == png_bytes()


def test_broken_transfer_encoding_is_rejected():
    from email.message import EmailMessage

    msg = EmailMessage()
    msg.make_related()
    page = EmailMessage()
    page.set_type("text/html")
    page.set_param("charset", "utf-8")
    page["Content-Transfer-Encoding"] = "base64"
    page.set_payload("!!!not-valid-base64!!!")
    msg.attach(page)
    with pytest.raises(EmlParseError, match="解码|UTF-8|解析"):
        parse_eml(msg.as_bytes())
