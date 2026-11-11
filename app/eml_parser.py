"""受限的 .eml 解析器（multipart/related 专用）。

设计约束（对应需求）：

* 仅接受顶层 ``multipart/related``；嵌套 multipart、嵌套文档（message/*）一律拒绝；
* 最多 :data:`MAX_PARTS` 个 MIME 部分，超出拒绝；
* 必须恰好包含一份 UTF-8 编码的 ``text/html`` 正文，多份/零份/非 UTF-8 均拒绝；
* 图片部分仅接受 image/png、image/jpeg，且必须带 Content-ID；重复 Content-ID 拒绝；
* 全部输入仅在内存处理，绝不落地磁盘、绝不发起任何网络访问。

本模块只做结构解析与校验，HTML 清理见 :mod:`app.sanitizer`，
图片解码重编码见 :mod:`app.images`。
"""

from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email import message_from_bytes
from email.utils import unquote

MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MiB
MAX_PARTS = 20
HTML_CHARSET = "utf-8"
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg"}


class EmlParseError(ValueError):
    """输入 .eml 不满足受控预览条件时抛出，message 可直接展示给分析员。"""


@dataclass(frozen=True)
class MimePart:
    """一个叶子 MIME 部分的解析结果。"""

    part_type: str          # 归一化后的 content-type，如 text/html / image/png
    cid: str | None         # 去掉尖括号的 Content-ID
    payload: bytes          # 原始解码后的字节（图片由 images 模块再解码重编码）


@dataclass(frozen=True)
class ParsedEmail:
    html: bytes                 # UTF-8 HTML 正文字节（尚未做标签级清理）
    image_parts: tuple[MimePart, ...]  # 全部带 Content-ID 的图片部分（按出现顺序）


def _normalized_type(part: EmailMessage) -> str:
    # get_content_type 在缺省/畸形时回退为 text/plain，正好按拒绝处理
    return (part.get_content_type() or "").lower()


def _extract_cid(part: EmailMessage) -> str | None:
    raw = part.get("Content-ID")
    if raw is None:
        return None
    cid = unquote(str(raw).strip())
    # email.utils.unquote 会去掉成对尖括号/引号；再兜底处理一次
    if len(cid) >= 2 and cid.startswith("<") and cid.endswith(">"):
        cid = cid[1:-1].strip()
    return cid or None


def parse_eml(data: bytes) -> ParsedEmail:
    """解析并校验一份 .eml 字节串，返回 :class:`ParsedEmail`。

    任何结构/编码/约束不符合要求都抛 :class:`EmlParseError`，
    调用方必须把该错误当作“不产生预览”处理。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise EmlParseError("上传内容必须是 .eml 二进制文件")
    if len(data) == 0:
        raise EmlParseError("上传文件为空")
    if len(data) > MAX_UPLOAD_BYTES:
        raise EmlParseError(
            f"文件超过 {MAX_UPLOAD_BYTES // 1024 // 1024} MiB 上限"
        )

    # policy.default：严格解析头部，解析缺陷保留在 defect 上，由后续校验拦截
    try:
        msg = message_from_bytes(bytes(data), policy=policy.default)
    except Exception as exc:  # email 库可能抛多种解析异常
        raise EmlParseError(f"MIME 解析失败：{exc.__class__.__name__}") from exc

    top_type = _normalized_type(msg)
    if not top_type.startswith("multipart/related"):
        raise EmlParseError(
            f"仅支持顶层 multipart/related，当前为 {top_type or '缺失 Content-Type'}"
        )

    parts = list(msg.iter_parts())
    if not parts:
        raise EmlParseError("multipart/related 内没有任何 MIME 部分")
    if len(parts) > MAX_PARTS:
        raise EmlParseError(f"MIME 部分数量 {len(parts)} 超过上限 {MAX_PARTS}")

    html_payloads: list[bytes] = []
    image_parts: list[MimePart] = []
    seen_cids: set[str] = set()

    for part in parts:
        # 任何嵌套 multipart 或 message/*（嵌套文档）都不支持，直接拒绝
        if part.is_multipart():
            raise EmlParseError(
                "不支持嵌套 multipart 结构（仅允许单层 multipart/related）"
            )
        ptype = _normalized_type(part)
        if ptype.startswith("message/"):
            raise EmlParseError("不支持嵌套邮件/文档部分（message/*）")

        if ptype == "text/html":
            charset = (part.get_content_charset() or "").lower()
            if charset != HTML_CHARSET:
                raise EmlParseError(
                    f"HTML 正文必须是 UTF-8 编码，当前声明为 {charset or '缺失 charset'}"
                )
            try:
                payload = part.get_payload(decode=True)
            except Exception as exc:
                raise EmlParseError(
                    f"HTML 正文传输解码失败：{exc.__class__.__name__}"
                ) from exc
            if payload is None:
                raise EmlParseError("HTML 正文为空或无法解码")
            # 严格 UTF-8 校验：非法字节序列直接拒绝，绝不静默替换
            try:
                payload.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise EmlParseError(
                    f"HTML 正文不是合法 UTF-8 字节序列（位置 {exc.start}）"
                ) from exc
            html_payloads.append(payload)
            continue

        if ptype in ALLOWED_IMAGE_TYPES:
            cid = _extract_cid(part)
            if not cid:
                raise EmlParseError(f"{ptype} 图片部分缺少 Content-ID")
            if cid in seen_cids:
                raise EmlParseError(f"重复的 Content-ID: {cid}")
            try:
                payload = part.get_payload(decode=True)
            except Exception as exc:
                raise EmlParseError(
                    f"图片 {cid} 传输解码失败：{exc.__class__.__name__}"
                ) from exc
            if not payload:
                raise EmlParseError(f"图片 {cid} 的内容为空")
            seen_cids.add(cid)
            image_parts.append(MimePart(part_type=ptype, cid=cid, payload=payload))
            continue

        raise EmlParseError(f"不支持的 MIME 部分类型：{ptype or '缺失 Content-Type'}")

    if len(html_payloads) != 1:
        raise EmlParseError(
            f"必须恰好包含一份 text/html 正文，当前为 {len(html_payloads)} 份"
        )

    return ParsedEmail(html=html_payloads[0], image_parts=tuple(image_parts))
