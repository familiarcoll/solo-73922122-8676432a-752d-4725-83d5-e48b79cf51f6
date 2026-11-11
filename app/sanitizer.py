"""白名单式 HTML 清理器。

安全模型是**默认拒绝**：未在 :data:`ALLOWED_TAGS` 中的标签整体不输出；
未在 :data:`ALLOWED_ATTRS` 中的属性一律删除；``on*`` 事件属性、``style``、
``class``、``id`` 等没有任何保留路径。脚本、样式、表单、嵌套文档、跳转类
标签连同其子树一并丢弃。

链接（``<a>``）被降级为不可点击的 ``<span>``，仅展示文字与原始地址；
图片只接受指向本邮件已知 Content-ID 的 ``cid:`` 引用，其余（外部 http(s)
跟踪图、data:、缺失 cid 等）全部改写为服务端占位图。

输出是经过转义的 HTML 片段，配合响应头 CSP/沙箱形成纵深防御。
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

# 允许保留的结构化/语义标签（不含任何可执行或可加载外部资源的标签）
ALLOWED_TAGS = frozenset({
    # 段落/标题/强调
    "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
    "strong", "b", "em", "i", "u", "s", "small", "sub", "sup",
    "blockquote", "pre", "code", "abbr", "cite", "mark", "span", "div",
    # 链接（降级为不可点击的 span，仅展示文字与原始地址）
    "a",
    # 列表
    "ul", "ol", "li", "dl", "dt", "dd",
    # 表格
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col",
    # 图片（src 会被强制改写）
    "img",
})

# 整棵子树丢弃的标签：脚本/样式/元数据/表单/嵌套文档/跳转能力
DROP_SUBTREE_TAGS = frozenset({
    "script", "style", "template", "noscript", "head", "title", "meta",
    "base", "link", "iframe", "frame", "frameset", "object", "embed",
    "applet", "form", "button", "input", "select", "textarea", "option",
    "optgroup", "label", "fieldset", "legend", "output", "svg", "math",
    "canvas", "audio", "video", "source", "track", "portal", "xml",
})

# 无内容模型（void）或邮件 HTML 中通常不闭合的元素：
# 没有可靠的闭合标签可用于退出子树模式，因此只丢弃标签自身，不改变跳过深度
VOID_DROP_TAGS = frozenset({
    "meta", "base", "link", "frame", "embed", "input", "source", "track",
    "hr", "br", "img", "col", "area", "param", "wbr",
})

# 每个标签允许保留的属性（默认拒绝：不在表内即删除）
ALLOWED_ATTRS: dict[str, frozenset[str]] = {
    # src 仅允许出现在 img，且在 _emit_img 中被强制改写为同源预览 URL
    "img": frozenset({"src", "alt", "width", "height"}),
    # href 在 <a> 降级逻辑中只用于文本展示，不会生成可点击链接
    "a": frozenset({"href"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan"}),
    "col": frozenset({"span"}),
    "colgroup": frozenset({"span"}),
    "ol": frozenset({"start", "type"}),
    "li": frozenset({"value"}),
}

# 链接允许出现的 scheme（仅用于文本展示，不产生可点击链接）
SAFE_LINK_SCHEMES = frozenset({"http", "https", "mailto"})

MAX_START_TAGS = 5_000
MAX_DEPTH = 100
MAX_HTML_BYTES = 900 * 1024  # 正文小于 1 MiB 上传上限，给其余部分留余量


class SanitizeError(ValueError):
    """HTML 结构超出受控范围（过大/过深/解析错误）。"""


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _is_safe_link(href: str) -> bool:
    href = href.strip()
    if not href or any(ch in href for ch in ("\x00", "\r", "\n", "\t")):
        return False
    parts = urlsplit(href)
    scheme = parts.scheme.lower()
    if scheme and scheme not in SAFE_LINK_SCHEMES:
        return False
    # 无 scheme 的相对地址也不展示为链接地址（分析场景价值低且易混淆）
    return bool(scheme) and bool(parts.netloc or scheme == "mailto")


def _normalize_cid(src: str) -> str | None:
    """从 img src 提取 cid 标识；非 cid: 引用一律返回 None。"""
    src = src.strip()
    if not src:
        return None
    # 显式 cid: 方案（大小写不敏感，前后空白已去除）
    if src[:4].lower() == "cid:":
        cid = unquote(src[4:]).strip()
        # 去掉历史邮件客户端可能保留的尖括号
        if len(cid) >= 2 and cid.startswith("<") and cid.endswith(">"):
            cid = cid[1:-1].strip()
        return cid or None
    return None


class _SanitizingParser(HTMLParser):
    def __init__(self, known_cids: set[str], image_url_for):
        super().__init__(convert_charrefs=True)
        self._known_cids = known_cids
        self._image_url_for = image_url_for
        self._out: list[str] = []
        self._skip_depth = 0          # >0 表示当前位于 DROP_SUBTREE 内
        self._depth = 0
        self._start_tags = 0
        # <a> 降级为 span 时记录 href，关闭时用
        self._link_stack: list[str | None] = []

    # --- 工具 -------------------------------------------------------------
    def _clean_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        allowed = ALLOWED_ATTRS.get(tag, frozenset())
        result: dict[str, str] = {}
        for name, value in attrs:
            if value is None:
                continue
            lname = name.lower()
            # 双保险：任何事件属性、style、class、id 都不可能放行
            if lname.startswith("on") or lname in ("style", "class", "id"):
                continue
            if lname not in allowed:
                continue
            result[lname] = value
        return result

    # --- HTMLParser 钩子 --------------------------------------------------
    def handle_starttag(self, tag, attrs):
        self._start_tags += 1
        if self._start_tags > MAX_START_TAGS:
            raise SanitizeError(f"HTML 标签数量超过上限 {MAX_START_TAGS}")
        self._depth += 1
        if self._depth > MAX_DEPTH:
            raise SanitizeError(f"HTML 嵌套深度超过上限 {MAX_DEPTH}")

        # 已处于丢弃子树：只跟踪嵌套深度，不输出任何东西
        if self._skip_depth > 0:
            if tag in DROP_SUBTREE_TAGS and tag not in VOID_DROP_TAGS:
                self._skip_depth += 1
            return
        if tag in DROP_SUBTREE_TAGS:
            if tag in VOID_DROP_TAGS:
                # void/隐式关闭元素：只丢弃自身，避免跳过状态卡死
                return
            # 本标签连同整棵子树丢弃
            self._skip_depth = 1
            return
        if tag not in ALLOWED_TAGS:
            # 未知标签：丢弃标签本身，保留内部文本与合法子节点
            return

        clean = self._clean_attrs(tag, attrs)

        if tag == "a":
            href = clean.get("href", "")
            safe = _is_safe_link(href)
            self._link_stack.append(href if safe else None)
            self._out.append('<span class="msg-link">' if safe else "<span>")
            return

        if tag == "img":
            self._emit_img(clean)
            return

        attr_text = "".join(
            f' {k}="{_escape(v)}"' for k, v in clean.items()
        )
        if tag in ("br", "hr", "col"):
            self._out.append(f"<{tag}{attr_text} />")
        else:
            self._out.append(f"<{tag}{attr_text}>")

    def handle_startendtag(self, tag, attrs):
        # <img .../> 等自闭合标签：不增加配对深度
        self._start_tags += 1
        if self._start_tags > MAX_START_TAGS:
            raise SanitizeError(f"HTML 标签数量超过上限 {MAX_START_TAGS}")
        if self._skip_depth > 0:
            return
        if tag in DROP_SUBTREE_TAGS:
            return
        if tag not in ALLOWED_TAGS:
            return
        if tag == "img":
            self._emit_img(self._clean_attrs(tag, attrs))
            return
        clean = self._clean_attrs(tag, attrs)
        attr_text = "".join(f' {k}="{_escape(v)}"' for k, v in clean.items())
        self._out.append(f"<{tag}{attr_text} />")

    def handle_endtag(self, tag):
        if self._skip_depth > 0:
            # 只有丢弃标签自身的闭合标签才退出一层；普通标签的闭合不影响深度
            if tag in DROP_SUBTREE_TAGS:
                self._skip_depth -= 1
            return
        self._depth = max(0, self._depth - 1)
        if tag not in ALLOWED_TAGS:
            return
        if tag == "a":
            # 容忍畸形：没有对应 starttag 时不输出
            if self._link_stack:
                href = self._link_stack.pop()
                if href:
                    self._out.append(
                        f' <span class="msg-url">[{_escape(href)}]</span>'
                    )
                self._out.append("</span>")
            return
        if tag in ("br", "hr", "col", "img"):
            return
        self._out.append(f"</{tag}>")

    def handle_data(self, data):
        if self._skip_depth:
            return
        self._out.append(_escape(data))

    def handle_entityref(self, name):  # convert_charrefs=True 时不会进入
        if not self._skip_depth:
            self._out.append(f"&{name};")

    def handle_charref(self, name):  # 同上
        if not self._skip_depth:
            self._out.append(f"&#{name};")

    def handle_comment(self, data):
        return  # 注释一律丢弃

    def handle_decl(self, decl):
        return  # <!DOCTYPE ...> 丢弃

    def handle_pi(self, data):
        return  # 处理指令丢弃

    def unknown_decl(self, data):
        return

    # --- 图片处理 ---------------------------------------------------------
    def _emit_img(self, clean: dict[str, str]) -> None:
        alt = _escape(clean.get("alt", ""))
        cid = _normalize_cid(clean.get("src", ""))
        dims = ""
        for dim in ("width", "height"):
            if dim in clean:
                # 只接受正整数，杜绝表达式/百分比注入
                val = clean[dim].strip()
                if val.isdigit() and int(val) > 0:
                    dims += f' {dim}="{int(val)}"'
        if cid and cid in self._known_cids:
            src = self._image_url_for(cid)
            self._out.append(
                f'<img src="{_escape(src)}" alt="{alt or "inline image"}"{dims} />'
            )
        else:
            reason = "missing cid" if cid else "external or unsupported image"
            src = self._image_url_for(None)
            self._out.append(
                f'<img src="{_escape(src)}" alt="blocked: {_escape(reason)}"{dims} />'
            )


def sanitize_html(html_bytes: bytes, known_cids: set[str], image_url_for) -> str:
    """清理邮件 HTML 正文。

    :param html_bytes: UTF-8 编码的原始 HTML
    :param known_cids: 本邮件实际携带的 Content-ID 集合
    :param image_url_for: ``cid -> 图片 URL`` 的映射函数；``cid=None`` 返回占位图 URL
    :return: 安全的 HTML 片段字符串
    """
    if len(html_bytes) > MAX_HTML_BYTES:
        raise SanitizeError("HTML 正文过大")
    try:
        html_text = html_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SanitizeError(f"HTML 正文不是合法 UTF-8（位置 {exc.start}）") from exc

    parser = _SanitizingParser(known_cids, image_url_for)
    try:
        parser.feed(html_text)
        parser.close()
    except SanitizeError:
        raise
    except Exception as exc:  # 解析器内部异常统一归类，避免 500 泄漏细节
        raise SanitizeError(f"HTML 解析失败：{exc.__class__.__name__}") from exc
    return "".join(parser._out)
