"""HTML 清理器测试：白名单保留、危险元素/属性剥离、cid 解析与链接降级。"""

import pytest

from app.sanitizer import SanitizeError, sanitize_html


def clean(html: str, cids: set[str] | None = None) -> str:
    return sanitize_html(
        html.encode("utf-8"),
        set(cids or {"logo@x", "seal@x"}),
        lambda cid: f"/p/img/{cid if cid else 'placeholder'}",
    )


# ---- 结构性内容保留 ------------------------------------------------------- #
def test_keeps_paragraphs_headings_emphasis_lists_tables():
    html = """
    <h1>标题</h1><p>段落含 <strong>粗</strong> 与 <em>斜</em>。</p>
    <ul><li>一</li><li>二</li></ul>
    <ol><li>有序</li></ol>
    <table><thead><tr><th>H</th></tr></thead>
      <tbody><tr><td colspan="2">单元格</td></tr></tbody></table>
    <blockquote>引用</blockquote><pre>预格式化</pre>"""
    out = clean(html)
    for token in ("<h1>标题</h1>", "<strong>粗</strong>", "<em>斜</em>",
                  "<ul>", "<li>一</li>", "<table>", "<thead>",
                  '<td colspan="2">单元格</td>', "<blockquote>", "<pre>"):
        assert token in out, token


def test_text_inside_unknown_tags_is_preserved():
    out = clean("<custom-tag>保留文字</custom-tag>")
    assert "保留文字" in out
    assert "custom-tag" not in out


# ---- 脚本/事件/样式/表单/嵌套文档/跳转 ----------------------------------- #
@pytest.mark.parametrize("tag,html_snippet", [
    ("script", '<script>alert(1)</script>'),
    ("style", '<style>p{color:red}</style>'),
    ("template", '<template><p>x</p></template>'),
    ("noscript", '<noscript><img src="https://t/x.gif"></noscript>'),
    ("head", '<head><title>T</title></head>'),
    ("meta", '<meta http-equiv="refresh" content="0;url=https://evil">'),
    ("base", '<base href="https://evil/">'),
    ("link", '<link rel="stylesheet" href="https://evil/x.css">'),
    ("iframe", '<iframe src="https://evil/frame"></iframe>'),
    ("frame", '<frameset><frame src="https://evil"></frameset>'),
    ("object", '<object data="https://evil/o"></object>'),
    ("embed", '<embed src="https://evil/e">'),
    ("form", '<form action="https://evil"><input name="p"></form>'),
    ("svg", '<svg onload="alert(1)"></svg>'),
    ("math", '<math><mi>x</mi></math>'),
    ("canvas", '<canvas id="c"></canvas>'),
    ("audio", '<audio src="https://evil/a.mp3"></audio>'),
    ("video", '<video src="https://evil/v.mp4"></video>'),
])
def test_dangerous_subtrees_removed(tag, html_snippet):
    out = clean(f"<div>{html_snippet}<p>保留</p></div>")
    assert tag not in out.lower()
    assert "evil" not in out
    assert "保留" in out


def test_nested_dropped_tag_depth_tracking():
    out = clean("<div><script>var a=1;</script><p>after</p></div>")
    assert "var a" not in out
    assert "<p>after</p>" in out


def test_event_attributes_removed_everywhere():
    out = clean('<p onclick="alert(1)" onload="x()" onmouseover="y()">t</p>'
                '<img src="cid:logo@x" onerror="alert(1)">')
    assert "onclick" not in out.lower()
    assert "onload" not in out.lower()
    assert "onerror" not in out.lower()
    assert "alert" not in out


def test_inline_style_class_id_removed():
    out = clean('<p style="color:red" class="danger" id="p1" data-x="1">t</p>')
    assert "style" not in out
    assert "class" not in out
    assert "id=" not in out
    assert "data-x" not in out
    assert out == "<p>t</p>"


def test_javascript_uri_in_anchor_not_linkified():
    out = clean('<a href="javascript:alert(1)">点我</a>')
    assert "javascript" not in out
    assert "<a" not in out
    assert "点我" in out


def test_anchor_renders_text_and_url_but_not_clickable():
    out = clean('<a href="https://evil.test/path?q=1">验证账户</a>')
    assert "<a" not in out and "</a" not in out
    assert "验证账户" in out
    assert "https://evil.test/path?q=1" in out
    assert "msg-link" in out and "msg-url" in out


def test_mailto_link_kept_as_text():
    out = clean('<a href="mailto:sec@example.test">发信</a>')
    assert "mailto:sec@example.test" in out
    assert "<a" not in out


# ---- 图片 cid 处理 -------------------------------------------------------- #
def test_known_cid_image_rewritten_to_same_origin_url():
    out = clean('<img src="cid:logo@x" alt="logo">')
    assert 'src="/p/img/logo@x"' in out
    assert "cid:" not in out


def test_cid_with_angle_brackets_supported():
    out = clean('<img src="cid:<logo@x>">')
    assert 'src="/p/img/logo@x"' in out


def test_external_http_image_becomes_placeholder():
    out = clean('<img src="https://tracker.test/pixel.gif" alt="t">')
    assert "tracker.test" not in out
    assert 'src="/p/img/placeholder"' in out
    assert "blocked" in out


def test_data_uri_image_becomes_placeholder():
    out = clean('<img src="data:image/png;base64,AAAA">')
    assert "data:" not in out
    assert 'src="/p/img/placeholder"' in out


def test_missing_cid_becomes_placeholder():
    out = clean('<img src="cid:unknown@x">')
    assert 'src="/p/img/placeholder"' in out
    assert "missing cid" in out


def test_protocol_relative_url_blocked():
    out = clean('<img src="//evil.test/x.png">')
    assert "evil.test" not in out
    assert 'src="/p/img/placeholder"' in out


def test_img_dimensions_only_accept_integers():
    out = clean('<img src="cid:logo@x" width="100" height="50" '
                'onerror="x" style="width:1px">')
    assert 'width="100"' in out and 'height="50"' in out
    out2 = clean('<img src="cid:logo@x" width="100px" height="auto">')
    assert "width" not in out2 and "height" not in out2


# ---- 转义与解析健壮性 ----------------------------------------------------- #
def test_text_nodes_are_escaped():
    out = clean("<p>5 < 6 & 7 > 3 \"q\" 's'</p>")
    assert "<" not in out.replace("<p>", "").replace("</p>", "")
    assert "&lt;" in out and "&amp;" in out and "&gt;" in out


def test_attribute_values_escaped():
    out = clean('<img src="cid:logo@x" alt="a&quot;b>c">')
    assert "<script" not in out


def test_comments_doctype_pi_dropped():
    out = clean('<!DOCTYPE html><!-- comment --><?xml version="1.0"?><p>x</p>')
    assert "DOCTYPE" not in out and "comment" not in out and "xml" not in out
    assert "<p>x</p>" in out


def test_reject_oversized_html():
    with pytest.raises(SanitizeError, match="过大"):
        sanitize_html(b"<p>" + b"a" * (1024 * 1024) + b"</p>", set(), lambda c: "/x")


def test_reject_too_deep_nesting():
    deep = "<div>" * 200 + "x" + "</div>" * 200
    with pytest.raises(SanitizeError, match="深度"):
        clean(deep)


def test_reject_invalid_utf8():
    with pytest.raises(SanitizeError, match="UTF-8"):
        sanitize_html(b"<p>\xff</p>", set(), lambda c: "/x")


def test_malformed_nesting_does_not_lock_or_crash():
    # 多余闭合标签不能让跳过深度变负而吞掉后续内容
    assert "<p>x</p>" in clean("</script><p>x</p>")
    out = clean("<script>foo</script></form><p>after</p>")
    assert "foo" not in out and "<p>after</p>" in out
    # 连续丢弃标签后兄弟节点正常输出
    out2 = clean("<script></script><script></script><p>ok</p>")
    assert "<p>ok</p>" in out2
    # void 丢弃元素不闭合也不卡住后续渲染
    out3 = clean("<meta><meta><link><p>after-void</p>")
    assert "<p>after-void</p>" in out3 and "<meta" not in out3


def test_unclosed_drop_subtree_swallows_to_end_safely():
    # 未闭合的 form/script 到文档结束都处于丢弃态，不会泄漏标签
    out = clean("<form><p>no close form")
    assert "<form" not in out and "<p>" not in out


def test_extra_anchor_close_is_tolerated():
    out = clean("<a href='https://a.test'>t</a></a>")
    assert out.count("</span>") == 2  # 一个链接 span + 内部 url span
    assert "https://a.test" in out


def test_mutation_xss_vectors_neutralized():    # 常见绕过载荷集合：输出中不得出现可执行形态
    payloads = [
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<a href="  javascript:alert(1)">x</a>',
        '<body background="javascript:alert(1)">',
        '<input type=image src=x onerror=alert(1)>',
        '<p title="</p><script>alert(1)</script>">x</p>',
        '<iframe srcdoc="<script>alert(1)</script>">',
    ]
    for payload in payloads:
        out = clean(payload)
        assert "<script" not in out.lower()
        assert "onerror" not in out.lower()
        assert "onload" not in out.lower()
        assert "ontoggle" not in out.lower()
        assert "javascript:" not in out.lower()
        assert "srcdoc" not in out.lower()
        assert "<iframe" not in out.lower()
        assert "<svg" not in out.lower()
