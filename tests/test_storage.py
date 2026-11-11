"""预览存储测试：端到端组装、cid 隔离、占位逻辑、错误不产生预览。"""

import time

import pytest

from app.storage import PreviewError, PreviewStore
from tests.helpers import build_eml, gif_bytes, jpeg_bytes, png_bytes


HTML_TEMPLATE = """<html><body>
<h1>{title}</h1>
<img src="cid:shared@x" alt="shared" />
<img src="cid:only-{title}@x" alt="only" />
<img src="cid:missing@x" alt="missing" />
</body></html>"""


def _eml(title: str, color: tuple[int, int, int], include_gif: bool = False) -> bytes:
    images = [
        ("shared@x", "image/png", png_bytes(color)),
        (f"only-{title}@x", "image/jpeg", jpeg_bytes(color)),
    ]
    if include_gif:
        # GIF 会在解析阶段被拒，这里只在需要时单独构造
        pass
    return build_eml(HTML_TEMPLATE.format(title=title), images)


def test_build_preview_success_and_stats():
    store = PreviewStore()
    preview = store.build_preview(_eml("a", (1, 2, 3)))
    assert preview.safe_html
    # 两张真实图片 + 一张缺失 cid 占位
    assert preview.stats["embedded_images"] == 2
    assert preview.stats["rendered_images"] == 2
    assert preview.stats["placeholders"] == 1
    assert len(preview.images) == 3


def test_same_cid_in_two_emails_does_not_leak():
    store = PreviewStore()
    p1 = store.build_preview(_eml("a", (10, 20, 30)))
    p2 = store.build_preview(_eml("b", (200, 100, 50)))
    assert p1.preview_id != p2.preview_id

    # 找到两个预览里 shared 图片的 key，逐字节比较必须不同
    def shared_image(preview):
        # 前两个插入的 key 对应真实图（shared 在前），占位图 is_placeholder=True
        real = [img for img in preview.images.values() if not img.is_placeholder]
        return real[0]

    img1 = shared_image(p1)
    img2 = shared_image(p2)
    assert img1.data != img2.data

    # 跨预览取图片必须失败（无法用 p2 的 key 访问 p1 的图）
    p2_keys = list(p2.images.keys())
    assert store.get_image(p1.preview_id, p2_keys[0]) is None
    assert store.get("nonexistent-id") is None


def test_broken_image_falls_back_to_placeholder():
    # 声明 image/png 但内容损坏
    eml = build_eml(
        '<img src="cid:broken@x">',
        [("broken@x", "image/png", b"corrupt-bytes")],
    )
    store = PreviewStore()
    preview = store.build_preview(eml)
    assert preview.stats["rendered_images"] == 0
    assert preview.stats["placeholders"] == 1
    only = next(iter(preview.images.values()))
    assert only.is_placeholder is True


def test_external_and_gif_references_become_placeholders():
    # GIF 部分在解析期就会被拒；这里构造 PNG 部分但 HTML 引用外部 URL
    eml = build_eml(
        '<img src="https://tracker.test/x.gif">'
        '<img src="cid:real@x">',
        [("real@x", "image/png", png_bytes())],
    )
    store = PreviewStore()
    preview = store.build_preview(eml)
    assert "tracker.test" not in preview.safe_html
    assert preview.stats["placeholders"] == 1
    assert preview.stats["rendered_images"] == 1


def test_invalid_eml_creates_no_preview():
    store = PreviewStore()
    before = len(store._previews)
    with pytest.raises(PreviewError):
        store.build_preview(b"not a mime message")
    assert len(store._previews) == before


def test_ttl_expiry(monkeypatch):
    store = PreviewStore(ttl_seconds=10)
    preview = store.build_preview(_eml("a", (1, 2, 3)))
    assert store.get(preview.preview_id) is not None
    # 把时钟拨到过期之后
    monkeypatch.setattr("app.storage.time.monotonic",
                        lambda: preview.created_at + 11)
    assert store.get(preview.preview_id) is None
    assert store.get_image(preview.preview_id, list(preview.images)[0]) is None


def test_capacity_eviction():
    store = PreviewStore(max_previews=2)
    p1 = store.build_preview(_eml("a", (1, 1, 1)))
    p2 = store.build_preview(_eml("b", (2, 2, 2)))
    p3 = store.build_preview(_eml("c", (3, 3, 3)))
    assert store.get(p1.preview_id) is None      # 最旧被淘汰
    assert store.get(p2.preview_id) is not None
    assert store.get(p3.preview_id) is not None


def test_all_image_urls_are_scoped_under_preview_id():
    store = PreviewStore()
    preview = store.build_preview(_eml("a", (1, 2, 3)))
    prefix = f"/preview/{preview.preview_id}/img/"
    assert prefix in preview.safe_html
    # 每个 URL 的 key 都能在本预览内取到
    import re
    for key in re.findall(r"/img/([A-Za-z0-9_-]+)", preview.safe_html):
        assert store.get_image(preview.preview_id, key) is not None
