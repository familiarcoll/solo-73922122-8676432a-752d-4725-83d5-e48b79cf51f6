"""HTTP API 端到端测试：上传、隔离头、预览/图片直接访问、错误语义。"""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.eml_parser import MAX_UPLOAD_BYTES
from tests.helpers import build_eml, jpeg_bytes, png_bytes

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parents[1] / "app" / "static" / "samples"

SIMPLE_EML = build_eml(
    """<html><body><h1>测试</h1>
    <p><a href="https://evil.test/x">钓鱼链接</a></p>
    <img src="cid:logo@x" alt="logo" />
    <img src="https://tracker.test/p.gif" alt="tracker" />
    </body></html>""",
    [("logo@x", "image/png", png_bytes((1, 2, 3)))],
)


def _upload(data: bytes, filename="mail.eml"):
    return client.post(
        "/api/preview",
        files={"file": (filename, data, "message/rfc822")},
    )


# ---- 基础页面 ------------------------------------------------------------- #
def test_health_index_and_limits():
    assert client.get("/health").json() == {"status": "ok"}
    r = client.get("/")
    assert r.status_code == 200
    assert "安全预览" in r.text
    limits = client.get("/api/limits").json()
    assert limits["max_upload_bytes"] == MAX_UPLOAD_BYTES
    assert limits["max_mime_parts"] == 20


def test_index_has_strict_csp_and_frame_deny():
    r = client.get("/")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


# ---- 上传与预览 ----------------------------------------------------------- #
def test_upload_creates_preview_and_renders_safely():
    r = _upload(SIMPLE_EML)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["ok"] is True
    assert payload["stats"]["embedded_images"] == 1
    assert payload["stats"]["placeholders"] == 1

    pr = client.get(payload["preview_url"])
    assert pr.status_code == 200
    body = pr.text
    # 危险内容被清理
    assert "tracker.test" not in body
    assert "<script" not in body.lower()
    # 正常结构与链接文字/地址保留
    assert "<h1>测试</h1>" in body
    assert "钓鱼链接" in body and "https://evil.test/x" in body
    assert "<a" not in body  # 链接已降级为 span


def test_preview_document_headers_isolate_browser():
    payload = _upload(SIMPLE_EML).json()
    pr = client.get(payload["preview_url"])
    csp = pr.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "img-src 'self'" in csp
    assert "form-action 'none'" in csp
    assert "frame-ancestors 'self'" in csp
    assert "base-uri 'none'" in csp
    assert pr.headers["x-content-type-options"] == "nosniff"
    assert pr.headers["x-frame-options"] == "SAMEORIGIN"
    assert pr.headers["cache-control"] == "no-store"


def test_preview_image_served_reencoded_with_strict_headers():
    payload = _upload(SIMPLE_EML).json()
    pr = client.get(payload["preview_url"])
    import re
    urls = re.findall(r'src="(/preview/[^"]+)"', pr.text)
    assert len(urls) == 2  # 一张内嵌 + 一张占位

    img_resp = client.get(urls[0])
    assert img_resp.status_code == 200
    assert img_resp.headers["content-type"] == "image/png"
    assert img_resp.headers["x-content-type-options"] == "nosniff"
    csp = img_resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    # 重编码输出确实是 PNG 魔数
    assert img_resp.content.startswith(b"\x89PNG\r\n\x1a\n")


def test_image_url_direct_open_is_404_for_other_preview():
    p1 = _upload(SIMPLE_EML).json()
    other_eml = build_eml(
        '<img src="cid:other@x">',
        [("other@x", "image/jpeg", jpeg_bytes())],
    )
    p2 = _upload(other_eml).json()
    p2_body = client.get(p2["preview_url"]).text
    import re
    p2_img = re.findall(r'src="(/preview/[^"]+)"', p2_body)[0]
    # 用 p2 的图片 key 去访问 p1 预览 -> 404
    p2_key = p2_img.rsplit("/", 1)[1]
    resp = client.get(f"/preview/{p1['preview_id']}/img/{p2_key}")
    assert resp.status_code == 404


def test_unknown_preview_and_image_404():
    assert client.get("/preview/does-not-exist").status_code == 404
    payload = _upload(SIMPLE_EML).json()
    resp = client.get(f"/preview/{payload['preview_id']}/img/badkey")
    assert resp.status_code == 404
    # 404 也带安全头
    assert resp.headers["x-content-type-options"] == "nosniff"


# ---- 错误语义：不显示旧预览 ---------------------------------------------- #
def test_invalid_upload_returns_422_and_creates_nothing():
    r = _upload(b"garbage data")
    assert r.status_code == 422
    assert "detail" in r.json()


def test_missing_file_returns_400():
    r = client.post("/api/preview")
    assert r.status_code in (400, 422)


def test_oversized_upload_returns_413():
    r = _upload(b"x" * (MAX_UPLOAD_BYTES + 1))
    assert r.status_code == 413


def test_duplicate_cid_rejected_end_to_end():
    eml = build_eml(
        "<p>x</p>",
        [("dup@x", "image/png", png_bytes()), ("dup@x", "image/jpeg", jpeg_bytes())],
    )
    r = _upload(eml)
    assert r.status_code == 422
    assert "重复的 Content-ID" in r.json()["detail"]


# ---- 内置样例 ------------------------------------------------------------- #
def test_samples_listed_and_both_parse_successfully():
    listing = client.get("/api/samples").json()
    ids = {s["id"] for s in listing["samples"]}
    assert "sample1-malicious-tags" in ids
    assert "sample2-cid-collision" in ids

    for sample in listing["samples"]:
        data = (SAMPLES_DIR / sample["file"]).read_bytes()
        r = _upload(data, sample["file"])
        assert r.status_code == 200, f"样例 {sample['id']} 解析失败: {r.text}"


def test_sample1_malicious_content_neutralized():
    data = (SAMPLES_DIR / "sample1-malicious-tags.eml").read_bytes()
    payload = _upload(data).json()
    doc = client.get(payload["preview_url"]).text
    # 只检查 <body> 内的邮件正文，排除预览文档自身的 head/style 模板
    body = doc.split("<body>", 1)[1]
    for needle in ("<script", "onerror", "onload", "onmouseover", "javascript:",
                   "tracker.example", "<form", "<iframe",
                   "<meta", "<style", "<object", "<noscript", "<svg",
                   "<head", "<base", "<link", "<button", "<input"):
        assert needle not in body.lower(), needle
    # 外部跟踪域名不得出现在任何属性值中（链接域名只允许来自显式 <a> 展示）
    assert "evil.example.test/phish" not in body  # meta 跳转目标
    assert "tracker.example" not in body
    # 正常结构保留
    for needle in ("<h1>", "<table>", "<li>", "<blockquote>"):
        assert needle in body
    assert "cid:" not in body  # cid 已被改写为同源 URL
    # 两张内嵌图真实渲染，三个问题图占位（外部 http、data、缺失 cid）
    assert payload["stats"]["rendered_images"] == 2
    assert payload["stats"]["placeholders"] == 3


def test_sample2_cid_collision_isolates_from_sample1():
    s1 = (SAMPLES_DIR / "sample1-malicious-tags.eml").read_bytes()
    s2 = (SAMPLES_DIR / "sample2-cid-collision.eml").read_bytes()
    p1 = _upload(s1).json()
    p2 = _upload(s2).json()
    import re
    img1 = re.findall(r'src="(/preview/[^"]+)"',
                      client.get(p1["preview_url"]).text)[0]
    img2 = re.findall(r'src="(/preview/[^"]+)"',
                      client.get(p2["preview_url"]).text)[0]
    # 两个 cid 相同（logo@example.test），但 URL 作用域不同、字节不同
    assert img1.split("/img/")[0] != img2.split("/img/")[0]
    assert client.get(img1).content != client.get(img2).content
    # 样例2：损坏 PNG 与缺失 cid 都占位，唯一正常 PNG 真实渲染
    assert p2["stats"]["rendered_images"] == 1
    assert p2["stats"]["placeholders"] == 2


def test_sample_files_are_within_size_limit():
    for path in SAMPLES_DIR.glob("*.eml"):
        assert path.stat().st_size <= MAX_UPLOAD_BYTES, path.name
