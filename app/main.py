"""钓鱼邮件安全预览 · FastAPI 入口。

纵深防御分两层，且任一层单独成立（直接打开预览/图片 URL 也安全）：

1. **正文清理层**（:mod:`app.sanitizer`）：白名单标签/属性，剥离脚本、事件、
   样式、表单、嵌套文档与一切跳转能力，图片仅限本邮件 cid，外部资源不输出；
2. **浏览器隔离层**：预览文档与图片响应自带严格 CSP（``default-src 'none'``）、
   ``nosniff``、``frame-ancestors 'self'`` 等头；首页 iframe 再叠加无令牌
   ``sandbox``。即便清理层出现遗漏，浏览器也不会执行脚本或加载外部资源。
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .eml_parser import MAX_PARTS, MAX_UPLOAD_BYTES
from .storage import PreviewError, store

STATIC_DIR = Path(__file__).resolve().parent / "static"
SAMPLES_DIR = STATIC_DIR / "samples"

# 预览/图片文档的最严格 CSP：默认不允许任何资源类型
ISOLATION_CSP = (
    "default-src 'none'; "
    "img-src 'self'; "
    "style-src 'unsafe-inline'; "
    "form-action 'none'; "
    "frame-ancestors 'self'; "
    "base-uri 'none'"
)
# 首页自身：静态页只需要内联样式/脚本与同站 fetch、同站 iframe
INDEX_CSP = (
    "default-src 'none'; "
    "img-src 'self'; "
    "style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; "
    "connect-src 'self'; "
    "frame-src 'self'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)
COMMON_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}

app = FastAPI(
    title="钓鱼邮件安全预览",
    version="1.0.0",
    description="上传 .eml 后在隔离环境中渲染 HTML 正文，不执行邮件代码、不加载外部资源。",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    for name, value in COMMON_SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    response = FileResponse(STATIC_DIR / "index.html")
    response.headers["Content-Security-Policy"] = INDEX_CSP
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/api/limits")
def limits() -> dict[str, int]:
    return {
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "max_mime_parts": MAX_PARTS,
    }


@app.get("/api/samples")
def list_samples() -> JSONResponse:
    """样例清单（样例文件本身随仓库分发，全部为无害构造）。"""
    items = []
    for path in sorted(SAMPLES_DIR.glob("*.eml")):
        items.append({"id": path.stem, "file": path.name})
    return JSONResponse({"samples": items})


@app.post("/api/preview")
async def create_preview(file: UploadFile | None = File(default=None)):
    if file is None or not file.filename:
        raise HTTPException(status_code=400, detail="请选择一个 .eml 文件上传")

    # 分块读取并在超过 1 MiB 时立即终止，避免把大文件读进内存
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"文件超过 {MAX_UPLOAD_BYTES // 1024 // 1024} MiB 上限",
            )
        chunks.append(chunk)
    data = b"".join(chunks)

    try:
        preview = store.build_preview(data)
    except PreviewError as exc:
        # 校验失败：不创建任何预览，前端据此清空旧预览
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "ok": True,
        "preview_id": preview.preview_id,
        "preview_url": f"/preview/{preview.preview_id}",
        "stats": preview.stats,
    }


def _preview_document(preview) -> HTMLResponse:
    # 独立完整文档：直接打开 URL 时同样受 CSP 与 nosniff 保护
    document = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>隔离邮件预览</title>
<style>
  body {{ margin: 0; padding: 18px 22px; background: #ffffff; color: #1f2937;
         font-family: system-ui, -apple-system, "Segoe UI", "PingFang SC", sans-serif;
         font-size: 14px; line-height: 1.6; word-wrap: break-word; }}
  table {{ border-collapse: collapse; }}
  table td, table th {{ border: 1px solid #94a3b8; padding: 4px 8px; }}
  img {{ max-width: 100%; height: auto; }}
  .msg-link {{ color: #1d4ed8; }}
  .msg-url {{ color: #6d28d9; font-family: ui-monospace, Menlo, Consolas, monospace;
             font-size: 12px; word-break: break-all; }}
  blockquote {{ border-left: 3px solid #cbd5e1; margin: 8px 0; padding-left: 12px; color: #475569; }}
  pre {{ white-space: pre-wrap; background: #f1f5f9; padding: 8px; border-radius: 6px; }}
</style>
</head>
<body>
{preview.safe_html}
</body>
</html>
"""
    response = HTMLResponse(document)
    response.headers["Content-Security-Policy"] = ISOLATION_CSP
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    # 预览内容随邮件变化，不做缓存，避免分析员看到过期渲染
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/preview/{preview_id}", response_class=HTMLResponse)
def get_preview(preview_id: str):
    preview = store.get(preview_id)
    if preview is None:
        raise HTTPException(status_code=404, detail="预览不存在或已过期")
    return _preview_document(preview)


@app.get("/preview/{preview_id}/img/{image_key}")
def get_preview_image(preview_id: str, image_key: str):
    image = store.get_image(preview_id, image_key)
    if image is None:
        # 不暴露预览是否存在的差异，统一 404
        raise HTTPException(status_code=404, detail="图片不存在")
    response = Response(content=image.data, media_type=image.media_type)
    # 直接打开图片 URL：最严格 CSP + nosniff，浏览器只当图片渲染
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; img-src 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "private, max-age=300"
    return response
