"""预览会话的内存存储与组装。

隔离保证：

* 每次上传生成一个不可猜测的随机预览 ID，图片按 ``(preview_id, cid)``
  作用域存储——两封邮件即使使用相同 Content-ID 也绝不可能串图；
* 预览只存于进程内存（容器根文件系统为只读），带容量上限、LRU 淘汰与
  TTL 过期，重启即全部消失；
* 不存在的预览/图片返回 404，不回退到任何其他预览的数据。
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from . import images
from .eml_parser import EmlParseError, parse_eml
from .sanitizer import SanitizeError, sanitize_html

MAX_PREVIEWS = 64
PREVIEW_TTL_SECONDS = 30 * 60  # 30 分钟
PREVIEW_ID_BYTES = 18          # 144 bit 熵
KEY_BYTES = 16                 # 图片 key 的随机熵


class PreviewError(ValueError):
    """预览组装失败（解析或清理不通过），message 可直接展示。"""


@dataclass(frozen=True)
class StoredImage:
    data: bytes
    media_type: str
    extension: str
    is_placeholder: bool


@dataclass
class Preview:
    preview_id: str
    safe_html: str
    created_at: float
    # image_key -> StoredImage（key 由本模块随机生成，与 cid 解耦）
    images: dict[str, StoredImage]
    stats: dict[str, int]


class PreviewStore:
    def __init__(self, max_previews: int = MAX_PREVIEWS,
                 ttl_seconds: int = PREVIEW_TTL_SECONDS):
        self._previews: dict[str, Preview] = {}
        self._lock = threading.Lock()
        self._max = max_previews
        self._ttl = ttl_seconds

    def _purge_locked(self) -> None:
        now = time.monotonic()
        expired = [
            pid for pid, pv in self._previews.items()
            if now - pv.created_at > self._ttl
        ]
        for pid in expired:
            del self._previews[pid]
        while len(self._previews) >= self._max:
            # 字典按插入顺序，弹出最旧的一个（LRU 近似）
            oldest = next(iter(self._previews))
            del self._previews[oldest]

    def build_preview(self, raw_eml: bytes) -> Preview:
        """解析、重编码、清理一条龙；任何一步失败都不产生预览。"""
        try:
            parsed = parse_eml(raw_eml)
        except EmlParseError as exc:
            raise PreviewError(str(exc)) from exc

        preview_id = secrets.token_urlsafe(PREVIEW_ID_BYTES)
        placeholder = images.placeholder()
        stored: dict[str, StoredImage] = {}
        # 按唯一 cid 记录真实渲染结果；占位按引用实例记录
        rendered_cids: set[str] = set()
        placeholder_refs: list[str] = []

        def image_url_for(cid: str | None) -> str:
            key = secrets.token_urlsafe(KEY_BYTES)
            if cid is None:
                stored[key] = StoredImage(
                    placeholder.data, placeholder.media_type,
                    placeholder.extension, is_placeholder=True,
                )
                placeholder_refs.append(key)
            else:
                # 调用时 cid 一定是本邮件已知且被正文引用的 cid
                part = next(p for p in parsed.image_parts if p.cid == cid)
                reencoded = images.reencode(part.payload, part.part_type)
                if reencoded is None:
                    stored[key] = StoredImage(
                        placeholder.data, placeholder.media_type,
                        placeholder.extension, is_placeholder=True,
                    )
                    placeholder_refs.append(key)
                else:
                    stored[key] = StoredImage(
                        reencoded.data, reencoded.media_type,
                        reencoded.extension, is_placeholder=False,
                    )
                    rendered_cids.add(cid)
            return f"/preview/{preview_id}/img/{key}"

        known_cids = {p.cid for p in parsed.image_parts}
        try:
            safe_html = sanitize_html(parsed.html, known_cids, image_url_for)
        except SanitizeError as exc:
            raise PreviewError(str(exc)) from exc

        # 真实图按唯一 cid 计数（同一 cid 被引用多次只算一张）；
        # 占位图按引用实例计数（外部跟踪、缺失 cid 等是不同的拦截点）
        preview = Preview(
            preview_id=preview_id,
            safe_html=safe_html,
            created_at=time.monotonic(),
            images=stored,
            stats={
                "mime_parts": 1 + len(parsed.image_parts),
                "embedded_images": len(parsed.image_parts),
                "rendered_images": len(rendered_cids),
                "placeholders": len(placeholder_refs),
            },
        )
        with self._lock:
            self._purge_locked()
            self._previews[preview_id] = preview
        return preview

    def get(self, preview_id: str) -> Preview | None:
        with self._lock:
            preview = self._previews.get(preview_id)
            if preview is None:
                return None
            if time.monotonic() - preview.created_at > self._ttl:
                del self._previews[preview_id]
                return None
            return preview

    def get_image(self, preview_id: str, image_key: str) -> StoredImage | None:
        preview = self.get(preview_id)
        if preview is None:
            return None
        return preview.images.get(image_key)


# 进程级单例（单 worker 部署；见 Dockerfile 的 gunicorn 配置）
store = PreviewStore()
