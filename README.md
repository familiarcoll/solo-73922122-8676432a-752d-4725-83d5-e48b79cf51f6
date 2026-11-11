# 钓鱼邮件 · 安全预览台

安全分析员查看被举报的钓鱼邮件时，需要看清 HTML 正文，又不能触发邮件里的脚本、
远程跟踪像素或任何跳转。本服务接收浏览器上传的 `.eml`，在**受控解析 + 白名单清理 +
浏览器隔离**三重防护下渲染正文：不执行邮件代码、不加载外部资源、不访问父页面。

## 一、能力与约束

| 维度 | 规则 |
| --- | --- |
| 上传大小 | 最大 **1 MiB**，超限在读取阶段即拒绝（413） |
| 邮件结构 | 仅接受顶层 **multipart/related**，最多 **20 个 MIME 部分** |
| 正文 | 必须**恰好一份** `text/html`，且为严格 **UTF-8**（非法字节拒绝） |
| 嵌套 | 嵌套 multipart、`message/*` 嵌套文档一律拒绝 |
| 图片 | 仅接受带 `Content-ID` 的 **PNG/JPEG**；重复 Content-ID 拒绝 |
| 图片处理 | Pillow **实际解码后重新编码**输出，原始字节不直接下发；损坏/伪装/超像素→占位图 |
| 外部资源 | `http(s)`、`data:`、`//host` 等非 `cid:` 图片一律替换为服务端占位图 |
| 缺失 cid | 正文引用了邮件中不存在的 cid → 占位图 |
| 危险内容 | 剥离 `script/style/form/iframe/object/svg/meta/base/link` 等及整棵子树、全部 `on*` 事件、`style/class/id` 属性 |
| 链接 | `<a>` 降级为不可点击的 `<span>`，只展示**链接文字与原始地址**；`javascript:` 等不展示为地址 |
| 排版 | 保留段落、标题、强调、列表、表格、引用、预格式化等白名单结构 |

## 二、纵深防御（任意单层独立成立）

1. **结构层**（`app/eml_parser.py`）：白名单 MIME 类型、严格 UTF-8、cid 唯一性、
   部分数量与嵌套约束，输入不合法直接拒绝且**不创建任何预览**。
2. **内容层**（`app/sanitizer.py`）：基于标准库 `html.parser` 的**默认拒绝**白名单清理器。
   未显式允许的标签/属性没有任何保留路径；图片 `src` 被强制改写为同源预览 URL。
3. **浏览器隔离层**（响应头）：
   - 预览文档 `Content-Security-Policy: default-src 'none'; img-src 'self';
     style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'self'; base-uri 'none'`；
   - 图片响应 `default-src 'none'; frame-ancestors 'none'` + `X-Content-Type-Options: nosniff`；
   - 首页以无令牌 `sandbox=""` 的 iframe 嵌入预览（无脚本、无弹窗、无表单、无同源访问）。

**直接打开预览 URL 或图片 URL 同样安全**：隔离来自响应头与清理后的文档本身，
不依赖外层 iframe。

4. **数据隔离**：每次上传生成不可猜测的随机预览 ID，图片按 `(预览ID, 随机key)` 作用域存储。
   两封邮件即使使用**相同 Content-ID 也不会串图**；跨预览取图返回 404。
   预览仅存进程内存（容器根文件系统只读），带 30 分钟 TTL 与 64 份容量上限（LRU 淘汰），
   重启即清空。

## 三、启动

### 方式 A：Docker Compose（推荐，可实际演示）

```bash
docker compose up --build
# 浏览器打开 http://localhost:8000/
```

容器以非 root（uid 10001）、只读根文件系统、`no-new-privileges`、丢弃全部 Linux
capability 运行，不挂载任何宿主目录。单 uvicorn worker + 多线程，保证内存预览一致。

### 方式 B：本机 Python（3.11+）

```bash
python3 -m pip install -r requirements.txt
./run.sh                         # 等价 uvicorn app.main:app --workers 1
# 打开 http://localhost:8000/
```

健康检查：`GET /health`；约束查询：`GET /api/limits`；样例清单：`GET /api/samples`。

## 四、HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/` | 上传页（单文件、零外部依赖，可离线） |
| GET  | `/health` | 健康检查 |
| GET  | `/api/limits` | 上传大小与 MIME 部分上限 |
| GET  | `/api/samples` | 内置无害样例清单 |
| POST | `/api/preview` | multipart 表单字段 `file`；成功返回 `preview_id/preview_url/stats`，失败 4xx 且不产生预览 |
| GET  | `/preview/{id}` | 隔离预览文档（严格 CSP） |
| GET  | `/preview/{id}/img/{key}` | 重编码图片或占位图（严格 CSP、nosniff） |

## 五、内置样例

样例由 `tools/generate_samples.py` 生成（Pillow 构造，全部无害），随仓库分发于
`app/static/samples/`，可在首页直接载入：

- `sample1-malicious-tags.eml`：内嵌 PNG/JPEG（cid 引用）、外部跟踪像素、`data:` 图、
  缺失 cid、`script/on*/style/form/iframe/object/meta 跳转/noscript`、钓鱼链接、表格；
- `sample2-cid-collision.eml`：与样例 1 使用**相同 cid 但图片内容不同**（验证不串图），
  另含一份字节损坏的 PNG（验证解码失败回退占位）与缺失 cid。

重新生成：

```bash
python3 tools/generate_samples.py
```

## 六、测试

```bash
python3 -m pytest tests/ -q
```

覆盖（90+ 用例）：MIME 结构/编码/重复 cid/嵌套拒绝、HTML 白名单与各类 XSS 变异载荷、
图片解码重编码/格式伪装/解压炸弹/polyglot 尾部剥离、预览 TTL/LRU/cid 隔离、
API 安全响应头、错误不产生预览、两份样例的端到端渲染与隔离。

## 七、目录结构

```
app/
  eml_parser.py     # 受限 .eml 解析与结构校验
  images.py         # Pillow 解码重编码、像素上限、占位图
  sanitizer.py      # 白名单 HTML 清理（默认拒绝）
  storage.py        # 内存预览存储、TTL/LRU、cid 作用域隔离
  main.py           # FastAPI 路由与安全响应头
  static/
    index.html      # 上传页（沙箱 iframe 嵌入预览）
    samples/*.eml   # 两份无害样例
tools/
  generate_samples.py
tests/              # pytest 测试套件
Dockerfile, docker-compose.yml, requirements.txt, run.sh
```
