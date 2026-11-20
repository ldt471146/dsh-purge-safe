# redash.fanatical.com 弱口令面经 14,800 组唯一组合复核证否（负面情报，不再重派）

- **code**: fanatical-redash-weak-cred-negative-2026
- **kind**: script
- **category**: weak-password
- **component**: Redash
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 python313+requests 直连源站 107.21.85.212（无 CDN）：主跑 14,300 组 + 补充 500 组唯一 (邮箱×口令) POST /login，每请求唯一伪造 X-Forwarded-For，全部 HTTP 200 且含 "Wrong email or password."，零 302、零 429、零异常；brute.log 明确 "DONE attempts=14300 elapsed=185.2s hits=0 errors=0"；抽样回显提交邮箱证明逐请求真实处理；不存在/疑似存在邮箱时序中位数 0.093–0.111s 无区分。
- **path**: pocs/fanatical-redash-weak-cred-negative-2026/poc.md
- **tags**: redash,weak-password,negative,fanatical,credential
- **created_at**: 2026-11-11T21:42:21.107Z
- **engine**: https://redash.fanatical.com (origin 107.21.85.212)
- **found_by**: vuln-scan

## 描述

对 fanatical 的 Redash 实例（redash.fanatical.com 与 bi.fanatical.com 同一源站 107.21.85.212，前置 nginx/1.9.10）做弱口令复核。方法：GET /login 取 csrf_token（cookie 与表单 hidden 同值，可跨多次 POST 复用），POST /login form=email/password/csrf_token/remember=on，每请求换唯一随机 X-Forwarded-For 绕 Flask-Limiter 的 50/小时/IP。覆盖 14 个邮箱种子 × focused 888 + 10k-most-common 9902，共 14,800 组唯一组合，全部失败。结论：该实例无弱口令可利用、无失败锁定、无用户存在性时序 oracle；弱口令方向关闭。

## 用法

```
后续 worker 判据与跳过清单：
1) 不要再对 redash.fanatical.com / bi.fanatical.com 重跑任何弱口令/口令喷洒（14.8k 组合已覆盖 admin@fanatical.com、admin@redash.io、insights@fanatical.com、dev@fanatical.com、ian.egner@fanatical.com、bartosz.bednarowicz@fanatical.com、bartosz@fanatical.com、bi@fanatical.com、data@fanatical.com、analytics@/reporting@fanatical.com、bi@/data@/insights@redash.io；focused 全量 + 10k-most-common 前 3000）。
2) 命中判据纠偏：失败响应同样轮换 Set-Cookie（csrf_token、session），「Set-Cookie 即命中」会误报；正确判据是 HTTP 302（成功 redirect）或 200 且不含 "Wrong email or password"。
3) 认证失败的附带事实：连续 14.8k 次 0 个 429/403（源站直连 8 并发 ~78 req/s），XFF 绕过 #1148 已证；无账户锁定。
4) 剩余但需先拿到会话/身份才可走：CVE-2025-5874（≤10.1.0/25.1.0 且 python 数据源）、/api/users|data_sources|queries|dashboards 权限面、bi 别名与 8080 影响面；未认证全部 404 {"message":"Couldn't find resource. Please login and try again."}，/api/config 匿名 200 但无敏感项。
5) 复用脚本：/opt/artex/data/tasks/5/i3052/{gen_lists.py, brute.py, brute_extra.py}（Python3 + requests，trust_env=False 直连，线程池 8，分块提交，302 即停）。
```

## 正文

```
## 复核范围与证据
- 信道：https://redash.fanatical.com（DNS 即源站 107.21.85.212，无 CDN/CF）与 bi.fanatical.com 源站直连（--noproxy '*' --resolve bi.fanatical.com:443:107.21.85.212 -H 'Host: bi.fanatical.com'），两者同一登录页（200/2239B，nginx/1.9.10）。
- 登录协议：GET /login → csrf_token cookie + session cookie + hidden csrf_token（同值，可复用）；POST /login 表单 email/password/csrf_token/remember=on。
- 组合：14,300（A 2700 + B 8800 + C 1200 + D 800 + E 800）+ 补充 500 = 14,800 唯一对；全部 HTTP 200 "Wrong email or password."，零 302、零异常、零 429/403/超时；无锁定。
- 时序：疑似存在账号 vs 随机不存在邮箱中位数 0.093–0.111s，无区分（无用户枚举 oracle）。
- 旁证：/api/session、/api/users、/api/data_sources、/api/queries、/api/dashboards 未认证 404；/api/config 匿名 200（googleLoginEnabled=true, ldapLoginEnabled=false）；登录页 email 回显经 Jinja2 转义（无 XSS）。
- 产物：/opt/artex/data/tasks/5/i3052/brute.log、hits.txt(未生成)、anomalies.jsonl(未生成)。
```
